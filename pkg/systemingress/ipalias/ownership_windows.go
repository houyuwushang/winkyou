//go:build windows

package ipalias

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"winkyou/pkg/processidentity"
)

const ownershipMarkerVersion = 1

const (
	ownershipPhaseIntent   = "intent"
	ownershipPhaseActive   = "active"
	ownershipPhaseDeleting = "deleting"
)

type ownershipMarker struct {
	Version           int    `json:"version"`
	InterfaceIndex    int    `json:"interface_index"`
	Address           string `json:"address"`
	OwnerScope        string `json:"owner_scope"`
	ConfigFingerprint string `json:"config_fingerprint"`
	InstanceID        string `json:"instance_id"`
	PID               int    `json:"pid"`
	ProcessStartID    string `json:"process_start_id"`
	Token             string `json:"token"`
	Phase             string `json:"phase"`
	RowCreationID     string `json:"row_creation_id,omitempty"`
}

type processMatcher func(int, string) (bool, error)

type ownershipStore struct {
	dir               string
	interfaceIndex    int
	ownerScope        string
	configFingerprint string
	instanceID        string
	pid               int
	processStartID    string
	matches           processMatcher
}

type aliasClaim struct {
	store         *ownershipStore
	address       string
	markerPath    string
	lockFile      *os.File
	token         string
	recoverable   bool
	wroteMarker   bool
	previous      *ownershipMarker
	rowCreationID string
}

func newOwnershipStore(options OwnershipOptions, interfaceIndex int) (*ownershipStore, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	if interfaceIndex <= 0 {
		return nil, fmt.Errorf("system ingress ipalias: invalid ownership interface index %d", interfaceIndex)
	}
	dir := strings.TrimSpace(options.StoreDir)
	if dir == "" {
		base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
		if err != nil {
			return nil, fmt.Errorf("system ingress ipalias: resolve machine-wide ownership store: %w", err)
		}
		base = strings.TrimSpace(base)
		if base == "" {
			return nil, fmt.Errorf("system ingress ipalias: machine-wide ownership store path is empty")
		}
		dir = filepath.Join(base, "WinkYou", "system-ingress-ipalias")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("system ingress ipalias: create ownership store: %w", err)
	}
	scopeSum := sha256.Sum256([]byte(strings.TrimSpace(options.Scope)))
	return &ownershipStore{
		dir: filepath.Clean(dir), interfaceIndex: interfaceIndex,
		ownerScope: hex.EncodeToString(scopeSum[:]), configFingerprint: strings.TrimSpace(options.ConfigFingerprint),
		instanceID: strings.TrimSpace(options.InstanceID), pid: options.PID,
		processStartID: strings.TrimSpace(options.ProcessStartID), matches: processidentity.Matches,
	}, nil
}

func (s *ownershipStore) acquire(address string) (*aliasClaim, error) {
	keySum := sha256.Sum256([]byte(fmt.Sprintf("%d\x00%s", s.interfaceIndex, address)))
	base := fmt.Sprintf("if%d-%s", s.interfaceIndex, hex.EncodeToString(keySum[:]))
	lockPath := filepath.Join(s.dir, base+".lock")
	markerPath := filepath.Join(s.dir, base+".json")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("system ingress ipalias: open ownership lock: %w", err)
	}
	if err := lockOwnershipFile(lockFile); err != nil {
		_ = lockFile.Close()
		return nil, err
	}
	token, err := randomOwnershipToken()
	if err != nil {
		_ = unlockOwnershipFile(lockFile)
		_ = lockFile.Close()
		return nil, err
	}
	claim := &aliasClaim{store: s, address: address, markerPath: markerPath, lockFile: lockFile, token: token}
	marker, exists, err := loadOwnershipMarker(markerPath)
	if err != nil {
		claim.release()
		return nil, err
	}
	if !exists {
		return claim, nil
	}
	if err := s.validateMarker(marker, address); err != nil {
		claim.release()
		return nil, err
	}
	alive, err := s.matches(marker.PID, marker.ProcessStartID)
	if err != nil {
		claim.release()
		return nil, fmt.Errorf("%w: verify previous owner pid %d: %v", ErrOwnershipConflict, marker.PID, err)
	}
	if alive {
		claim.release()
		return nil, fmt.Errorf("%w: address %s belongs to live pid %d", ErrOwnershipConflict, address, marker.PID)
	}
	claim.recoverable = true
	markerCopy := marker
	claim.previous = &markerCopy
	return claim, nil
}

func (s *ownershipStore) validateMarker(marker ownershipMarker, address string) error {
	if marker.Version != ownershipMarkerVersion || marker.InterfaceIndex != s.interfaceIndex || marker.Address != address {
		return fmt.Errorf("%w: ownership marker identity does not match address %s", ErrOwnershipConflict, address)
	}
	if marker.OwnerScope != s.ownerScope || marker.ConfigFingerprint != s.configFingerprint {
		return fmt.Errorf("%w: address %s belongs to another owner scope or configuration", ErrOwnershipConflict, address)
	}
	if marker.PID <= 0 || strings.TrimSpace(marker.ProcessStartID) == "" || strings.TrimSpace(marker.InstanceID) == "" ||
		strings.TrimSpace(marker.Token) == "" {
		return fmt.Errorf("%w: address %s has an incomplete ownership marker", ErrOwnershipConflict, address)
	}
	switch marker.Phase {
	case ownershipPhaseIntent, ownershipPhaseActive, ownershipPhaseDeleting:
		if marker.Phase == ownershipPhaseActive && strings.TrimSpace(marker.RowCreationID) == "" {
			return fmt.Errorf("%w: active address %s has no row creation identity", ErrOwnershipConflict, address)
		}
		return nil
	default:
		return fmt.Errorf("%w: address %s has unknown ownership phase %q", ErrOwnershipConflict, address, marker.Phase)
	}
}

func (c *aliasClaim) validateRecovery(state aliasAddressState) error {
	if c == nil || !c.recoverable || c.previous == nil {
		address := "<unknown>"
		if c != nil {
			address = c.address
		}
		return fmt.Errorf("%w: address %s has no recoverable ownership marker", ErrOwnershipConflict, address)
	}
	if !state.validOwnedShape() {
		return fmt.Errorf(
			"%w: address %s has prefix /%d skip-as-source=%t, want /128 and true",
			ErrOwnershipConflict, c.address, state.PrefixLength, state.SkipAsSource,
		)
	}
	previousRowID := strings.TrimSpace(c.previous.RowCreationID)
	switch c.previous.Phase {
	case ownershipPhaseActive:
		if previousRowID != state.RowCreationID {
			return fmt.Errorf("%w: operating-system row identity changed for address %s", ErrOwnershipConflict, c.address)
		}
	case ownershipPhaseDeleting:
		if previousRowID != "" && previousRowID != state.RowCreationID {
			return fmt.Errorf("%w: deleting operating-system row identity changed for address %s", ErrOwnershipConflict, c.address)
		}
	case ownershipPhaseIntent:
		// The intent marker is deliberately written before the netsh mutation,
		// so a crash between netsh and the active commit has no row identity yet.
	default:
		return fmt.Errorf("%w: unknown previous ownership phase %q for %s", ErrOwnershipConflict, c.previous.Phase, c.address)
	}
	return nil
}

func (c *aliasClaim) write(phase string) error {
	if c.wroteMarker {
		marker, exists, err := loadOwnershipMarker(c.markerPath)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: ownership marker disappeared for %s", ErrOwnershipConflict, c.address)
		}
		if err := c.store.validateMarker(marker, c.address); err != nil {
			return err
		}
		if marker.Token != c.token {
			return fmt.Errorf("%w: ownership token changed for %s", ErrOwnershipConflict, c.address)
		}
	}
	marker := ownershipMarker{
		Version: ownershipMarkerVersion, InterfaceIndex: c.store.interfaceIndex, Address: c.address,
		OwnerScope: c.store.ownerScope, ConfigFingerprint: c.store.configFingerprint,
		InstanceID: c.store.instanceID, PID: c.store.pid, ProcessStartID: c.store.processStartID,
		Token: c.token, Phase: phase, RowCreationID: c.rowCreationID,
	}
	data, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		return fmt.Errorf("system ingress ipalias: encode ownership marker: %w", err)
	}
	data = append(data, '\n')
	if err := atomicWriteOwnershipFile(c.markerPath, data); err != nil {
		return err
	}
	c.wroteMarker = true
	return nil
}

func (c *aliasClaim) removeMarker() error {
	marker, exists, err := loadOwnershipMarker(c.markerPath)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: ownership marker disappeared before cleanup of %s", ErrOwnershipConflict, c.address)
	}
	if err := c.store.validateMarker(marker, c.address); err != nil {
		return err
	}
	if marker.Token != c.token {
		return fmt.Errorf("%w: ownership marker changed before cleanup of %s", ErrOwnershipConflict, c.address)
	}
	if err := os.Remove(c.markerPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("system ingress ipalias: remove ownership marker: %w", err)
	}
	c.wroteMarker = false
	return nil
}

func (c *aliasClaim) release() {
	if c == nil || c.lockFile == nil {
		return
	}
	_ = unlockOwnershipFile(c.lockFile)
	_ = c.lockFile.Close()
	c.lockFile = nil
}

func loadOwnershipMarker(path string) (ownershipMarker, bool, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return ownershipMarker{}, false, nil
	}
	if err != nil {
		return ownershipMarker{}, false, fmt.Errorf("system ingress ipalias: read ownership marker: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker ownershipMarker
	if err := decoder.Decode(&marker); err != nil {
		return ownershipMarker{}, false, fmt.Errorf("%w: decode ownership marker: %v", ErrOwnershipConflict, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return ownershipMarker{}, false, fmt.Errorf("%w: ownership marker has multiple JSON values", ErrOwnershipConflict)
		}
		return ownershipMarker{}, false, fmt.Errorf("%w: decode ownership marker trailing data: %v", ErrOwnershipConflict, err)
	}
	return marker, true, nil
}

func randomOwnershipToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("system ingress ipalias: generate ownership token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func atomicWriteOwnershipFile(path string, data []byte) (retErr error) {
	temp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("system ingress ipalias: create ownership marker temp: %w", err)
	}
	tempPath := temp.Name()
	defer func() {
		_ = temp.Close()
		if retErr != nil {
			_ = os.Remove(tempPath)
		}
	}()
	if err := temp.Chmod(0o600); err != nil {
		return fmt.Errorf("system ingress ipalias: chmod ownership marker temp: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("system ingress ipalias: write ownership marker temp: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("system ingress ipalias: sync ownership marker temp: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("system ingress ipalias: close ownership marker temp: %w", err)
	}
	oldPtr, err := windows.UTF16PtrFromString(tempPath)
	if err != nil {
		return fmt.Errorf("system ingress ipalias: encode ownership marker temp path: %w", err)
	}
	newPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("system ingress ipalias: encode ownership marker path: %w", err)
	}
	if err := windows.MoveFileEx(oldPtr, newPtr, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return fmt.Errorf("system ingress ipalias: replace ownership marker: %w", err)
	}
	return nil
}

func lockOwnershipFile(file *os.File) error {
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, new(windows.Overlapped))
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return fmt.Errorf("system ingress ipalias: lock ownership file: %w", err)
		}
		if !time.Now().Before(deadline) {
			return ErrOwnershipLocked
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func unlockOwnershipFile(file *os.File) error {
	if err := windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, new(windows.Overlapped)); err != nil {
		return fmt.Errorf("system ingress ipalias: unlock ownership file: %w", err)
	}
	return nil
}
