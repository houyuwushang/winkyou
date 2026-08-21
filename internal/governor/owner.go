package governor

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ownerLockFilename     = "governor.lock"
	ownerMetadataFilename = "governor.owner.json"
	maxOwnerFileBytes     = 16 << 10
)

var (
	// ErrOwnerHeld means another process owns the supplied safety namespace.
	ErrOwnerHeld = errors.New("governor namespace is already owned")

	// ErrInvalidNamespace means the supplied namespace cannot safely identify
	// one prepared lock location.
	ErrInvalidNamespace = errors.New("invalid governor namespace")

	// ErrOwnerInUse means a Governor currently owns the Owner lifecycle.
	ErrOwnerInUse = errors.New("governor namespace owner is in use")
)

// Scope is the safety boundary represented by an Owner.
type Scope string

const (
	ScopeMachine          Scope = "machine"
	ScopeUserAcknowledged Scope = "user_acknowledged"
)

func (s Scope) valid() bool {
	return s == ScopeMachine || s == ScopeUserAcknowledged
}

// OwnerInfo is diagnostic metadata. The operating-system lock, not this
// metadata, decides ownership.
type OwnerInfo struct {
	PID          int       `json:"pid"`
	InstanceID   string    `json:"instance_id"`
	StartedAt    time.Time `json:"started_at"`
	BuildVersion string    `json:"build_version"`
	Scope        Scope     `json:"scope"`
}

// OwnerHeldError carries best-effort diagnostics about the current owner.
// MetadataErr can be non-nil when a valid OS lock is held but stale or corrupt
// diagnostic data cannot be decoded.
type OwnerHeldError struct {
	Owner       OwnerInfo
	MetadataErr error
}

func (e *OwnerHeldError) Error() string {
	if e == nil {
		return ErrOwnerHeld.Error()
	}
	if e.Owner.PID > 0 {
		return fmt.Sprintf(
			"%s by pid %d (instance %s, build %s, scope %s)",
			ErrOwnerHeld,
			e.Owner.PID,
			e.Owner.InstanceID,
			e.Owner.BuildVersion,
			e.Owner.Scope,
		)
	}
	if e.MetadataErr != nil {
		return fmt.Sprintf("%s (owner metadata unavailable: %v)", ErrOwnerHeld, e.MetadataErr)
	}
	return ErrOwnerHeld.Error()
}

func (e *OwnerHeldError) Unwrap() error {
	return ErrOwnerHeld
}

// Owner holds the operating-system lock for one prepared safety namespace.
// The lock file is intentionally retained after Close so contenders never
// split across file identities.
type Owner struct {
	mu            sync.Mutex
	file          *os.File
	lockPath      string
	tripStore     *safetyTripStore
	pairingLedger *PairingAdmissionLedger
	info          OwnerInfo
	closed        bool
	claimed       bool
}

// AcquirePreparedNamespace acquires an OS-level exclusive lock in namespace.
//
// The namespace must already exist, be absolute, be a real directory, and be
// protected by its installer or per-user parent. Machine-scoped production
// callers should use AcquireMachineNamespace, which chooses and validates the
// canonical platform path first. Requiring a prepared directory prevents this
// low-level primitive from silently falling back to an arbitrary data directory.
func AcquirePreparedNamespace(namespace string, scope Scope, buildVersion string) (*Owner, error) {
	if !scope.valid() {
		return nil, fmt.Errorf("%w: unsupported scope %q", ErrInvalidNamespace, scope)
	}
	if buildVersion == "" {
		buildVersion = "unknown"
	}
	if len(buildVersion) > 128 {
		return nil, fmt.Errorf("%w: build version is too long", ErrInvalidNamespace)
	}
	if err := validateIdentifier("build version", buildVersion); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidNamespace, err)
	}

	clean, err := validatePreparedNamespace(namespace)
	if err != nil {
		return nil, err
	}
	lockPath := filepath.Join(clean, ownerLockFilename)
	metadataPath := filepath.Join(clean, ownerMetadataFilename)
	if err := rejectSymlink(lockPath); err != nil {
		return nil, err
	}
	if err := rejectSymlink(metadataPath); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open governor owner file: %w", err)
	}
	if err := lockOwnerFile(file); err != nil {
		if errors.Is(err, ErrOwnerHeld) {
			info, metadataErr := readOwnerInfo(metadataPath)
			_ = file.Close()
			return nil, &OwnerHeldError{Owner: info, MetadataErr: metadataErr}
		}
		_ = file.Close()
		return nil, err
	}

	instanceID, err := newInstanceID()
	if err != nil {
		_ = unlockOwnerFile(file)
		_ = file.Close()
		return nil, fmt.Errorf("create governor owner instance id: %w", err)
	}
	info := OwnerInfo{
		PID:          os.Getpid(),
		InstanceID:   instanceID,
		StartedAt:    time.Now().UTC(),
		BuildVersion: buildVersion,
		Scope:        scope,
	}
	if err := writeOwnerInfo(metadataPath, info); err != nil {
		_ = unlockOwnerFile(file)
		_ = file.Close()
		return nil, err
	}

	return &Owner{
		file:      file,
		lockPath:  lockPath,
		tripStore: newSafetyTripStore(clean),
		info:      info,
	}, nil
}

func validatePreparedNamespace(namespace string) (string, error) {
	if strings.TrimSpace(namespace) == "" {
		return "", fmt.Errorf("%w: path is empty", ErrInvalidNamespace)
	}
	clean := filepath.Clean(namespace)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: path must be absolute", ErrInvalidNamespace)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return "", fmt.Errorf("%w: inspect prepared path: %v", ErrInvalidNamespace, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%w: namespace cannot be a symlink", ErrInvalidNamespace)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%w: namespace is not a directory", ErrInvalidNamespace)
	}
	return clean, nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: inspect owner file: %v", ErrInvalidNamespace, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: owner file cannot be a symlink", ErrInvalidNamespace)
	}
	if info.IsDir() {
		return fmt.Errorf("%w: owner file path is a directory", ErrInvalidNamespace)
	}
	return nil
}

func newInstanceID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func writeOwnerInfo(path string, info OwnerInfo) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open governor owner metadata: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate governor owner metadata: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek governor owner metadata: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(info); err != nil {
		return fmt.Errorf("write governor owner metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync governor owner metadata: %w", err)
	}
	return nil
}

func readOwnerInfo(path string) (OwnerInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return OwnerInfo{}, err
	}
	defer func() { _ = file.Close() }()
	fileInfo, err := file.Stat()
	if err != nil {
		return OwnerInfo{}, fmt.Errorf("stat owner metadata: %w", err)
	}
	if fileInfo.Size() > maxOwnerFileBytes {
		return OwnerInfo{}, fmt.Errorf("owner metadata exceeds %d bytes", maxOwnerFileBytes)
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxOwnerFileBytes))
	var info OwnerInfo
	if err := decoder.Decode(&info); err != nil {
		return OwnerInfo{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return OwnerInfo{}, errors.New("owner metadata contains trailing JSON")
		}
		return OwnerInfo{}, fmt.Errorf("decode trailing owner metadata: %w", err)
	}
	if err := validateOwnerInfo(info); err != nil {
		return OwnerInfo{}, err
	}
	return info, nil
}

func validateOwnerInfo(info OwnerInfo) error {
	if info.PID <= 0 {
		return errors.New("owner metadata PID must be positive")
	}
	if info.StartedAt.IsZero() {
		return errors.New("owner metadata start time is missing")
	}
	if !info.Scope.valid() {
		return fmt.Errorf("owner metadata scope %q is invalid", info.Scope)
	}
	if err := validateIdentifier("owner instance id", info.InstanceID); err != nil {
		return fmt.Errorf("invalid owner metadata: %w", err)
	}
	if len(info.InstanceID) != 32 {
		return errors.New("owner metadata instance id must contain 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(info.InstanceID); err != nil {
		return fmt.Errorf("owner metadata instance id is not hexadecimal: %w", err)
	}
	if len(info.BuildVersion) > 128 {
		return errors.New("owner metadata build version is too long")
	}
	if err := validateIdentifier("owner build version", info.BuildVersion); err != nil {
		return fmt.Errorf("invalid owner metadata: %w", err)
	}
	return nil
}

// Info returns immutable diagnostic metadata for this owner.
func (o *Owner) Info() OwnerInfo {
	if o == nil {
		return OwnerInfo{}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.info
}

// Scope returns the boundary represented by this owner.
func (o *Owner) Scope() Scope {
	return o.Info().Scope
}

// SafetyTripStatus reads the persistent circuit state associated with this
// owner's prepared namespace.
func (o *Owner) SafetyTripStatus() SafetyTripStatus {
	if o == nil || o.tripStore == nil {
		return indeterminateSafetyTripStatus("namespace owner has no safety trip store")
	}
	return o.tripStore.status()
}

func (o *Owner) usable() bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return !o.closed && o.file != nil
}

func (o *Owner) claim() error {
	if o == nil {
		return fmt.Errorf("%w: owner is nil", ErrInvalidRequest)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.file == nil {
		return fmt.Errorf("%w: owner is closed", ErrInvalidRequest)
	}
	if o.claimed {
		return ErrOwnerInUse
	}
	o.claimed = true
	return nil
}

// Close releases ownership. It is idempotent.
func (o *Owner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.claimed {
		return ErrOwnerInUse
	}
	return o.closeLocked()
}

func (o *Owner) closeClaimed() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.claimed = false
	return o.closeLocked()
}

func (o *Owner) closeLocked() error {
	if o.closed {
		return nil
	}
	o.closed = true
	if o.file == nil {
		return nil
	}
	unlockErr := unlockOwnerFile(o.file)
	closeErr := o.file.Close()
	o.file = nil
	return errors.Join(unlockErr, closeErr)
}
