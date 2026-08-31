package gatecstage

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/pairgen"
)

const (
	SlotSchema      = "winkyou-gate-c-responder-stage/1"
	pendingFilename = "gate-c-responder-pending-v1.json"
	claimedFilename = "gate-c-responder-claimed-v1.json"
	maxSlotBytes    = gatecrequest.MaxRequestBytes + 2048
)

var (
	ErrStageInvalid     = errors.New("gatecstage: invalid responder stage")
	ErrStageUnavailable = errors.New("gatecstage: responder stage unavailable")
	ErrStageConflict    = errors.New("gatecstage: responder stage conflict")
)

type slot struct {
	Schema              string          `json:"schema"`
	State               string          `json:"state"`
	ArtifactFingerprint string          `json:"artifact_fingerprint"`
	ExpiresAt           string          `json:"expires_at"`
	Request             json.RawMessage `json:"request"`
}

// Claimed contains the already validated local request and the one-shot
// product artifact. Close must be called to zero the artifact secret.
type Claimed struct {
	Request  gatecrequest.Request
	Artifact *gatecattempt.Artifact
}

func (claimed *Claimed) Close() {
	if claimed == nil {
		return
	}
	if claimed.Artifact != nil {
		claimed.Artifact.Close()
	}
	claimed.Request = gatecrequest.Request{}
	claimed.Artifact = nil
}

type dependencies struct{ afterClaimCommit func() error }

// Stage validates a private responder request and creates the canonical
// pending slot with O_EXCL. It performs no active or network operation.
func Stage(requestFile string, now time.Time) error {
	root, err := canonicalRoot()
	if err != nil {
		return err
	}
	return stageAt(root, requestFile, now.UTC())
}

// ClaimPending atomically consumes the canonical pending slot. A durable
// claimed tombstone remains until explicit fingerprint-matched cleanup, so a
// failed child can never automatically re-arm the request.
func ClaimPending(now time.Time) (*Claimed, error) {
	root, err := canonicalRoot()
	if err != nil {
		return nil, err
	}
	return claimAt(root, now.UTC(), dependencies{})
}

// Cleanup removes only fixed slot filenames whose contents all match the
// explicitly supplied product artifact fingerprint. It never scans or queues.
func Cleanup(expectedFingerprint string) error {
	root, err := canonicalRoot()
	if err != nil {
		return err
	}
	return cleanupAt(root, expectedFingerprint)
}

func canonicalRoot() (string, error) {
	status := governor.InspectMachineNamespace()
	if !status.Ready || status.Path == "" {
		return "", ErrStageUnavailable
	}
	return status.Path, nil
}

func stageAt(root, requestFile string, now time.Time) error {
	if root == "" || now.IsZero() {
		return ErrStageInvalid
	}
	if count, err := slotCount(root); err != nil || count != 0 {
		if err != nil {
			return ErrStageUnavailable
		}
		return ErrStageConflict
	}
	request, err := gatecrequest.LoadPrivate(requestFile)
	if err != nil || request.Role != gatecattempt.RoleResponder || request.SSH != nil {
		return ErrStageInvalid
	}
	artifactPayload, err := pairgen.ReadPrivateFile(request.ArtifactFile, gatecattempt.MaxArtifactBytes)
	if err != nil {
		return ErrStageInvalid
	}
	defer clear(artifactPayload)
	artifact, err := gatecattempt.ParseArtifact(artifactPayload, now)
	if err != nil {
		return ErrStageInvalid
	}
	defer artifact.Close()
	if artifact.LocalRole != gatecattempt.RoleResponder {
		return ErrStageInvalid
	}
	requestPayload, err := gatecrequest.Encode(request)
	if err != nil {
		return ErrStageInvalid
	}
	defer clear(requestPayload)
	encoded, err := encodeSlot(slot{
		Schema: SlotSchema, State: "pending", ArtifactFingerprint: artifact.Fingerprint,
		ExpiresAt: artifact.ExpiresAt.Format(time.RFC3339), Request: requestPayload,
	})
	if err != nil {
		return ErrStageInvalid
	}
	defer clear(encoded)
	if err := pairgen.WritePrivateFileExclusive(filepath.Join(root, pendingFilename), encoded); err != nil {
		return ErrStageConflict
	}
	if err := pairgen.SyncPrivateDirectory(root); err != nil {
		return ErrStageUnavailable
	}
	// A concurrent fixed-name claim/cleanup cannot silently turn a one-slot
	// state into authority. Any resulting two-file state remains fail-closed.
	if count, err := slotCount(root); err != nil || count != 1 {
		return ErrStageConflict
	}
	return nil
}

func claimAt(root string, now time.Time, deps dependencies) (*Claimed, error) {
	if root == "" || now.IsZero() {
		return nil, ErrStageInvalid
	}
	if count, err := slotCount(root); err != nil || count != 1 {
		if err != nil {
			return nil, ErrStageUnavailable
		}
		return nil, ErrStageConflict
	}
	pendingPath := filepath.Join(root, pendingFilename)
	if _, err := os.Lstat(filepath.Join(root, claimedFilename)); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrStageConflict
	}
	pendingPayload, err := pairgen.ReadPrivateFile(pendingPath, maxSlotBytes)
	if err != nil {
		return nil, ErrStageInvalid
	}
	defer clear(pendingPayload)
	pending, request, artifact, err := validateSlot(pendingPayload, "pending", now)
	if err != nil {
		return nil, err
	}
	claimedPayload, err := encodeSlot(slot{
		Schema: SlotSchema, State: "claimed", ArtifactFingerprint: pending.ArtifactFingerprint,
		ExpiresAt: pending.ExpiresAt, Request: pending.Request,
	})
	if err != nil {
		artifact.Close()
		return nil, ErrStageInvalid
	}
	defer clear(claimedPayload)
	claimedPath := filepath.Join(root, claimedFilename)
	if err := pairgen.WritePrivateFileExclusive(claimedPath, claimedPayload); err != nil {
		artifact.Close()
		return nil, ErrStageConflict
	}
	if err := pairgen.SyncPrivateDirectory(root); err != nil {
		artifact.Close()
		return nil, ErrStageUnavailable
	}
	if deps.afterClaimCommit != nil {
		if err := deps.afterClaimCommit(); err != nil {
			artifact.Close()
			return nil, ErrStageUnavailable
		}
	}
	if err := os.Remove(pendingPath); err != nil {
		artifact.Close()
		return nil, ErrStageUnavailable
	}
	if err := pairgen.SyncPrivateDirectory(root); err != nil {
		artifact.Close()
		return nil, ErrStageUnavailable
	}
	return &Claimed{Request: request, Artifact: artifact}, nil
}

func cleanupAt(root, expectedFingerprint string) error {
	if root == "" || expectedFingerprint == "" {
		return ErrStageInvalid
	}
	paths := []string{filepath.Join(root, pendingFilename), filepath.Join(root, claimedFilename)}
	found := make([]string, 0, len(paths))
	for _, path := range paths {
		payload, err := pairgen.ReadPrivateFile(path, maxSlotBytes)
		if err != nil {
			if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return ErrStageInvalid
		}
		var candidate slot
		decodeErr := decodeSlot(payload, &candidate)
		clear(payload)
		if decodeErr != nil || candidate.ArtifactFingerprint != expectedFingerprint {
			return ErrStageInvalid
		}
		found = append(found, path)
	}
	if len(found) == 0 {
		return ErrStageConflict
	}
	for _, path := range found {
		if err := os.Remove(path); err != nil {
			return ErrStageUnavailable
		}
	}
	if err := pairgen.SyncPrivateDirectory(root); err != nil {
		return ErrStageUnavailable
	}
	return nil
}

func validateSlot(payload []byte, wantState string, now time.Time) (slot, gatecrequest.Request, *gatecattempt.Artifact, error) {
	var value slot
	if decodeSlot(payload, &value) != nil || value.State != wantState {
		return slot{}, gatecrequest.Request{}, nil, ErrStageInvalid
	}
	expiresAt, err := time.Parse(time.RFC3339, value.ExpiresAt)
	if err != nil || !now.Before(expiresAt) || expiresAt.Nanosecond() != 0 {
		return slot{}, gatecrequest.Request{}, nil, ErrStageInvalid
	}
	request, err := gatecrequest.Parse(value.Request)
	if err != nil || request.Role != gatecattempt.RoleResponder || request.SSH != nil {
		return slot{}, gatecrequest.Request{}, nil, ErrStageInvalid
	}
	artifactPayload, err := pairgen.ReadPrivateFile(request.ArtifactFile, gatecattempt.MaxArtifactBytes)
	if err != nil {
		return slot{}, gatecrequest.Request{}, nil, ErrStageInvalid
	}
	defer clear(artifactPayload)
	artifact, err := gatecattempt.ParseArtifact(artifactPayload, now)
	if err != nil || artifact.LocalRole != gatecattempt.RoleResponder || artifact.Fingerprint != value.ArtifactFingerprint || artifact.ExpiresAt != expiresAt {
		if artifact != nil {
			artifact.Close()
		}
		return slot{}, gatecrequest.Request{}, nil, ErrStageInvalid
	}
	return value, request, artifact, nil
}

func encodeSlot(value slot) ([]byte, error) {
	if value.Schema != SlotSchema || (value.State != "pending" && value.State != "claimed") ||
		value.ArtifactFingerprint == "" || len(value.Request) == 0 {
		return nil, ErrStageInvalid
	}
	payload, err := json.Marshal(value)
	if err != nil || len(payload) > maxSlotBytes {
		return nil, ErrStageInvalid
	}
	return payload, nil
}

func decodeSlot(payload []byte, destination *slot) error {
	if destination == nil || len(payload) == 0 || len(payload) > maxSlotBytes || !json.Valid(payload) {
		return ErrStageInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrStageInvalid
	}
	if destination.Schema != SlotSchema || (destination.State != "pending" && destination.State != "claimed") ||
		destination.ArtifactFingerprint == "" || len(destination.Request) == 0 {
		return ErrStageInvalid
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(payload, canonical) {
		return ErrStageInvalid
	}
	return nil
}

func slotCount(root string) (int, error) {
	count := 0
	for _, name := range []string{pendingFilename, claimedFilename} {
		info, err := os.Lstat(filepath.Join(root, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return 0, ErrStageUnavailable
		}
		count++
	}
	return count, nil
}
