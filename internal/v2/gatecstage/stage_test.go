package gatecstage

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/pairgen"
)

func TestStageClaimAndExplicitCleanup(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	environment := newStageEnvironment(t, now, gatecattempt.RoleResponder)
	if err := stageAt(environment.root, environment.requestFile, now); err != nil {
		t.Fatalf("stageAt: %v", err)
	}
	if err := stageAt(environment.root, environment.requestFile, now); !errors.Is(err, ErrStageConflict) {
		t.Fatalf("second stageAt error=%v, want conflict", err)
	}
	claimed, err := claimAt(environment.root, now, dependencies{})
	if err != nil {
		t.Fatalf("claimAt: %v", err)
	}
	defer claimed.Close()
	if claimed.Request.Role != gatecattempt.RoleResponder || claimed.Artifact.LocalRole != gatecattempt.RoleResponder ||
		claimed.Artifact.Fingerprint != environment.fingerprint {
		t.Fatal("claimed responder binding mismatch")
	}
	if _, err := os.Lstat(filepath.Join(environment.root, pendingFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending still exists: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(environment.root, claimedFilename)); err != nil {
		t.Fatalf("claimed tombstone missing: %v", err)
	}
	if _, err := claimAt(environment.root, now, dependencies{}); !errors.Is(err, ErrStageConflict) {
		t.Fatalf("second claim error=%v, want conflict", err)
	}
	if err := cleanupAt(environment.root, opaqueID(99, 32)); !errors.Is(err, ErrStageInvalid) {
		t.Fatalf("wrong fingerprint cleanup error=%v", err)
	}
	if err := cleanupAt(environment.root, environment.fingerprint); err != nil {
		t.Fatalf("cleanupAt: %v", err)
	}
	if count, err := slotCount(environment.root); err != nil || count != 0 {
		t.Fatalf("slot count after cleanup=%d err=%v", count, err)
	}
}

func TestClaimCommitCrashNeverRearmsPending(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	environment := newStageEnvironment(t, now, gatecattempt.RoleResponder)
	if err := stageAt(environment.root, environment.requestFile, now); err != nil {
		t.Fatalf("stageAt: %v", err)
	}
	injected := errors.New("simulated crash after claim commit")
	if _, err := claimAt(environment.root, now, dependencies{afterClaimCommit: func() error { return injected }}); !errors.Is(err, ErrStageUnavailable) {
		t.Fatalf("claimAt injected error=%v", err)
	}
	if count, err := slotCount(environment.root); err != nil || count != 2 {
		t.Fatalf("crash slot count=%d err=%v, want two-file fail-closed state", count, err)
	}
	if _, err := claimAt(environment.root, now, dependencies{}); !errors.Is(err, ErrStageConflict) {
		t.Fatalf("post-crash claim error=%v, want conflict", err)
	}
	if err := cleanupAt(environment.root, environment.fingerprint); err != nil {
		t.Fatalf("explicit crash cleanup: %v", err)
	}
}

func TestClaimRejectsZeroAndTwoSlotsBeforeArtifactUse(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	root := privateRoot(t)
	if _, err := claimAt(root, now, dependencies{}); !errors.Is(err, ErrStageConflict) {
		t.Fatalf("zero-slot claim error=%v", err)
	}
	environment := newStageEnvironmentAt(t, root, now, gatecattempt.RoleResponder)
	if err := stageAt(root, environment.requestFile, now); err != nil {
		t.Fatalf("stageAt: %v", err)
	}
	payload, err := pairgen.ReadPrivateFile(filepath.Join(root, pendingFilename), maxSlotBytes)
	if err != nil {
		t.Fatalf("read pending: %v", err)
	}
	if err := pairgen.WritePrivateFileExclusive(filepath.Join(root, claimedFilename), payload); err != nil {
		clear(payload)
		t.Fatalf("write second slot: %v", err)
	}
	clear(payload)
	if _, err := claimAt(root, now, dependencies{}); !errors.Is(err, ErrStageConflict) {
		t.Fatalf("two-slot claim error=%v", err)
	}
}

func TestStageRejectsExpiredForeignRoleAndUnsafeArtifact(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expired := newStageEnvironment(t, now.Add(-10*time.Minute), gatecattempt.RoleResponder)
	if err := stageAt(expired.root, expired.requestFile, now); !errors.Is(err, ErrStageInvalid) {
		t.Fatalf("expired stage error=%v", err)
	}
	foreign := newStageEnvironment(t, now, gatecattempt.RoleInitiator)
	if err := stageAt(foreign.root, foreign.requestFile, now); !errors.Is(err, ErrStageInvalid) {
		t.Fatalf("foreign-role stage error=%v", err)
	}

	unsafe := newStageEnvironment(t, now, gatecattempt.RoleResponder)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(unsafe.artifactFile, 0o644); err != nil {
			t.Fatalf("chmod artifact: %v", err)
		}
		if err := stageAt(unsafe.root, unsafe.requestFile, now); !errors.Is(err, ErrStageInvalid) {
			t.Fatalf("unsafe artifact stage error=%v", err)
		}
	}
}

func TestStageRejectsArtifactSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unprivileged Windows symlink creation is not guaranteed")
	}
	now := time.Now().UTC().Truncate(time.Second)
	environment := newStageEnvironment(t, now, gatecattempt.RoleResponder)
	link := filepath.Join(filepath.Dir(environment.artifactFile), "artifact-link.json")
	if err := os.Symlink(environment.artifactFile, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	request := environment.request
	request.ArtifactFile = link
	payload, err := gatecrequest.Encode(request)
	if err != nil {
		t.Fatalf("Encode linked request: %v", err)
	}
	linkedRequest := filepath.Join(t.TempDir(), "linked-request.json")
	if err := pairgen.WritePrivateFileExclusive(linkedRequest, payload); err != nil {
		clear(payload)
		t.Fatalf("write linked request: %v", err)
	}
	clear(payload)
	if err := stageAt(environment.root, linkedRequest, now); !errors.Is(err, ErrStageInvalid) {
		t.Fatalf("symlink artifact stage error=%v", err)
	}
}

type stageEnvironment struct {
	root, requestFile, artifactFile, fingerprint string
	request                                      gatecrequest.Request
}

func newStageEnvironment(t *testing.T, issuedAt time.Time, artifactRole gatecattempt.Role) stageEnvironment {
	t.Helper()
	return newStageEnvironmentAt(t, privateRoot(t), issuedAt, artifactRole)
}

func newStageEnvironmentAt(t *testing.T, root string, issuedAt time.Time, artifactRole gatecattempt.Role) stageEnvironment {
	t.Helper()
	var psk [32]byte
	for index := range psk {
		psk[index] = byte(index + 1)
	}
	set, err := gatecattempt.EncodeArtifactSet(gatecattempt.ArtifactMaterial{
		CredentialID: opaqueID(1, 16), AttemptID: opaqueID(2, 16), InitiatorParticipantID: opaqueID(3, 16),
		ResponderParticipantID: opaqueID(4, 16), OOBChannelID: opaqueID(5, 16),
		PlannerProfile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive,
		InitiatorPlannerRole: hardnatplan.RoleInitiator, ResponderPlannerRole: hardnatplan.RoleResponder,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(10 * time.Minute),
	}, psk)
	clear(psk[:])
	if err != nil {
		t.Fatalf("EncodeArtifactSet: %v", err)
	}
	defer set.Close()
	artifactPayload := set.Responder
	if artifactRole == gatecattempt.RoleInitiator {
		artifactPayload = set.Initiator
	}
	privateInputs := t.TempDir()
	artifactFile := filepath.Join(privateInputs, "artifact.json")
	if err := pairgen.WritePrivateFileExclusive(artifactFile, artifactPayload); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	manifest, err := gatecattempt.ParseManifest(set.Manifest)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	request := gatecrequest.Request{
		Role: gatecattempt.RoleResponder, ArtifactFile: artifactFile, PeerRef: "peer-a",
		ExpectedPeerPublicAddress: mustAddress("203.0.113.8"),
		ObserverSet: gatecrequest.ObserverSet{
			Primary: mustEndpoint("192.0.2.1:3478"), AlternatePort: mustEndpoint("192.0.2.1:3479"),
			AlternateAddress: mustEndpoint("198.51.100.2:3478"), AlternateAddressPort: mustEndpoint("198.51.100.2:3479"),
		},
	}
	requestPayload, err := gatecrequest.Encode(request)
	if err != nil {
		t.Fatalf("Encode request: %v", err)
	}
	requestFile := filepath.Join(privateInputs, "request.json")
	if err := pairgen.WritePrivateFileExclusive(requestFile, requestPayload); err != nil {
		clear(requestPayload)
		t.Fatalf("write request: %v", err)
	}
	clear(requestPayload)
	return stageEnvironment{root: root, requestFile: requestFile, artifactFile: artifactFile, fingerprint: manifest.ArtifactFingerprint, request: request}
}

func privateRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "stage")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatalf("Mkdir stage root: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatalf("chmod stage root: %v", err)
		}
	}
	return root
}

func opaqueID(fill byte, size int) string {
	value := make([]byte, size)
	for index := range value {
		value[index] = fill
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func mustAddress(value string) netip.Addr      { return netip.MustParseAddr(value) }
func mustEndpoint(value string) netip.AddrPort { return netip.MustParseAddrPort(value) }
