package gatea

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/oobattempt"
)

func TestGateAProtocolSurfaceGolden(t *testing.T) {
	actual, err := json.MarshalIndent(struct {
		Progress []string `json:"progress"`
		Failures []string `json:"failures"`
	}{ProgressSequence, StableGateAFailureClasses}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected, err := os.ReadFile("testdata/gate-a-surface.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	expected = bytes.ReplaceAll(expected, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(actual, expected) {
		t.Fatalf("Gate A surface changed:\n%s", actual)
	}
	if len(StableGateAFailureClasses) != 8 || ProgressSequence[len(ProgressSequence)-1] != StageTerminal {
		t.Fatal("Gate A surface cardinality changed")
	}
}

func TestPreflightFailurePreservesStableAdmissionClasses(t *testing.T) {
	tests := []struct {
		cause error
		class string
	}{
		{governor.ErrPairingCredentialUsed, ClassCredentialUsed},
		{governor.ErrPairingAdmissionRejected, ClassAdmissionBlocked},
		{governor.ErrPairingAdmissionRateLimited, ClassAdmissionBlocked},
		{governor.ErrPairingAdmissionCircuitOpen, ClassAdmissionBlocked},
		{governor.ErrPairingLedgerIndeterminate, ClassAdmissionBlocked},
		{governor.ErrSafetyTripped, ClassResourceBudgetExceeded},
		{oobattempt.ErrInvalidArtifact, ClassOOBStreamInvalid},
	}
	for _, testCase := range tests {
		var failure *Failure
		if !errors.As(preflightFailure(testCase.cause), &failure) || failure.Class != testCase.class ||
			failure.Stage != StagePreflight || failure.CredentialBurned || failure.Retryable {
			t.Fatalf("preflight failure for %v = %#v", testCase.cause, failure)
		}
	}
}

func TestFailureSchemaIsStableRedactedAndNeverRetryable(t *testing.T) {
	for _, class := range StableGateAFailureClasses {
		failure := &Failure{
			Class: class, Stage: StageHandoff, CredentialBurned: true,
			Retryable: false, Cause: errors.New("private endpoint and process detail"),
		}
		payload, err := json.Marshal(failure)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, []byte("private")) || bytes.Contains(payload, []byte("endpoint")) ||
			!bytes.Contains(payload, []byte(`"retryable":false`)) {
			t.Fatalf("failure %q leaked or changed: %s", class, payload)
		}
	}
}

func TestUnknownArtifactAndInvalidCostStopBeforeStreamIO(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	set := testArtifactSet(t, now)
	defer set.Close()
	unknown := bytes.Replace(set.Initiator, []byte(oobattempt.ArtifactProfile), []byte("unknown-oob-artifact-profile/1"), 1)
	for name, artifact := range map[string][]byte{"unknown": unknown, "missing authority": set.Initiator} {
		t.Run(name, func(t *testing.T) {
			stream := &countingStream{}
			var progress []string
			_, err := Run(context.Background(), Config{
				Artifact: artifact, Stream: stream,
				STUNTargets:  []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478"), netip.MustParseAddrPort("127.0.0.1:3479")},
				BuildVersion: "gate-a-test", Progress: func(stage string, _ bool) error {
					progress = append(progress, stage)
					return nil
				},
			})
			var failure *Failure
			if !errors.As(err, &failure) || failure.Class != ClassOOBStreamInvalid || failure.CredentialBurned {
				t.Fatalf("failure = %#v / %v", failure, err)
			}
			if stream.calls != 0 {
				t.Fatalf("preflight performed %d stream operations", stream.calls)
			}
			if !reflect.DeepEqual(progress, []string{StageTerminal}) {
				t.Fatalf("progress = %v", progress)
			}
		})
	}
}

func TestSTUNTargetValidationIsLiteralDeduplicatedAndFamilyBound(t *testing.T) {
	valid := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:3478"), netip.MustParseAddrPort("127.0.0.1:3479")}
	if got, err := validateSTUNTargets(valid, false); err != nil || !reflect.DeepEqual(got, valid) {
		t.Fatalf("valid targets = %v/%v", got, err)
	}
	for _, targets := range [][]netip.AddrPort{
		{valid[0]},
		{valid[0], valid[0]},
		{valid[0], netip.MustParseAddrPort("[::1]:3479")},
		{valid[0], netip.MustParseAddrPort("192.0.2.1:3479")},
	} {
		if _, err := validateSTUNTargets(targets, false); err == nil {
			t.Fatalf("invalid targets accepted: %v", targets)
		}
	}
	for _, targets := range [][]netip.AddrPort{
		{netip.MustParseAddrPort("192.0.2.1:3478"), netip.MustParseAddrPort("192.0.2.1:3479")},
		{netip.MustParseAddrPort("198.51.100.1:3478"), netip.MustParseAddrPort("198.51.100.1:3479")},
	} {
		if _, err := validateSTUNTargets(targets, true); err != nil {
			t.Fatalf("isolated-unicast targets rejected: %v", err)
		}
	}
}

func TestDataPlaneChallengeBindsRoleAttemptContextAndHandshake(t *testing.T) {
	binding := directattempt.Binding{
		AttemptID: testOpaqueID("attempt"), Generation: directattempt.Generation,
		ContextDigest: sha256.Sum256([]byte("context")), HandshakeHash: sha256.Sum256([]byte("handshake")),
	}
	packet := challengePacket(binding, directattempt.RoleInitiator, 2)
	defer clear(packet)
	ordinal, err := validateChallengePacket(packet, binding, directattempt.RoleInitiator)
	if err != nil || ordinal != 2 {
		t.Fatalf("challenge = %d/%v", ordinal, err)
	}
	for name, mutate := range map[string]func([]byte, *directattempt.Binding, *directattempt.Role){
		"bytes": func(packet []byte, _ *directattempt.Binding, _ *directattempt.Role) { packet[len(packet)-1] ^= 1 },
		"attempt": func(_ []byte, binding *directattempt.Binding, _ *directattempt.Role) {
			binding.AttemptID = testOpaqueID("other")
		},
		"context":   func(_ []byte, binding *directattempt.Binding, _ *directattempt.Role) { binding.ContextDigest[0] ^= 1 },
		"handshake": func(_ []byte, binding *directattempt.Binding, _ *directattempt.Role) { binding.HandshakeHash[0] ^= 1 },
		"role": func(_ []byte, _ *directattempt.Binding, role *directattempt.Role) {
			*role = directattempt.RoleResponder
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]byte(nil), packet...)
			candidateBinding := binding
			role := directattempt.RoleInitiator
			mutate(candidate, &candidateBinding, &role)
			if _, err := validateChallengePacket(candidate, candidateBinding, role); err == nil {
				t.Fatal("mutated challenge accepted")
			}
		})
	}
}

func testArtifactSet(t testing.TB, now time.Time) oobattempt.ArtifactSet {
	t.Helper()
	set, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID: testOpaqueID("credential"), AttemptID: testOpaqueID("attempt"),
		InitiatorParticipantID: testOpaqueID("initiator"), ResponderParticipantID: testOpaqueID("responder"),
		OOBChannelID: testOpaqueID("channel"), IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(10*time.Minute - time.Second),
	}, [32]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func testOpaqueID(label string) string {
	digest := sha256.Sum256([]byte("gate-a-unit/" + label))
	return base64.RawURLEncoding.EncodeToString(digest[:16])
}

type countingStream struct{ calls int }

func (stream *countingStream) Read([]byte) (int, error) { stream.calls++; return 0, io.EOF }
func (stream *countingStream) Write(payload []byte) (int, error) {
	stream.calls++
	return len(payload), nil
}
func (stream *countingStream) Close() error                { stream.calls++; return nil }
func (stream *countingStream) SetDeadline(time.Time) error { stream.calls++; return nil }
