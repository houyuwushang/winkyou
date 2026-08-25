package directconnect

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stunobserve"
	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvouscarrier"
)

func TestPrepareRejectsArtifactTimeAndProfileWithStableZeroBurnClasses(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := testArtifact(t, now.Add(-time.Second))
	unsupported := append([]byte(nil), valid...)
	unsupported = replaceJSONValue(t, unsupported, "artifact", "future-profile")
	notYet := testArtifact(t, now.Add(time.Minute))
	expired := testArtifact(t, now.Add(-11*time.Minute))
	for _, test := range []struct {
		name    string
		payload []byte
		class   string
	}{
		{"invalid", []byte(`{}`), ClassInvalidDirectArtifact},
		{"unsupported", unsupported, ClassUnsupportedAttemptProfile},
		{"not yet", notYet, ClassArtifactNotYetValid},
		{"expired", expired, ClassArtifactExpired},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stages []string
			_, err := Connect(context.Background(), Config{
				Artifact: test.payload, Progress: func(stage string, _ bool) error {
					stages = append(stages, stage)
					return nil
				},
			})
			assertFailure(t, err, test.class, StagePreflight, false, CategoryPreflightRejected)
			if !reflect.DeepEqual(stages, []string{StageTerminal}) {
				t.Fatalf("progress = %v", stages)
			}
		})
	}
	clear(valid)
	clear(unsupported)
	clear(notYet)
	clear(expired)
}

func TestPrepareValidatesEveryRoutingInputBeforeAuthorityOrIO(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	artifact := testArtifact(t, now.Add(-time.Second))
	defer clear(artifact)
	base := Config{
		Artifact: artifact,
		Rendezvous: RendezvousConfig{
			Endpoint: "192.0.2.10:443", DeploymentTier: DeploymentSelfHosted,
			TLS: TLSConfig{Verification: TLSSPKISHA256, SPKISHA256: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		},
		STUNEndpoint: "192.0.2.20:3478", BuildVersion: "test",
		Progress: func(string, bool) error { return nil },
	}
	tests := []struct {
		name   string
		mutate func(*Config)
		class  string
	}{
		{"tier", func(config *Config) { config.Rendezvous.DeploymentTier = "future" }, ClassRendezvousEndpointInvalid},
		{"endpoint", func(config *Config) { config.Rendezvous.Endpoint = "127.0.0.1:443" }, ClassRendezvousEndpointInvalid},
		{"tls", func(config *Config) { config.Rendezvous.TLS.SPKISHA256 = "bad" }, ClassRendezvousEndpointInvalid},
		{"stun", func(config *Config) { config.STUNEndpoint = "stun.invalid:3478" }, ClassSTUNEndpointInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			test.mutate(&config)
			_, err := Connect(context.Background(), config)
			assertFailure(t, err, test.class, StagePreflight, false, CategoryPreflightRejected)
		})
	}
	_, err := Connect(context.Background(), base)
	assertFailure(t, err, ClassDirectAttemptFailed, StagePreflight, false, CategoryPreflightRejected)
}

func TestEndpointValidationIsCanonicalAndSingleTarget(t *testing.T) {
	for _, endpoint := range []string{"192.0.2.1:443", "[2001:db8::1]:443", "rendezvous.example:443"} {
		if err := validateRendezvousInput(endpoint, false); err != nil {
			t.Errorf("valid endpoint %q: %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"127.0.0.1:443", "0.0.0.0:443", "192.0.2.1:0", "192.0.2.1:443 ", "[2001:0db8::1]:443", "one.example:443,two.example:443"} {
		if err := validateRendezvousInput(endpoint, false); err == nil {
			t.Errorf("invalid endpoint %q accepted", endpoint)
		}
	}
	if _, err := validateSTUNInput("192.0.2.2:3478", false); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"127.0.0.1:3478", "192.0.2.2:0", "[2001:0db8::2]:3478", "stun.example:3478"} {
		if _, err := validateSTUNInput(endpoint, false); err == nil {
			t.Errorf("invalid STUN endpoint %q accepted", endpoint)
		}
	}
}

func TestDirectResultAndFailureSchemasAreSecretFree(t *testing.T) {
	result := Result{
		AttemptKind: "direct_oob_artifact", Terminal: "success", Bidirectional: true,
		PromotedTerminal: true, CredentialBurned: true, FinishRecorded: true,
		Emissions: Emissions{HandshakeFrames: 1, ControlFrames: 4, STUNPackets: 1, DirectPackets: 2, UDPPacketsTotal: 3},
		ReservedEnvelope: governor.PairingEnvelopeFromAttemptCost(governor.AttemptCost{
			Resources: governor.Resources{Sockets: 3, Targets: 4, PacketsPerSecond: 5, Packets: 5, FiveTuples: 4},
			Duration:  15 * time.Second, Heavyweight: true,
		}),
		PairingLedger: governor.PairingLedgerStatus{
			State: governor.PairingLedgerReady, Limits: governor.PairingAdmissionHardLimits(),
		},
		SafetyTrip: governor.SafetyTripStatus{State: governor.SafetyTripClear},
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(payload)
	for _, required := range []string{"attempt_kind", "terminal", "bidirectional", "promoted_terminal", "credential_burned", "finish_recorded", "emissions", "reserved_envelope", "pairing_ledger", "safety_trip"} {
		if !jsonMember(payload, required) {
			t.Fatalf("result lacks %q: %s", required, payload)
		}
	}
	for _, forbidden := range []string{"endpoint", "association", "credential_id", "attempt_id", "fingerprint", "pairing_secret", "transcript", "ciphertext"} {
		if bytes.Contains(payload, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("result exposes %q: %s", forbidden, payload)
		}
	}
	formatted, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	formatted = append(formatted, '\n')
	want, err := os.ReadFile("testdata/direct-success.golden.json")
	if err != nil {
		t.Fatalf("read success golden: %v\ngot:\n%s", err, formatted)
	}
	want = bytes.ReplaceAll(want, []byte("\r\n"), []byte("\n"))
	if !bytes.Equal(formatted, want) {
		t.Fatalf("direct success golden changed\ngot:\n%s\nwant:\n%s", formatted, want)
	}
}

func TestStableFailureClassificationMatrix(t *testing.T) {
	background := context.Background()
	tests := []struct {
		name, stage, class, category string
		cause                        error
		burned                       bool
	}{
		{"dns failed", StagePreflight, ClassRendezvousDNSFailed, CategoryPreflightRejected, rendezvouscarrier.ErrDNSFailed, false},
		{"dns ambiguous", StagePreflight, ClassRendezvousDNSAmbiguous, CategoryPreflightRejected, rendezvouscarrier.ErrDNSAmbiguous, false},
		{"tls", StagePreflight, ClassRendezvousTLSFailed, CategoryPreflightRejected, rendezvouscarrier.ErrTLSHandshake, false},
		{"unreachable", StagePreflight, ClassRendezvousUnreachable, CategoryPreflightRejected, rendezvouscarrier.ErrCarrierTransport, false},
		{"presence", StagePresent, ClassPresenceTimeout, CategoryPreflightRejected, rendezvouscarrier.ErrPresenceTimeout, false},
		{"credential", StageBurned, ClassCredentialUsed, CategoryAdmissionBlocked, governor.ErrPairingCredentialUsed, false},
		{"rate", StageBurned, ClassPairingRateLimited, CategoryAdmissionBlocked, governor.ErrPairingAdmissionRateLimited, false},
		{"circuit", StageBurned, ClassPairingCircuitOpen, CategoryAdmissionBlocked, governor.ErrPairingAdmissionCircuitOpen, false},
		{"ledger", StageBurned, ClassLedgerIndeterminate, CategoryAdmissionBlocked, governor.ErrPairingLedgerIndeterminate, false},
		{"scope after burn", StageBurned, ClassPairingScopeChanged, CategoryAdmissionBlocked, governor.ErrCommittedAttemptInvalid, true},
		{"activation", StageActivated, ClassActivationFailed, CategoryAttemptFailed, errors.New("private activation cause"), true},
		{"domain", StagePrepare, ClassCarrierDomainViolation, CategoryAttemptFailed, rendezvouscarrier.ErrCarrierDomain, true},
		{"carrier budget", StagePrepare, ClassRendezvousBudgetExceeded, CategoryAttemptFailed, rendezvouscarrier.ErrApplicationBudget, true},
		{"carrier protocol", StagePrepare, ClassRendezvousProtocol, CategoryAttemptFailed, rendezvouscarrier.ErrInvalidFrame, true},
		{"stun silent", StageSTUN, ClassSTUNSilent, CategoryAttemptFailed, stunobserve.ErrTimeout, true},
		{"stun source", StageSTUN, ClassSTUNSourceMismatch, CategoryAttemptFailed, stunobserve.ErrSourceMismatch, true},
		{"stun protocol", StageSTUN, ClassSTUNProtocol, CategoryAttemptFailed, stunobserve.ErrMagicCookieMismatch, true},
		{"ready", StageReady, ClassReadyRejected, CategoryAttemptFailed, directattempt.ErrInvalidReady, true},
		{"control auth", StagePrepare, ClassControlAuthentication, CategoryAttemptFailed, directattempt.ErrInvalidFrame, true},
		{"direct packet", StagePunch, ClassDirectPacketRejected, CategoryAttemptFailed, directattempt.ErrInvalidFrame, true},
		{"punch timeout", StagePunch, ClassPunchTimeout, CategoryAttemptFailed, context.DeadlineExceeded, true},
		{"verify", StageVerify, ClassVerificationFailed, CategoryAttemptFailed, directattempt.ErrInvalidTransition, true},
		{"peer cancel", StageReady, ClassPeerCancelled, CategoryCancelled, directattempt.ErrCancelled, true},
		{"attempt envelope", StageReady, ClassAttemptExpired, CategoryAttemptFailed, context.DeadlineExceeded, true},
		{"resource trip", StageSocket, ClassResourceBudgetExceeded, CategorySafetyTripped, governor.ErrSafetyTripped, true},
		{"resource ceiling", StageSocket, ClassResourceBudgetExceeded, CategoryAttemptFailed, probeio.ErrHardLimit, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime := &runtime{burned: test.burned, requestContext: background}
			assertFailure(t, runtime.classify(test.stage, test.cause), test.class, func() string {
				if test.class == ClassPresenceTimeout {
					return StageTerminal
				}
				return test.stage
			}(), test.burned, test.category)
		})
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	runtime := &runtime{burned: true, requestContext: cancelled}
	assertFailure(t, runtime.classify(StageReady, context.Canceled), ClassAttemptExpired, StageReady, true, CategoryCancelled)
}

func testArtifact(t *testing.T, issuedAt time.Time) []byte {
	t.Helper()
	id := func(value byte) string {
		return base64.RawURLEncoding.EncodeToString(bytesRepeat(value, 16))
	}
	initiator, responder, _, err := directattempt.EncodeArtifactPair(directattempt.ArtifactMaterial{
		CredentialID: id(1), AttemptID: id(2), InitiatorParticipantID: id(3),
		ResponderParticipantID: id(4), AssociationID: id(5),
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(10 * time.Minute),
	}, [32]byte{1, 2, 3})
	clear(responder)
	if err != nil {
		t.Fatal(err)
	}
	return initiator
}

func replaceJSONValue(t *testing.T, payload []byte, name, value string) []byte {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(payload, &object); err != nil {
		t.Fatal(err)
	}
	object[name] = value
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func bytesRepeat(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func assertFailure(t *testing.T, err error, class, stage string, burned bool, category string) {
	t.Helper()
	var failure *Failure
	if !errors.As(err, &failure) || failure.Class != class || failure.Stage != stage || failure.CredentialBurned != burned || failure.TerminalCategory != category {
		t.Fatalf("failure = %+v (%v)", failure, err)
	}
}

func jsonMember(payload []byte, name string) bool {
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil {
		return false
	}
	_, ok := object[name]
	return ok
}
