package directattempt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/pairingcontext"
)

func TestArtifactStrictRoundTripHasNoDirectEndpointAndSharesFingerprintAcrossRoles(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 10, 11, 0, time.UTC)
	initiatorPayload := testArtifactPayload(t, RoleInitiator, now)
	responderPayload := testArtifactPayload(t, RoleResponder, now)
	for _, forbidden := range []string{"local_endpoint", "peer_endpoint", "direct_endpoint"} {
		if bytes.Contains(initiatorPayload, []byte(forbidden)) || bytes.Contains(responderPayload, []byte(forbidden)) {
			t.Fatalf("artifact contains forbidden endpoint member %q", forbidden)
		}
	}

	initiator, err := ParseArtifact(initiatorPayload, now.Add(time.Second))
	if err != nil {
		t.Fatalf("parse initiator artifact: %v", err)
	}
	defer initiator.Close()
	responder, err := ParseArtifact(responderPayload, now.Add(time.Second))
	if err != nil {
		t.Fatalf("parse responder artifact: %v", err)
	}
	defer responder.Close()
	if initiator.LocalRole != RoleInitiator || responder.LocalRole != RoleResponder {
		t.Fatalf("roles = %s/%s", initiator.LocalRole, responder.LocalRole)
	}
	if initiator.Fingerprint != responder.Fingerprint {
		t.Fatal("recipient-local role changed the shared artifact fingerprint")
	}
	if initiator.AttemptID != responder.AttemptID || initiator.RendezvousAssociationID != responder.RendezvousAssociationID {
		t.Fatal("paired artifacts do not share attempt/rendezvous association")
	}
	initiatorContext, _ := initiator.PairingContext()
	responderContext, _ := responder.PairingContext()
	if initiatorContext != responderContext {
		t.Fatal("paired artifacts produced different authenticated contexts")
	}
	initiatorDigest, _ := initiator.ContextDigest()
	responderDigest, _ := responder.ContextDigest()
	if initiatorDigest != responderDigest {
		t.Fatal("paired artifacts produced different context digests")
	}
	secret, err := initiator.TakePSK()
	if err != nil || secret != repeated32(0x33) {
		t.Fatalf("take PSK = %x, %v", secret, err)
	}
	clear(secret[:])
	if _, err := initiator.TakePSK(); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("second TakePSK error = %v", err)
	}
}

func TestArtifactRejectsUnknownProfilesBeforeAnyAuthorityExists(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 10, 11, 0, time.UTC)
	valid := testArtifactPayload(t, RoleInitiator, now)
	tests := map[string][]byte{
		"artifact":   bytes.Replace(valid, []byte(ArtifactProfile), []byte("winkyou-test-direct-attempt-oob/unknown"), 1),
		"direct":     bytes.Replace(valid, []byte(DirectAttemptProfile), []byte("winkyou-test-direct-attempt-control/unknown"), 1),
		"rendezvous": bytes.Replace(valid, []byte(RendezvousPresenceProfile), []byte("winkyou-test-direct-presence/unknown"), 1),
		"pairing":    bytes.Replace(valid, []byte(pairingcontext.ProtocolVersion), []byte("winkyou-test-pairing/unknown"), 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			artifact, err := ParseArtifact(payload, now.Add(time.Second))
			if artifact != nil || !errors.Is(err, ErrUnsupportedProfile) {
				t.Fatalf("ParseArtifact = %#v, %v", artifact, err)
			}
		})
	}
	if ArtifactProfile == pairingcontext.ProtocolVersion || DirectAttemptProfile == pairingcontext.ProtocolVersion {
		t.Fatal("direct identifier aliases loopback pairing /1")
	}
}

func TestArtifactRejectsMalformedUnknownDuplicateNonMachineAndTimeBounds(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 10, 11, 0, time.UTC)
	valid := testArtifactPayload(t, RoleInitiator, now)
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = "value"
	unknown, _ := json.Marshal(object)
	duplicate := bytes.Replace(valid, []byte(`"local_role":"initiator"`), []byte(`"local_role":"initiator","local_role":"initiator"`), 1)
	userScope := bytes.Replace(valid, []byte(`"initiator_governor_scope":"machine"`), []byte(`"initiator_governor_scope":"user_acknowledged"`), 1)
	badGeneration := bytes.Replace(valid, []byte(`"observation_generation":"1"`), []byte(`"observation_generation":"2"`), 1)
	badFingerprint := bytes.Replace(valid, []byte(`"artifact_fingerprint":"`), []byte(`"artifact_fingerprint":"A`), 1)
	tests := map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "user scope": userScope,
		"generation": badGeneration, "fingerprint": badFingerprint,
		"oversize":     bytes.Repeat([]byte{' '}, MaxArtifactBytes+1),
		"trailing":     append(append([]byte(nil), valid...), []byte(` {}`)...),
		"invalid utf8": {0xff}, "empty": nil,
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if artifact, err := ParseArtifact(payload, now.Add(time.Second)); artifact != nil || !errors.Is(err, ErrInvalidArtifact) {
				t.Fatalf("ParseArtifact = %#v, %v", artifact, err)
			}
		})
	}
	if artifact, err := ParseArtifact(valid, now.Add(-time.Second)); artifact != nil || !errors.Is(err, ErrCredentialNotYetValid) {
		t.Fatalf("not-yet-valid = %#v, %v", artifact, err)
	}
	if artifact, err := ParseArtifact(valid, now.Add(10*time.Minute)); artifact != nil || !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expired = %#v, %v", artifact, err)
	}
}

func TestDirectNoisePrologueAddsProfileBindingWithoutChangingPairingBuilder(t *testing.T) {
	now := time.Date(2026, 8, 24, 9, 10, 11, 0, time.UTC)
	artifact, err := ParseArtifact(testArtifactPayload(t, RoleInitiator, now), now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	context, _ := artifact.PairingContext()
	base, err := pairingcontext.BuildNoisePrologue(context)
	if err != nil {
		t.Fatal(err)
	}
	direct, err := BuildNoisePrologue(context)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := append(append([]byte(nil), base...), '\n')
	if bytes.Equal(base, direct) || !bytes.HasPrefix(direct, wantPrefix) {
		t.Fatal("direct prologue did not extend the exact existing prologue")
	}
	for _, required := range []string{ArtifactProfile, DirectAttemptProfile, RendezvousPresenceProfile} {
		if !bytes.Contains(direct, []byte(required)) {
			t.Fatalf("direct prologue does not bind %q", required)
		}
	}
	secondBase, err := pairingcontext.BuildNoisePrologue(context)
	if err != nil || !bytes.Equal(base, secondBase) {
		t.Fatal("direct builder changed the existing pairing prologue")
	}
	clear(base)
	clear(secondBase)
	clear(direct)
}

func testArtifactPayload(t testing.TB, role Role, issuedAt time.Time) []byte {
	t.Helper()
	wire := wireArtifact{
		Artifact: ArtifactProfile, DirectAttemptProfile: DirectAttemptProfile,
		RendezvousProfile: RendezvousPresenceProfile, RendezvousAssociationID: encodedID(0x15),
		LocalRole: string(role), Protocol: pairingcontext.ProtocolVersion, AuthScope: pairingcontext.AuthScope,
		CredentialID: encodedID(0x11), AttemptID: encodedID(0x12), ObservationGeneration: "1",
		InitiatorParticipantID: encodedID(0x13), ResponderParticipantID: encodedID(0x14),
		InitiatorGovernorScope: pairingcontext.GovernorScopeMachine, ResponderGovernorScope: pairingcontext.GovernorScopeMachine,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile,
		IssuedAt:             issuedAt.Format(time.RFC3339), ExpiresAt: issuedAt.Add(10 * time.Minute).Format(time.RFC3339),
	}
	wire.PairingSecret.value = repeated32(0x33)
	wire.PairingSecret.set = true
	fingerprint, err := artifactFingerprint(&wire)
	if err != nil {
		t.Fatal(err)
	}
	wire.ArtifactFingerprint = fingerprint
	object := map[string]string{
		"artifact": wire.Artifact, "direct_attempt_profile": wire.DirectAttemptProfile,
		"rendezvous_profile": wire.RendezvousProfile, "rendezvous_association_id": wire.RendezvousAssociationID,
		"local_role": wire.LocalRole, "protocol": wire.Protocol, "auth_scope": wire.AuthScope,
		"credential_id": wire.CredentialID, "pairing_secret": base64.RawURLEncoding.EncodeToString(wire.PairingSecret.value[:]),
		"attempt_id": wire.AttemptID, "observation_generation": wire.ObservationGeneration,
		"initiator_participant_id": wire.InitiatorParticipantID, "responder_participant_id": wire.ResponderParticipantID,
		"initiator_governor_scope": wire.InitiatorGovernorScope, "responder_governor_scope": wire.ResponderGovernorScope,
		"secure_channel_profile": wire.SecureChannelProfile, "issued_at": wire.IssuedAt, "expires_at": wire.ExpiresAt,
		"artifact_fingerprint": wire.ArtifactFingerprint,
	}
	payload, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "endpoint") {
		t.Fatal("artifact helper emitted an endpoint field")
	}
	return payload
}

func repeated32(value byte) [32]byte {
	var result [32]byte
	for index := range result {
		result[index] = value
	}
	return result
}

func encodedID(value byte) string {
	raw := bytes.Repeat([]byte{value}, 16)
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	clear(raw)
	return encoded
}
