package loopbackcarrier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/internal/v2/punchproto"
)

func TestCompleteBundleStrictValidationAndOwnership(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	payload := testCompleteBundle(t, punchproto.RoleInitiator, "127.0.0.1:41001", "127.0.0.1:41002", pairingcontext.GovernorScopeMachine, repeatedSecret(9), now)
	bundle, err := parseCompleteBundle(payload, now.Add(time.Second))
	if err != nil {
		t.Fatalf("parse complete bundle: %v", err)
	}
	defer bundle.zeroize()
	if bundle.role != punchproto.RoleInitiator || bundle.local != netip.MustParseAddrPort("127.0.0.1:41001") || bundle.peer != netip.MustParseAddrPort("127.0.0.1:41002") {
		t.Fatalf("parsed routing = role=%s local=%s peer=%s", bundle.role, bundle.local, bundle.peer)
	}
	if bundle.psk != repeatedSecret(9) || bundle.contextDigest == "" || len(bundle.contextDigest) != 64 {
		t.Fatal("parsed secret/context ownership is incomplete")
	}
	if err := bundle.requireLoopbackMachine(); err != nil {
		t.Fatalf("loopback machine policy: %v", err)
	}
	bundle.zeroize()
	if bundle.psk != ([32]byte{}) || bundle.context != (pairingcontext.PairingContext{}) || bundle.contextDigest != "" {
		t.Fatal("bundle zeroize retained secret or context")
	}
	if bytes.Contains(payload, []byte("<redacted>")) {
		t.Fatal("test fixture unexpectedly replaced the source secret")
	}
}

func TestCompleteBundleRejectsMalformedUnknownDuplicateAndOversize(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	valid := testCompleteBundle(t, punchproto.RoleResponder, "[::1]:42001", "[::1]:42002", pairingcontext.GovernorScopeMachine, repeatedSecret(7), now)
	var object map[string]any
	if err := json.Unmarshal(valid, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = true
	unknown, _ := json.Marshal(object)

	duplicate := bytes.Replace(valid, []byte(`"local_role":"responder"`), []byte(`"local_role":"responder","local_role":"responder"`), 1)
	trailing := append(append([]byte(nil), valid...), []byte(` {}`)...)
	oversize := bytes.Repeat([]byte{' '}, MaxCompleteBundleBytes+1)
	noncanonicalEndpoint := bytes.Replace(valid, []byte(`"local_endpoint":"[::1]:42001"`), []byte(`"local_endpoint":"[0:0:0:0:0:0:0:1]:42001"`), 1)
	tests := map[string][]byte{
		"unknown": unknown, "duplicate": duplicate, "trailing": trailing,
		"oversize": oversize, "noncanonical endpoint": noncanonicalEndpoint,
		"empty": nil, "invalid utf8": {0xff},
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if bundle, err := parseCompleteBundle(payload, now.Add(time.Second)); bundle != nil || !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("parse = %#v/%v, want strict rejection", bundle, err)
			}
		})
	}
}

func TestCompleteBundleRejectsArtifactDriftExpiryAndFingerprintMismatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	secret := repeatedSecret(5)
	valid := testCompleteBundle(t, punchproto.RoleInitiator, "127.0.0.1:43001", "127.0.0.1:43002", pairingcontext.GovernorScopeMachine, secret, now)
	tests := map[string][]byte{
		"repeated field": bytes.Replace(valid, []byte(`"protocol":"winkyou-test-pairing/1"`), []byte(`"protocol":"wrong"`), 1),
		"fingerprint":    bytes.Replace(valid, []byte(`"offer_fingerprint":"`), []byte(`"offer_fingerprint":"A`), 1),
		"profile":        bytes.ReplaceAll(valid, []byte(pairingcontext.SelectedSecureChannelProfile), []byte("simulation/no-crypto-no-network/1")),
		"secret length":  bytes.Replace(valid, []byte(base64.RawURLEncoding.EncodeToString(secret[:])), []byte("short"), 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseCompleteBundle(payload, now.Add(time.Second)); !errors.Is(err, ErrInvalidBundle) {
				t.Fatalf("error = %v, want invalid bundle", err)
			}
		})
	}
	if _, err := parseCompleteBundle(valid, now.Add(11*time.Minute)); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expired error = %v", err)
	}
	if _, err := parseCompleteBundle(valid, now.Add(-time.Second)); !errors.Is(err, ErrCredentialNotYetValid) {
		t.Fatalf("future-issued error = %v", err)
	}
}

func TestLoopbackAndMachineChecksAreSeparatePreAdmissionGates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	nonLoopback := testCompleteBundle(t, punchproto.RoleInitiator, "127.0.0.1:44001", "192.0.2.10:44002", pairingcontext.GovernorScopeMachine, repeatedSecret(3), now)
	bundle, err := parseCompleteBundle(nonLoopback, now.Add(time.Second))
	if err != nil {
		t.Fatalf("syntactically valid non-loopback bundle: %v", err)
	}
	defer bundle.zeroize()
	if err := bundle.requireLoopbackMachine(); !errors.Is(err, ErrNonLoopbackBlocked) {
		t.Fatalf("non-loopback gate = %v", err)
	}

	userScope := testCompleteBundle(t, punchproto.RoleResponder, "127.0.0.1:44003", "127.0.0.1:44004", pairingcontext.GovernorScopeUser, repeatedSecret(4), now)
	bundle, err = parseCompleteBundle(userScope, now.Add(time.Second))
	if err != nil {
		t.Fatalf("syntactically valid user bundle: %v", err)
	}
	defer bundle.zeroize()
	if err := bundle.requireLoopbackMachine(); !errors.Is(err, ErrUserScopeBlocked) {
		t.Fatalf("user-scope gate = %v", err)
	}
}

func TestConnectBlocksNonLoopbackBeforeAttemptOrDurableBurn(t *testing.T) {
	namespace := t.TempDir()
	writeClearSafetyTrip(t, namespace)
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "loopback-pre-admission-test")
	if err != nil {
		t.Fatalf("acquire owner: %v", err)
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		t.Fatalf("new governor: %v", err)
	}
	defer machine.Close()
	now := time.Now().UTC().Truncate(time.Second)
	payload := testCompleteBundle(t, punchproto.RoleInitiator, "127.0.0.1:45001", "192.0.2.20:45002", pairingcontext.GovernorScopeMachine, repeatedSecret(8), now)
	if _, err := Connect(context.Background(), machine, payload, "loopback-pre-admission-test", nil); !errors.Is(err, ErrNonLoopbackBlocked) {
		t.Fatalf("Connect error = %v, want non-loopback block", err)
	}
	snapshot := machine.Snapshot()
	if snapshot.ActivePeers != 0 || snapshot.ActiveAttempts != 0 || snapshot.Reserved != (governor.Resources{}) {
		t.Fatalf("pre-admission block changed governor state: %+v", snapshot)
	}
	if _, err := os.Lstat(filepath.Join(namespace, "pairing-admission-v1.journal")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pre-admission block touched pairing journal: %v", err)
	}
}

func testCompleteBundle(t *testing.T, role punchproto.Role, local, peer, scopes string, secret [32]byte, issuedAt time.Time) []byte {
	t.Helper()
	offer := wireOffer{
		Artifact: "offer", Protocol: pairingcontext.ProtocolVersion, AuthScope: pairingcontext.AuthScope,
		CredentialID: testID(1), AttemptID: testID(2), ObservationGeneration: "1",
		InitiatorParticipantID: testID(3), InitiatorGovernorScope: scopes,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile,
		IssuedAt:             issuedAt.Format(time.RFC3339), ExpiresAt: issuedAt.Add(5 * time.Minute).Format(time.RFC3339),
	}
	fingerprint, err := offerFingerprint(&offer)
	if err != nil {
		t.Fatalf("offer fingerprint: %v", err)
	}
	offerObject := map[string]any{
		"artifact": offer.Artifact, "protocol": offer.Protocol, "auth_scope": offer.AuthScope,
		"credential_id": offer.CredentialID, "pairing_secret": base64.RawURLEncoding.EncodeToString(secret[:]),
		"attempt_id": offer.AttemptID, "observation_generation": offer.ObservationGeneration,
		"initiator_participant_id": offer.InitiatorParticipantID, "initiator_governor_scope": offer.InitiatorGovernorScope,
		"secure_channel_profile": offer.SecureChannelProfile, "issued_at": offer.IssuedAt, "expires_at": offer.ExpiresAt,
	}
	acceptance := map[string]any{
		"artifact": pairingcontext.PairingArtifactAcceptance, "protocol": offer.Protocol, "auth_scope": offer.AuthScope,
		"credential_id": offer.CredentialID, "attempt_id": offer.AttemptID, "observation_generation": offer.ObservationGeneration,
		"initiator_participant_id": offer.InitiatorParticipantID, "responder_participant_id": testID(4),
		"initiator_governor_scope": scopes, "responder_governor_scope": scopes,
		"secure_channel_profile": offer.SecureChannelProfile, "issued_at": offer.IssuedAt, "expires_at": offer.ExpiresAt,
		"offer_fingerprint": fingerprint,
	}
	payload, err := json.Marshal(map[string]any{
		"local_role": string(role), "local_endpoint": local, "peer_endpoint": peer,
		"offer": offerObject, "acceptance": acceptance,
	})
	if err != nil {
		t.Fatalf("marshal complete bundle: %v", err)
	}
	if len(payload) > MaxCompleteBundleBytes || strings.Contains(string(payload), "<redacted>") {
		t.Fatalf("invalid test bundle shape")
	}
	return payload
}

func testID(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 16))
}

func repeatedSecret(seed byte) [32]byte {
	var secret [32]byte
	for index := range secret {
		secret[index] = seed
	}
	return secret
}

func writeClearSafetyTrip(t *testing.T, namespace string) {
	t.Helper()
	record := governor.SafetyTripRecord{
		SchemaVersion: 1, State: governor.SafetyTripClear,
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}
	recordPayload, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	checksum := sha256.Sum256(recordPayload)
	envelope, err := json.Marshal(struct {
		Record   governor.SafetyTripRecord `json:"record"`
		Checksum string                    `json:"checksum"`
	}{Record: record, Checksum: hex.EncodeToString(checksum[:])})
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{'C'}, envelope...)
	payload = append(payload, '\n')
	if err := os.WriteFile(filepath.Join(namespace, "safety-trip.json"), payload, 0o600); err != nil {
		t.Fatalf("write safety trip: %v", err)
	}
}
