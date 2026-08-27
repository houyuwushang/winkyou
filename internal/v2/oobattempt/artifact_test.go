package oobattempt

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
)

var testMaterial = ArtifactMaterial{
	CredentialID:           "AAECAwQFBgcICQoLDA0ODw",
	AttemptID:              "EBESExQVFhcYGRobHB0eHw",
	InitiatorParticipantID: "ICEiIyQlJicoKSorLC0uLw",
	ResponderParticipantID: "MDEyMzQ1Njc4OTo7PD0-Pw",
	OOBChannelID:           "QEFCQ0RFRkdISUpLTE1OTw",
	IssuedAt:               time.Date(2026, 8, 27, 0, 0, 0, 0, time.UTC),
	ExpiresAt:              time.Date(2026, 8, 27, 0, 10, 0, 0, time.UTC),
}

var testPSK = [32]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
}

func TestArtifactSetRoundTripAndProfileBinding(t *testing.T) {
	set, err := EncodeArtifactSet(testMaterial, testPSK)
	if err != nil {
		t.Fatalf("EncodeArtifactSet() error = %v", err)
	}
	defer set.Close()

	initiator, err := ParseArtifact(set.Initiator, testMaterial.IssuedAt)
	if err != nil {
		t.Fatalf("ParseArtifact(initiator) error = %v", err)
	}
	defer initiator.Close()
	responder, err := ParseArtifact(set.Responder, testMaterial.IssuedAt)
	if err != nil {
		t.Fatalf("ParseArtifact(responder) error = %v", err)
	}
	defer responder.Close()
	if initiator.LocalRole != RoleInitiator || responder.LocalRole != RoleResponder ||
		initiator.Fingerprint != responder.Fingerprint || initiator.OOBChannelID != testMaterial.OOBChannelID {
		t.Fatalf("artifact identities diverged")
	}
	leftPrologue, err := initiator.NoisePrologue()
	if err != nil {
		t.Fatalf("initiator NoisePrologue() error = %v", err)
	}
	defer clear(leftPrologue)
	rightPrologue, err := responder.NoisePrologue()
	if err != nil {
		t.Fatalf("responder NoisePrologue() error = %v", err)
	}
	defer clear(rightPrologue)
	if !bytes.Equal(leftPrologue, rightPrologue) {
		t.Fatal("recipient prologues differ")
	}
	for _, required := range []string{
		"artifact=" + ArtifactProfile,
		"carrier=" + OOBCarrierProfile,
		"control=" + DirectAttemptProfile,
		"observation=" + ObservationProfile,
		"runtime_fallback=disabled",
		"oob_channel_id=" + testMaterial.OOBChannelID,
	} {
		if !bytes.Contains(leftPrologue, []byte(required)) {
			t.Fatalf("prologue missing %q", required)
		}
	}
	secret, err := initiator.TakePSK()
	if err != nil || secret != testPSK {
		t.Fatalf("TakePSK() mismatch: err=%v", err)
	}
	clear(secret[:])
	if _, err := initiator.TakePSK(); !errors.Is(err, ErrSecretUnavailable) {
		t.Fatalf("second TakePSK() error = %v", err)
	}
	manifest, err := ParseManifest(set.Manifest)
	if err != nil || manifest.ArtifactFingerprint != responder.Fingerprint {
		t.Fatalf("ParseManifest() = %+v, %v", manifest, err)
	}
}

func TestArtifactSchemaExcludesAssemblyAndRoutingData(t *testing.T) {
	set, err := EncodeArtifactSet(testMaterial, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	for _, payload := range [][]byte{set.Initiator, set.Responder, set.Manifest} {
		text := string(payload)
		for _, forbidden := range []string{"endpoint", "tls", "command", "username", "hostname", "path", "environment"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("artifact material contains forbidden member %q", forbidden)
			}
		}
	}
}

func TestArtifactProfilesAndFallbackFailClosed(t *testing.T) {
	set, err := EncodeArtifactSet(testMaterial, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	mutations := map[string][2]string{
		"artifact":         {ArtifactProfile, "unknown-artifact/1"},
		"control":          {DirectAttemptProfile, "unknown-control/1"},
		"carrier":          {OOBCarrierProfile, "unknown-carrier/1"},
		"observation":      {ObservationProfile, "unknown-observation/1"},
		"secure channel":   {"noise-nnpsk0-25519-chachapoly-sha256/1", "unknown-noise/1"},
		"runtime fallback": {"\"runtime_fallback\":\"disabled\"", "\"runtime_fallback\":\"enabled\""},
	}
	for name, values := range mutations {
		t.Run(name, func(t *testing.T) {
			payload := bytes.Replace(set.Initiator, []byte(values[0]), []byte(values[1]), 1)
			if _, err := ParseArtifact(payload, testMaterial.IssuedAt); err == nil {
				t.Fatal("mutated artifact accepted")
			}
		})
	}
}

func TestArtifactParsersMutuallyRejectProfiles(t *testing.T) {
	oobSet, err := EncodeArtifactSet(testMaterial, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer oobSet.Close()
	if _, err := directattempt.ParseArtifact(oobSet.Initiator, testMaterial.IssuedAt); err == nil {
		t.Fatal("N3b parser accepted Gate A artifact")
	}
	n3bInitiator, n3bResponder, _, err := directattempt.EncodeArtifactPair(directattempt.ArtifactMaterial{
		CredentialID: testMaterial.CredentialID, AttemptID: testMaterial.AttemptID,
		InitiatorParticipantID: testMaterial.InitiatorParticipantID,
		ResponderParticipantID: testMaterial.ResponderParticipantID,
		AssociationID:          testMaterial.OOBChannelID, IssuedAt: testMaterial.IssuedAt, ExpiresAt: testMaterial.ExpiresAt,
	}, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(n3bInitiator)
	defer clear(n3bResponder)
	for _, payload := range [][]byte{n3bInitiator, n3bResponder} {
		if _, err := ParseArtifact(payload, testMaterial.IssuedAt); err == nil {
			t.Fatal("Gate A parser accepted N3b artifact")
		}
	}
}

func TestArtifactRejectsUnknownDuplicateAndTimeBoundaries(t *testing.T) {
	set, err := EncodeArtifactSet(testMaterial, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	unknown := bytes.Replace(set.Initiator, []byte("{\"artifact\":"), []byte("{\"unknown\":\"x\",\"artifact\":"), 1)
	if _, err := ParseArtifact(unknown, testMaterial.IssuedAt); err == nil {
		t.Fatal("unknown member accepted")
	}
	duplicate := bytes.Replace(set.Initiator, []byte("{\"artifact\":"), []byte("{\"artifact\":\"winkyou-test-direct-oob-attempt/1\",\"artifact\":"), 1)
	if _, err := ParseArtifact(duplicate, testMaterial.IssuedAt); err == nil {
		t.Fatal("duplicate member accepted")
	}
	if _, err := ParseArtifact(set.Initiator, testMaterial.IssuedAt.Add(-time.Second)); !errors.Is(err, ErrCredentialNotYetValid) {
		t.Fatalf("not-yet-valid error = %v", err)
	}
	if _, err := ParseArtifact(set.Initiator, testMaterial.ExpiresAt); !errors.Is(err, ErrCredentialExpired) {
		t.Fatalf("expiry error = %v", err)
	}
}

func TestArtifactGolden(t *testing.T) {
	set, err := EncodeArtifactSet(testMaterial, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer set.Close()
	n3b, _, _, err := directattempt.EncodeArtifactPair(directattempt.ArtifactMaterial{
		CredentialID: testMaterial.CredentialID, AttemptID: testMaterial.AttemptID,
		InitiatorParticipantID: testMaterial.InitiatorParticipantID,
		ResponderParticipantID: testMaterial.ResponderParticipantID,
		AssociationID:          testMaterial.OOBChannelID, IssuedAt: testMaterial.IssuedAt, ExpiresAt: testMaterial.ExpiresAt,
	}, testPSK)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(n3b)
	actual, err := json.MarshalIndent(struct {
		Initiator   json.RawMessage `json:"initiator"`
		Responder   json.RawMessage `json:"responder"`
		Manifest    json.RawMessage `json:"manifest"`
		RejectedN3B json.RawMessage `json:"rejected_n3b"`
	}{set.Initiator, set.Responder, set.Manifest, n3b}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected, err := readGolden("testdata/oob_attempt.synthetic.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalizeCRLF(expected), normalizeCRLF(actual)) {
		t.Fatalf("golden mismatch; actual:\n%s", actual)
	}
}
