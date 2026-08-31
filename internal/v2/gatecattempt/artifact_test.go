package gatecattempt_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobattempt"
)

func TestArtifactRoundTripProfilesAndDomainBinding(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                 string
		profile              hardnatplan.Profile
		resource             hardnatplan.ResourceClass
		initiator, responder hardnatplan.Role
	}{
		{"predictive", hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, hardnatplan.RoleInitiator, hardnatplan.RoleResponder},
		{"asymmetric", hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric, hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet},
		{"hard16", hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab, hardnatplan.RoleInitiator, hardnatplan.RoleResponder},
	} {
		t.Run(test.name, func(t *testing.T) {
			set, psk := productSet(t, now, test.profile, test.resource, test.initiator, test.responder)
			defer set.Close()
			for role, payload := range map[gatecattempt.Role][]byte{
				gatecattempt.RoleInitiator: set.Initiator,
				gatecattempt.RoleResponder: set.Responder,
			} {
				artifact, err := gatecattempt.ParseArtifact(payload, now)
				if err != nil {
					t.Fatalf("parse %s: %v", role, err)
				}
				if artifact.LocalRole != role || artifact.PlannerProfile != test.profile || artifact.ResourceClass != test.resource {
					t.Fatal("parsed artifact binding mismatch")
				}
				prologue, err := artifact.NoisePrologue()
				if err != nil {
					t.Fatalf("prologue: %v", err)
				}
				for _, binding := range []string{
					"artifact=" + gatecattempt.ArtifactProfile,
					"carrier=" + gatecattempt.OOBCarrierProfile,
					"control=" + gatecattempt.DirectAttemptProfile,
					"consumer=" + gatecattempt.DataPlaneConsumerProfile,
					"challenge=" + gatecattempt.DataPlaneChallengeProfile,
					"runtime_fallback=disabled",
				} {
					if !bytes.Contains(prologue, []byte(binding)) {
						t.Fatalf("prologue missing %q", binding)
					}
				}
				gotPSK, err := artifact.TakePSK()
				if err != nil || gotPSK != psk {
					t.Fatalf("TakePSK mismatch: %v", err)
				}
				if _, err := artifact.TakePSK(); !errors.Is(err, gatecattempt.ErrSecretUnavailable) {
					t.Fatalf("second TakePSK = %v", err)
				}
				artifact.Close()
			}
			manifest, err := gatecattempt.ParseManifest(set.Manifest)
			if err != nil || manifest.Schema != gatecattempt.ManifestProfile {
				t.Fatalf("manifest validation failed: %v", err)
			}
		})
	}
}

func TestArtifactStrictnessAndExpiry(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	set, _ := productSet(t, now, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer set.Close()

	var object map[string]json.RawMessage
	if err := json.Unmarshal(set.Initiator, &object); err != nil {
		t.Fatal(err)
	}
	object["unexpected"] = json.RawMessage(`"value"`)
	unknown, _ := json.Marshal(object)
	if _, err := gatecattempt.ParseArtifact(unknown, now); !errors.Is(err, gatecattempt.ErrInvalidArtifact) {
		t.Fatalf("unknown field error = %v", err)
	}
	duplicate := bytes.Replace(set.Initiator, []byte(`"artifact":`), []byte(`"artifact":"duplicate","artifact":`), 1)
	if _, err := gatecattempt.ParseArtifact(duplicate, now); !errors.Is(err, gatecattempt.ErrInvalidArtifact) {
		t.Fatalf("duplicate field error = %v", err)
	}
	if _, err := gatecattempt.ParseArtifact(set.Initiator, now.Add(10*time.Minute)); !errors.Is(err, gatecattempt.ErrCredentialExpired) {
		t.Fatalf("expiry error = %v", err)
	}
}

func TestAllFourArtifactParsersMutuallyReject(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	product, _ := productSet(t, now, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer product.Close()
	gateA, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID: id(11), AttemptID: id(12), InitiatorParticipantID: id(13), ResponderParticipantID: id(14),
		OOBChannelID: id(15), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer gateA.Close()
	gateB, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: id(21), AttemptID: id(22), InitiatorParticipantID: id(23), ResponderParticipantID: id(24),
		OOBChannelID: id(25), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	defer gateB.Close()
	n3Initiator, n3Responder, _, err := directattempt.EncodeArtifactPair(directattempt.ArtifactMaterial{
		CredentialID: id(31), AttemptID: id(32), InitiatorParticipantID: id(33), ResponderParticipantID: id(34),
		AssociationID: id(35), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(n3Initiator)
	defer clear(n3Responder)

	payloads := map[string][]byte{
		"n3b": n3Initiator, "gate-a": gateA.Initiator, "gate-b": gateB.Initiator, "gate-c": product.Initiator,
	}
	parsers := map[string]func([]byte) error{
		"n3b": func(payload []byte) error {
			value, err := directattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err
		},
		"gate-a": func(payload []byte) error {
			value, err := oobattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err
		},
		"gate-b": func(payload []byte) error {
			value, err := hardnatattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err
		},
		"gate-c": func(payload []byte) error {
			value, err := gatecattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err
		},
	}
	for parserName, parse := range parsers {
		for payloadName, payload := range payloads {
			err := parse(payload)
			if parserName == payloadName && err != nil {
				t.Errorf("%s rejected own payload: %v", parserName, err)
			}
			if parserName != payloadName && err == nil {
				t.Errorf("%s accepted %s payload", parserName, payloadName)
			}
		}
	}
}

func productSet(t *testing.T, now time.Time, profile hardnatplan.Profile, resource hardnatplan.ResourceClass, initiator, responder hardnatplan.Role) (gatecattempt.ArtifactSet, [32]byte) {
	t.Helper()
	psk := [32]byte{9, 8, 7}
	set, err := gatecattempt.EncodeArtifactSet(gatecattempt.ArtifactMaterial{
		CredentialID: id(1), AttemptID: id(2), InitiatorParticipantID: id(3), ResponderParticipantID: id(4),
		OOBChannelID: id(5), PlannerProfile: profile, ResourceClass: resource,
		InitiatorPlannerRole: initiator, ResponderPlannerRole: responder,
		IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, psk)
	if err != nil {
		t.Fatal(err)
	}
	return set, psk
}

func id(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 16))
}

func TestArtifactContainsNoLocalAuthorityFields(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	set, _ := productSet(t, now, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer set.Close()
	text := strings.ToLower(string(set.Initiator) + string(set.Manifest))
	for _, forbidden := range []string{"endpoint", "hostname", "identity_file", "known_hosts", "expected_peer", "observer_set", "wireguard_key", "candidate"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("artifact contains forbidden authority field %q", forbidden)
		}
	}
}

func TestProductArtifactAndParserSeparationGolden(t *testing.T) {
	now := time.Date(2026, 8, 31, 8, 0, 0, 0, time.UTC)
	product, _ := productSet(t, now, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive, hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer product.Close()
	hashes := []string{
		fmt.Sprintf("initiator_sha256=%x", sha256.Sum256(product.Initiator)),
		fmt.Sprintf("responder_sha256=%x", sha256.Sum256(product.Responder)),
		fmt.Sprintf("manifest_sha256=%x", sha256.Sum256(product.Manifest)),
	}

	gateA, err := oobattempt.EncodeArtifactSet(oobattempt.ArtifactMaterial{
		CredentialID: id(11), AttemptID: id(12), InitiatorParticipantID: id(13), ResponderParticipantID: id(14),
		OOBChannelID: id(15), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	defer gateA.Close()
	gateB, err := hardnatattempt.EncodeArtifactSet(hardnatattempt.ArtifactMaterial{
		CredentialID: id(21), AttemptID: id(22), InitiatorParticipantID: id(23), ResponderParticipantID: id(24),
		OOBChannelID: id(25), PlannerProfile: hardnatplan.ProfilePredictiveEdm,
		ResourceClass: hardnatplan.ResourcePredictive, InitiatorPlannerRole: hardnatplan.RoleInitiator,
		ResponderPlannerRole: hardnatplan.RoleResponder, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	defer gateB.Close()
	n3Initiator, n3Responder, _, err := directattempt.EncodeArtifactPair(directattempt.ArtifactMaterial{
		CredentialID: id(31), AttemptID: id(32), InitiatorParticipantID: id(33), ResponderParticipantID: id(34),
		AssociationID: id(35), IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}, [32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(n3Initiator)
	defer clear(n3Responder)
	payloads := map[string][]byte{"gate-a": gateA.Initiator, "gate-b": gateB.Initiator, "gate-c": product.Initiator, "n3b": n3Initiator}
	parsers := map[string]func([]byte) bool{
		"gate-a": func(payload []byte) bool {
			value, err := oobattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err == nil
		},
		"gate-b": func(payload []byte) bool {
			value, err := hardnatattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err == nil
		},
		"gate-c": func(payload []byte) bool {
			value, err := gatecattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err == nil
		},
		"n3b": func(payload []byte) bool {
			value, err := directattempt.ParseArtifact(payload, now)
			if value != nil {
				value.Close()
			}
			return err == nil
		},
	}
	names := []string{"gate-a", "gate-b", "gate-c", "n3b"}
	for _, parserName := range names {
		for _, payloadName := range names {
			hashes = append(hashes, fmt.Sprintf("parser=%s payload=%s accepted=%t", parserName, payloadName, parsers[parserName](payloads[payloadName])))
		}
	}
	sort.Strings(hashes[3:])
	actual := strings.Join(hashes, "\n") + "\n"
	goldenPath := filepath.Join("testdata", "product_artifact_and_parser_separation.golden")
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if actual != strings.ReplaceAll(string(want), "\r\n", "\n") {
		t.Fatalf("Gate C artifact golden changed; safe digest/matrix follows:\n%s", actual)
	}
}
