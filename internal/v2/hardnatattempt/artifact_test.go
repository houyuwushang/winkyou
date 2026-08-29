package hardnatattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/oobattempt"
)

func TestArtifactSetRoundTripAndParserSeparation(t *testing.T) {
	set := syntheticSet(t, hardnatplan.ProfileAsymmetricBirthday, hardnatplan.ResourceAsymmetric,
		hardnatplan.RoleMappingSet, hardnatplan.RoleTargetSet)
	defer set.Close()
	now := time.Date(2026, 8, 28, 0, 1, 0, 0, time.UTC)
	initiator, err := ParseArtifact(set.Initiator, now)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	responder, err := ParseArtifact(set.Responder, now)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	if initiator.LocalPlannerRole != hardnatplan.RoleMappingSet || responder.LocalPlannerRole != hardnatplan.RoleTargetSet ||
		initiator.PeerPlannerRole != responder.LocalPlannerRole || responder.PeerPlannerRole != initiator.LocalPlannerRole {
		t.Fatalf("planner assignments = %s/%s", initiator.LocalPlannerRole, responder.LocalPlannerRole)
	}
	leftPrologue, err := initiator.NoisePrologue()
	if err != nil {
		t.Fatal(err)
	}
	rightPrologue, err := responder.NoisePrologue()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(leftPrologue, rightPrologue) {
		t.Fatal("role artifacts produced different Noise prologues")
	}
	for _, forbidden := range [][]byte{[]byte(`"endpoint"`), []byte(`"host"`), []byte(`"command"`), []byte(`"candidate"`), []byte(`"packets"`)} {
		if bytes.Contains(set.Initiator, forbidden) {
			t.Fatalf("artifact contains forbidden field %s", forbidden)
		}
	}
	if _, err := directattempt.ParseArtifact(set.Initiator, now); err == nil {
		t.Fatal("N3b parser accepted Gate B artifact")
	}
	if _, err := oobattempt.ParseArtifact(set.Initiator, now); err == nil {
		t.Fatal("Gate A parser accepted Gate B artifact")
	}
	if _, err := ParseManifest(set.Manifest); err != nil {
		t.Fatal(err)
	}
}

func TestHard16ArtifactExactArmAndParserSeparation(t *testing.T) {
	set := syntheticSet(t, hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab,
		hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer set.Close()
	now := time.Date(2026, 8, 28, 0, 1, 0, 0, time.UTC)
	for _, payload := range [][]byte{set.Initiator, set.Responder} {
		artifact, err := ParseArtifact(payload, now)
		if err != nil {
			t.Fatal(err)
		}
		if artifact.PlannerProfile != hardnatplan.ProfileHardBirthday || artifact.ResourceClass != hardnatplan.ResourceHard16KLab ||
			artifact.InitiatorPlannerRole != hardnatplan.RoleInitiator || artifact.ResponderPlannerRole != hardnatplan.RoleResponder {
			t.Fatalf("hard16 artifact = %+v", artifact)
		}
		artifact.Close()
		if _, err := directattempt.ParseArtifact(payload, now); err == nil {
			t.Fatal("N3b parser accepted hard16 artifact")
		}
		if _, err := oobattempt.ParseArtifact(payload, now); err == nil {
			t.Fatal("Gate A parser accepted hard16 artifact")
		}
	}

	var object map[string]any
	if err := json.Unmarshal(set.Initiator, &object); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"hard32":        func(value map[string]any) { value["resource_class"] = string(hardnatplan.ResourceHard32KCandidate) },
		"wrong role":    func(value map[string]any) { value["initiator_planner_role"] = string(hardnatplan.RoleMappingSet) },
		"cross profile": func(value map[string]any) { value["planner_profile"] = string(hardnatplan.ProfileAsymmetricBirthday) },
	} {
		t.Run(name, func(t *testing.T) {
			clone := make(map[string]any, len(object))
			for key, value := range object {
				clone[key] = value
			}
			mutate(clone)
			payload, err := json.Marshal(clone)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseArtifact(payload, now); err == nil {
				t.Fatal("mutated hard16 arm was accepted")
			}
		})
	}
}

func TestArtifactRejectsProfileFallbackAndUnknownFields(t *testing.T) {
	set := syntheticSet(t, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive,
		hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer set.Close()
	now := time.Date(2026, 8, 28, 0, 1, 0, 0, time.UTC)
	unknown := bytes.Replace(set.Initiator, []byte(`"runtime_fallback":"disabled"`), []byte(`"runtime_fallback":"automatic"`), 1)
	if _, err := ParseArtifact(unknown, now); err == nil {
		t.Fatal("fallback was accepted")
	}
	var object map[string]any
	if err := json.Unmarshal(set.Initiator, &object); err != nil {
		t.Fatal(err)
	}
	object["target_ports"] = []int{1, 2}
	payload, _ := json.Marshal(object)
	if _, err := ParseArtifact(payload, now); err == nil {
		t.Fatal("remote candidate field was accepted")
	}
}

func TestArtifactPSKIsSingleTake(t *testing.T) {
	set := syntheticSet(t, hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive,
		hardnatplan.RoleInitiator, hardnatplan.RoleResponder)
	defer set.Close()
	artifact, err := ParseArtifact(set.Initiator, time.Date(2026, 8, 28, 0, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	defer artifact.Close()
	if secret, err := artifact.TakePSK(); err != nil || secret == ([32]byte{}) {
		t.Fatalf("first take = %x/%v", secret, err)
	}
	if _, err := artifact.TakePSK(); err == nil {
		t.Fatal("second PSK take succeeded")
	}
}

func syntheticSet(t *testing.T, profile hardnatplan.Profile, resource hardnatplan.ResourceClass, initiatorRole, responderRole hardnatplan.Role) ArtifactSet {
	t.Helper()
	id := func(label string) string {
		digest := sha256.Sum256([]byte(label))
		return base64.RawURLEncoding.EncodeToString(digest[:16])
	}
	issued := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	psk := sha256.Sum256([]byte("synthetic-hardnat-psk"))
	set, err := EncodeArtifactSet(ArtifactMaterial{
		CredentialID: id("credential"), AttemptID: id("attempt"), InitiatorParticipantID: id("initiator"),
		ResponderParticipantID: id("responder"), OOBChannelID: id("channel"),
		PlannerProfile: profile, ResourceClass: resource, InitiatorPlannerRole: initiatorRole, ResponderPlannerRole: responderRole,
		IssuedAt: issued, ExpiresAt: issued.Add(10 * time.Minute),
	}, psk)
	if err != nil {
		t.Fatal(err)
	}
	return set
}
