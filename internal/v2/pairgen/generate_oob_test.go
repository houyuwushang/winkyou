package pairgen

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/hardnatplan"
)

func TestGenerateOOBWritesThreePrivateFilesManifestLast(t *testing.T) {
	out := filepath.Join(t.TempDir(), "pair")
	var stages []string
	_, err := generateOOB(context.Background(), OOBOptions{OutDir: out, Profile: OOBProfileAsymmetric, MappingSetRole: OOBMappingSetResponder}, dependencies{
		random: bytes.NewReader(oobRandomMaterial()),
		now:    func() time.Time { return time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC) },
		hook: func(stage string) error {
			stages = append(stages, stage)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantStages := []string{
		"before_oob_" + OOBInitiatorFilename, "after_oob_" + OOBInitiatorFilename,
		"before_oob_" + OOBResponderFilename, "after_oob_" + OOBResponderFilename,
		"before_oob_" + OOBManifestFilename, "after_oob_" + OOBManifestFilename,
	}
	if !reflect.DeepEqual(stages, wantStages) {
		t.Fatalf("stages = %v, want %v", stages, wantStages)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("files = %d, want 3", len(entries))
	}
	initiator, _ := os.ReadFile(filepath.Join(out, OOBInitiatorFilename))
	responder, _ := os.ReadFile(filepath.Join(out, OOBResponderFilename))
	manifestPayload, _ := os.ReadFile(filepath.Join(out, OOBManifestFilename))
	defer clear(initiator)
	defer clear(responder)
	for role, payload := range map[gatecattempt.Role][]byte{gatecattempt.RoleInitiator: initiator, gatecattempt.RoleResponder: responder} {
		artifact, err := gatecattempt.ParseArtifact(payload, time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatalf("parse %s: %v", role, err)
		}
		if artifact.LocalRole != role || artifact.PlannerProfile != hardnatplan.ProfileAsymmetricBirthday || artifact.LocalPlannerRole == artifact.PeerPlannerRole {
			t.Fatal("generated artifact binding mismatch")
		}
		artifact.Close()
	}
	if _, err := gatecattempt.ParseManifest(manifestPayload); err != nil {
		t.Fatalf("manifest: %v", err)
	}
}

func TestGenerateOOBRejectsProfileRoleAndExistingOutput(t *testing.T) {
	base := OOBOptions{OutDir: filepath.Join(t.TempDir(), "pair")}
	for index, options := range []OOBOptions{
		{OutDir: base.OutDir, Profile: OOBProfileAsymmetric},
		{OutDir: base.OutDir, Profile: OOBProfilePredictive, MappingSetRole: OOBMappingSetInitiator},
		{OutDir: base.OutDir, Profile: OOBProfileHard16K, MappingSetRole: OOBMappingSetResponder},
		{OutDir: base.OutDir, Profile: "hard-32k"},
	} {
		if _, err := generateOOB(context.Background(), options, dependencies{random: bytes.NewReader(oobRandomMaterial()), now: time.Now}); !errors.Is(err, ErrInvalidOptions) {
			t.Errorf("invalid option case %d returned error class %v", index, err)
		}
	}
	if err := os.Mkdir(base.OutDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateOOB(context.Background(), OOBOptions{OutDir: base.OutDir, Profile: OOBProfilePredictive}); !errors.Is(err, ErrOutputUnavailable) {
		t.Fatalf("existing output error = %v", err)
	}
}

func TestGenerateOOBCrashBeforeManifestLeavesNoCommittedOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "pair")
	_, err := generateOOB(context.Background(), OOBOptions{OutDir: out, Profile: OOBProfilePredictive}, dependencies{
		random: bytes.NewReader(oobRandomMaterial()), now: time.Now,
		hook: func(stage string) error {
			if stage == "before_oob_"+OOBManifestFilename {
				return ErrInjectedFailure
			}
			return nil
		},
	})
	if !errors.Is(err, ErrInjectedFailure) {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("output residue = %v", err)
	}
}

func TestGenerateOOBManifestLinkCrashIsFailClosedAndCleaned(t *testing.T) {
	out := filepath.Join(t.TempDir(), "pair")
	witnessed := false
	_, err := generateOOB(context.Background(), OOBOptions{OutDir: out, Profile: OOBProfilePredictive}, dependencies{
		random: bytes.NewReader(oobRandomMaterial()), now: time.Now,
		afterOOBManifestLink: func() error {
			if _, err := os.Lstat(filepath.Join(out, ".manifest.pending")); err != nil {
				t.Fatal("manifest pending link is absent at the injected crash boundary")
			}
			if _, err := os.Lstat(filepath.Join(out, OOBManifestFilename)); err != nil {
				t.Fatal("manifest commit name is absent at the injected crash boundary")
			}
			if payload, err := ReadPrivateFile(filepath.Join(out, OOBManifestFilename), gatecattempt.MaxManifestBytes); err == nil {
				clear(payload)
				t.Fatal("two-link crash state was accepted as a committed private manifest")
			}
			witnessed = true
			return ErrInjectedFailure
		},
	})
	if !errors.Is(err, ErrInjectedFailure) || !witnessed {
		t.Fatal("manifest link crash injection did not reach the fail-closed boundary")
	}
	if _, err := os.Lstat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("manifest link crash cleanup left output residue")
	}
}

func oobRandomMaterial() []byte {
	payload := make([]byte, 32+5*16)
	for index := range payload {
		payload[index] = byte(index + 1)
	}
	return payload
}
