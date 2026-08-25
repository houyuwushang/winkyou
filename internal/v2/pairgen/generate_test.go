package pairgen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/rendezvousadmission"
)

var pairgenTestNow = time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)

func TestGenerateCreatesExactPrivatePairAndManifestLast(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "pair")
	var stages []string
	result, err := generate(context.Background(), Options{OutDir: outDir}, dependencies{
		random: deterministicRandom(), now: func() time.Time { return pairgenTestNow },
		hook: func(stage string) error {
			stages = append(stages, stage)
			return nil
		},
	})
	if err != nil || result.ClipboardUsed {
		t.Fatalf("generate = %+v, %v", result, err)
	}
	wantStages := []string{
		"before_" + InitiatorFilename, "after_" + InitiatorFilename,
		"before_" + ResponderFilename, "after_" + ResponderFilename,
		"before_" + AdmissionFilename, "after_" + AdmissionFilename,
		"before_" + ManifestFilename, "after_" + ManifestFilename,
	}
	if !reflect.DeepEqual(stages, wantStages) {
		t.Fatalf("write stages = %v, want %v", stages, wantStages)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	wantNames := []string{AdmissionFilename, InitiatorFilename, ManifestFilename, ResponderFilename}
	sort.Strings(wantNames)
	if !reflect.DeepEqual(names, wantNames) {
		t.Fatalf("files = %v, want %v", names, wantNames)
	}
	if err := validateCompleteOutput(outDir); err != nil {
		t.Fatalf("private output validation: %v", err)
	}

	initiatorPayload := readPrivateFile(t, outDir, InitiatorFilename)
	responderPayload := readPrivateFile(t, outDir, ResponderFilename)
	defer clear(initiatorPayload)
	defer clear(responderPayload)
	initiator, err := directattempt.ParseArtifact(initiatorPayload, pairgenTestNow)
	if err != nil {
		t.Fatalf("parse initiator: %v", err)
	}
	defer initiator.Close()
	responder, err := directattempt.ParseArtifact(responderPayload, pairgenTestNow)
	if err != nil {
		t.Fatalf("parse responder: %v", err)
	}
	defer responder.Close()
	if initiator.LocalRole != directattempt.RoleInitiator || responder.LocalRole != directattempt.RoleResponder ||
		initiator.Fingerprint != responder.Fingerprint || initiator.CredentialID != responder.CredentialID ||
		initiator.AttemptID != responder.AttemptID || initiator.RendezvousAssociationID != responder.RendezvousAssociationID {
		t.Fatalf("recipient artifacts do not describe one pair")
	}
	contextValue, err := initiator.PairingContext()
	if err != nil {
		t.Fatal(err)
	}
	identifiers := []string{
		initiator.CredentialID, initiator.AttemptID, contextValue.InitiatorParticipantID,
		contextValue.ResponderParticipantID, initiator.RendezvousAssociationID,
	}
	seen := map[string]struct{}{}
	for _, identifier := range identifiers {
		seen[identifier] = struct{}{}
	}
	if len(seen) != 5 {
		t.Fatalf("identifiers are not pairwise distinct: %v", identifiers)
	}

	manifestPayload := readPrivateFile(t, outDir, ManifestFilename)
	defer clear(manifestPayload)
	var gotManifest manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestPayload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&gotManifest); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if gotManifest.Manifest != ManifestProfile || gotManifest.ArtifactFingerprint != initiator.Fingerprint ||
		gotManifest.IssuedAt != pairgenTestNow.Format(time.RFC3339) ||
		gotManifest.ExpiresAt != pairgenTestNow.Add(10*time.Minute).Format(time.RFC3339) ||
		!reflect.DeepEqual(gotManifest.Files, []string{InitiatorFilename, ResponderFilename, AdmissionFilename}) {
		t.Fatalf("manifest = %+v", gotManifest)
	}
	if strings.Contains(string(manifestPayload), "pairing_secret") || strings.Contains(string(manifestPayload), outDir) ||
		strings.Contains(string(manifestPayload), initiator.CredentialID) || strings.Contains(string(manifestPayload), initiator.AttemptID) {
		t.Fatalf("manifest contains secret or reusable identifier")
	}

	admissionPayload := readPrivateFile(t, outDir, AdmissionFilename)
	defer clear(admissionPayload)
	admission, err := rendezvousadmission.Parse(admissionPayload, pairgenTestNow)
	if err != nil || admission.AssociationID != initiator.RendezvousAssociationID {
		t.Fatalf("admission = %+v, %v", admission, err)
	}
}

func TestGenerateFailuresLeaveZeroOutput(t *testing.T) {
	t.Run("rng", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "pair")
		_, err := generate(context.Background(), Options{OutDir: outDir}, dependencies{
			random: bytes.NewReader([]byte{1}), now: func() time.Time { return pairgenTestNow },
		})
		if !errors.Is(err, ErrRandomUnavailable) {
			t.Fatalf("rng error = %v", err)
		}
		assertPathAbsent(t, outDir)
	})
	t.Run("collision", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "pair")
		_, err := generate(context.Background(), Options{OutDir: outDir}, dependencies{
			random: bytes.NewReader(make([]byte, 256)), now: func() time.Time { return pairgenTestNow },
		})
		if !errors.Is(err, ErrRandomUnavailable) {
			t.Fatalf("collision error = %v", err)
		}
		assertPathAbsent(t, outDir)
	})
	t.Run("injected partial write", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "pair")
		_, err := generate(context.Background(), Options{OutDir: outDir}, dependencies{
			random: deterministicRandom(), now: func() time.Time { return pairgenTestNow },
			hook: func(stage string) error {
				if stage == "after_"+ResponderFilename {
					return ErrInjectedFailure
				}
				return nil
			},
		})
		if !errors.Is(err, ErrInjectedFailure) {
			t.Fatalf("injected error = %v", err)
		}
		assertPathAbsent(t, outDir)
	})
	t.Run("clipboard", func(t *testing.T) {
		outDir := filepath.Join(t.TempDir(), "pair")
		_, err := generate(context.Background(), Options{
			OutDir: outDir, ClipboardRole: ClipboardRoleInitiator, AcknowledgeClipboardHistory: true,
		}, dependencies{
			random: deterministicRandom(), now: func() time.Time { return pairgenTestNow },
			clipboard: func(context.Context, []byte) error { return ErrClipboardUnavailable },
		})
		if !errors.Is(err, ErrClipboardUnavailable) {
			t.Fatalf("clipboard error = %v", err)
		}
		assertPathAbsent(t, outDir)
	})
}

func TestGenerateClipboardCopiesExactlyOneRecipient(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "pair")
	var clipboard []byte
	result, err := generate(context.Background(), Options{
		OutDir: outDir, ClipboardRole: ClipboardRoleResponder, AcknowledgeClipboardHistory: true,
	}, dependencies{
		random: deterministicRandom(), now: func() time.Time { return pairgenTestNow },
		clipboard: func(_ context.Context, payload []byte) error {
			if err := validateCompleteOutput(outDir); err != nil {
				return errors.Join(ErrClipboardUnavailable, err)
			}
			if _, err := os.Lstat(filepath.Join(outDir, ManifestFilename)); err != nil {
				return errors.Join(ErrClipboardUnavailable, err)
			}
			clipboard = append([]byte(nil), payload...)
			return nil
		},
	})
	defer clear(clipboard)
	if err != nil || !result.ClipboardUsed {
		t.Fatalf("clipboard generation = %+v, %v", result, err)
	}
	artifact, err := directattempt.ParseArtifact(clipboard, pairgenTestNow)
	if err != nil || artifact.LocalRole != directattempt.RoleResponder {
		t.Fatalf("clipboard artifact = %+v, %v", artifact, err)
	}
	artifact.Close()
	initiator := readPrivateFile(t, outDir, InitiatorFilename)
	defer clear(initiator)
	if bytes.Equal(clipboard, initiator) {
		t.Fatal("clipboard copied both roles or the wrong role")
	}
}

func TestGenerateRefusesExistingAndSymlinkOutput(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(context.Background(), Options{OutDir: existing}); !errors.Is(err, ErrOutputUnavailable) {
		t.Fatalf("existing output error = %v", err)
	}
	entries, err := os.ReadDir(existing)
	if err != nil || len(entries) != 0 {
		t.Fatalf("existing output changed: %v, %v", entries, err)
	}

	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := Generate(context.Background(), Options{OutDir: link}); !errors.Is(err, ErrOutputUnavailable) {
		t.Fatalf("symlink output error = %v", err)
	}
}

func TestGenerateOptionCombinationsFailClosed(t *testing.T) {
	for _, options := range []Options{
		{},
		{OutDir: "ignored", ClipboardRole: "both", AcknowledgeClipboardHistory: true},
		{OutDir: "ignored", ClipboardRole: ClipboardRoleInitiator},
		{OutDir: "ignored", AcknowledgeClipboardHistory: true},
	} {
		if _, err := generate(context.Background(), options, dependencies{random: deterministicRandom(), now: func() time.Time { return pairgenTestNow }}); !errors.Is(err, ErrInvalidOptions) {
			t.Fatalf("options %+v error = %v", options, err)
		}
	}
}

func TestPairgenCrashProcess(t *testing.T) {
	if os.Getenv("WINKYOU_PAIRGEN_CRASH_HELPER") != "1" {
		return
	}
	outDir := os.Getenv("WINKYOU_PAIRGEN_CRASH_OUT")
	_, _ = generate(context.Background(), Options{OutDir: outDir}, dependencies{
		random: deterministicRandom(), now: func() time.Time { return pairgenTestNow },
		hook: func(stage string) error {
			if stage == "after_"+AdmissionFilename {
				os.Exit(77)
			}
			return nil
		},
	})
	os.Exit(78)
}

func TestCrashWitnessLeavesUncommittedDirectoryWithoutManifest(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "crashed-pair")
	command := exec.Command(os.Args[0], "-test.run=^TestPairgenCrashProcess$")
	command.Env = append(os.Environ(), "WINKYOU_PAIRGEN_CRASH_HELPER=1", "WINKYOU_PAIRGEN_CRASH_OUT="+outDir)
	output, err := command.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 77 {
		t.Fatalf("crash helper = %v output=%q", err, output)
	}
	if _, err := os.Lstat(filepath.Join(outDir, ManifestFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crashed output has a manifest: %v", err)
	}
	for _, name := range []string{InitiatorFilename, ResponderFilename, AdmissionFilename} {
		if err := validatePrivatePath(filepath.Join(outDir, name), false); err != nil {
			t.Fatalf("crash witness %s: %v", name, err)
		}
	}
}

func deterministicRandom() *bytes.Reader {
	payload := make([]byte, 256)
	for index := range payload {
		payload[index] = byte(index + 1)
	}
	return bytes.NewReader(payload)
}

func readPrivateFile(t *testing.T, directory, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func assertPathAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("path %q exists after failure: %v", path, err)
	}
}
