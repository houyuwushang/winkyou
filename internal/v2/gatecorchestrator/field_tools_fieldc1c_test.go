//go:build fieldc1c

package gatecorchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/fieldc1c"
)

const fieldToolSSHDGolden = `permitrootlogin forced-commands-only
authenticationmethods publickey
pubkeyauthentication yes
passwordauthentication no
kbdinteractiveauthentication no
permituserenvironment no
disableforwarding yes
permittty no
permituserrc no
usepam no
logingracetime 3
maxsessions 1
forcecommand none
`

func TestFieldToolsVerifySSHDGoldenAndNegatives(t *testing.T) {
	for _, payload := range []string{fieldToolSSHDGolden, strings.ReplaceAll(fieldToolSSHDGolden, "\n", "\r\n")} {
		result, err := VerifyFieldSSHD(strings.NewReader(payload))
		encoded, _ := json.Marshal(result)
		if err != nil || string(encoded) != `{"ok":true}` {
			t.Fatal("valid resolved config rejected")
		}
	}
	for name, payload := range map[string]string{
		"missing_root":         strings.ReplaceAll(fieldToolSSHDGolden, "permitrootlogin forced-commands-only\n", ""),
		"password":             strings.ReplaceAll(fieldToolSSHDGolden, "passwordauthentication no", "passwordauthentication yes"),
		"force_command":        fieldToolSSHDGolden + "ForceCommand synthetic\n",
		"duplicate_force_none": fieldToolSSHDGolden + "forcecommand none\n",
		"force_multifield":     strings.ReplaceAll(fieldToolSSHDGolden, "forcecommand none", "forcecommand none extra"),
		"oversize":             strings.Repeat("x", fieldToolTextLimit+1), "utf8": fieldToolSSHDGolden + "\xff", "nul": fieldToolSSHDGolden + "\x00", "empty": "",
	} {
		t.Run(name, func(t *testing.T) {
			result, err := VerifyFieldSSHD(strings.NewReader(payload))
			encoded, _ := json.Marshal(result)
			if !errors.Is(err, fieldc1c.ErrInvalid) || string(encoded) != `{"ok":false,"class":"sshd_config_invalid"}` {
				t.Fatal("unsafe resolved config escaped")
			}
		})
	}
	if _, err := VerifyFieldSSHD(nil); !errors.Is(err, fieldc1c.ErrInvalid) {
		t.Fatal("nil accepted")
	}
}

func fieldLedgerFixture(t *testing.T) fieldLedgerInputs {
	t.Helper()
	root := t.TempDir()
	return fieldLedgerInputs{
		namespace: func() governor.NamespaceStatus {
			return governor.NamespaceStatus{Path: root, State: governor.NamespaceReady, Ready: true}
		},
		scope: func() (string, error) { return "machine-scope-sha256/1:" + strings.Repeat("a", 64), nil },
		pairing: func() governor.FieldPairingLedgerReport {
			return governor.FieldPairingLedgerReport{
				Pairing: governor.PairingLedgerStatus{State: governor.PairingLedgerReady}, Campaign: governor.HardNATCampaignStatus{State: governor.PairingLedgerReady}, Entries: []governor.FieldPairingEntry{},
			}
		},
		trip: func() governor.SafetyTripStatus {
			return governor.SafetyTripStatus{State: governor.SafetyTripClear,
				Detail: "synthetic-private-detail", Record: governor.SafetyTripRecord{PeerID: "synthetic-private-peer", AttemptID: "synthetic-private-attempt", ResetNote: "synthetic-private-note", BuildVersion: "synthetic-private-build"}}
		},
		slot: inspectFieldSlot,
	}
}

func TestFieldToolsLedgerGoldenMissingPrivacyAndBlocking(t *testing.T) {
	inputs := fieldLedgerFixture(t)
	report, err := inspectFieldLedger(inputs)
	encoded, _ := json.Marshal(report)
	if err != nil || !report.OK || report.NextAdmission.Authorization || report.NextAdmission.OrdinaryBlocked || report.NextAdmission.CampaignBlocked ||
		strings.Contains(string(encoded), "synthetic-private-") || strings.Contains(string(encoded), inputs.namespace().Path) {
		t.Fatal("read-only ledger projection or privacy failed")
	}
	if report.Pending.MissingReason != "absent" || report.Claimed.AttemptPrefix != nil || report.SnapshotSemantics != "diagnostic_non_atomic_not_authorization" {
		t.Fatal("snapshot semantics lost")
	}
	inputs.namespace = func() governor.NamespaceStatus { return governor.NamespaceStatus{State: governor.NamespaceMissing} }
	inputs.scope = func() (string, error) { panic("missing namespace performed extra I/O") }
	report, err = inspectFieldLedger(inputs)
	encoded, _ = json.Marshal(report)
	if !errors.Is(err, fieldc1c.ErrInvalid) || string(encoded) != `{"ok":false,"class":"namespace_absent"}` {
		t.Fatal("missing namespace golden mismatch")
	}
	for _, mode := range []string{"trip", "ordinary", "campaign", "pending", "claimed", "slot_unreadable"} {
		t.Run(mode, func(t *testing.T) {
			inputs := fieldLedgerFixture(t)
			switch mode {
			case "trip":
				inputs.trip = func() governor.SafetyTripStatus {
					return governor.SafetyTripStatus{State: governor.SafetyTripTripped, BlocksActiveWork: true}
				}
			case "ordinary", "campaign":
				inputs.pairing = func() governor.FieldPairingLedgerReport {
					return governor.FieldPairingLedgerReport{Pairing: governor.PairingLedgerStatus{BlocksActiveWork: mode == "ordinary"}, Campaign: governor.HardNATCampaignStatus{BlocksCampaign: mode == "campaign"}}
				}
			default:
				inputs.slot = func(_ string, state string) FieldSlotReport {
					return FieldSlotReport{Valid: mode != "slot_unreadable", Exists: state == mode}
				}
			}
			result, err := inspectFieldLedger(inputs)
			if err != nil || result.NextAdmission.Authorization || (!result.NextAdmission.OrdinaryBlocked && !result.NextAdmission.CampaignBlocked) {
				t.Fatal("blocking fact advertised as ready")
			}
		})
	}
}

func TestFieldToolsSlotInspectionNeverFollowsArtifact(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "gate-c-responder-pending-v1.json")
	for _, payload := range []string{`{}`, `{"schema":"unknown"}`, strings.Repeat("x", gatecrequestSlotTestLimit+1)} {
		if err := os.WriteFile(path, []byte(payload), 0600); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(path)
		got := inspectFieldSlot(root, "pending")
		after, _ := os.ReadFile(path)
		if !got.Exists || got.Valid || got.AttemptPrefix != nil || !bytes.Equal(before, after) {
			t.Fatal("invalid slot accepted or modified")
		}
	}
	if got := inspectFieldSlot(root, "../escape"); got.Valid {
		t.Fatal("extra filename admitted")
	}
}

const gatecrequestSlotTestLimit = 16*1024 + 2048

func fieldSyntheticBuildInfo() *debug.BuildInfo {
	return &debug.BuildInfo{GoVersion: "go1.23.1", Settings: []debug.BuildSetting{
		{Key: "vcs", Value: "git"}, {Key: "vcs.revision", Value: strings.Repeat("a", 40)}, {Key: "vcs.modified", Value: "false"}, {Key: "-tags", Value: "fieldc1c"},
	}}
}

func TestFieldToolsBuildPairMutations(t *testing.T) {
	first, second := fieldSyntheticBuildInfo(), fieldSyntheticBuildInfo()
	if revision, ok := fieldToolBuildPair(first, second); !ok || revision != strings.Repeat("a", 40) {
		t.Fatal("synthetic build pair rejected")
	}
	for _, item := range []struct{ key, value string }{{"vcs", "hg"}, {"vcs.revision", strings.Repeat("b", 40)}, {"vcs.modified", "true"}, {"vcs.modified", ""}, {"-tags", "fieldc1c,natlab"}, {"-tags", ""}} {
		second = fieldSyntheticBuildInfo()
		for i := range second.Settings {
			if second.Settings[i].Key == item.key {
				second.Settings[i].Value = item.value
			}
		}
		if _, ok := fieldToolBuildPair(first, second); ok {
			t.Fatal("build mismatch accepted")
		}
	}
	second = fieldSyntheticBuildInfo()
	second.GoVersion = "go1.23.2"
	if _, ok := fieldToolBuildPair(first, second); ok {
		t.Fatal("different toolchains accepted")
	}
	second = fieldSyntheticBuildInfo()
	second.Settings = append(second.Settings, second.Settings[0])
	if _, ok := fieldToolBuildPair(first, second); ok {
		t.Fatal("duplicate build setting accepted")
	}
}

func TestFieldToolsDeriveInvalidArgumentsAreZeroIO(t *testing.T) {
	for _, paths := range []FieldDerivePaths{{}, {Field: "relative"}, {Field: "//synthetic.invalid/share"}} {
		result, err := deriveFieldTools(paths, func() (string, error) { panic("invalid path reached scope read") })
		encoded, _ := json.Marshal(result)
		if !errors.Is(err, fieldc1c.ErrInvalid) || string(encoded) != `{"ok":false,"class":"gate_c_request_invalid"}` {
			t.Fatal("invalid arguments escaped")
		}
	}
}

// The built executable is only inspected as data. It is never started. Its
// deliberately absent VCS witness is a negative; positive metadata uses the
// pure synthetic BuildInfo fixture and the Load digest equality test.
func TestFieldToolsBuiltBinaryAndConfigurationHashes(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "main.go")
	if err := os.WriteFile(source, []byte("package main\nfunc main() {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "synthetic.exe")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-tags=fieldc1c", "-o", binary, source)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("synthetic build failed: bytes=%d sha256=%x", len(output), sha256.Sum256(output))
	}
	hash, info, err := fieldToolHash(binary, true)
	if err != nil || len(hash) != 64 || info == nil {
		t.Fatal("compiled binary was not read")
	}
	if _, ok := fieldToolBuildPair(info, info); ok {
		t.Fatal("unstamped binary accepted")
	}
	configuration := filepath.Join(root, "synthetic.yaml")
	payload := []byte("version: synthetic\n")
	if err := os.WriteFile(configuration, payload, 0600); err != nil {
		t.Fatal(err)
	}
	got, _, err := fieldToolHash(configuration, false)
	want := sha256.Sum256(payload)
	if err != nil || got != hex.EncodeToString(want[:]) {
		t.Fatal("configuration bytes were transformed")
	}
	result, err := deriveFieldTools(FieldDerivePaths{binary, binary, configuration, configuration}, func() (string, error) { panic("unstamped build read scope") })
	encoded, _ := json.Marshal(result)
	if !errors.Is(err, fieldc1c.ErrInvalid) || string(encoded) != `{"ok":false,"class":"build_mismatch"}` {
		t.Fatal("unstamped build golden mismatch")
	}
	if _, _, err := fieldToolHash(root, false); err == nil {
		t.Fatal("directory accepted")
	}
}

// Build both real entry packages into temporary files but never run them.
// A dirty development checkout must be rejected; a clean committed tree must
// succeed, using its actual VCS/dependency tables (not fabricated metadata).
func TestFieldToolsDeriveActualBuildPair(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	field, router := filepath.Join(dir, "field.exe"), filepath.Join(dir, "router.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	for _, target := range []struct{ out, pkg string }{{field, "./cmd/wink"}, {router, "./cmd/c1crouter"}} {
		command := exec.CommandContext(ctx, "go", "build", "-buildvcs=true", "-tags=fieldc1c", "-o", target.out, target.pkg)
		command.Dir = root
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "GOOS=") && !strings.HasPrefix(entry, "CGO_ENABLED=") {
				command.Env = append(command.Env, entry)
			}
		}
		// The field router is Linux-only. Inspect ELF on every test host;
		// cross-compilation grants no permission to execute either file.
		command.Env = append(command.Env, "GOOS=linux", "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("read-only build fixture failed bytes=%d sha256=%x", len(output), sha256.Sum256(output))
		}
	}
	fieldHash, fieldInfo, err := fieldToolHash(field, true)
	if err != nil {
		t.Fatal("field metadata unavailable")
	}
	routerHash, routerInfo, err := fieldToolHash(router, true)
	if err != nil {
		t.Fatal("router metadata unavailable")
	}
	configI, configR := filepath.Join(dir, "initiator.yaml"), filepath.Join(dir, "responder.yaml")
	if os.WriteFile(configI, []byte("synthetic: initiator\n"), 0600) != nil || os.WriteFile(configR, []byte("synthetic: responder\n"), 0600) != nil {
		t.Fatal("configuration fixture failed")
	}
	paths := FieldDerivePaths{field, router, configI, configR}
	result, err := deriveFieldTools(paths, func() (string, error) { return "machine-scope-sha256/1:" + strings.Repeat("a", 64), nil })
	if _, valid := fieldToolBuildPair(fieldInfo, routerInfo); !valid {
		if !errors.Is(err, fieldc1c.ErrInvalid) || result.Class != "build_mismatch" {
			t.Fatal("dirty build did not fail closed")
		}
		t.Log("build_pair=dirty_rejected")
		return
	}
	if err != nil || !result.OK || result.InitiatorBinarySHA256 != fieldHash || result.ResponderBinarySHA256 != fieldHash || result.RouterBinarySHA256 != routerHash {
		t.Fatal("actual compiled pair failed derive")
	}
	configuration := [2]string{result.InitiatorConfigurationSHA256, result.ResponderConfigurationSHA256}
	for _, tc := range []struct {
		info   *debug.BuildInfo
		digest string
	}{{fieldInfo, result.DependencyAndConfigurationSHA256}, {routerInfo, result.RouterDependencyAndConfigurationSHA256}} {
		expected, err := fieldc1c.DependencyConfigurationDigest(tc.info, configuration)
		if err != nil || tc.digest != expected {
			t.Fatal("actual binary digest disagrees with Load projection")
		}
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), dir) || strings.Contains(string(encoded), root) {
		t.Fatal("derive leaked local path")
	}
	t.Log("build_pair=clean_derived source=compiled_vcs_metadata")
}
