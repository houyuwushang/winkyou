//go:build fieldc1c

package gatecorchestrator

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"
	"unicode/utf8"

	"winkyou/internal/governor"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/sshchildwrapper"
)

const fieldToolTextLimit = 64 * 1024
const fieldToolBinaryLimit = 512 * 1024 * 1024

type FieldToolStatus struct {
	OK    bool   `json:"ok"`
	Class string `json:"class,omitempty"`
}

func fieldToolFailure(class string) (FieldToolStatus, error) {
	return FieldToolStatus{Class: class}, fieldc1c.ErrInvalid
}

// VerifyFieldSSHD consumes bounded stdin, never a command or config path.
func VerifyFieldSSHD(input io.Reader) (FieldToolStatus, error) {
	if input == nil {
		return fieldToolFailure("gate_c_request_invalid")
	}
	payload, err := io.ReadAll(io.LimitReader(input, fieldToolTextLimit+1))
	if err != nil || len(payload) > fieldToolTextLimit || !utf8.Valid(payload) {
		return fieldToolFailure("sshd_config_invalid")
	}
	defer clear(payload)
	forceSeen := false
	for _, line := range strings.Split(string(payload), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !strings.EqualFold(fields[0], "forcecommand") {
			continue
		}
		if forceSeen || len(fields) != 2 || !strings.EqualFold(fields[1], "none") {
			return fieldToolFailure("sshd_config_invalid")
		}
		forceSeen = true
	}
	if sshchildwrapper.ValidateRootSSHDResolvedConfig(payload) != nil {
		return fieldToolFailure("sshd_config_invalid")
	}
	return FieldToolStatus{OK: true}, nil
}

type FieldSlotReport struct {
	Exists        bool    `json:"exists"`
	Valid         bool    `json:"valid"`
	AttemptPrefix *string `json:"attempt_prefix"`
	MissingReason string  `json:"missing_reason"`
}

type FieldAdmissionReport struct {
	OrdinaryBlocked bool `json:"ordinary_blocked"`
	CampaignBlocked bool `json:"campaign_blocked"`
	Authorization   bool `json:"authorization"`
}

type FieldTripReport struct {
	State            governor.SafetyTripState  `json:"state"`
	BlocksActiveWork bool                      `json:"blocks_active_work"`
	Reason           governor.SafetyTripReason `json:"reason,omitempty"`
	Sequence         uint64                    `json:"sequence"`
	UpdatedAt        time.Time                 `json:"updated_at"`
}

type FieldLedgerReport struct {
	FieldToolStatus
	MachineScopeReference string                             `json:"machine_scope_reference,omitempty"`
	Ledger                *governor.FieldPairingLedgerReport `json:"ledger,omitempty"`
	Trip                  *FieldTripReport                   `json:"trip,omitempty"`
	Pending               *FieldSlotReport                   `json:"pending,omitempty"`
	Claimed               *FieldSlotReport                   `json:"claimed,omitempty"`
	NextAdmission         *FieldAdmissionReport              `json:"next_admission,omitempty"`
	SnapshotSemantics     string                             `json:"snapshot_semantics,omitempty"`
}

type fieldLedgerInputs struct {
	namespace func() governor.NamespaceStatus
	scope     func() (string, error)
	pairing   func() governor.FieldPairingLedgerReport
	trip      func() governor.SafetyTripStatus
	slot      func(string, string) FieldSlotReport
}

// InspectFieldLedger performs no setup, owner acquisition or side effect.
func InspectFieldLedger() (FieldLedgerReport, error) {
	return inspectFieldLedger(fieldLedgerInputs{governor.InspectMachineNamespace, fieldc1c.MachineScopeReference,
		governor.InspectFieldPairingLedger, governor.InspectMachineSafetyTrip, inspectFieldSlot})
}

func inspectFieldLedger(inputs fieldLedgerInputs) (FieldLedgerReport, error) {
	fail := func(class string) (FieldLedgerReport, error) {
		return FieldLedgerReport{FieldToolStatus: FieldToolStatus{Class: class}}, fieldc1c.ErrInvalid
	}
	namespace := inputs.namespace()
	if namespace.State == governor.NamespaceMissing {
		return fail("namespace_absent")
	}
	if !namespace.Ready {
		return fail("namespace_unsafe")
	}
	scope, err := inputs.scope()
	if err != nil {
		return fail("machine_scope_unavailable")
	}
	ledger, trip := inputs.pairing(), inputs.trip()
	redactedTrip := FieldTripReport{State: trip.State, BlocksActiveWork: trip.BlocksActiveWork,
		Reason: trip.Record.Reason, Sequence: trip.Record.Sequence, UpdatedAt: trip.Record.UpdatedAt}
	pending := inputs.slot(namespace.Path, "pending")
	claimed := inputs.slot(namespace.Path, "claimed")
	blocked := trip.BlocksActiveWork || pending.Exists || claimed.Exists || !pending.Valid || !claimed.Valid
	return FieldLedgerReport{FieldToolStatus: FieldToolStatus{OK: true}, MachineScopeReference: scope,
		Ledger: &ledger, Trip: &redactedTrip, Pending: &pending, Claimed: &claimed,
		NextAdmission: &FieldAdmissionReport{OrdinaryBlocked: blocked || ledger.Pairing.BlocksActiveWork,
			CampaignBlocked: blocked || ledger.Campaign.BlocksCampaign},
		SnapshotSemantics: "diagnostic_non_atomic_not_authorization"}, nil
}

func inspectFieldSlot(namespace, state string) FieldSlotReport {
	result := FieldSlotReport{MissingReason: "slot_unreadable"}
	if state != "pending" && state != "claimed" {
		return result
	}
	path := filepath.Join(namespace, "gate-c-responder-"+state+"-v1.json")
	file, err := fieldToolOpenRead(path, gatecrequest.MaxRequestBytes+2048)
	if errors.Is(err, os.ErrNotExist) {
		return FieldSlotReport{Valid: true, MissingReason: "absent"}
	}
	result.Exists = true
	if err != nil {
		return result
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, gatecrequest.MaxRequestBytes+2049))
	defer clear(payload)
	if err != nil || len(payload) > gatecrequest.MaxRequestBytes+2048 || !utf8.Valid(payload) {
		return result
	}
	var slot struct {
		Schema              string          `json:"schema"`
		State               string          `json:"state"`
		ArtifactFingerprint string          `json:"artifact_fingerprint"`
		ExpiresAt           string          `json:"expires_at"`
		Request             json.RawMessage `json:"request"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&slot) != nil || decoder.Decode(new(any)) != io.EOF || slot.Schema != "winkyou-gate-c-responder-stage/1" ||
		slot.State != state || !fieldToolHex(slot.ArtifactFingerprint, 32) {
		return result
	}
	if _, err := time.Parse(time.RFC3339, slot.ExpiresAt); err != nil {
		return result
	}
	request, err := gatecrequest.Parse(slot.Request)
	if err != nil || string(request.Role) != "responder" || request.SSH != nil {
		return result
	}
	// The slot stores an artifact path, not an attempt ID. Do not follow that
	// path (which may contain secrets) or mislabel its fingerprint as an ID.
	result.Valid, result.MissingReason = true, "not_recorded"
	return result
}

type FieldDerivePaths struct {
	Field, Router, InitiatorConfig, ResponderConfig string
}

type FieldDeriveReport struct {
	FieldToolStatus
	ExactSHA                               string `json:"exact_sha,omitempty"`
	Toolchain                              string `json:"toolchain,omitempty"`
	InitiatorBinarySHA256                  string `json:"initiator_binary_sha256,omitempty"`
	ResponderBinarySHA256                  string `json:"responder_binary_sha256,omitempty"`
	RouterBinarySHA256                     string `json:"router_binary_sha256,omitempty"`
	DependencyAndConfigurationSHA256       string `json:"dependency_and_configuration_sha256,omitempty"`
	RouterDependencyAndConfigurationSHA256 string `json:"router_dependency_and_configuration_sha256,omitempty"`
	InitiatorConfigurationSHA256           string `json:"initiator_configuration_sha256,omitempty"`
	ResponderConfigurationSHA256           string `json:"responder_configuration_sha256,omitempty"`
	MachineScopeReference                  string `json:"machine_scope_reference,omitempty"`
}

func (paths FieldDerivePaths) Valid() bool {
	for _, path := range []string{paths.Field, paths.Router, paths.InitiatorConfig, paths.ResponderConfig} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") ||
			strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, "//") {
			return false
		}
	}
	return true
}

// DeriveFieldTools reads only the four explicit local files and current scope.
// It never executes a binary and never constructs an Instance.
func DeriveFieldTools(paths FieldDerivePaths) (FieldDeriveReport, error) {
	return deriveFieldTools(paths, fieldc1c.MachineScopeReference)
}

func deriveFieldTools(paths FieldDerivePaths, scope func() (string, error)) (FieldDeriveReport, error) {
	fail := func(class string) (FieldDeriveReport, error) {
		return FieldDeriveReport{FieldToolStatus: FieldToolStatus{Class: class}}, fieldc1c.ErrInvalid
	}
	if !paths.Valid() {
		return fail("gate_c_request_invalid")
	}
	fieldHash, fieldInfo, err := fieldToolHash(paths.Field, true)
	if err != nil {
		return fail("build_mismatch")
	}
	routerHash, routerInfo, err := fieldToolHash(paths.Router, true)
	if err != nil {
		return fail("build_mismatch")
	}
	revision, ok := fieldToolBuildPair(fieldInfo, routerInfo)
	if !ok {
		return fail("build_mismatch")
	}
	var configuration [2]string
	for index, path := range []string{paths.InitiatorConfig, paths.ResponderConfig} {
		configuration[index], _, err = fieldToolHash(path, false)
		if err != nil {
			return fail("configuration_unreadable")
		}
	}
	fieldDigest, err := fieldc1c.DependencyConfigurationDigest(fieldInfo, configuration)
	if err != nil {
		return fail("build_mismatch")
	}
	routerDigest, err := fieldc1c.DependencyConfigurationDigest(routerInfo, configuration)
	if err != nil {
		return fail("build_mismatch")
	}
	machineScope, err := scope()
	if err != nil {
		return fail("machine_scope_unavailable")
	}
	return FieldDeriveReport{FieldToolStatus: FieldToolStatus{OK: true}, ExactSHA: revision, Toolchain: fieldInfo.GoVersion,
		InitiatorBinarySHA256: fieldHash, ResponderBinarySHA256: fieldHash, RouterBinarySHA256: routerHash,
		DependencyAndConfigurationSHA256: fieldDigest, RouterDependencyAndConfigurationSHA256: routerDigest,
		InitiatorConfigurationSHA256: configuration[0], ResponderConfigurationSHA256: configuration[1], MachineScopeReference: machineScope}, nil
}

func fieldToolBuildPair(field, router *debug.BuildInfo) (string, bool) {
	if field == nil || router == nil || field.GoVersion == "" || field.GoVersion != router.GoVersion {
		return "", false
	}
	var revisions [2]string
	for index, info := range []*debug.BuildInfo{field, router} {
		values := make(map[string]string)
		for _, setting := range info.Settings {
			if _, found := values[setting.Key]; found {
				return "", false
			}
			values[setting.Key] = setting.Value
		}
		if values["vcs"] != "git" || values["vcs.modified"] != "false" || values["-tags"] != "fieldc1c" || !fieldToolHex(values["vcs.revision"], 20) {
			return "", false
		}
		revisions[index] = values["vcs.revision"]
	}
	return revisions[0], revisions[0] == revisions[1]
}

func fieldToolHex(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

func fieldToolOpenRead(path string, limit int64) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 || before.Size() < 0 || before.Size() > limit {
		return nil, fieldc1c.ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Size() > limit {
		_ = file.Close()
		return nil, fieldc1c.ErrInvalid
	}
	return file, nil
}

func fieldToolHash(path string, binary bool) (string, *debug.BuildInfo, error) {
	limit := int64(fieldToolTextLimit)
	if binary {
		limit = fieldToolBinaryLimit
	}
	file, err := fieldToolOpenRead(path, limit)
	if err != nil {
		return "", nil, fieldc1c.ErrInvalid
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", nil, fieldc1c.ErrInvalid
	}
	var info *debug.BuildInfo
	if binary {
		info, err = buildinfo.Read(file)
		if err != nil {
			return "", nil, fieldc1c.ErrInvalid
		}
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, limit+1))
	after, statErr := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || n != before.Size() || n > limit || statErr != nil || pathErr != nil || !os.SameFile(after, current) ||
		after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", nil, fieldc1c.ErrInvalid
	}
	return hex.EncodeToString(hash.Sum(nil)), info, nil
}
