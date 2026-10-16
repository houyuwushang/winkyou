//go:build fieldc1c

package fieldc1c

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// This test checks shape only. Synthetic approvals and derived values exist
// only in memory, are individually reported, and cannot issue an Instance.
// It never calls Load, reads machine-id, writes the input, or executes an image.
func TestFieldInstancePreapprovalShape(t *testing.T) {
	path := os.Getenv("WINKYOU_C1C_PREAPPROVAL_FILE")
	if path == "" {
		if os.Getenv("WINKYOU_C1C_PREAPPROVAL_REQUIRED") == "1" {
			t.Fatal("WINKYOU_C1C_PREAPPROVAL_FILE is required")
		}
		t.Skip("WINKYOU_C1C_PREAPPROVAL_FILE is not set")
	}
	if runtime.GOOS != "linux" {
		t.Fatal("external preapproval requires Linux path semantics; use synthetic tests on other platforms")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("preapproval input unavailable")
	}
	defer file.Close()
	original, err := io.ReadAll(io.LimitReader(file, MaxInstanceBytes+1))
	if err != nil {
		t.Fatal("preapproval input unreadable")
	}
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	payload, synthesized, err := preapprovalPrepare(original, now)
	if err != nil {
		t.Fatal(err)
	}
	var header struct {
		ExactSHA  string `json:"exact_sha"`
		Toolchain string `json:"toolchain"`
	}
	if err := json.Unmarshal(payload, &header); err != nil {
		t.Fatal("preapproval header invalid")
	}
	field, err := preapprovalReadBuild(os.Getenv("WINKYOU_C1C_FIELD_BINARY"), header.ExactSHA, header.Toolchain)
	if err != nil {
		t.Fatalf("field build: %v", err)
	}
	router, err := preapprovalReadBuild(os.Getenv("WINKYOU_C1C_ROUTER_BINARY"), header.ExactSHA, header.Toolchain)
	if err != nil {
		t.Fatalf("router build: %v", err)
	}
	for _, path := range synthesized {
		t.Logf("C1C_PREAPPROVAL synthetic_path=%s", path)
	}
	preapprovalAssertValid(t, payload, field, router, now)
	preapprovalAssertMutations(t, payload, field, router, now)
	t.Logf("C1C_PREAPPROVAL shape=pass roles=3 synthesized=%d original_sha256=%x authorization=none", len(synthesized), sha256.Sum256(original))
}

func preapprovalReadBuild(path, exactSHA, toolchain string) (buildWitness, error) {
	if path == "" {
		return buildWitness{}, errors.New("exact binary environment input missing")
	}
	file, err := os.Open(path)
	if err != nil {
		return buildWitness{}, errors.New("exact binary unavailable")
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > 512*1024*1024 {
		return buildWitness{}, errors.New("exact binary shape invalid")
	}
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return buildWitness{}, errors.New("exact binary build metadata unreadable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return buildWitness{}, errors.New("exact binary hash unreadable")
	}
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return buildWitness{}, errors.New("exact binary changed while reading")
	}
	return preapprovalBuild(info, fmt.Sprintf("%x", hash.Sum(nil)), exactSHA, toolchain)
}

func preapprovalBuild(info *debug.BuildInfo, digest, exactSHA, toolchain string) (buildWitness, error) {
	if info == nil || !hexValue(exactSHA, 20) || !hexValue(digest, 32) || info.GoVersion != toolchain || toolchain == "" {
		return buildWitness{}, errors.New("build identity mismatch")
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		if _, exists := settings[setting.Key]; exists {
			return buildWitness{}, errors.New("duplicate build setting")
		}
		settings[setting.Key] = setting.Value
	}
	if settings["vcs.revision"] != exactSHA || settings["vcs.modified"] != "false" || settings["-tags"] != "fieldc1c" || settings["-race"] == "true" {
		return buildWitness{}, errors.New("sealed build settings mismatch")
	}
	build := buildWitness{sha: exactSHA, revision: settings["vcs.revision"], binaryHash: digest,
		toolchain: info.GoVersion, tags: strings.Split(settings["-tags"], ","), modified: false}
	seen := make(map[string]bool)
	for _, dep := range info.Deps {
		if dep == nil || dep.Replace != nil || dep.Path == "" || seen[dep.Path] || strings.ContainsRune(dep.Path+dep.Version+dep.Sum, 0) {
			return buildWitness{}, errors.New("dependency metadata invalid or replaced")
		}
		seen[dep.Path] = true
		build.dependencies = append(build.dependencies, dep.Path+"\x00"+dep.Version+"\x00"+dep.Sum)
	}
	sort.Strings(build.dependencies)
	return build, nil
}

func preapprovalPrepare(original []byte, now time.Time) ([]byte, []string, error) {
	if len(original) == 0 || len(original) > MaxInstanceBytes || !utf8.Valid(original) || now.IsZero() {
		return nil, nil, errors.New("preapproval input shape invalid")
	}
	var raw map[string]json.RawMessage
	if strictJSON(original, &raw) != nil {
		return nil, nil, errors.New("preapproval JSON invalid")
	}
	// Keep numbers exact: decoding inode values through float64 could round a
	// non-synthetic value before production validation sees it.
	decoder := json.NewDecoder(bytes.NewReader(original))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil {
		return nil, nil, errors.New("preapproval object invalid")
	}
	ident, ok := value["instance_id"].(string)
	if !ok {
		return nil, nil, errors.New("instance_id missing or invalid")
	}
	if ident == "<ATTEMPT>" {
		ident = "AAAAAAAAAAAAAAAAAAAAAA"
	}
	if !attemptID(ident) {
		return nil, nil, errors.New("instance_id is not canonical")
	}
	prefix := fmt.Sprintf("wyc1c%x", sha256.Sum256([]byte("winkyou-c1c-anchor/1\n"+ident)))[:13]
	type substitution struct{ before, after string }
	stringsAt := map[string]substitution{
		"$.instance_id":           {"<ATTEMPT>", ident},
		"$.manifest_sha256":       {"<D_MANIFEST_SHA256>", strings.Repeat("c", 64)},
		"$.credential_expires_at": {"<D_EXPIRES>", now.Add(9 * time.Minute).Format(time.RFC3339)},
		"$.signed_at":             {"<H_SIGNED_AT>", now.Add(-time.Minute).Format(time.RFC3339)},
		"$.not_before":            {"<H_NOT_BEFORE>", now.Add(-time.Minute).Format(time.RFC3339)},
		"$.not_after":             {"<H_NOT_AFTER>", now.Add(9 * time.Minute).Format(time.RFC3339)},
		"$.operator_signature":    {"<H_OPERATOR_SIGNATURE>", "synthetic-shape-only-operator"},
		"$.reviewer_signature":    {"<H_REVIEWER_SIGNATURE>", "synthetic-shape-only-reviewer"},
	}
	paths := map[string]bool{"$.credential_reference": true, "$.host_key_pin_reference": true, "$.ssh_identity_reference": true}
	nulls := map[string]any{
		"$.root_risk_accepted_by_operator": true, "$.root_risk_accepted_by_reviewer": true,
		"$.unused_credential_verified": true, "$.single_invocation_verified": true,
	}
	for i, suffix := range []string{"-i", "-t", "-r"} {
		key := fmt.Sprintf("$.router.anchors[%d]", i)
		stringsAt[key+".name"] = substitution{"wyc1c<ATTEMPT8>" + suffix, prefix + suffix}
		nulls[key+".inode"] = uint64(101 + i)
	}
	for i := 0; i < 2; i++ {
		for _, field := range []string{"request_reference", "configuration_reference"} {
			paths[fmt.Sprintf("$.devices[%d].%s", i, field)] = true
		}
	}
	allowedNull := map[string]bool{"$.mapping_set_role": true, "$.containment_authorization": true}
	for _, field := range postRunFields {
		allowedNull["$."+field] = true
	}
	var synthesized []string
	var visit func(any, string) (any, error)
	visit = func(current any, path string) (any, error) {
		switch item := current.(type) {
		case map[string]any:
			for key, child := range item {
				changed, err := visit(child, path+"."+key)
				if err != nil {
					return nil, err
				}
				item[key] = changed
			}
		case []any:
			for i, child := range item {
				changed, err := visit(child, fmt.Sprintf("%s[%d]", path, i))
				if err != nil {
					return nil, err
				}
				item[i] = changed
			}
		case string:
			if replacement, exists := stringsAt[path]; exists && item == replacement.before {
				item = replacement.after
				synthesized = append(synthesized, path)
			} else if paths[path] && strings.Contains(item, "<ATTEMPT>") {
				item = strings.ReplaceAll(item, "<ATTEMPT>", ident)
				synthesized = append(synthesized, path)
			}
			if strings.ContainsAny(item, "<>") {
				return nil, fmt.Errorf("unapproved placeholder at %s", path)
			}
			return item, nil
		case nil:
			if replacement, exists := nulls[path]; exists {
				synthesized = append(synthesized, path)
				return replacement, nil
			}
			if !allowedNull[path] {
				return nil, fmt.Errorf("unapproved null at %s", path)
			}
		}
		return current, nil
	}
	if _, err := visit(value, "$"); err != nil {
		return nil, nil, err
	}
	prepared, err := json.Marshal(value)
	sort.Strings(synthesized)
	return prepared, synthesized, err
}

func preapprovalAssertValid(t *testing.T, payload []byte, field, router buildWitness, now time.Time) {
	t.Helper()
	for _, role := range []string{"initiator", "responder", "router"} {
		build := field
		if role == "router" {
			build = router
		}
		if _, err := validate(payload, role, now, build); err != nil {
			t.Fatalf("preapproval shape rejected for %s: %v", role, err)
		}
	}
}

func preapprovalAssertMutations(t *testing.T, payload []byte, field, router buildWitness, now time.Time) {
	t.Helper()
	for _, mutation := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"missing_top_level", func(v map[string]any) { delete(v, "implementation_review") }},
		{"layout", func(v map[string]any) { v["layout"] = "unreviewed-layout" }},
		{"observer_cross_address", func(v map[string]any) { v["observer_topology"].(map[string]any)["alternate_port"] = "203.0.113.9:3479" }},
		{"implemented_hardening", func(v map[string]any) { v["hardening_drop_privileges"].(map[string]any)["status"] = "implemented" }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(payload, &value); err != nil {
				t.Fatal(err)
			}
			mutation.change(value)
			mutated := encodeFixture(t, value)
			for _, role := range []string{"initiator", "responder", "router"} {
				build := field
				if role == "router" {
					build = router
				}
				if _, err := validate(mutated, role, now, build); !errors.Is(err, ErrInvalid) {
					t.Fatalf("mutation escaped for %s: %v", role, err)
				}
			}
			t.Logf("C1C_PREAPPROVAL mutation=%s rejected_roles=3", mutation.name)
		})
	}
}

func preapprovalSynthetic(t *testing.T) ([]byte, buildWitness, buildWitness, time.Time) {
	t.Helper()
	value, field, now := routerV2Fixture(t)
	router := field
	router.binaryHash, router.dependencies = strings.Repeat("f", 64), []string{"synthetic-router\x00v2\x00synthetic-sum"}
	value["router_binary_sha256"] = router.binaryHash
	var doc document
	common := make(map[string]any)
	for key, item := range value {
		if key != "router" {
			common[key] = item
		}
	}
	if err := json.Unmarshal(encodeFixture(t, common), &doc); err != nil {
		t.Fatal(err)
	}
	value["router"].(map[string]any)["dependency_and_configuration_sha256"] = dependencyDigest(router, doc.Devices)
	for field, token := range map[string]string{
		"instance_id": "<ATTEMPT>", "manifest_sha256": "<D_MANIFEST_SHA256>", "credential_expires_at": "<D_EXPIRES>",
		"signed_at": "<H_SIGNED_AT>", "not_before": "<H_NOT_BEFORE>", "not_after": "<H_NOT_AFTER>",
		"operator_signature": "<H_OPERATOR_SIGNATURE>", "reviewer_signature": "<H_REVIEWER_SIGNATURE>",
	} {
		value[field] = token
	}
	for _, field := range []string{"root_risk_accepted_by_operator", "root_risk_accepted_by_reviewer", "unused_credential_verified", "single_invocation_verified"} {
		value[field] = nil
	}
	base := t.TempDir()
	for _, field := range []string{"credential_reference", "host_key_pin_reference", "ssh_identity_reference"} {
		value[field] = filepath.Join(base, "<ATTEMPT>", field)
	}
	for i, device := range value["devices"].([]any) {
		for _, field := range []string{"request_reference", "configuration_reference"} {
			device.(map[string]any)[field] = filepath.Join(base, "<ATTEMPT>", fmt.Sprintf("%d-%s", i, field))
		}
	}
	for i, anchor := range value["router"].(map[string]any)["anchors"].([]any) {
		anchor.(map[string]any)["name"] = "wyc1c<ATTEMPT8>" + []string{"-i", "-t", "-r"}[i]
		anchor.(map[string]any)["inode"] = nil
	}
	return encodeFixture(t, value), field, router, now
}

func TestFieldPreapprovalSynthetic(t *testing.T) {
	original, field, router, now := preapprovalSynthetic(t)
	before := bytes.Clone(original)
	payload, synthesized, err := preapprovalPrepare(original, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(synthesized) != 25 || !sort.StringsAreSorted(synthesized) || len(slices.Compact(slices.Clone(synthesized))) != 25 || !bytes.Equal(before, original) {
		t.Fatal("synthetic field inventory or immutable original changed")
	}
	preapprovalAssertValid(t, payload, field, router, now)
	preapprovalAssertMutations(t, payload, field, router, now)
	if _, err := validate(payload, "router", now, field); !errors.Is(err, ErrInvalid) {
		t.Fatal("router accepted endpoint build witness")
	}
	for _, path := range synthesized {
		t.Logf("C1C_PREAPPROVAL synthetic_path=%s", path)
	}
	t.Log("C1C_PREAPPROVAL synthetic_control=pass roles=3 original_unchanged=true authorization=none")
}

func TestFieldPreapprovalRemaindersRejected(t *testing.T) {
	for _, mutation := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"unknown_placeholder", func(v map[string]any) { v["implementation_review"] = "<UNREVIEWED>" }},
		{"unknown_null", func(v map[string]any) { v["implementation_review"] = nil }},
		{"misplaced_attempt", func(v map[string]any) { v["operator"] = "<ATTEMPT>" }},
		{"missing_signature", func(v map[string]any) { delete(v, "operator_signature") }},
		{"false_risk", func(v map[string]any) { v["root_risk_accepted_by_operator"] = false }},
		{"false_unused", func(v map[string]any) { v["unused_credential_verified"] = false }},
		{"post_run_prefilled", func(v map[string]any) { v["terminal_result_by_role"] = "success" }},
		{"fractional_inode", func(v map[string]any) {
			v["router"].(map[string]any)["anchors"].([]any)[0].(map[string]any)["inode"] = json.Number("9007199254740992.1")
		}},
		{"field_digest", func(v map[string]any) { v["dependency_and_configuration_sha256"] = strings.Repeat("0", 64) }},
		{"router_digest", func(v map[string]any) {
			v["router"].(map[string]any)["dependency_and_configuration_sha256"] = strings.Repeat("0", 64)
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			original, field, router, now := preapprovalSynthetic(t)
			var value map[string]any
			if err := json.Unmarshal(original, &value); err != nil {
				t.Fatal(err)
			}
			mutation.change(value)
			payload, _, err := preapprovalPrepare(encodeFixture(t, value), now)
			if err != nil {
				return
			}
			build, role := field, "initiator"
			if mutation.name == "router_digest" {
				build, role = router, "router"
			}
			if _, err := validate(payload, role, now, build); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid preapproval survived: %v", err)
			}
		})
	}
}

func TestFieldPreapprovalBuildMetadata(t *testing.T) {
	makeInfo := func() *debug.BuildInfo {
		return &debug.BuildInfo{GoVersion: "go1.23.1", Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: strings.Repeat("a", 40)}, {Key: "vcs.modified", Value: "false"}, {Key: "-tags", Value: "fieldc1c"},
		}, Deps: []*debug.Module{{Path: "z/module", Version: "v2", Sum: "sum-z"}, {Path: "a/module", Version: "v1", Sum: "sum-a"}}}
	}
	build, err := preapprovalBuild(makeInfo(), strings.Repeat("b", 64), strings.Repeat("a", 40), "go1.23.1")
	if err != nil || !slices.Equal(build.dependencies, []string{"a/module\x00v1\x00sum-a", "z/module\x00v2\x00sum-z"}) || build.modified {
		t.Fatal("metadata did not construct the sorted exact build witness")
	}
	for _, mutation := range []struct {
		name   string
		change func(*debug.BuildInfo)
	}{
		{"revision", func(v *debug.BuildInfo) { v.Settings[0].Value = strings.Repeat("c", 40) }},
		{"modified", func(v *debug.BuildInfo) { v.Settings[1].Value = "true" }},
		{"missing_modified", func(v *debug.BuildInfo) { v.Settings = append(v.Settings[:1], v.Settings[2:]...) }},
		{"tags", func(v *debug.BuildInfo) { v.Settings[2].Value = "fieldc1c,c1bproof" }},
		{"toolchain", func(v *debug.BuildInfo) { v.GoVersion = "go1.23.2" }},
		{"replace", func(v *debug.BuildInfo) { v.Deps[0].Replace = &debug.Module{Path: "replacement"} }},
		{"duplicate_dependency", func(v *debug.BuildInfo) { v.Deps = append(v.Deps, v.Deps[0]) }},
		{"duplicate_setting", func(v *debug.BuildInfo) { v.Settings = append(v.Settings, v.Settings[0]) }},
		{"race", func(v *debug.BuildInfo) {
			v.Settings = append(v.Settings, debug.BuildSetting{Key: "-race", Value: "true"})
		}},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			info := makeInfo()
			mutation.change(info)
			if _, err := preapprovalBuild(info, strings.Repeat("b", 64), strings.Repeat("a", 40), "go1.23.1"); err == nil {
				t.Fatal("unsealed metadata accepted")
			}
		})
	}
}
