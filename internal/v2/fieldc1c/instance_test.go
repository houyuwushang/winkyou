//go:build fieldc1c

package fieldc1c

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func fixtureDocument(t *testing.T) (document, buildWitness, time.Time) {
	t.Helper()
	var doc document
	v := reflect.ValueOf(&doc).Elem()
	for index := 0; index < v.NumField(); index++ {
		field := v.Field(index)
		if field.Kind() == reflect.String {
			field.SetString("synthetic-reviewed-reference")
		}
		if field.Kind() == reflect.Bool {
			field.SetBool(true)
		}
		if field.Type() == reflect.TypeOf(json.RawMessage{}) {
			field.SetBytes([]byte("null"))
		}
	}
	stamp := time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC)
	root := t.TempDir()
	path := func(name string) string { return filepath.Join(root, name) }
	build := buildWitness{sha: strings.Repeat("a", 40), revision: strings.Repeat("a", 40),
		binaryHash: strings.Repeat("b", 64), toolchain: "go1.23.1", tags: []string{"fieldc1c"}, dependencies: []string{"synthetic-module\x00v1\x00synthetic-sum"}}
	doc.InstanceID, doc.Scenario = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16)), "predictive_apdm_pair"
	doc.Operator, doc.IndependentReviewer = "synthetic-operator", "synthetic-reviewer"
	doc.SignedAt, doc.NotBefore = stamp.Add(-time.Minute).Format(time.RFC3339), stamp.Format(time.RFC3339)
	doc.NotAfter, doc.CredentialExpiresAt = stamp.Add(5*time.Minute).Format(time.RFC3339), stamp.Add(10*time.Minute).Format(time.RFC3339)
	doc.Layout, doc.AuthoritySchemaRevision = Layout, Schema
	doc.ExactSHA, doc.Toolchain, doc.BuildTags = build.sha, build.toolchain, []string{"fieldc1c"}
	doc.InitiatorBinarySHA256, doc.ResponderBinarySHA256, doc.RouterBinarySHA256 = build.binaryHash, build.binaryHash, build.binaryHash
	doc.ManifestSHA256 = strings.Repeat("c", 64)
	doc.InitiatorMachineScopeReference = "machine-scope-sha256/1:" + strings.Repeat("1", 64)
	doc.ResponderMachineScopeReference = "machine-scope-sha256/1:" + strings.Repeat("2", 64)
	doc.Profile, doc.ResourceClass, doc.ExactCostReference = "predictive_edm/1", "predictive_32/1", "gate-c/predictive_32/1"
	doc.InitiatorRole, doc.ResponderRole = "initiator", "responder"
	doc.CredentialReference, doc.HostKeyPinReference, doc.SSHIdentityReference = path("material"), path("pin"), path("identity")
	doc.SessionLivenessMode, doc.AbsoluteSessionCeiling = "challenge_v1", "3m"
	doc.InitiatorMissedRounds, doc.ResponderMissedRounds = 2, 3
	doc.Devices = []Device{
		{Role: "initiator", OS: "linux", RequestReference: path("initiator-request"), ConfigurationReference: path("initiator-config"), ConfigurationSHA256: strings.Repeat("d", 64), ManagementReference: "synthetic-management"},
		{Role: "responder", OS: "linux", RequestReference: path("responder-request"), ConfigurationReference: path("responder-config"), ConfigurationSHA256: strings.Repeat("e", 64), ManagementReference: "synthetic-management"},
	}
	doc.DependencyAndConfigurationSHA256 = dependencyDigest(build, doc.Devices)
	doc.RouterResourceInventory = []Resource{{"router", "synthetic-resource", "synthetic-teardown"}}
	doc.EndpointResourceInventory = []Resource{{"initiator", "synthetic-resource", "synthetic-teardown"}, {"responder", "synthetic-resource", "synthetic-teardown"}}
	doc.InitiatorExpectedPeerAddress, doc.ResponderExpectedPeerAddress = "203.0.113.2", "198.51.100.1"
	doc.ObserverTopology = Topology{"198.51.100.2:3478", "198.51.100.2:3479", "203.0.113.1:3478", "203.0.113.1:3479"}
	doc.SSHLiteralEndpoint = "203.0.113.2:22"
	hardening := Hardening{"not_implemented", "separate-design-required", "root-parser-surface", "synthetic-review"}
	doc.HardeningDropPrivileges, doc.HardeningSyscallFilesystemIsolation, doc.HardeningLowPrivilegeParser = hardening, hardening, hardening
	doc.InterfaceRouteAddressAuthority = Interfaces{Interface{"wink-c1c-proof", "192.0.2.100", "192.0.2.101", 1280}, Interface{"wink-c1c-proof", "192.0.2.101", "192.0.2.100", 1280}}
	doc.OwnedStopTargetIdentity = StopIdentity{"owned-foreground-and-child/1", "synthetic-reviewed-stop"}
	doc.ExpectedTerminalAndFaultStage = ExpectedTerminal{"success", "terminal", "none"}
	doc.WitnessPlan = WitnessPlan{"synthetic", "synthetic", "synthetic", "synthetic", "synthetic", "synthetic", "synthetic", "synthetic", "synthetic"}
	return doc, build, stamp
}

func encodeFixture(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestInstanceSchemaMatchesAllTemplateFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "templates", "gate-c1c-authorization.template.json"))
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Fields []struct {
			Field string `json:"field"`
		} `json:"fields"`
	}
	if json.Unmarshal(data, &catalog) != nil || len(catalog.Fields) != 88 {
		t.Fatal("88-field template changed")
	}
	typeOf := reflect.TypeOf(document{})
	if typeOf.NumField() != len(catalog.Fields) {
		t.Fatal("field count changed")
	}
	for index, field := range catalog.Fields {
		if typeOf.Field(index).Tag.Get("json") != field.Field {
			t.Fatalf("field %d mismatches template", index)
		}
	}
}

func TestInstanceEveryRequiredMemberAndNullFailsClosed(t *testing.T) {
	doc, build, now := fixtureDocument(t)
	payload := encodeFixture(t, doc)
	if _, err := validate(payload, "initiator", now, build); err != nil {
		t.Fatal("complete synthetic document rejected")
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(payload, &members) != nil {
		t.Fatal("fixture failed")
	}
	for name, original := range members {
		t.Run(name, func(t *testing.T) {
			delete(members, name)
			if _, err := validate(encodeFixture(t, members), "initiator", now, build); !errors.Is(err, ErrInvalid) {
				t.Fatal("omitted member accepted")
			}
			members[name] = []byte("null")
			optional := name == "mapping_set_role" || name == "containment_authorization" || slices.Contains(postRunFields, name)
			if _, err := validate(encodeFixture(t, members), "initiator", now, build); (err == nil) != optional {
				t.Fatal("null member contract changed")
			}
			members[name] = original
		})
	}
}

func TestInstanceInvalidPermissionsBuildTimeAndShape(t *testing.T) {
	tests := []struct {
		name   string
		change func(*document, *buildWitness, *time.Time)
	}{
		{"schema", func(d *document, _ *buildWitness, _ *time.Time) { d.AuthoritySchemaRevision += "unknown" }},
		{"wrong_sha", func(d *document, _ *buildWitness, _ *time.Time) { d.ExactSHA = strings.Repeat("e", 40) }},
		{"missing_vcs", func(_ *document, b *buildWitness, _ *time.Time) { b.revision = "" }},
		{"dirty_build", func(_ *document, b *buildWitness, _ *time.Time) { b.modified = true }},
		{"binary_hash", func(_ *document, b *buildWitness, _ *time.Time) { b.binaryHash = strings.Repeat("0", 64) }},
		{"extra_tag", func(_ *document, b *buildWitness, _ *time.Time) { b.tags = append(b.tags, "natlab") }},
		{"ordinary_tag", func(_ *document, b *buildWitness, _ *time.Time) { b.tags = nil }},
		{"dependency", func(_ *document, b *buildWitness, _ *time.Time) { b.dependencies = append(b.dependencies, "extra") }},
		{"not_yet", func(_ *document, _ *buildWitness, n *time.Time) { *n = n.Add(-time.Nanosecond) }},
		{"expired", func(_ *document, _ *buildWitness, n *time.Time) { *n = n.Add(5 * time.Minute) }},
		{"one_person", func(d *document, _ *buildWitness, _ *time.Time) { d.IndependentReviewer = d.Operator }},
		{"no_observer_permission", func(d *document, _ *buildWitness, _ *time.Time) { d.ObserverOperatorPermission = "" }},
		{"role", func(d *document, _ *buildWitness, _ *time.Time) { d.ResponderRole = "initiator" }},
		{"resource", func(d *document, _ *buildWitness, _ *time.Time) { d.ResourceClass = "hard_16k_lab/1" }},
		{"dns", func(d *document, _ *buildWitness, _ *time.Time) { d.SSHLiteralEndpoint = "synthetic.invalid:22" }},
		{"cidr", func(d *document, _ *buildWitness, _ *time.Time) { d.InitiatorExpectedPeerAddress += "/32" }},
		{"list", func(d *document, _ *buildWitness, _ *time.Time) { d.InitiatorExpectedPeerAddress += ",192.0.2.1" }},
		{"observer_topology", func(d *document, _ *buildWitness, _ *time.Time) {
			d.ObserverTopology.AlternatePort = d.ObserverTopology.Primary
		}},
		{"windows", func(d *document, _ *buildWitness, _ *time.Time) { d.Devices[1].OS = "windows" }},
		{"hardening_claim", func(d *document, _ *buildWitness, _ *time.Time) { d.HardeningDropPrivileges.Status = "implemented" }},
		{"false_root_permission", func(d *document, _ *buildWitness, _ *time.Time) { d.RootRiskAcceptedByReviewer = false }},
		{"forged_post_run", func(d *document, _ *buildWitness, _ *time.Time) { d.LedgerSealedBeforeDestruction = []byte("true") }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doc, build, now := fixtureDocument(t)
			test.change(&doc, &build, &now)
			if _, err := validate(encodeFixture(t, doc), "initiator", now, build); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid authorization accepted")
			}
		})
	}
	doc, build, now := fixtureDocument(t)
	valid := encodeFixture(t, doc)
	for name, payload := range map[string][]byte{
		"unknown":          append([]byte(`{"unknown":true,`), valid[1:]...),
		"duplicate":        append([]byte(`{"instance_id":"duplicate",`), valid[1:]...),
		"two_values":       append(bytes.Clone(valid), []byte(` {}`)...),
		"oversize":         append(bytes.Clone(valid), bytes.Repeat([]byte(" "), MaxInstanceBytes)...),
		"nested_unknown":   bytes.Replace(valid, []byte(`"primary":`), []byte(`"unknown":true,"primary":`), 1),
		"nested_duplicate": bytes.Replace(valid, []byte(`"primary":`), []byte(`"primary":"duplicate","primary":`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validate(payload, "initiator", now, build); !errors.Is(err, ErrInvalid) {
				t.Fatal("malformed authorization accepted")
			}
		})
	}
}

func TestInstanceOpaqueZeroAndBoundary(t *testing.T) {
	var instance Instance
	if instance.Check(time.Now()) != ErrInvalid {
		t.Fatal("zero token accepted")
	}
	if _, err := instance.SSHEndpoint(); err != ErrInvalid {
		t.Fatal("zero SSH scope accepted")
	}
	doc, build, now := fixtureDocument(t)
	validated, err := validate(encodeFixture(t, doc), "initiator", now, build)
	if err != nil {
		t.Fatal(err)
	}
	instance = Instance{value: validated}
	if instance.Check(now) != nil || instance.Check(now.Add(5*time.Minute)) != ErrInvalid || instance.Check(now.Add(-time.Nanosecond)) != ErrInvalid {
		t.Fatal("window not half open")
	}
	for _, field := range reflect.VisibleFields(reflect.TypeOf(instance)) {
		if field.IsExported() || field.Anonymous {
			t.Fatal("authority exposes mutable representation")
		}
	}
}

func TestFieldEnvironmentCannotEnableRawTunnelDiagnostics(t *testing.T) {
	t.Setenv("WINKYOU_TUNNEL_DEBUG", "")
	t.Setenv("WINKYOU_TRACE_TUN_PACKETS", "")
	if !fieldEnvironmentSafe() {
		t.Fatal("silent default rejected")
	}
	for _, key := range []string{"WINKYOU_TUNNEL_DEBUG", "WINKYOU_TRACE_TUN_PACKETS"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "1")
			if fieldEnvironmentSafe() {
				t.Fatal("raw diagnostic environment accepted")
			}
		})
	}
}
