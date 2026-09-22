//go:build linux && natlab && c1bproof && fieldc1c

package natlab

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"winkyou/internal/v2/fieldc1c"
	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/pairingcontext"
	"winkyou/pkg/config"
)

type fieldC1cHostConfig struct {
	Host                              gateC1bHostConfig
	Instance, Evidence, MachineIDFile string
}

func fieldC1cFixture(t *testing.T, original [2]gateC1bHostConfig, profile gateC1bProfile, binary string) [2]fieldC1cHostConfig {
	t.Helper()
	build, err := buildinfo.ReadFile(binary)
	if err != nil {
		t.Fatal("C1c exact build metadata unavailable")
	}
	var sha string
	for _, setting := range build.Settings {
		if setting.Key == "vcs.revision" {
			sha = setting.Value
		}
		if setting.Key == "vcs.modified" && setting.Value != "false" {
			t.Fatal("C1c dirty build rejected")
		}
	}
	if len(sha) != 40 {
		t.Fatal("C1c exact build revision absent")
	}
	binaryHash := fieldC1cFileDigest(t, binary)
	var dependencies []string
	for _, dependency := range build.Deps {
		if dependency.Replace != nil {
			t.Fatal("C1c replacement build rejected")
		}
		dependencies = append(dependencies, dependency.Path+"\x00"+dependency.Version+"\x00"+dependency.Sum)
	}
	sort.Strings(dependencies)
	var devices [2]fieldc1c.Device
	var requests [2]gatecrequestForField
	var result [2]fieldC1cHostConfig
	for side, host := range original {
		configuration, err := config.Load(host.ConfigFile)
		if err != nil {
			t.Fatal("C1c fixture config unavailable")
		}
		configuration.GateC.Peers[0].SessionCeiling = 60 * time.Second
		configuration.GateC.Peers[0].SessionLiveness = &config.SessionLivenessConfig{Mode: "challenge_v1", MissedRounds: 3}
		data, err := yaml.Marshal(configuration)
		if err != nil {
			t.Fatal("C1c fixture config invalid")
		}
		// These are newly generated private fixture files, never a host config.
		if os.WriteFile(host.ConfigFile, data, 0o600) != nil {
			t.Fatal("C1c private configuration failed")
		}
		clear(data)
		role := []string{"initiator", "responder"}[side]
		devices[side] = fieldc1c.Device{Role: role, OS: "linux", RequestReference: host.RequestFile, ConfigurationReference: host.ConfigFile,
			ConfigurationSHA256: fieldC1cFileDigest(t, host.ConfigFile), ManagementReference: "synthetic-independent-management"}
		requests[side] = fieldC1cReadRequest(t, host.RequestFile)
		for _, name := range []string{"wink", "gate-c-child-wrapper"} {
			path := filepath.Join(host.InstallBase, "winkyou", name)
			if os.Remove(path) != nil {
				t.Fatal("C1c generated fixture replacement failed")
			}
			copyGateC1bBinary(t, binary, path)
		}
		machineID := filepath.Join(filepath.Dir(host.RequestFile), "machine-id")
		if pairgen.WritePrivateFileExclusive(machineID, []byte(strings.Repeat([]string{"1", "2"}[side], 32)+"\n")) != nil {
			t.Fatal("C1c private machine witness failed")
		}
		result[side] = fieldC1cHostConfig{Host: host, MachineIDFile: machineID}
	}
	artifact := fieldC1cArtifact(t, requests[0].ArtifactFile)
	defer artifact.Close()
	manifest := gatecattempt.Manifest{Schema: gatecattempt.ManifestProfile, ArtifactProfile: gatecattempt.ArtifactProfile, DirectAttemptProfile: gatecattempt.DirectAttemptProfile,
		PlannerProfile: string(profile.profile), ResourceClass: string(profile.resource), OOBCarrierProfile: gatecattempt.OOBCarrierProfile,
		ObservationProfile: gatecattempt.ObservationProfile, DataPlaneConsumerProfile: gatecattempt.DataPlaneConsumerProfile, DataPlaneChallengeProfile: gatecattempt.DataPlaneChallengeProfile,
		SecureChannelProfile: pairingcontext.SelectedSecureChannelProfile, AuthScope: gatecattempt.AuthScope, RuntimeFallback: "disabled",
		CredentialID: artifact.CredentialID, AttemptID: artifact.AttemptID, OOBChannelID: artifact.OOBChannelID, IssuedAt: artifact.IssuedAt.Format(time.RFC3339),
		ExpiresAt: artifact.ExpiresAt.Format(time.RFC3339), ArtifactFingerprint: artifact.Fingerprint}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal("C1c synthetic manifest failed")
	}
	materialDir := filepath.Dir(original[0].RequestFile)
	if pairgen.WritePrivateFileExclusive(filepath.Join(materialDir, "manifest.json"), manifestBytes) != nil {
		t.Fatal("C1c manifest write failed")
	}
	manifestHash := sha256.Sum256(manifestBytes)
	clear(manifestBytes)
	dependencyBytes, _ := json.Marshal(struct {
		Domain        string    `json:"domain"`
		Dependencies  []string  `json:"dependencies"`
		Configuration [2]string `json:"configuration"`
	}{
		"winkyou-c1c-dependencies-config/1", dependencies, [2]string{devices[0].ConfigurationSHA256, devices[1].ConfigurationSHA256}})
	dependencyHash := sha256.Sum256(dependencyBytes)
	root := fieldC1cRepositoryRoot(t)
	var catalog struct {
		Fields []struct{ Field, Type string }
	}
	data, err := os.ReadFile(filepath.Join(root, "docs", "templates", "gate-c1c-authorization.template.json"))
	if err != nil || json.Unmarshal(data, &catalog) != nil {
		t.Fatal("C1c field catalog unavailable")
	}
	document := make(map[string]any, 88)
	for _, entry := range catalog.Fields {
		document[entry.Field] = "synthetic-isolated-proof"
		if entry.Type == "boolean" {
			document[entry.Field] = true
		}
	}
	for _, name := range []string{"mapping_set_role", "containment_authorization", "tuple_observations", "raw_evidence_references", "evidence_sha256", "terminal_result_by_role",
		"durable_finish_and_circuit_evidence", "owned_residue_by_layer", "ledger_sealed_before_destruction", "cloud_teardown_evidence", "independent_management_preserved",
		"redacted_summary_review", "authorization_closed_at", "teardown_operator_signature", "teardown_reviewer_signature"} {
		document[name] = nil
	}
	document["instance_id"] = artifact.AttemptID
	document["scenario"] = "predictive_apdm_pair"
	if profile.name == "asymmetric" {
		document["scenario"] = "asymmetric_initiator_mapping_set"
		document["mapping_set_role"] = "initiator"
	}
	document["operator"], document["independent_reviewer"] = "synthetic-operator", "synthetic-reviewer"
	stamp := time.Now().UTC().Truncate(time.Second)
	document["signed_at"], document["not_before"], document["not_after"] = stamp.Add(-time.Second).Format(time.RFC3339), stamp.Format(time.RFC3339), stamp.Add(3*time.Minute).Format(time.RFC3339)
	document["layout"], document["authority_schema_revision"] = fieldc1c.Layout, fieldc1c.Schema
	document["exact_sha"], document["toolchain"], document["build_tags"] = sha, build.GoVersion, []string{"fieldc1c"}
	document["initiator_binary_sha256"], document["responder_binary_sha256"], document["router_binary_sha256"] = binaryHash, binaryHash, fieldC1cFileDigest(t, os.Args[0])
	document["dependency_and_configuration_sha256"] = hex.EncodeToString(dependencyHash[:])
	document["profile"], document["resource_class"], document["exact_cost_reference"] = string(profile.profile), string(profile.resource), "gate-c/"+string(profile.resource)
	document["initiator_role"], document["responder_role"] = "initiator", "responder"
	document["credential_reference"], document["manifest_sha256"], document["credential_expires_at"] = materialDir, hex.EncodeToString(manifestHash[:]), artifact.ExpiresAt.Format(time.RFC3339)
	document["session_liveness_mode"], document["initiator_missed_rounds"], document["responder_missed_rounds"], document["absolute_session_ceiling"] = "challenge_v1", 3, 3, "1m0s"
	document["devices"] = devices
	document["router_resource_inventory"] = []fieldc1c.Resource{{Role: "router", Reference: "synthetic-router", TeardownReference: "synthetic-owned-namespaces"}}
	document["endpoint_resource_inventory"] = []fieldc1c.Resource{{Role: "initiator", Reference: "synthetic-initiator", TeardownReference: "synthetic-owned-namespaces"}, {Role: "responder", Reference: "synthetic-responder", TeardownReference: "synthetic-owned-namespaces"}}
	for side, key := range []string{"initiator_machine_scope_reference", "responder_machine_scope_reference"} {
		digest := sha256.Sum256([]byte("winkyou-c1c-machine-scope/1\n" + strings.Repeat([]string{"1", "2"}[side], 32) + "\n/var/lib/winkyou-safety-v2"))
		document[key] = "machine-scope-sha256/1:" + hex.EncodeToString(digest[:])
	}
	document["initiator_expected_peer_address"], document["responder_expected_peer_address"] = n2dNATBWAN, n2dNATAWAN
	observers := original[0].Observers
	document["observer_topology"] = fieldc1c.Topology{Primary: observers[0].String(), AlternatePort: observers[1].String(), AlternateAddress: observers[2].String(), AlternateAddressPort: observers[3].String()}
	document["ssh_literal_endpoint"], document["host_key_pin_reference"], document["ssh_identity_reference"] = requests[0].Endpoint, requests[0].KnownHosts, requests[0].Identity
	hardening := fieldc1c.Hardening{Status: "not_implemented", Reason: "separate-design-required", Risk: "root-parser-surface", EvidenceReference: "synthetic-reviewed-risk"}
	for _, key := range []string{"hardening_drop_privileges", "hardening_syscall_filesystem_isolation", "hardening_low_privilege_parser"} {
		document[key] = hardening
	}
	document["interface_route_address_authority"] = fieldc1c.Interfaces{Initiator: fieldc1c.Interface{Name: "wink-c1b-proof", LocalAddress: "192.0.2.100", PeerAddress: "192.0.2.101", MTU: 1280}, Responder: fieldc1c.Interface{Name: "wink-c1b-proof", LocalAddress: "192.0.2.101", PeerAddress: "192.0.2.100", MTU: 1280}}
	document["owned_stop_target_identity"] = fieldc1c.StopIdentity{Kind: "owned-foreground-and-child/1", VerificationReference: "synthetic-owned-signal"}
	document["expected_terminal_and_fault_stage"] = fieldc1c.ExpectedTerminal{Terminal: "success", Stage: "terminal", InjectionReference: "synthetic-owned-signal"}
	document["witness_plan"] = fieldc1c.WitnessPlan{Packet: "synthetic", Socket: "synthetic", Process: "synthetic", Conntrack: "synthetic", Child: "synthetic", Ledger: "synthetic", TransportLeaseRecord: "synthetic", WireGuard: "synthetic", InterfaceRouteAddress: "synthetic"}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal("C1c synthetic instance encode failed")
	}
	defer clear(payload)
	for side := range result {
		base := filepath.Join(result[side].Host.HomeDirectory, ".winkyou-field", "c1c")
		if os.MkdirAll(base, 0o700) != nil {
			t.Fatal("C1c private instance directory failed")
		}
		if pairgen.WritePrivateFileExclusive(filepath.Join(base, artifact.AttemptID+".json"), payload) != nil {
			t.Fatal("C1c private instance write failed")
		}
		result[side].Instance = filepath.Join("/root", ".winkyou-field", "c1c", artifact.AttemptID+".json")
		result[side].Evidence = filepath.Join(base, "evidence", artifact.AttemptID, "endpoint.jsonl")
	}
	return result
}

func fieldC1cFileDigest(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("C1c private digest source unavailable")
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		t.Fatal("C1c private digest failed")
	}
	return hex.EncodeToString(hash.Sum(nil))
}

type gatecrequestForField struct{ ArtifactFile, Endpoint, KnownHosts, Identity string }

func fieldC1cReadRequest(t *testing.T, path string) gatecrequestForField {
	t.Helper()
	request, err := gatecrequest.LoadPrivate(path)
	if err != nil {
		t.Fatal("C1c synthetic request unavailable")
	}
	result := gatecrequestForField{ArtifactFile: request.ArtifactFile}
	if request.SSH != nil {
		result.Endpoint = request.SSH.Endpoint.String()
		result.KnownHosts = request.SSH.KnownHostsFile
		result.Identity = request.SSH.IdentityFile
	}
	return result
}
func fieldC1cArtifact(t *testing.T, path string) *gatecattempt.Artifact {
	t.Helper()
	data, err := pairgen.ReadPrivateFile(path, gatecattempt.MaxArtifactBytes)
	if err != nil {
		t.Fatal("C1c synthetic artifact unavailable")
	}
	defer clear(data)
	artifact, err := gatecattempt.ParseArtifact(data, time.Now())
	if err != nil {
		t.Fatal("C1c synthetic artifact invalid")
	}
	return artifact
}
