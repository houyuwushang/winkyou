//go:build fieldc1c

// Package fieldc1c validates a private, one-invocation field authorization.
// It owns no network, process, governor, or interface capability. An Instance
// is an immutable, opaque validation witness, not a deserializable capability.
package fieldc1c

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"winkyou/internal/v2/pairgen"
)

const (
	Schema           = "winkyou-gate-c1c-authorization/1"
	Layout           = "disposable-endpoints-and-router/1"
	MaxInstanceBytes = 64 * 1024
)

// BuildSHA is injected with -ldflags -X for the exact reviewed field build.
// Neither a command argument nor environment variable can replace it.
var BuildSHA string

var ErrInvalid = errors.New("gate_c_request_invalid")

type Device struct {
	Role                   string `json:"role"`
	OS                     string `json:"os"`
	RequestReference       string `json:"request_reference"`
	ConfigurationReference string `json:"configuration_reference"`
	ConfigurationSHA256    string `json:"configuration_sha256"`
	ManagementReference    string `json:"management_reference"`
}

type Resource struct {
	Role              string `json:"role"`
	Reference         string `json:"reference"`
	TeardownReference string `json:"teardown_reference"`
}

type Topology struct {
	Primary              string `json:"primary"`
	AlternatePort        string `json:"alternate_port"`
	AlternateAddress     string `json:"alternate_address"`
	AlternateAddressPort string `json:"alternate_address_port"`
}

type Hardening struct {
	Status            string `json:"status"`
	Reason            string `json:"reason"`
	Risk              string `json:"risk"`
	EvidenceReference string `json:"evidence_reference"`
}

type Interface struct {
	Name         string `json:"interface"`
	LocalAddress string `json:"local_address"`
	PeerAddress  string `json:"peer_address"`
	MTU          int    `json:"mtu"`
}

type Interfaces struct {
	Initiator Interface `json:"initiator"`
	Responder Interface `json:"responder"`
}

type StopIdentity struct {
	Kind                  string `json:"kind"`
	VerificationReference string `json:"verification_reference"`
}

type ExpectedTerminal struct {
	Terminal           string `json:"terminal"`
	Stage              string `json:"stage"`
	InjectionReference string `json:"injection_reference"`
}

type WitnessPlan struct {
	Packet                string `json:"packet"`
	Socket                string `json:"socket"`
	Process               string `json:"process"`
	Conntrack             string `json:"conntrack"`
	Child                 string `json:"child"`
	Ledger                string `json:"ledger"`
	TransportLease        string `json:"transport_lease"`
	WireGuard             string `json:"wireguard"`
	InterfaceRouteAddress string `json:"interface_route_address"`
}

// document is deliberately private. Parsing a document alone cannot issue an
// Instance: Load additionally proves the exact executable and canonical file.
type document struct {
	InstanceID                             string           `json:"instance_id"`
	Scenario                               string           `json:"scenario"`
	Operator                               string           `json:"operator"`
	IndependentReviewer                    string           `json:"independent_reviewer"`
	OperatorSignature                      string           `json:"operator_signature"`
	ReviewerSignature                      string           `json:"reviewer_signature"`
	SignedAt                               string           `json:"signed_at"`
	NotBefore                              string           `json:"not_before"`
	NotAfter                               string           `json:"not_after"`
	Layout                                 string           `json:"layout"`
	ImplementationReview                   string           `json:"implementation_review"`
	BuildAuthorization                     string           `json:"build_authorization"`
	RunAuthorization                       string           `json:"run_authorization"`
	ExactSHA                               string           `json:"exact_sha"`
	InitiatorBinarySHA256                  string           `json:"initiator_binary_sha256"`
	ResponderBinarySHA256                  string           `json:"responder_binary_sha256"`
	RouterBinarySHA256                     string           `json:"router_binary_sha256"`
	BuildTags                              []string         `json:"build_tags"`
	Toolchain                              string           `json:"toolchain"`
	OrdinaryBuildNoFieldSymbolsEvidence    string           `json:"ordinary_build_no_field_symbols_evidence"`
	AuthoritySchemaRevision                string           `json:"authority_schema_revision"`
	DependencyAndConfigurationSHA256       string           `json:"dependency_and_configuration_sha256"`
	Profile                                string           `json:"profile"`
	ResourceClass                          string           `json:"resource_class"`
	InitiatorRole                          string           `json:"initiator_role"`
	ResponderRole                          string           `json:"responder_role"`
	MappingSetRole                         *string          `json:"mapping_set_role"`
	CredentialReference                    string           `json:"credential_reference"`
	ManifestSHA256                         string           `json:"manifest_sha256"`
	CredentialExpiresAt                    string           `json:"credential_expires_at"`
	UnusedCredentialVerified               bool             `json:"unused_credential_verified"`
	SingleInvocationVerified               bool             `json:"single_invocation_verified"`
	ExactCostReference                     string           `json:"exact_cost_reference"`
	SessionLivenessMode                    string           `json:"session_liveness_mode"`
	InitiatorMissedRounds                  int              `json:"initiator_missed_rounds"`
	ResponderMissedRounds                  int              `json:"responder_missed_rounds"`
	AbsoluteSessionCeiling                 string           `json:"absolute_session_ceiling"`
	Devices                                []Device         `json:"devices"`
	RouterResourceInventory                []Resource       `json:"router_resource_inventory"`
	EndpointResourceInventory              []Resource       `json:"endpoint_resource_inventory"`
	KernelMinimumReview                    string           `json:"kernel_minimum_review"`
	TUNAndConntrackCapabilityEvidence      string           `json:"tun_and_conntrack_capability_evidence"`
	NamespaceAndGlobalCeilingAuthority     string           `json:"namespace_and_global_ceiling_authority"`
	SupplierNetworkPermission              string           `json:"supplier_network_permission"`
	InitiatorMachineScopeReference         string           `json:"initiator_machine_scope_reference"`
	ResponderMachineScopeReference         string           `json:"responder_machine_scope_reference"`
	LedgerRetentionAndRestorePlan          string           `json:"ledger_retention_and_restore_plan"`
	LedgerDeterminateEvidence              string           `json:"ledger_determinate_evidence"`
	AdmissionAndCampaignCircuitEvidence    string           `json:"admission_and_campaign_circuit_evidence"`
	SafetyTripClearEvidence                string           `json:"safety_trip_clear_evidence"`
	NoStaleProcessTaskSlotEvidence         string           `json:"no_stale_process_task_slot_evidence"`
	InitiatorExpectedPeerAddress           string           `json:"initiator_expected_peer_address"`
	ResponderExpectedPeerAddress           string           `json:"responder_expected_peer_address"`
	ObserverTopology                       Topology         `json:"observer_topology"`
	ObserverOperatorPermission             string           `json:"observer_operator_permission"`
	SSHLiteralEndpoint                     string           `json:"ssh_literal_endpoint"`
	SSHAuthorityReference                  string           `json:"ssh_authority_reference"`
	HostKeyPinReference                    string           `json:"host_key_pin_reference"`
	SSHIdentityReference                   string           `json:"ssh_identity_reference"`
	ForcedCommandProfileEvidence           string           `json:"forced_command_profile_evidence"`
	RootRiskAcceptedByOperator             bool             `json:"root_risk_accepted_by_operator"`
	RootRiskAcceptedByReviewer             bool             `json:"root_risk_accepted_by_reviewer"`
	HardeningDropPrivileges                Hardening        `json:"hardening_drop_privileges"`
	HardeningSyscallFilesystemIsolation    Hardening        `json:"hardening_syscall_filesystem_isolation"`
	HardeningLowPrivilegeParser            Hardening        `json:"hardening_low_privilege_parser"`
	InterfaceRouteAddressAuthority         Interfaces       `json:"interface_route_address_authority"`
	SeparateHostConfigurationAuthorization string           `json:"separate_host_configuration_authorization"`
	PreflightNegativeMatrixEvidence        string           `json:"preflight_negative_matrix_evidence"`
	OwnedStopTargetIdentity                StopIdentity     `json:"owned_stop_target_identity"`
	KillSwitchCommandReference             string           `json:"kill_switch_command_reference"`
	KillSwitchReadinessEvidence            string           `json:"kill_switch_readiness_evidence"`
	IndependentManagementChannelReference  string           `json:"independent_management_channel_reference"`
	ContainmentAuthorization               *string          `json:"containment_authorization"`
	ExpectedTerminalAndFaultStage          ExpectedTerminal `json:"expected_terminal_and_fault_stage"`
	WitnessPlan                            WitnessPlan      `json:"witness_plan"`
	TupleObservations                      json.RawMessage  `json:"tuple_observations"`
	RawEvidenceReferences                  json.RawMessage  `json:"raw_evidence_references"`
	EvidenceSHA256                         json.RawMessage  `json:"evidence_sha256"`
	TerminalResultByRole                   json.RawMessage  `json:"terminal_result_by_role"`
	DurableFinishAndCircuitEvidence        json.RawMessage  `json:"durable_finish_and_circuit_evidence"`
	OwnedResidueByLayer                    json.RawMessage  `json:"owned_residue_by_layer"`
	LedgerSealedBeforeDestruction          json.RawMessage  `json:"ledger_sealed_before_destruction"`
	CloudTeardownEvidence                  json.RawMessage  `json:"cloud_teardown_evidence"`
	IndependentManagementPreserved         json.RawMessage  `json:"independent_management_preserved"`
	RedactedSummaryReview                  json.RawMessage  `json:"redacted_summary_review"`
	AuthorizationClosedAt                  json.RawMessage  `json:"authorization_closed_at"`
	TeardownOperatorSignature              json.RawMessage  `json:"teardown_operator_signature"`
	TeardownReviewerSignature              json.RawMessage  `json:"teardown_reviewer_signature"`
}

type validated struct {
	doc       document
	role      string
	notBefore time.Time
	notAfter  time.Time
	ssh       netip.AddrPort
	observers [4]netip.AddrPort
	peer      netip.Addr
	device    Device
	iface     Interface
	digest    [32]byte
}

type Instance struct{ value *validated }

// Load performs only private-file reads. The opaque value cannot be issued
// from a caller-supplied build witness, clock, raw document, or environment.
func Load(path, role string) (Instance, error) {
	if runtime.GOOS != "linux" || (role != "initiator" && role != "responder") {
		return Instance{}, ErrInvalid
	}
	if safeParents(filepath.Dir(path)) != nil {
		return Instance{}, ErrInvalid
	}
	payload, err := pairgen.ReadPrivateFile(path, MaxInstanceBytes)
	if err != nil {
		return Instance{}, ErrInvalid
	}
	defer clear(payload)
	build, err := currentBuild()
	if err != nil {
		return Instance{}, ErrInvalid
	}
	value, err := validate(payload, role, time.Now().UTC(), build)
	if err != nil {
		return Instance{}, ErrInvalid
	}
	expected, err := InstancePath(value.doc.InstanceID)
	if err != nil || path != expected {
		return Instance{}, ErrInvalid
	}
	scope, err := localMachineReference()
	wantScope := value.doc.InitiatorMachineScopeReference
	if role == "responder" {
		wantScope = value.doc.ResponderMachineScopeReference
	}
	if err != nil || scope != wantScope {
		return Instance{}, ErrInvalid
	}
	return Instance{value: value}, nil
}

func InstancePath(id string) (string, error) {
	if !attemptID(id) {
		return "", ErrInvalid
	}
	root, err := canonicalFieldHome()
	if err != nil || !filepath.IsAbs(root) {
		return "", ErrInvalid
	}
	return filepath.Join(root, ".winkyou-field", "c1c", id+".json"), nil
}

func attemptID(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (instance Instance) Check(now time.Time) error {
	if instance.value == nil || now.IsZero() || now.Before(instance.value.notBefore) || !now.Before(instance.value.notAfter) {
		return ErrInvalid
	}
	return nil
}

func (instance Instance) SSHEndpoint() (netip.AddrPort, error) {
	if instance.Check(time.Now()) != nil || instance.value.role != "initiator" {
		return netip.AddrPort{}, ErrInvalid
	}
	return instance.value.ssh, nil
}

func (instance Instance) SSHFiles() (pin, identity string, err error) {
	if instance.Check(time.Now()) != nil || instance.value.role != "initiator" {
		return "", "", ErrInvalid
	}
	return instance.value.doc.HostKeyPinReference, instance.value.doc.SSHIdentityReference, nil
}

func (instance Instance) Network() (netip.Addr, [4]netip.AddrPort, error) {
	if instance.Check(time.Now()) != nil {
		return netip.Addr{}, [4]netip.AddrPort{}, ErrInvalid
	}
	return instance.value.peer, instance.value.observers, nil
}

func (instance Instance) Device() (Device, error) {
	if instance.Check(time.Now()) != nil {
		return Device{}, ErrInvalid
	}
	return instance.value.device, nil
}

func (instance Instance) Interface() (Interface, error) {
	if instance.Check(time.Now()) != nil {
		return Interface{}, ErrInvalid
	}
	return instance.value.iface, nil
}

type buildWitness struct {
	sha, revision, binaryHash, toolchain string
	modified                             bool
	tags                                 []string
	dependencies                         []string
}

func currentBuild() (buildWitness, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok || !hexValue(BuildSHA, 20) {
		return buildWitness{}, ErrInvalid
	}
	witness := buildWitness{sha: BuildSHA, toolchain: info.GoVersion, modified: true}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			witness.revision = setting.Value
		case "vcs.modified":
			witness.modified = setting.Value != "false"
		case "-tags":
			witness.tags = strings.Split(setting.Value, ",")
		}
	}
	for _, dependency := range info.Deps {
		if dependency.Replace != nil {
			return buildWitness{}, ErrInvalid
		}
		witness.dependencies = append(witness.dependencies, dependency.Path+"\x00"+dependency.Version+"\x00"+dependency.Sum)
	}
	sort.Strings(witness.dependencies)
	path, err := os.Executable()
	if err != nil {
		return buildWitness{}, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return buildWitness{}, ErrInvalid
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return buildWitness{}, ErrInvalid
	}
	witness.binaryHash = hex.EncodeToString(hash.Sum(nil))
	return witness, nil
}

func dependencyDigest(build buildWitness, devices []Device) string {
	configuration := [2]string{}
	for _, device := range devices {
		if device.Role == "initiator" {
			configuration[0] = device.ConfigurationSHA256
		}
		if device.Role == "responder" {
			configuration[1] = device.ConfigurationSHA256
		}
	}
	encoded, _ := json.Marshal(struct {
		Domain        string    `json:"domain"`
		Dependencies  []string  `json:"dependencies"`
		Configuration [2]string `json:"configuration"`
	}{"winkyou-c1c-dependencies-config/1", build.dependencies, configuration})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func hexValue(value string, size int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == size && hex.EncodeToString(decoded) == value
}

func literalAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.String() != value || address.Zone() != "" || address.Is4In6() ||
		!address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() {
		return netip.Addr{}, ErrInvalid
	}
	return address, nil
}

func literalEndpoint(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || endpoint.Addr().Is4In6() {
		return netip.AddrPort{}, ErrInvalid
	}
	if _, err := literalAddress(endpoint.Addr().String()); err != nil {
		return netip.AddrPort{}, ErrInvalid
	}
	return endpoint, nil
}

// strictJSON rejects duplicate keys at every depth before DisallowUnknownFields
// checks the typed shape. JSON null is not an alternate spelling of zero.
func strictJSON(payload []byte, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := visitJSON(decoder, 0); err != nil {
		return ErrInvalid
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(output) != nil {
		return ErrInvalid
	}
	return nil
}

func visitJSON(decoder *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			key, err := decoder.Token()
			name, ok := key.(string)
			if err != nil || !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			if err := visitJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := visitJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalid
	}
	end, err := decoder.Token()
	if err != nil || (delimiter == '{' && end != json.Delim('}')) || (delimiter == '[' && end != json.Delim(']')) {
		return ErrInvalid
	}
	return nil
}
