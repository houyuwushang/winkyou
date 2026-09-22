//go:build fieldc1c

package fieldc1c

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

var postRunFields = []string{
	"tuple_observations", "raw_evidence_references", "evidence_sha256",
	"terminal_result_by_role", "durable_finish_and_circuit_evidence", "owned_residue_by_layer",
	"ledger_sealed_before_destruction", "cloud_teardown_evidence", "independent_management_preserved",
	"redacted_summary_review", "authorization_closed_at", "teardown_operator_signature", "teardown_reviewer_signature",
}

func validate(payload []byte, role string, now time.Time, build buildWitness) (*validated, error) {
	if len(payload) == 0 || len(payload) > MaxInstanceBytes || !utf8.Valid(payload) || now.IsZero() ||
		(role != "initiator" && role != "responder") {
		return nil, ErrInvalid
	}
	var raw map[string]json.RawMessage
	var doc document
	if strictJSON(payload, &raw) != nil || strictJSON(payload, &doc) != nil || len(raw) != 88 {
		return nil, ErrInvalid
	}
	typeOf := reflect.TypeOf(doc)
	if typeOf.NumField() != 88 {
		return nil, ErrInvalid
	}
	for index := 0; index < typeOf.NumField(); index++ {
		name := typeOf.Field(index).Tag.Get("json")
		value, present := raw[name]
		if !present {
			return nil, ErrInvalid
		}
		isNull := bytes.Equal(bytes.TrimSpace(value), []byte("null"))
		if slices.Contains(postRunFields, name) {
			if !isNull {
				return nil, ErrInvalid
			}
			continue
		}
		if name == "mapping_set_role" || name == "containment_authorization" {
			continue
		}
		if isNull || !filled(reflect.ValueOf(doc).Field(index)) {
			return nil, ErrInvalid
		}
	}
	if doc.AuthoritySchemaRevision != Schema || doc.Layout != Layout || !attemptID(doc.InstanceID) ||
		doc.Operator == doc.IndependentReviewer || doc.InitiatorRole != "initiator" || doc.ResponderRole != "responder" ||
		!hexValue(doc.ExactSHA, 20) || doc.ExactSHA != build.sha || doc.ExactSHA != build.revision || build.modified ||
		doc.Toolchain != build.toolchain || !slices.Equal(doc.BuildTags, []string{"fieldc1c"}) ||
		!slices.Equal(build.tags, doc.BuildTags) || doc.SessionLivenessMode != "challenge_v1" ||
		(doc.InitiatorMissedRounds != 2 && doc.InitiatorMissedRounds != 3) ||
		(doc.ResponderMissedRounds != 2 && doc.ResponderMissedRounds != 3) {
		return nil, ErrInvalid
	}
	for _, digest := range []string{doc.InitiatorBinarySHA256, doc.ResponderBinarySHA256, doc.RouterBinarySHA256,
		doc.ManifestSHA256, doc.DependencyAndConfigurationSHA256} {
		if !hexValue(digest, sha256.Size) {
			return nil, ErrInvalid
		}
	}
	binaryHash := doc.InitiatorBinarySHA256
	for _, scope := range []string{doc.InitiatorMachineScopeReference, doc.ResponderMachineScopeReference} {
		if !strings.HasPrefix(scope, "machine-scope-sha256/1:") || !hexValue(strings.TrimPrefix(scope, "machine-scope-sha256/1:"), sha256.Size) {
			return nil, ErrInvalid
		}
	}
	if role == "responder" {
		binaryHash = doc.ResponderBinarySHA256
	}
	if binaryHash != build.binaryHash {
		return nil, ErrInvalid
	}
	signed, err1 := utcTime(doc.SignedAt)
	before, err2 := utcTime(doc.NotBefore)
	after, err3 := utcTime(doc.NotAfter)
	expires, err4 := utcTime(doc.CredentialExpiresAt)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || signed.After(before) || !before.Before(after) ||
		now.Before(before) || !now.Before(after) || !now.Before(expires) {
		return nil, ErrInvalid
	}
	ceiling, err := time.ParseDuration(doc.AbsoluteSessionCeiling)
	if err != nil || ceiling < 5*time.Second || ceiling > 24*time.Hour {
		return nil, ErrInvalid
	}
	if validateProfile(doc) != nil || len(doc.Devices) != 2 || len(doc.RouterResourceInventory) != 1 ||
		len(doc.EndpointResourceInventory) != 2 || doc.RouterResourceInventory[0].Role != "router" ||
		doc.EndpointResourceInventory[0].Role != "initiator" || doc.EndpointResourceInventory[1].Role != "responder" {
		return nil, ErrInvalid
	}
	if doc.Devices[0].Role != "initiator" || doc.Devices[1].Role != "responder" {
		return nil, ErrInvalid
	}
	for _, device := range doc.Devices {
		if device.OS != "linux" || !privateReference(device.RequestReference) || !privateReference(device.ConfigurationReference) ||
			!hexValue(device.ConfigurationSHA256, sha256.Size) {
			return nil, ErrInvalid
		}
	}
	if doc.DependencyAndConfigurationSHA256 != dependencyDigest(build, doc.Devices) {
		return nil, ErrInvalid
	}
	for _, path := range []string{doc.CredentialReference, doc.HostKeyPinReference, doc.SSHIdentityReference} {
		if !privateReference(path) {
			return nil, ErrInvalid
		}
	}
	if doc.ContainmentAuthorization != nil && !textValue(*doc.ContainmentAuthorization) {
		return nil, ErrInvalid
	}
	for _, hardening := range []Hardening{doc.HardeningDropPrivileges, doc.HardeningSyscallFilesystemIsolation, doc.HardeningLowPrivilegeParser} {
		if hardening.Status != "not_implemented" || !filled(reflect.ValueOf(hardening)) {
			return nil, ErrInvalid
		}
	}
	if doc.OwnedStopTargetIdentity.Kind != "owned-foreground-and-child/1" {
		return nil, ErrInvalid
	}
	if validateInterface(doc.InterfaceRouteAddressAuthority.Initiator) != nil || validateInterface(doc.InterfaceRouteAddressAuthority.Responder) != nil {
		return nil, ErrInvalid
	}
	left, right := doc.InterfaceRouteAddressAuthority.Initiator, doc.InterfaceRouteAddressAuthority.Responder
	if left.LocalAddress != right.PeerAddress || right.LocalAddress != left.PeerAddress {
		return nil, ErrInvalid
	}
	peerValue := doc.InitiatorExpectedPeerAddress
	device, iface := doc.Devices[0], left
	if role == "responder" {
		peerValue, device, iface = doc.ResponderExpectedPeerAddress, doc.Devices[1], right
	}
	peer, err := literalAddress(peerValue)
	if err != nil || !peer.Is4() {
		return nil, ErrInvalid
	}
	for _, address := range []string{doc.InitiatorExpectedPeerAddress, doc.ResponderExpectedPeerAddress} {
		if value, err := literalAddress(address); err != nil || !value.Is4() {
			return nil, ErrInvalid
		}
	}
	ssh, err := literalEndpoint(doc.SSHLiteralEndpoint)
	if err != nil || !ssh.Addr().Is4() {
		return nil, ErrInvalid
	}
	var observers [4]netip.AddrPort
	for index, address := range []string{doc.ObserverTopology.Primary, doc.ObserverTopology.AlternatePort,
		doc.ObserverTopology.AlternateAddress, doc.ObserverTopology.AlternateAddressPort} {
		observers[index], err = literalEndpoint(address)
		if err != nil || !observers[index].Addr().Is4() {
			return nil, ErrInvalid
		}
	}
	a, b := observers[0], observers[3]
	if a.Addr() == b.Addr() || a.Port() == b.Port() ||
		observers[1] != netip.AddrPortFrom(a.Addr(), b.Port()) || observers[2] != netip.AddrPortFrom(b.Addr(), a.Port()) {
		return nil, ErrInvalid
	}
	return &validated{doc: doc, role: role, notBefore: before, notAfter: after, ssh: ssh, peer: peer,
		observers: observers, device: device, iface: iface, digest: sha256.Sum256(payload)}, nil
}

func validateProfile(doc document) error {
	var resource string
	switch doc.Profile {
	case "predictive_edm/1":
		resource = "predictive_32/1"
	case "asymmetric_birthday/1":
		resource = "asymmetric_128x512/1"
	case "hard_birthday_campaign/1":
		resource = "hard_16k_lab/1"
	default:
		return ErrInvalid
	}
	if doc.ResourceClass != resource || doc.ExactCostReference != "gate-c/"+resource {
		return ErrInvalid
	}
	if doc.Profile == "asymmetric_birthday/1" {
		if doc.MappingSetRole == nil || (*doc.MappingSetRole != "initiator" && *doc.MappingSetRole != "responder") {
			return ErrInvalid
		}
	} else if doc.MappingSetRole != nil {
		return ErrInvalid
	}
	switch doc.Scenario {
	case "predictive_apdm_pair":
		if doc.Profile != "predictive_edm/1" {
			return ErrInvalid
		}
	case "asymmetric_initiator_mapping_set", "asymmetric_responder_mapping_set":
		if doc.Profile != "asymmetric_birthday/1" || doc.Scenario != "asymmetric_"+*doc.MappingSetRole+"_mapping_set" {
			return ErrInvalid
		}
	case "hard16_near_tail", "hard16_exhaustion":
		if doc.Profile != "hard_birthday_campaign/1" {
			return ErrInvalid
		}
	case "crash", "teardown":
	default:
		return ErrInvalid
	}
	return nil
}

func utcTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return parsed, nil
}

func privateReference(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value && textValue(value)
}

func textValue(value string) bool {
	if value == "" || len(value) > 2048 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}

func filled(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.String:
		return textValue(value.String())
	case reflect.Bool:
		return value.Bool()
	case reflect.Int:
		return value.Int() > 0
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			if !filled(value.Field(i)) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if value.Len() == 0 {
			return false
		}
		for i := 0; i < value.Len(); i++ {
			if !filled(value.Index(i)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func validateInterface(value Interface) error {
	if value.Name == "" || len(value.Name) > 15 || value.MTU < 1280 || value.MTU > 9000 {
		return ErrInvalid
	}
	for index, r := range value.Name {
		if r >= 'a' && r <= 'z' || index > 0 && (r >= '0' && r <= '9' || r == '-') {
			continue
		}
		return ErrInvalid
	}
	local, err1 := netip.ParseAddr(value.LocalAddress)
	peer, err2 := netip.ParseAddr(value.PeerAddress)
	if err1 != nil || err2 != nil || !local.Is4() || !peer.Is4() || local == peer ||
		local.String() != value.LocalAddress || peer.String() != value.PeerAddress || !local.IsGlobalUnicast() || !peer.IsGlobalUnicast() {
		return ErrInvalid
	}
	return nil
}
