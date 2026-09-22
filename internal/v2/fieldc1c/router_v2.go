//go:build fieldc1c

package fieldc1c

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"winkyou/internal/v2/pairgen"
)

const SchemaV2 = "winkyou-gate-c1c-authorization/2"
const RouterSchema = "winkyou-c1c-router/1"

// These exported DTOs carry only local comparison data. They cannot construct
// a RouterAuthority or issue endpoint authority.
type RouterAnchor struct {
	Role  string `json:"role"`
	Name  string `json:"name"`
	Inode uint64 `json:"inode"`
}
type RouterDomain struct {
	Role           string `json:"role"`
	Mode           string `json:"mode"`
	EndpointPrefix string `json:"endpoint_prefix"`
	GatewayPrefix  string `json:"gateway_prefix"`
	PublicPrefix   string `json:"public_prefix"`
	TransitPrefix  string `json:"transit_prefix"`
}
type RouterConfiguration struct {
	Schema                           string         `json:"schema"`
	MachineScopeReference            string         `json:"machine_scope_reference"`
	DependencyAndConfigurationSHA256 string         `json:"dependency_and_configuration_sha256"`
	Anchors                          []RouterAnchor `json:"anchors"`
	Domains                          []RouterDomain `json:"domains"`
	AllowGlobalConntrackCeiling      bool           `json:"allow_global_conntrack_ceiling"`
	DisposableEnvironmentReference   string         `json:"disposable_environment_reference"`
}
type RouterAuthority struct {
	value       *validated
	cleanupOnly bool
}

func validate(payload []byte, role string, now time.Time, build buildWitness) (*validated, error) {
	if len(payload) == 0 || len(payload) > MaxInstanceBytes || !utf8.Valid(payload) || now.IsZero() {
		return nil, ErrInvalid
	}
	var raw map[string]json.RawMessage
	if strictJSON(payload, &raw) != nil {
		return nil, ErrInvalid
	}
	var revision string
	if json.Unmarshal(raw["authority_schema_revision"], &revision) != nil {
		return nil, ErrInvalid
	}
	switch revision {
	case Schema:
		return validateV1(payload, role, now, build)
	case SchemaV2:
		return validateV2(payload, raw, role, now, build)
	default:
		return nil, ErrInvalid
	}
}

func validateV2(payload []byte, raw map[string]json.RawMessage, role string, now time.Time, build buildWitness) (*validated, error) {
	if len(raw) != 89 || (role != "initiator" && role != "responder" && role != "router") {
		return nil, ErrInvalid
	}
	var router RouterConfiguration
	data, exists := raw["router"]
	if !exists || strictJSON(data, &router) != nil || !exactRouterMembers(data) {
		return nil, ErrInvalid
	}
	delete(raw, "router")
	commonBytes, err := json.Marshal(raw)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(commonBytes)
	doc, err := decodeDocument(commonBytes)
	if err != nil || doc.AuthoritySchemaRevision != SchemaV2 || validateRouterConfiguration(doc, router) != nil {
		return nil, ErrInvalid
	}
	v, err := validateCommon(payload, doc, role, now, build, router.DependencyAndConfigurationSHA256)
	if err != nil {
		return nil, ErrInvalid
	}
	v.router = &router
	return v, nil
}

func exactRouterMembers(data []byte) bool {
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil || len(raw) != 7 {
		return false
	}
	for _, key := range []string{"schema", "machine_scope_reference", "dependency_and_configuration_sha256", "anchors", "domains", "allow_global_conntrack_ceiling", "disposable_environment_reference"} {
		if value, ok := raw[key]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	for key, count := range map[string]int{"anchors": 3, "domains": 2} {
		var entries []map[string]json.RawMessage
		if json.Unmarshal(raw[key], &entries) != nil || len(entries) != count {
			return false
		}
		members := []string{"role", "name", "inode"}
		if key == "domains" {
			members = []string{"role", "mode", "endpoint_prefix", "gateway_prefix", "public_prefix", "transit_prefix"}
		}
		for _, entry := range entries {
			if len(entry) != len(members) {
				return false
			}
			for _, member := range members {
				if value, ok := entry[member]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
					return false
				}
			}
		}
	}
	return true
}

func validateRouterConfiguration(doc document, cfg RouterConfiguration) error {
	if cfg.Schema != RouterSchema || !textValue(cfg.DisposableEnvironmentReference) ||
		!strings.HasPrefix(cfg.MachineScopeReference, "machine-scope-sha256/1:") ||
		!hexValue(strings.TrimPrefix(cfg.MachineScopeReference, "machine-scope-sha256/1:"), sha256.Size) ||
		!hexValue(cfg.DependencyAndConfigurationSHA256, sha256.Size) || len(cfg.Anchors) != 3 || len(cfg.Domains) != 2 {
		return ErrInvalid
	}
	names, inodes := map[string]bool{}, map[uint64]bool{}
	for i, anchor := range cfg.Anchors {
		if anchor.Role != []string{"initiator", "transit", "responder"}[i] || !routerName(anchor.Name) || anchor.Inode == 0 || names[anchor.Name] || inodes[anchor.Inode] {
			return ErrInvalid
		}
		names[anchor.Name], inodes[anchor.Inode] = true, true
	}
	modes := [2]string{"apdm_sequential/1", "apdm_sequential/1"}
	switch doc.Profile {
	case "predictive_edm/1":
	case "asymmetric_birthday/1":
		if doc.MappingSetRole == nil {
			return ErrInvalid
		}
		if *doc.MappingSetRole == "initiator" {
			modes[1] = "eim/1"
		} else if *doc.MappingSetRole == "responder" {
			modes[0] = "eim/1"
		} else {
			return ErrInvalid
		}
	case "hard_birthday_campaign/1":
		modes = [2]string{"apdm_uniform16/1", "apdm_uniform16/1"}
	default:
		return ErrInvalid
	}
	addresses := map[netip.Addr]bool{}
	for i, domain := range cfg.Domains {
		if domain.Role != []string{"initiator", "responder"}[i] || domain.Mode != modes[i] {
			return ErrInvalid
		}
		var prefixes [4]netip.Prefix
		for j, value := range []string{domain.EndpointPrefix, domain.GatewayPrefix, domain.PublicPrefix, domain.TransitPrefix} {
			p, err := netip.ParsePrefix(value)
			if err != nil || p.String() != value || !p.Addr().Is4() || !p.Addr().IsGlobalUnicast() || p.Bits() < 24 || p.Bits() > 30 || addresses[p.Addr()] {
				return ErrInvalid
			}
			addresses[p.Addr()] = true
			prefixes[j] = p
		}
		if prefixes[0].Masked() != prefixes[1].Masked() || prefixes[2].Masked() != prefixes[3].Masked() || prefixes[0].Masked() == prefixes[2].Masked() {
			return ErrInvalid
		}
		peer := doc.ResponderExpectedPeerAddress
		observer := doc.ObserverTopology.Primary
		if i == 1 {
			peer, observer = doc.InitiatorExpectedPeerAddress, doc.ObserverTopology.AlternateAddress
		}
		endpoint, err := netip.ParseAddrPort(observer)
		if err != nil || prefixes[2].Addr().String() != peer || prefixes[3].Addr() != endpoint.Addr() {
			return ErrInvalid
		}
	}
	return nil
}

func routerName(name string) bool {
	if !strings.HasPrefix(name, "wy") || len(name) < 3 || len(name) > 48 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func LoadRouter(path string) (RouterAuthority, error)            { return loadRouter(path, false) }
func LoadRouterForTeardown(path string) (RouterAuthority, error) { return loadRouter(path, true) }

func loadRouter(path string, cleanup bool) (RouterAuthority, error) {
	if runtime.GOOS != "linux" || !fieldEnvironmentSafe() || safeParents(filepath.Dir(path)) != nil {
		return RouterAuthority{}, ErrInvalid
	}
	payload, err := pairgen.ReadPrivateFile(path, MaxInstanceBytes)
	if err != nil {
		return RouterAuthority{}, ErrInvalid
	}
	defer clear(payload)
	build, err := currentBuild()
	if err != nil {
		return RouterAuthority{}, ErrInvalid
	}
	now := time.Now().UTC()
	if cleanup {
		// Cleanup validates the immutable authorization at its original start,
		// then issues a cleanup-only token. It never extends emission authority.
		var raw map[string]json.RawMessage
		var before string
		if strictJSON(payload, &raw) != nil || json.Unmarshal(raw["not_before"], &before) != nil {
			return RouterAuthority{}, ErrInvalid
		}
		at, e := utcTime(before)
		if e != nil || now.Before(at) {
			return RouterAuthority{}, ErrInvalid
		}
		now = at
	}
	v, err := validate(payload, "router", now, build)
	if err != nil || v.router == nil {
		return RouterAuthority{}, ErrInvalid
	}
	expected, err := InstancePath(v.doc.InstanceID)
	if err != nil || path != expected {
		return RouterAuthority{}, ErrInvalid
	}
	scope, err := localMachineReference()
	if err != nil || scope != v.router.MachineScopeReference {
		return RouterAuthority{}, ErrInvalid
	}
	return RouterAuthority{value: v, cleanupOnly: cleanup}, nil
}

func (a RouterAuthority) Check(now time.Time) error {
	if a.value == nil || a.value.router == nil || a.cleanupOnly || now.IsZero() || now.Before(a.value.notBefore) || !now.Before(a.value.notAfter) {
		return ErrInvalid
	}
	return nil
}

// RouterSnapshot is a defensive copy, not an authority constructor.
type RouterSnapshot struct {
	Configuration                 RouterConfiguration
	ID, Profile, Scenario, Digest string
	Observers                     [4]netip.AddrPort
	SSHEndpoint                   netip.AddrPort
	Namespaces                    [2]string
	Deadline                      time.Time
	Directory                     string
}

func (a RouterAuthority) Snapshot() (RouterSnapshot, error) {
	if a.value == nil || a.value.router == nil {
		return RouterSnapshot{}, ErrInvalid
	}
	v := a.value
	path, err := InstancePath(v.doc.InstanceID)
	if err != nil {
		return RouterSnapshot{}, ErrInvalid
	}
	hash := sha256.Sum256([]byte("winkyou-c1c-router-owned/1\n" + v.doc.InstanceID))
	stem := "wycr" + hex.EncodeToString(hash[:6])
	cfg := *v.router
	cfg.Anchors = append([]RouterAnchor(nil), cfg.Anchors...)
	cfg.Domains = append([]RouterDomain(nil), cfg.Domains...)
	return RouterSnapshot{Configuration: cfg, ID: v.doc.InstanceID, Profile: v.doc.Profile, Scenario: v.doc.Scenario, Digest: hex.EncodeToString(v.digest[:]),
		Observers: v.observers, SSHEndpoint: v.ssh, Namespaces: [2]string{stem + "a", stem + "b"}, Deadline: v.notAfter,
		Directory: filepath.Join(filepath.Dir(path), "evidence", v.doc.InstanceID, "router")}, nil
}
