package gatecrequest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"unicode"

	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/pairgen"
)

const (
	Schema          = "winkyou-gate-c-local-request/1"
	MaxRequestBytes = 16 * 1024
)

var ErrInvalidRequest = errors.New("gatecrequest: invalid local request")

type ObserverSet struct {
	Primary              netip.AddrPort
	AlternatePort        netip.AddrPort
	AlternateAddress     netip.AddrPort
	AlternateAddressPort netip.AddrPort
}

func (set ObserverSet) Endpoints() [4]netip.AddrPort {
	return [4]netip.AddrPort{set.Primary, set.AlternatePort, set.AlternateAddress, set.AlternateAddressPort}
}

type SSHConfig struct {
	Endpoint       netip.AddrPort
	User           string
	IdentityFile   string
	KnownHostsFile string
}

type Request struct {
	Role                      gatecattempt.Role
	ArtifactFile              string
	PeerRef                   string
	ExpectedPeerPublicAddress netip.Addr
	ObserverSet               ObserverSet
	SSH                       *SSHConfig
}

type wireObserverSet struct {
	Primary              string `json:"primary"`
	AlternatePort        string `json:"alternate_port"`
	AlternateAddress     string `json:"alternate_address"`
	AlternateAddressPort string `json:"alternate_address_port"`
}

type wireSSH struct {
	Endpoint       string `json:"endpoint"`
	User           string `json:"user"`
	IdentityFile   string `json:"identity_file"`
	KnownHostsFile string `json:"known_hosts_file"`
}

type wireRequest struct {
	Schema                    string          `json:"schema"`
	Role                      string          `json:"role"`
	ArtifactFile              string          `json:"artifact_file"`
	PeerRef                   string          `json:"peer_ref"`
	ExpectedPeerPublicAddress string          `json:"expected_peer_public_address"`
	ObserverSet               wireObserverSet `json:"observer_set"`
	SSH                       *wireSSH        `json:"ssh,omitempty"`
}

// Encode produces the only canonical persisted representation used by the
// responder staging slot. It reuses Parse so callers cannot encode a request
// that the strict decoder would later reject.
func Encode(request Request) ([]byte, error) {
	wire := wireRequest{
		Schema:                    Schema,
		Role:                      string(request.Role),
		ArtifactFile:              request.ArtifactFile,
		PeerRef:                   request.PeerRef,
		ExpectedPeerPublicAddress: request.ExpectedPeerPublicAddress.String(),
		ObserverSet: wireObserverSet{
			Primary:              request.ObserverSet.Primary.String(),
			AlternatePort:        request.ObserverSet.AlternatePort.String(),
			AlternateAddress:     request.ObserverSet.AlternateAddress.String(),
			AlternateAddressPort: request.ObserverSet.AlternateAddressPort.String(),
		},
	}
	if request.SSH != nil {
		wire.SSH = &wireSSH{
			Endpoint:       request.SSH.Endpoint.String(),
			User:           request.SSH.User,
			IdentityFile:   request.SSH.IdentityFile,
			KnownHostsFile: request.SSH.KnownHostsFile,
		}
	}
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > MaxRequestBytes {
		return nil, ErrInvalidRequest
	}
	parsed, err := Parse(payload)
	if err != nil || !equalRequest(parsed, request) {
		clear(payload)
		return nil, ErrInvalidRequest
	}
	return payload, nil
}

func equalRequest(left, right Request) bool {
	if left.Role != right.Role || left.ArtifactFile != right.ArtifactFile || left.PeerRef != right.PeerRef ||
		left.ExpectedPeerPublicAddress != right.ExpectedPeerPublicAddress || left.ObserverSet != right.ObserverSet {
		return false
	}
	if left.SSH == nil || right.SSH == nil {
		return left.SSH == nil && right.SSH == nil
	}
	return *left.SSH == *right.SSH
}

func LoadPrivate(path string) (Request, error) {
	payload, err := pairgen.ReadPrivateFile(path, MaxRequestBytes)
	if err != nil {
		return Request{}, ErrInvalidRequest
	}
	defer clear(payload)
	return Parse(payload)
}

func Parse(payload []byte) (Request, error) {
	if len(payload) == 0 || len(payload) > MaxRequestBytes || !json.Valid(payload) || rejectDuplicateMembers(payload) != nil {
		return Request{}, ErrInvalidRequest
	}
	var wire wireRequest
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || requireJSONEOF(decoder) != nil {
		return Request{}, ErrInvalidRequest
	}
	role := gatecattempt.Role(wire.Role)
	if wire.Schema != Schema || !role.Valid() || !filepath.IsAbs(wire.ArtifactFile) ||
		!safeLocalReference(wire.PeerRef, 256) {
		return Request{}, ErrInvalidRequest
	}
	peerAddress, err := parseCanonicalAddress(wire.ExpectedPeerPublicAddress)
	if err != nil || !publicUnicast(peerAddress) {
		return Request{}, ErrInvalidRequest
	}
	primary, err1 := parseCanonicalEndpoint(wire.ObserverSet.Primary)
	alternatePort, err2 := parseCanonicalEndpoint(wire.ObserverSet.AlternatePort)
	alternateAddress, err3 := parseCanonicalEndpoint(wire.ObserverSet.AlternateAddress)
	alternateAddressPort, err4 := parseCanonicalEndpoint(wire.ObserverSet.AlternateAddressPort)
	observers := [4]netip.AddrPort{primary, alternatePort, alternateAddress, alternateAddressPort}
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || !validObserverTopology(observers) {
		return Request{}, ErrInvalidRequest
	}
	request := Request{
		Role: role, ArtifactFile: wire.ArtifactFile, PeerRef: wire.PeerRef,
		ExpectedPeerPublicAddress: peerAddress,
		ObserverSet: ObserverSet{Primary: primary, AlternatePort: alternatePort,
			AlternateAddress: alternateAddress, AlternateAddressPort: alternateAddressPort},
	}
	if role == gatecattempt.RoleInitiator {
		if wire.SSH == nil || !safeLocalReference(wire.SSH.User, 255) ||
			!filepath.IsAbs(wire.SSH.IdentityFile) || !filepath.IsAbs(wire.SSH.KnownHostsFile) {
			return Request{}, ErrInvalidRequest
		}
		endpoint, err := parseCanonicalEndpoint(wire.SSH.Endpoint)
		if err != nil {
			return Request{}, ErrInvalidRequest
		}
		request.SSH = &SSHConfig{Endpoint: endpoint, User: wire.SSH.User,
			IdentityFile: wire.SSH.IdentityFile, KnownHostsFile: wire.SSH.KnownHostsFile}
	} else if wire.SSH != nil {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

func parseCanonicalAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil || !address.IsValid() || address.Zone() != "" || address.String() != value {
		return netip.Addr{}, ErrInvalidRequest
	}
	return address.Unmap(), nil
}

func parseCanonicalEndpoint(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || !endpoint.IsValid() || endpoint.Port() == 0 || endpoint.Addr().Zone() != "" || endpoint.String() != value {
		return netip.AddrPort{}, ErrInvalidRequest
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), nil
}

func validObserverTopology(endpoints [4]netip.AddrPort) bool {
	for _, endpoint := range endpoints {
		if !endpoint.IsValid() || !publicUnicast(endpoint.Addr()) || endpoint.Addr().Is4() != endpoints[0].Addr().Is4() {
			return false
		}
	}
	a1, p1 := endpoints[0].Addr(), endpoints[0].Port()
	a2, p2 := endpoints[2].Addr(), endpoints[1].Port()
	return a1 != a2 && p1 != p2 && endpoints[1] == netip.AddrPortFrom(a1, p2) &&
		endpoints[2] == netip.AddrPortFrom(a2, p1) && endpoints[3] == netip.AddrPortFrom(a2, p2)
}

func publicUnicast(address netip.Addr) bool {
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	if address.Is4() && netip.MustParsePrefix("100.64.0.0/10").Contains(address) {
		return false
	}
	return true
}

func safeLocalReference(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func rejectDuplicateMembers(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := scanJSONValue(decoder, first); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			nameToken, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := nameToken.(string)
			if !ok {
				return ErrInvalidRequest
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate member %q", name)
			}
			seen[name] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidRequest
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := scanJSONValue(decoder, value); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidRequest
		}
	default:
		return ErrInvalidRequest
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrInvalidRequest
		}
		return err
	}
	return nil
}
