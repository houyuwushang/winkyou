package gatecrequest

import (
	"bytes"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"winkyou/internal/v2/gatecattempt"
	"winkyou/internal/v2/pairgen"
)

func TestRequestRoundTripAndRoleUnion(t *testing.T) {
	initiator := validRequest(t, gatecattempt.RoleInitiator)
	payload, err := Encode(initiator)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := Parse(payload)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !equalRequest(parsed, initiator) {
		t.Fatal("initiator request round trip mismatch")
	}

	responder := validRequest(t, gatecattempt.RoleResponder)
	payload, err = Encode(responder)
	if err != nil {
		t.Fatalf("Encode responder: %v", err)
	}
	parsed, err = Parse(payload)
	if err != nil || !equalRequest(parsed, responder) || parsed.SSH != nil {
		t.Fatalf("responder request round trip failed: %v", err)
	}
}

func TestRequestStrictJSONAndSizeBoundary(t *testing.T) {
	payload := mustEncodeRequest(t, validRequest(t, gatecattempt.RoleInitiator))
	mutations := [][]byte{
		bytes.Replace(payload, []byte(`"schema":`), []byte(`"unknown":"x","schema":`), 1),
		bytes.Replace(payload, []byte(`"primary":`), []byte(`"primary":"192.0.2.1:3478","primary":`), 1),
		append(append([]byte(nil), payload...), []byte(` {}`)...),
		[]byte(`[]`),
		bytes.Repeat([]byte{'x'}, MaxRequestBytes+1),
	}
	for index, mutation := range mutations {
		if _, err := Parse(mutation); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("mutation %d error=%v, want ErrInvalidRequest", index, err)
		}
	}
}

func TestRequestRejectsInvalidAuthorityFields(t *testing.T) {
	initiator := validRequest(t, gatecattempt.RoleInitiator)
	base := mustEncodeRequest(t, initiator)
	tests := map[string][]byte{
		"relative artifact":          bytes.Replace(base, []byte(strings.ReplaceAll(initiator.ArtifactFile, `\`, `\\`)), []byte("relative.json"), 1),
		"dns ssh endpoint":           bytes.Replace(base, []byte("127.0.0.1:22"), []byte("host.invalid:22"), 1),
		"private peer address":       bytes.Replace(base, []byte("203.0.113.8"), []byte("10.0.0.8"), 1),
		"observer duplicate address": bytes.Replace(base, []byte("198.51.100.2:3478"), []byte("192.0.2.1:3478"), 1),
		"observer duplicate port":    bytes.Replace(base, []byte("192.0.2.1:3479"), []byte("192.0.2.1:3478"), 1),
		"control in peer ref":        bytes.Replace(base, []byte(`"peer_ref":"peer-a"`), []byte(`"peer_ref":"peer-a\n"`), 1),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(payload); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Parse error=%v, want ErrInvalidRequest", err)
			}
		})
	}

	responderWithSSH := validRequest(t, gatecattempt.RoleResponder)
	responderWithSSH.SSH = initiator.SSH
	if _, err := Encode(responderWithSSH); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("responder SSH Encode error=%v, want ErrInvalidRequest", err)
	}
	initiator.SSH = nil
	if _, err := Encode(initiator); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("initiator without SSH Encode error=%v, want ErrInvalidRequest", err)
	}
}

func TestLoadPrivateUsesOwnerOnlyValidation(t *testing.T) {
	request := validRequest(t, gatecattempt.RoleResponder)
	payload := mustEncodeRequest(t, request)
	path := filepath.Join(t.TempDir(), "request.json")
	if err := pairgen.WritePrivateFileExclusive(path, payload); err != nil {
		t.Fatalf("WritePrivateFileExclusive: %v", err)
	}
	loaded, err := LoadPrivate(path)
	if err != nil || !equalRequest(loaded, request) {
		t.Fatalf("LoadPrivate round trip failed: %v", err)
	}
	if _, err := LoadPrivate("relative.json"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("relative LoadPrivate error=%v", err)
	}
}

func validRequest(t *testing.T, role gatecattempt.Role) Request {
	t.Helper()
	root := t.TempDir()
	request := Request{
		Role:                      role,
		ArtifactFile:              filepath.Join(root, "artifact.json"),
		PeerRef:                   "peer-a",
		ExpectedPeerPublicAddress: netip.MustParseAddr("203.0.113.8"),
		ObserverSet: ObserverSet{
			Primary:              netip.MustParseAddrPort("192.0.2.1:3478"),
			AlternatePort:        netip.MustParseAddrPort("192.0.2.1:3479"),
			AlternateAddress:     netip.MustParseAddrPort("198.51.100.2:3478"),
			AlternateAddressPort: netip.MustParseAddrPort("198.51.100.2:3479"),
		},
	}
	if role == gatecattempt.RoleInitiator {
		request.SSH = &SSHConfig{
			Endpoint:       netip.MustParseAddrPort("127.0.0.1:22"),
			User:           "gate-c-user",
			IdentityFile:   filepath.Join(root, "identity"),
			KnownHostsFile: filepath.Join(root, "known_hosts"),
		}
	}
	return request
}

func mustEncodeRequest(t *testing.T, request Request) []byte {
	t.Helper()
	payload, err := Encode(request)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(payload), "\\\\") && filepath.Separator != '\\' {
		t.Fatalf("unexpected path escape in payload")
	}
	return payload
}
