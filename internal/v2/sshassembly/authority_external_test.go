package sshassembly_test

import (
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"

	"winkyou/internal/v2/gatecrequest"
	"winkyou/internal/v2/pairgen"
	"winkyou/internal/v2/sshassembly"
)

// Embedding inherits private interface methods but can override an exported
// method. This regression performs no process creation or network operation.
type endpointOverride struct {
	sshassembly.SSHEndpointAuthority
}

func (endpointOverride) Endpoint() netip.AddrPort {
	return netip.MustParseAddrPort("203.0.113.8:22")
}

// The consumer must continue accepting the concrete token, not a wider
// endpoint-bearing interface that could admit the wrapper again.
var _ func(sshassembly.SSHEndpointAuthority, gatecrequest.SSHConfig) (sshassembly.ClientConfig, error) = sshassembly.BindClientConfig

func TestExternalAuthorityIsOpaqueValue(t *testing.T) {
	token := reflect.TypeOf((*sshassembly.SSHEndpointAuthority)(nil)).Elem()
	if token.Kind() != reflect.Struct {
		t.Fatal("authority must be a concrete value, not an implementable interface")
	}
	for index := 0; index < token.NumField(); index++ {
		field := token.Field(index)
		if field.IsExported() || field.Anonymous {
			t.Fatal("authority must not expose writable or embedded state")
		}
	}
	if reflect.TypeOf(endpointOverride{}).AssignableTo(token) {
		t.Fatal("wrapper must not be assignable to the authority argument")
	}
}

func TestExternalAuthorityEndpointOverrideRejected(t *testing.T) {
	loopback, err := sshassembly.NewLoopbackAuthority(netip.MustParseAddrPort("127.0.0.1:22"))
	if err != nil {
		t.Fatal("loopback constructor failed")
	}
	wrapped := endpointOverride{SSHEndpointAuthority: loopback}
	// A type assertion keeps this exact regression compilable on both sides of
	// the interface-to-concrete migration. The old interface admits the wrapper;
	// the concrete token rejects it before BindClientConfig can be called.
	authority, accepted := any(wrapped).(sshassembly.SSHEndpointAuthority)
	if !accepted {
		t.Log("external_endpoint_override_rejected_at_type_boundary socket_calls=0 child_calls=0")
		return
	}
	root := t.TempDir()
	identity, pin := filepath.Join(root, "identity"), filepath.Join(root, "pin")
	if err := pairgen.WritePrivateFileExclusive(identity, []byte("synthetic-test-key")); err != nil {
		t.Fatal("private fixture setup failed")
	}
	if err := pairgen.WritePrivateFileExclusive(pin, []byte("synthetic-pinned-entry")); err != nil {
		t.Fatal("private fixture setup failed")
	}
	_, err = sshassembly.BindClientConfig(authority, gatecrequest.SSHConfig{
		Endpoint: wrapped.Endpoint(), User: "fixture", IdentityFile: identity, KnownHostsFile: pin,
	})
	if !errors.Is(err, sshassembly.ErrProfileInvalid) {
		t.Fatal("external_endpoint_override_accepted socket_calls=0 child_calls=0")
	}
}
