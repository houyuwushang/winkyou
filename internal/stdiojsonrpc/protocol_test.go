package stdiojsonrpc

import (
	"encoding/json"
	"testing"
)

func TestParseRequestRequiresStrictJSONRPCEnvelope(t *testing.T) {
	valid, rpcErr := ParseRequest([]byte(`{"jsonrpc":"2.0","id":"request-1","method":"status","params":{}}`))
	if rpcErr != nil || valid.ID.Key() != "s:request-1" || valid.Method != "status" {
		t.Fatalf("valid request = %+v, error=%+v", valid, rpcErr)
	}
	tests := []struct {
		name  string
		body  string
		class string
	}{
		{name: "notification forbidden", body: `{"jsonrpc":"2.0","method":"status","params":{}}`, class: ClassInvalidRequest},
		{name: "fractional id forbidden", body: `{"jsonrpc":"2.0","id":1.5,"method":"status","params":{}}`, class: ClassInvalidRequest},
		{name: "positional params forbidden", body: `{"jsonrpc":"2.0","id":1,"method":"status","params":[]}`, class: ClassInvalidParams},
		{name: "unknown envelope field forbidden", body: `{"jsonrpc":"2.0","id":1,"method":"status","extra":true}`, class: ClassParseError},
		{name: "trailing JSON forbidden", body: `{"jsonrpc":"2.0","id":1,"method":"status"}{}`, class: ClassInvalidRequest},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, rpcErr := ParseRequest([]byte(test.body))
			if rpcErr == nil || rpcErr.Data.Class != test.class {
				t.Fatalf("error = %+v, want class %q", rpcErr, test.class)
			}
		})
	}
}

func TestIDRoundTripPreservesWireType(t *testing.T) {
	for _, raw := range []string{`"alpha"`, `42`, `-7`} {
		id, err := ParseID(json.RawMessage(raw))
		if err != nil {
			t.Fatalf("parse %s: %v", raw, err)
		}
		if string(id.Raw()) != raw {
			t.Fatalf("id raw = %s, want %s", id.Raw(), raw)
		}
	}
}
