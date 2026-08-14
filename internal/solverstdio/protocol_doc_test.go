package solverstdio

import (
	"os"
	"strings"
	"testing"
)

func TestProtocolDocumentPinsMethodAndNegativeCapabilityLists(t *testing.T) {
	payload, err := os.ReadFile("../../docs/STDIO-API-V1.md")
	if err != nil {
		t.Fatalf("read protocol document: %v", err)
	}
	document := string(payload)
	for _, method := range SupportedMethods() {
		if !strings.Contains(document, "`"+method+"`") {
			t.Fatalf("protocol document does not pin method %q", method)
		}
	}
	for _, boundary := range []string{"raw socket", "PacketConn", "open_socket", "send_packet", "批量目标", "端口扫描", "提高 governor"} {
		if !strings.Contains(document, boundary) {
			t.Fatalf("protocol document does not pin negative boundary %q", boundary)
		}
	}
}

func TestDocumentedExampleFrameLengthsAreExact(t *testing.T) {
	examples := []struct {
		length int
		body   string
	}{
		{146, `{"jsonrpc":"2.0","id":"handshake-1","method":"handshake","params":{"schema_version":"winkyou.stdio/v1","framing_version":"lsp-content-length/v1"}}`},
		{81, `{"jsonrpc":"2.0","id":"status-1","method":"status","params":{"deadline_ms":2000}}`},
	}
	for _, example := range examples {
		if len([]byte(example.body)) != example.length {
			t.Fatalf("example length = %d, want %d", len([]byte(example.body)), example.length)
		}
	}
}
