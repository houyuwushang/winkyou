package nat

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// --- STUN response parsing tests ---

func TestParseSTUNMessageTooShort(t *testing.T) {
	_, err := parseSTUNMessage([]byte{0x00, 0x01})
	if err == nil {
		t.Error("expected error for too-short message")
	}
}

func TestParseSTUNMessageBadCookie(t *testing.T) {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], stunMsgTypeBindingResp)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], 0xDEADBEEF) // wrong cookie
	_, err := parseSTUNMessage(buf)
	if err == nil {
		t.Error("expected error for bad magic cookie")
	}
}

func TestParseSTUNBindingResponse(t *testing.T) {
	buf := buildFakeBindingResponse(
		stunTransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		net.IPv4(203, 0, 113, 5), 45000,
	)

	msg, err := parseSTUNMessage(buf)
	if err != nil {
		t.Fatalf("parseSTUNMessage() error: %v", err)
	}
	if msg.msgType != stunMsgTypeBindingResp {
		t.Errorf("msgType = 0x%04x, want 0x%04x", msg.msgType, stunMsgTypeBindingResp)
	}
	if msg.transactionID != (stunTransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
		t.Errorf("transactionID mismatch")
	}

	addr, err := msg.extractMappedAddr()
	if err != nil {
		t.Fatalf("extractMappedAddr() error: %v", err)
	}
	if !addr.IP.Equal(net.IPv4(203, 0, 113, 5)) {
		t.Errorf("mapped IP = %v, want 203.0.113.5", addr.IP)
	}
	if addr.Port != 45000 {
		t.Errorf("mapped port = %d, want 45000", addr.Port)
	}
}

func TestParseSTUNWithMappedAddress(t *testing.T) {
	// Build a response with only MAPPED-ADDRESS (no XOR).
	buf := buildFakeMappedAddressResponse(
		stunTransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		net.IPv4(198, 51, 100, 1), 9999,
	)

	msg, err := parseSTUNMessage(buf)
	if err != nil {
		t.Fatalf("parseSTUNMessage() error: %v", err)
	}

	addr, err := msg.extractMappedAddr()
	if err != nil {
		t.Fatalf("extractMappedAddr() error: %v", err)
	}
	if !addr.IP.Equal(net.IPv4(198, 51, 100, 1)) {
		t.Errorf("mapped IP = %v, want 198.51.100.1", addr.IP)
	}
	if addr.Port != 9999 {
		t.Errorf("mapped port = %d, want 9999", addr.Port)
	}
}

func TestParseSTUNNoMappedAddress(t *testing.T) {
	// Build a response with no address attributes.
	buf := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], stunMsgTypeBindingResp)
	binary.BigEndian.PutUint16(buf[2:4], 0)
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)

	msg, _ := parseSTUNMessage(buf)
	_, err := msg.extractMappedAddr()
	if err == nil {
		t.Error("expected error when no mapped address present")
	}
}

// --- Local fake STUN server + end-to-end test ---

func TestStunBindLocalServer(t *testing.T) {
	// Start a local UDP "STUN server" that replies with a fake binding response.
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)
	mappedIP := net.IPv4(203, 0, 113, 42)
	mappedPort := 54321

	// Server goroutine: read request, send canned response.
	go func() {
		buf := make([]byte, stunMaxPacket)
		n, clientAddr, err := serverConn.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := parseSTUNMessage(buf[:n])
		if err != nil {
			return
		}
		resp := buildFakeBindingResponse(req.transactionID, mappedIP, mappedPort)
		serverConn.WriteTo(resp, clientAddr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := stunBind(ctx, serverAddr.String())
	if err != nil {
		t.Fatalf("stunBind() error: %v", err)
	}
	if !result.MappedAddr.IP.Equal(mappedIP) {
		t.Errorf("MappedAddr.IP = %v, want %v", result.MappedAddr.IP, mappedIP)
	}
	if result.MappedAddr.Port != mappedPort {
		t.Errorf("MappedAddr.Port = %d, want %d", result.MappedAddr.Port, mappedPort)
	}
}

func TestStunBindTimeout(t *testing.T) {
	// Server that never responds.
	serverConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = stunBind(ctx, serverAddr.String())
	if err == nil {
		t.Error("expected timeout error")
	}
}

// --- Host candidate dedup/filter tests ---

func TestGatherHostCandidates(t *testing.T) {
	candidates, err := gatherHostCandidates()
	if err != nil {
		t.Fatalf("gatherHostCandidates() error: %v", err)
	}

	// We can't assert a specific count (varies by machine), but
	// verify invariants.
	seen := make(map[string]bool)
	for _, c := range candidates {
		if c.Type != CandidateTypeHost {
			t.Errorf("candidate type = %v, want CandidateTypeHost", c.Type)
		}
		if c.Address == nil {
			t.Error("candidate has nil Address")
			continue
		}
		ip := c.Address.IP
		if ip.IsLoopback() {
			t.Errorf("loopback address should be filtered: %v", ip)
		}
		if ip.IsLinkLocalUnicast() {
			t.Errorf("link-local address should be filtered: %v", ip)
		}
		if ip.To4() == nil {
			t.Errorf("IPv6 address should be filtered: %v", ip)
		}
		key := ip.String()
		if seen[key] {
			t.Errorf("duplicate IP: %v", ip)
		}
		seen[key] = true

		if c.Foundation == "" {
			t.Error("Foundation should not be empty")
		}
		if c.Priority == 0 {
			t.Error("Priority should not be zero")
		}
	}
}

func TestHostFoundationDeterministic(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 100)
	f1 := hostFoundation(ip)
	f2 := hostFoundation(ip)
	if f1 != f2 {
		t.Errorf("hostFoundation not deterministic: %q vs %q", f1, f2)
	}

	f3 := hostFoundation(net.IPv4(10, 0, 0, 1))
	if f1 == f3 {
		t.Error("different IPs should produce different foundations")
	}
}

func TestSrflxFoundationDeterministic(t *testing.T) {
	ip := net.IPv4(192, 168, 1, 1)
	f1 := srflxFoundation(ip, "stun:stun.example.com:3478")
	f2 := srflxFoundation(ip, "stun:stun.example.com:3478")
	if f1 != f2 {
		t.Errorf("srflxFoundation not deterministic: %q vs %q", f1, f2)
	}

	f3 := srflxFoundation(ip, "stun:other.example.com:3478")
	if f1 == f3 {
		t.Error("different servers should produce different foundations")
	}
}

// --- DetectNATType tests ---

func TestDetectNATTypeAllFail(t *testing.T) {
	// Point at two servers that don't exist (they'll time out fast).
	nt, _ := NewNATTraversal(&Config{
		STUNServers: []string{
			"127.0.0.1:1", // nothing listening
			"127.0.0.1:2",
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	natType, err := nt.DetectNATType(ctx)
	if err == nil {
		t.Error("expected error when all probes fail")
	}
	if natType != NATTypeUnknown {
		t.Errorf("natType = %v, want NATTypeUnknown", natType)
	}
}

func TestDetectNATTypeSymmetric(t *testing.T) {
	// Spin up two local STUN servers that return DIFFERENT mapped addresses.
	s1 := startFakeSTUNServer(t, net.IPv4(203, 0, 113, 1), 10001)
	defer s1.Close()
	s2 := startFakeSTUNServer(t, net.IPv4(203, 0, 113, 1), 20002) // same IP, different port
	defer s2.Close()

	nt, _ := NewNATTraversal(&Config{
		STUNServers: []string{
			s1.LocalAddr().String(),
			s2.LocalAddr().String(),
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	natType, err := nt.DetectNATType(ctx)
	if err != nil {
		t.Fatalf("DetectNATType() error: %v", err)
	}
	if natType != NATTypeSymmetric {
		t.Errorf("natType = %v, want NATTypeSymmetric", natType)
	}
}

func TestDetectNATTypeConsistentMapping(t *testing.T) {
	// Two servers return the SAME mapped address.
	// Since the mapped address is non-local, result should be NATTypeUnknown
	// (we can't distinguish cone subtypes).
	s1 := startFakeSTUNServer(t, net.IPv4(203, 0, 113, 1), 55555)
	defer s1.Close()
	s2 := startFakeSTUNServer(t, net.IPv4(203, 0, 113, 1), 55555)
	defer s2.Close()

	nt, _ := NewNATTraversal(&Config{
		STUNServers: []string{
			s1.LocalAddr().String(),
			s2.LocalAddr().String(),
		},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	natType, err := nt.DetectNATType(ctx)
	if err != nil {
		t.Fatalf("DetectNATType() error: %v", err)
	}
	// With consistent non-local mapping, we return Unknown (not guessing cone type).
	if natType != NATTypeUnknown {
		t.Errorf("natType = %v, want NATTypeUnknown", natType)
	}
}

func TestDetectNATTypeNone(t *testing.T) {
	// Server returns mapped address = 127.0.0.1 (a local address).
	s := startFakeSTUNServer(t, net.IPv4(127, 0, 0, 1), 12345)
	defer s.Close()

	nt, _ := NewNATTraversal(&Config{
		STUNServers: []string{s.LocalAddr().String()},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	natType, err := nt.DetectNATType(ctx)
	if err != nil {
		t.Fatalf("DetectNATType() error: %v", err)
	}
	if natType != NATTypeNone {
		t.Errorf("natType = %v, want NATTypeNone", natType)
	}
}

// --- parseSTUNAddr tests ---

func TestParseSTUNAddr(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"stun:stun.l.google.com:19302", "stun.l.google.com", "19302"},
		{"stun.l.google.com:19302", "stun.l.google.com", "19302"},
		{"stun:stun.example.com", "stun.example.com", "3478"},
		{"127.0.0.1:3478", "127.0.0.1", "3478"},
	}
	for _, tt := range tests {
		h, p, err := parseSTUNAddr(tt.input)
		if err != nil {
			t.Errorf("parseSTUNAddr(%q) error: %v", tt.input, err)
			continue
		}
		if h != tt.wantHost || p != tt.wantPort {
			t.Errorf("parseSTUNAddr(%q) = (%q, %q), want (%q, %q)",
				tt.input, h, p, tt.wantHost, tt.wantPort)
		}
	}
}

// --- GatherCandidates via real agent ---

func TestICEAgentGatherCandidatesWithSTUN(t *testing.T) {
	// Spin up a fake STUN server.
	s := startFakeSTUNServer(t, net.IPv4(198, 51, 100, 42), 33333)
	defer s.Close()

	nt, _ := NewNATTraversal(&Config{
		STUNServers: []string{s.LocalAddr().String()},
	})
	agent, _ := nt.NewICEAgent(ICEConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	candidates, err := agent.GatherCandidates(ctx)
	if err != nil {
		t.Fatalf("GatherCandidates() error: %v", err)
	}

	var hasHost, hasSrflx bool
	for _, c := range candidates {
		switch c.Type {
		case CandidateTypeHost:
			hasHost = true
		case CandidateTypeSrflx:
			hasSrflx = true
			if !c.Address.IP.Equal(net.IPv4(198, 51, 100, 42)) {
				t.Errorf("srflx IP = %v, want 198.51.100.42", c.Address.IP)
			}
		}
	}

	// Host candidates depend on the machine, may be empty in containers.
	// But srflx should always be present with our fake server.
	_ = hasHost
	if !hasSrflx {
		t.Error("expected at least one srflx candidate")
	}
}

// --- Test helpers ---

// startFakeSTUNServer starts a local UDP server that responds to STUN Binding
// Requests with a fixed XOR-MAPPED-ADDRESS.
func startFakeSTUNServer(t *testing.T, mappedIP net.IP, mappedPort int) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake STUN server listen: %v", err)
	}

	go func() {
		buf := make([]byte, stunMaxPacket)
		for {
			n, clientAddr, err := conn.ReadFrom(buf)
			if err != nil {
				return // server closed
			}
			req, err := parseSTUNMessage(buf[:n])
			if err != nil {
				continue
			}
			if req.msgType != stunMsgTypeBindingReq {
				continue
			}
			resp := buildFakeBindingResponse(req.transactionID, mappedIP, mappedPort)
			conn.WriteTo(resp, clientAddr)
		}
	}()

	return conn
}

// buildFakeBindingResponse constructs a STUN Binding Response with an
// XOR-MAPPED-ADDRESS attribute.
func buildFakeBindingResponse(txID stunTransactionID, ip net.IP, port int) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		panic("test helper only supports IPv4")
	}

	// XOR-MAPPED-ADDRESS attribute: family(1) + reserved(1) + port(2) + ip(4) = 8 bytes
	attrData := make([]byte, 8)
	attrData[0] = 0x00 // reserved
	attrData[1] = 0x01 // IPv4 family
	xport := uint16(port) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(attrData[2:4], xport)
	cookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
	for i := 0; i < 4; i++ {
		attrData[4+i] = ip4[i] ^ cookieBytes[i]
	}

	// Build full attribute TLV: type(2) + length(2) + data(8) = 12 bytes
	attrBuf := make([]byte, 4+len(attrData))
	binary.BigEndian.PutUint16(attrBuf[0:2], stunAttrXORMappedAddress)
	binary.BigEndian.PutUint16(attrBuf[2:4], uint16(len(attrData)))
	copy(attrBuf[4:], attrData)

	// Build the full message.
	msgLen := len(attrBuf)
	buf := make([]byte, stunHeaderSize+msgLen)
	binary.BigEndian.PutUint16(buf[0:2], stunMsgTypeBindingResp)
	binary.BigEndian.PutUint16(buf[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], txID[:])
	copy(buf[stunHeaderSize:], attrBuf)

	return buf
}

// buildFakeMappedAddressResponse constructs a STUN Binding Response with
// a plain MAPPED-ADDRESS attribute (no XOR).
func buildFakeMappedAddressResponse(txID stunTransactionID, ip net.IP, port int) []byte {
	ip4 := ip.To4()
	if ip4 == nil {
		panic("test helper only supports IPv4")
	}

	attrData := make([]byte, 8)
	attrData[0] = 0x00 // reserved
	attrData[1] = 0x01 // IPv4 family
	binary.BigEndian.PutUint16(attrData[2:4], uint16(port))
	copy(attrData[4:8], ip4)

	attrBuf := make([]byte, 4+len(attrData))
	binary.BigEndian.PutUint16(attrBuf[0:2], stunAttrMappedAddress)
	binary.BigEndian.PutUint16(attrBuf[2:4], uint16(len(attrData)))
	copy(attrBuf[4:], attrData)

	msgLen := len(attrBuf)
	buf := make([]byte, stunHeaderSize+msgLen)
	binary.BigEndian.PutUint16(buf[0:2], stunMsgTypeBindingResp)
	binary.BigEndian.PutUint16(buf[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], txID[:])
	copy(buf[stunHeaderSize:], attrBuf)

	return buf
}
