package tunnel

import (
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	wgconn "golang.zx2c4.com/wireguard/conn"
)

type fakeNetif struct {
	name string
	mtu  int
}

func (f *fakeNetif) Name() string                                  { return f.name }
func (f *fakeNetif) Type() string                                  { return "tun" }
func (f *fakeNetif) MTU() int                                      { return f.mtu }
func (f *fakeNetif) Read(buf []byte) (int, error)                  { return 0, nil }
func (f *fakeNetif) Write(buf []byte) (int, error)                 { return len(buf), nil }
func (f *fakeNetif) Close() error                                  { return nil }
func (f *fakeNetif) SetIP(ip net.IP, mask net.IPMask) error        { return nil }
func (f *fakeNetif) AddRoute(dst *net.IPNet, gateway net.IP) error { return nil }
func (f *fakeNetif) RemoveRoute(dst *net.IPNet) error              { return nil }

func TestNewForceWGGo(t *testing.T) {
	t.Setenv("WINKYOU_TUNNEL_FORCE_WGGO", "1")
	t.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "")

	priv := mustPrivateKey(t)
	tun, err := New(Config{Interface: &fakeNetif{name: "wink0", mtu: 1280}, PrivateKey: priv})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if _, ok := tun.(*wggoTunnel); !ok {
		t.Fatalf("New() returned %T, want *wggoTunnel", tun)
	}
}

func TestPeerTransportBindSendAndReceive(t *testing.T) {
	bind := newPeerTransportBind()
	defer bind.Close()

	publicKey := makeTestKey(42)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	endpointID, err := bind.AttachTransport(publicKey, left)
	if err != nil {
		t.Fatalf("AttachTransport() error: %v", err)
	}
	defer bind.DetachTransport(publicKey)

	bind.UpdateTransportEndpoint(publicKey, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 51820})
	if got := bind.TransportRemoteAddr(publicKey); got == nil || !got.IP.Equal(net.IPv4(5, 6, 7, 8)) || got.Port != 51820 {
		t.Fatalf("TransportRemoteAddr() = %+v, want 5.6.7.8:51820", got)
	}
	if got := bind.ResolveEndpoint(endpointID); got == nil || !got.IP.Equal(net.IPv4(5, 6, 7, 8)) || got.Port != 51820 {
		t.Fatalf("ResolveEndpoint(%q) = %+v, want 5.6.7.8:51820", endpointID, got)
	}

	endpoint, err := bind.ParseEndpoint(endpointID)
	if err != nil {
		t.Fatalf("ParseEndpoint() error: %v", err)
	}

	wantSend := []byte("wink-send")
	sendDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := right.Read(buf)
		sendDone <- append([]byte(nil), buf[:n]...)
	}()
	if err := bind.Send([][]byte{wantSend}, endpoint); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	select {
	case got := <-sendDone:
		if string(got) != string(wantSend) {
			t.Fatalf("transport payload = %q, want %q", got, wantSend)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for transport send")
	}

	wantRecv := []byte("wink-recv")
	recvDone := make(chan error, 1)
	go func() {
		_, err := right.Write(wantRecv)
		recvDone <- err
	}()
	wireBufs := [][]byte{make([]byte, 64)}
	wireSizes := make([]int, 1)
	wireEndpointsBuf := make([]wgconn.Endpoint, 1)

	n, err := bind.receiveFromTransports(wireBufs, wireSizes, wireEndpointsBuf)
	if err != nil {
		t.Fatalf("receiveFromTransports() error: %v", err)
	}
	if n != 1 {
		t.Fatalf("receiveFromTransports() = %d packets, want 1", n)
	}
	if got := string(wireBufs[0][:wireSizes[0]]); got != string(wantRecv) {
		t.Fatalf("received payload = %q, want %q", got, wantRecv)
	}
	if wireEndpointsBuf[0] == nil || wireEndpointsBuf[0].DstToString() != endpointID {
		t.Fatalf("received endpoint = %#v, want %q", wireEndpointsBuf[0], endpointID)
	}
	if err := <-recvDone; err != nil {
		t.Fatalf("transport write error: %v", err)
	}
}

func TestParseDeviceSnapshotTransportEndpointAndStats(t *testing.T) {
	bind := newPeerTransportBind()
	defer bind.Close()

	publicKey := makeTestKey(11)
	bind.transports[publicKey] = &boundTransport{
		stopCh: make(chan struct{}),
		endpoint: &transportEndpoint{
			key:        publicKey,
			id:         transportEndpointID(publicKey),
			remoteAddr: &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 1000},
		},
	}

	dump := strings.Join([]string{
		"listen_port=51820",
		"public_key=" + hex.EncodeToString(publicKey[:]),
		"endpoint=" + transportEndpointID(publicKey),
		"allowed_ip=10.20.0.0/16",
		"last_handshake_time_sec=1710000000",
		"last_handshake_time_nsec=25",
		"tx_bytes=456",
		"rx_bytes=123",
		"",
	}, "\n")

	snapshot, err := parseDeviceSnapshot(dump, bind)
	if err != nil {
		t.Fatalf("parseDeviceSnapshot() error: %v", err)
	}
	if snapshot.ListenPort != 51820 {
		t.Fatalf("ListenPort = %d, want 51820", snapshot.ListenPort)
	}
	peer := snapshot.Peers[publicKey]
	if peer == nil {
		t.Fatal("snapshot peer missing")
	}
	if peer.Endpoint == nil || !peer.Endpoint.IP.Equal(net.IPv4(9, 9, 9, 9)) || peer.Endpoint.Port != 1000 {
		t.Fatalf("Endpoint = %+v, want 9.9.9.9:1000", peer.Endpoint)
	}
	if len(peer.AllowedIPs) != 1 || peer.AllowedIPs[0].String() != "10.20.0.0/16" {
		t.Fatalf("AllowedIPs = %+v, want 10.20.0.0/16", peer.AllowedIPs)
	}
	if peer.TxBytes != 456 || peer.RxBytes != 123 {
		t.Fatalf("stats = rx=%d tx=%d, want rx=123 tx=456", peer.RxBytes, peer.TxBytes)
	}
	if peer.LastHandshake.Unix() != 1710000000 || peer.LastHandshake.Nanosecond() != 25 {
		t.Fatalf("LastHandshake = %v, want unix=1710000000 nsec=25", peer.LastHandshake)
	}
}

func TestAllowMemoryTunnelForTestOverride(t *testing.T) {
	t.Setenv("WINKYOU_TUNNEL_FORCE_WGGO", "1")
	if allowMemoryTunnelForTest() {
		t.Fatal("allowMemoryTunnelForTest should be false when FORCE_WGGO=1")
	}
	t.Setenv("WINKYOU_TUNNEL_FORCE_WGGO", "")
	t.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "1")
	if !allowMemoryTunnelForTest() {
		t.Fatal("allowMemoryTunnelForTest should be true when ALLOW_MEMORY=1")
	}
}

func mustPrivateKey(t *testing.T) PrivateKey {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey() error: %v", err)
	}
	return k
}

func TestMain(m *testing.M) {
	_ = os.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "1")
	code := m.Run()
	os.Exit(code)
}
