package tunnel

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
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

func TestWGGoStartAndPeerLifecycle(t *testing.T) {
	w := newWGGoTunnel(Config{Interface: &fakeNetif{name: "wink0", mtu: 1280}, PrivateKey: mustPrivateKey(t), ListenPort: 0})

	var calls []string
	w.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if len(args) >= 3 && args[0] == "show" && args[2] == "dump" {
			return []byte("priv\tpub\t0\toff\n"), nil
		}
		return nil, nil
	}

	if err := w.Start(); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if w.listenPort == 0 {
		t.Fatal("listenPort should be auto-assigned when config listen_port is 0")
	}

	pk := makeTestKey(42)
	_, ipn, _ := net.ParseCIDR("10.10.0.0/24")
	peer := &PeerConfig{PublicKey: pk, AllowedIPs: []net.IPNet{*ipn}, Endpoint: &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 51820}}
	if err := w.AddPeer(peer); err != nil {
		t.Fatalf("AddPeer() error: %v", err)
	}
	if err := w.UpdatePeerEndpoint(pk, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 51821}); err != nil {
		t.Fatalf("UpdatePeerEndpoint() error: %v", err)
	}
	if err := w.RemovePeer(pk); err != nil {
		t.Fatalf("RemovePeer() error: %v", err)
	}

	if len(calls) < 4 {
		t.Fatalf("wg commands = %d, want at least 4", len(calls))
	}

	e1 := <-w.Events()
	e2 := <-w.Events()
	e3 := <-w.Events()
	if e1.Type != EventPeerAdded || e2.Type != EventPeerEndpointChanged || e3.Type != EventPeerRemoved {
		t.Fatalf("unexpected events: %v, %v, %v", e1.Type, e2.Type, e3.Type)
	}
}

func TestWGGoGetPeersDeepCopyAndStats(t *testing.T) {
	w := newWGGoTunnel(Config{Interface: &fakeNetif{name: "wink0", mtu: 1280}, PrivateKey: mustPrivateKey(t), ListenPort: 51820})

	pk := makeTestKey(11)
	w.peers[pk] = &PeerStatus{PublicKey: pk, Endpoint: &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 1000}}

	dump := "priv\tpub\t51820\toff\n" + pk.String() + "\t(none)\t9.9.9.9:1000\t10.20.0.0/16\t1710000000\t123\t456\t25\n"
	w.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) >= 3 && args[0] == "show" && args[2] == "dump" {
			return []byte(dump), nil
		}
		return nil, nil
	}

	peers := w.GetPeers()
	if len(peers) != 1 {
		t.Fatalf("GetPeers len = %d, want 1", len(peers))
	}
	peers[0].Endpoint.IP[0] = 1
	again := w.GetPeers()
	if again[0].Endpoint.IP[0] == 1 {
		t.Fatal("GetPeers returned internal reference, want snapshot")
	}

	stats := w.GetStats()
	if stats.RxBytes != 123 || stats.TxBytes != 456 || stats.Peers != 1 {
		t.Fatalf("stats = %+v, want rx=123 tx=456 peers=1", stats)
	}
}

func TestWGGoPeerOpsThreadSafe(t *testing.T) {
	w := newWGGoTunnel(Config{Interface: &fakeNetif{name: "wink0", mtu: 1280}, PrivateKey: mustPrivateKey(t), ListenPort: 51820})
	w.runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) { return nil, nil }
	_ = w.Start()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pk := makeTestKey(byte(i + 1))
			_ = w.AddPeer(&PeerConfig{PublicKey: pk})
			_ = w.UpdatePeerEndpoint(pk, &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(i+1)), Port: 5000 + i})
			_ = w.RemovePeer(pk)
		}(i)
	}
	wg.Wait()
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
	// Keep default unit tests on memory backend.
	_ = os.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "1")
	code := m.Run()
	os.Exit(code)
}
