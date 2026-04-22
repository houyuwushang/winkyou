package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"winkyou/pkg/config"
	"winkyou/pkg/logger"
	"winkyou/pkg/netif"
	relayserver "winkyou/pkg/relay/server"
)

func TestRelayWGGoTwoEnginesExchangeIPv4Packets(t *testing.T) {
	t.Setenv("WINKYOU_NETIF_ALLOW_MEMORY", "1")
	t.Setenv("WINKYOU_TUNNEL_FORCE_WGGO", "1")
	t.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "")
	t.Setenv("WINKYOU_TUNNEL_DEBUG", "1")

	grpcServer, listener := startTestCoordinator(t)
	defer grpcServer.Stop()
	defer func() {
		_ = listener.Close()
	}()

	relay := startEmbeddedClientRelay(t)
	turnURL := fmt.Sprintf("turn:%s", relay.Addr().String())

	alpha := newRelayWGGoTestEngine(t, "alpha", listener.Addr().String(), turnURL)
	beta := newRelayWGGoTestEngine(t, "beta", listener.Addr().String(), turnURL)

	if err := alpha.Start(context.Background()); err != nil {
		t.Fatalf("alpha.Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = alpha.Stop()
	})

	if err := beta.Start(context.Background()); err != nil {
		t.Fatalf("beta.Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = beta.Stop()
	})

	waitForEngineConnected(t, alpha, 10*time.Second)
	waitForEngineConnected(t, beta, 10*time.Second)

	alphaPeer := waitForRelayTransportReady(t, alpha, "beta", 30*time.Second)
	betaPeer := waitForRelayTransportReady(t, beta, "alpha", 30*time.Second)

	alphaBefore := clonePeerStatus(alphaPeer)
	betaBefore := clonePeerStatus(betaPeer)
	alphaNetif := requireMemoryTestInterface(t, alpha.netif)
	betaNetif := requireMemoryTestInterface(t, beta.netif)

	alphaPacket := buildIPv4UDPPacket(t, alpha.Status().VirtualIP, beta.Status().VirtualIP, 41001, 41002, []byte("wink-relay-alpha-beta"))
	betaPacket := buildIPv4UDPPacket(t, beta.Status().VirtualIP, alpha.Status().VirtualIP, 41002, 41001, []byte("wink-relay-beta-alpha"))

	if n, err := alphaNetif.InjectPacket(alphaPacket); err != nil {
		t.Fatalf("alphaNetif.InjectPacket() error = %v", err)
	} else if n != len(alphaPacket) {
		t.Fatalf("alphaNetif.InjectPacket() = %d bytes, want %d", n, len(alphaPacket))
	}
	alphaPeer = waitForRelayHandshake(t, alpha, "beta", 10*time.Second)
	betaPeer = waitForRelayHandshake(t, beta, "alpha", 10*time.Second)
	if got := receivePacketFromMemoryNetif(t, betaNetif, 10*time.Second); string(got) != string(alphaPacket) {
		t.Fatalf("beta received packet = %x, want %x", got, alphaPacket)
	}

	if n, err := betaNetif.InjectPacket(betaPacket); err != nil {
		t.Fatalf("betaNetif.InjectPacket() error = %v", err)
	} else if n != len(betaPacket) {
		t.Fatalf("betaNetif.InjectPacket() = %d bytes, want %d", n, len(betaPacket))
	}
	alphaPeer = waitForRelayHandshake(t, alpha, "beta", 10*time.Second)
	betaPeer = waitForRelayHandshake(t, beta, "alpha", 10*time.Second)
	if got := receivePacketFromMemoryNetif(t, alphaNetif, 10*time.Second); string(got) != string(betaPacket) {
		t.Fatalf("alpha received packet = %x, want %x", got, betaPacket)
	}

	alphaPeer = waitForRelayPeerConnected(t, alpha, "beta", 20*time.Second)
	betaPeer = waitForRelayPeerConnected(t, beta, "alpha", 20*time.Second)
	alphaRuntimePeer := waitForRuntimeRelayPeer(t, alpha.statePath, "beta", 20*time.Second)
	betaRuntimePeer := waitForRuntimeRelayPeer(t, beta.statePath, "alpha", 20*time.Second)

	assertRelayPeerDiagnostics(t, "alpha", alphaPeer)
	assertRelayPeerDiagnostics(t, "beta", betaPeer)
	assertRuntimeRelayPeerDiagnostics(t, "alpha", alphaRuntimePeer)
	assertRuntimeRelayPeerDiagnostics(t, "beta", betaRuntimePeer)

	waitForPeerStatsGrowth(t, alpha, "beta", 10*time.Second, alphaBefore)
	waitForPeerStatsGrowth(t, beta, "alpha", 10*time.Second, betaBefore)
}

func newRelayWGGoTestEngine(t *testing.T, nodeName, coordinatorAddr, turnURL string) *engine {
	t.Helper()

	cfg := config.Default()
	cfg.Node.Name = nodeName
	cfg.Coordinator.URL = "grpc://" + coordinatorAddr
	cfg.Coordinator.Timeout = 200 * time.Millisecond
	cfg.NetIf.Backend = "auto"
	cfg.WireGuard.ListenPort = 0
	cfg.NAT.STUNServers = nil
	cfg.NAT.GatherTimeout = 5 * time.Second
	cfg.NAT.ConnectTimeout = 15 * time.Second
	cfg.NAT.CheckTimeout = 5 * time.Second
	cfg.NAT.ForceRelay = true
	cfg.NAT.TURNServers = []config.TURNServerConfig{{
		URL:      turnURL,
		Username: "winkdemo",
		Password: "winkdemo-pass",
	}}

	engineInstance, err := NewEngine(&cfg, logger.Nop(), filepath.Join(t.TempDir(), nodeName+".yaml"))
	if err != nil {
		t.Fatalf("NewEngine(%s) error = %v", nodeName, err)
	}

	eng, ok := engineInstance.(*engine)
	if !ok {
		t.Fatalf("NewEngine(%s) returned %T, want *engine", nodeName, engineInstance)
	}
	return eng
}

func startEmbeddedClientRelay(t *testing.T) *relayserver.Server {
	t.Helper()

	srv, err := relayserver.New(relayserver.Config{
		ListenAddress: "127.0.0.1:0",
		Realm:         "winkyou",
		Users:         map[string]string{"winkdemo": "winkdemo-pass"},
	})
	if err != nil {
		t.Fatalf("relayserver.New() error = %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("relayserver.Start() error = %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
	})
	return srv
}

func waitForEngineConnected(t *testing.T, eng *engine, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if status := eng.Status(); status != nil && status.State == EngineStateConnected {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for engine %s to reach connected state; status=%+v", eng.cfg.Node.Name, eng.Status())
}

func waitForRelayHandshake(t *testing.T, eng *engine, peerName string, timeout time.Duration) *PeerStatus {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last *PeerStatus
	for time.Now().Before(deadline) {
		last = findPeerStatusByName(eng.GetPeers(), peerName)
		if isRelayPeerHandshakeReady(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for relay handshake %s on %s; last=%+v peers=%+v", peerName, eng.cfg.Node.Name, last, eng.GetPeers())
	return nil
}

func waitForRelayPeerConnected(t *testing.T, eng *engine, peerName string, timeout time.Duration) *PeerStatus {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last *PeerStatus
	for time.Now().Before(deadline) {
		last = findPeerStatusByName(eng.GetPeers(), peerName)
		if isRelayPeerConnected(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for relay peer %s on %s to reach connected state; last=%+v peers=%+v", peerName, eng.cfg.Node.Name, last, eng.GetPeers())
	return nil
}

func waitForRelayTransportReady(t *testing.T, eng *engine, peerName string, timeout time.Duration) *PeerStatus {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last *PeerStatus
	for time.Now().Before(deadline) {
		last = findPeerStatusByName(eng.GetPeers(), peerName)
		if isRelayTransportReady(last) {
			return last
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for relay transport %s on %s; last=%+v peers=%+v", peerName, eng.cfg.Node.Name, last, eng.GetPeers())
	return nil
}

func waitForRuntimeRelayPeer(t *testing.T, statePath, peerName string, timeout time.Duration) RuntimePeerStatus {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var last RuntimePeerStatus
	for time.Now().Before(deadline) {
		state, err := LoadRuntimeState(statePath)
		if err == nil {
			if peer, ok := findRuntimePeerByName(state.Peers, peerName); ok {
				last = peer
				if isRuntimeRelayPeerReady(peer) {
					return peer
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for runtime relay peer %s in %s; last=%+v", peerName, statePath, last)
	return RuntimePeerStatus{}
}

func waitForPeerStatsGrowth(t *testing.T, eng *engine, peerName string, timeout time.Duration, before *PeerStatus) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		current := findPeerStatusByName(eng.GetPeers(), peerName)
		if current != nil &&
			current.TransportTxBytes > before.TransportTxBytes &&
			current.TransportRxBytes > before.TransportRxBytes &&
			current.TxBytes > before.TxBytes &&
			current.RxBytes > before.RxBytes {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for peer %s transport stats to grow on %s; before=%+v after=%+v", peerName, eng.cfg.Node.Name, before, findPeerStatusByName(eng.GetPeers(), peerName))
}

func assertRelayPeerDiagnostics(t *testing.T, nodeName string, peer *PeerStatus) {
	t.Helper()

	if peer == nil {
		t.Fatalf("%s peer diagnostics = nil", nodeName)
	}
	if peer.State != PeerStateConnected {
		t.Fatalf("%s peer state = %s, want connected", nodeName, peer.State)
	}
	if peer.ConnectionType != ConnectionTypeRelay {
		t.Fatalf("%s connection type = %s, want relay", nodeName, peer.ConnectionType)
	}
	if peer.ICEState == "" {
		t.Fatalf("%s peer ICEState is empty", nodeName)
	}
	if peer.LocalCandidate == "" || peer.RemoteCandidate == "" {
		t.Fatalf("%s peer candidates missing: local=%q remote=%q", nodeName, peer.LocalCandidate, peer.RemoteCandidate)
	}
	if !strings.Contains(peer.LocalCandidate, "relay") && !strings.Contains(peer.RemoteCandidate, "relay") {
		t.Fatalf("%s peer candidates do not show relay path: local=%q remote=%q", nodeName, peer.LocalCandidate, peer.RemoteCandidate)
	}
	if peer.LastHandshake.IsZero() {
		t.Fatalf("%s peer last handshake is zero", nodeName)
	}
	if peer.TransportTxPackets == 0 || peer.TransportRxPackets == 0 {
		t.Fatalf("%s peer transport packets = tx=%d rx=%d, want non-zero", nodeName, peer.TransportTxPackets, peer.TransportRxPackets)
	}
	if peer.TransportLastError != "" {
		t.Fatalf("%s peer transport last error = %q, want empty", nodeName, peer.TransportLastError)
	}
}

func assertRuntimeRelayPeerDiagnostics(t *testing.T, nodeName string, peer RuntimePeerStatus) {
	t.Helper()

	if peer.State != PeerStateConnected.String() {
		t.Fatalf("%s runtime peer state = %q, want connected", nodeName, peer.State)
	}
	if peer.ConnectionType != ConnectionTypeRelay.String() {
		t.Fatalf("%s runtime peer connection type = %q, want relay", nodeName, peer.ConnectionType)
	}
	if peer.ICEState == "" {
		t.Fatalf("%s runtime peer ICEState is empty", nodeName)
	}
	if peer.LocalCandidate == "" || peer.RemoteCandidate == "" {
		t.Fatalf("%s runtime peer candidates missing: local=%q remote=%q", nodeName, peer.LocalCandidate, peer.RemoteCandidate)
	}
	if !strings.Contains(peer.LocalCandidate, "relay") && !strings.Contains(peer.RemoteCandidate, "relay") {
		t.Fatalf("%s runtime peer candidates do not show relay path: local=%q remote=%q", nodeName, peer.LocalCandidate, peer.RemoteCandidate)
	}
	if peer.LastHandshake.IsZero() {
		t.Fatalf("%s runtime peer last handshake is zero", nodeName)
	}
	if peer.TransportTxPackets == 0 || peer.TransportRxPackets == 0 {
		t.Fatalf("%s runtime peer transport packets = tx=%d rx=%d, want non-zero", nodeName, peer.TransportTxPackets, peer.TransportRxPackets)
	}
	if peer.TransportLastError != "" {
		t.Fatalf("%s runtime peer transport last error = %q, want empty", nodeName, peer.TransportLastError)
	}
}

func findPeerStatusByName(peers []*PeerStatus, name string) *PeerStatus {
	for _, peer := range peers {
		if peer != nil && peer.Name == name {
			return peer
		}
	}
	return nil
}

func findRuntimePeerByName(peers []RuntimePeerStatus, name string) (RuntimePeerStatus, bool) {
	for _, peer := range peers {
		if peer.Name == name {
			return peer, true
		}
	}
	return RuntimePeerStatus{}, false
}

func isRelayPeerHandshakeReady(peer *PeerStatus) bool {
	if peer == nil {
		return false
	}
	if peer.ConnectionType != ConnectionTypeRelay {
		return false
	}
	if peer.ICEState == "" || peer.LocalCandidate == "" || peer.RemoteCandidate == "" {
		return false
	}
	if !strings.Contains(peer.LocalCandidate, "relay") && !strings.Contains(peer.RemoteCandidate, "relay") {
		return false
	}
	if peer.LastHandshake.IsZero() {
		return false
	}
	return peer.TransportTxPackets > 0 && peer.TransportRxPackets > 0 && peer.TransportLastError == ""
}

func isRelayPeerConnected(peer *PeerStatus) bool {
	if !isRelayPeerHandshakeReady(peer) {
		return false
	}
	return peer.State == PeerStateConnected
}

func isRelayTransportReady(peer *PeerStatus) bool {
	if peer == nil {
		return false
	}
	if peer.ConnectionType != ConnectionTypeRelay {
		return false
	}
	if peer.ICEState == "" || peer.LocalCandidate == "" || peer.RemoteCandidate == "" {
		return false
	}
	if !strings.Contains(peer.LocalCandidate, "relay") && !strings.Contains(peer.RemoteCandidate, "relay") {
		return false
	}
	return peer.TransportTxPackets > 0 && peer.TransportRxPackets > 0 && peer.TransportLastError == ""
}

func isRuntimeRelayPeerReady(peer RuntimePeerStatus) bool {
	if peer.State != PeerStateConnected.String() || peer.ConnectionType != ConnectionTypeRelay.String() {
		return false
	}
	if peer.ICEState == "" || peer.LocalCandidate == "" || peer.RemoteCandidate == "" {
		return false
	}
	if !strings.Contains(peer.LocalCandidate, "relay") && !strings.Contains(peer.RemoteCandidate, "relay") {
		return false
	}
	if peer.LastHandshake.IsZero() {
		return false
	}
	return peer.TransportTxPackets > 0 && peer.TransportRxPackets > 0 && peer.TransportLastError == ""
}

func requireMemoryTestInterface(t *testing.T, ni netif.NetworkInterface) netif.MemoryTestInterface {
	t.Helper()

	memoryNetif, ok := ni.(netif.MemoryTestInterface)
	if !ok {
		t.Fatalf("netif %T does not implement netif.MemoryTestInterface", ni)
	}
	return memoryNetif
}

func receivePacketFromMemoryNetif(t *testing.T, ni netif.MemoryTestInterface, timeout time.Duration) []byte {
	t.Helper()

	packetCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		n, err := ni.ReceivePacket(buf)
		if err != nil {
			errCh <- err
			return
		}
		packetCh <- append([]byte(nil), buf[:n]...)
	}()

	select {
	case packet := <-packetCh:
		return packet
	case err := <-errCh:
		t.Fatalf("ReceivePacket() error = %v", err)
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for packet from memory netif")
	}
	return nil
}

func buildIPv4UDPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort int, payload []byte) []byte {
	t.Helper()

	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		t.Fatalf("buildIPv4UDPPacket() requires IPv4 src/dst, got src=%v dst=%v", srcIP, dstIP)
	}

	packet := make([]byte, 20+8+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[6] = 0x40
	copy(packet[12:16], src4)
	copy(packet[16:20], dst4)
	binary.BigEndian.PutUint16(packet[10:12], ipv4HeaderChecksum(packet[:20]))

	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dstPort))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)

	return packet
}

func ipv4HeaderChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
