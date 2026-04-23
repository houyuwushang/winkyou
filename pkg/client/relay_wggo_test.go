package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
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
	"winkyou/pkg/tunnel"
)

func TestRelayWGGoTwoEnginesExchangeIPv4Packets(t *testing.T) {
	t.Setenv("WINKYOU_NETIF_ALLOW_MEMORY", "1")
	t.Setenv("WINKYOU_TUNNEL_FORCE_WGGO", "1")
	t.Setenv("WINKYOU_TUNNEL_ALLOW_MEMORY", "")

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
	t.Cleanup(func() {
		if t.Failed() {
			dumpRelayWGGoTestDiagnostics(t, relay.Addr().String(), alpha, beta)
		}
	})

	waitForEngineConnected(t, alpha, 10*time.Second)
	waitForEngineConnected(t, beta, 10*time.Second)

	alphaPeer := waitForRelayTransportReady(t, alpha, "beta", 30*time.Second)
	betaPeer := waitForRelayTransportReady(t, beta, "alpha", 30*time.Second)

	alphaBefore := clonePeerStatus(alphaPeer)
	betaBefore := clonePeerStatus(betaPeer)
	alphaNetif := requireMemoryTestInterface(t, alpha.netif)
	betaNetif := requireMemoryTestInterface(t, beta.netif)
	alphaCapture := startMemoryPacketCapture(t, "alpha", alphaNetif)
	betaCapture := startMemoryPacketCapture(t, "beta", betaNetif)

	alphaPacket := buildIPv4UDPPacket(t, alpha.Status().VirtualIP, beta.Status().VirtualIP, 41001, 41002, []byte("wink-relay-alpha-beta"))
	betaPacket := buildIPv4UDPPacket(t, beta.Status().VirtualIP, alpha.Status().VirtualIP, 41002, 41001, []byte("wink-relay-beta-alpha"))

	alphaPeer = waitForRelayPeerConnected(t, alpha, "beta", 20*time.Second)
	betaPeer = waitForRelayPeerConnected(t, beta, "alpha", 20*time.Second)
	alphaPeer = waitForRelayHandshake(t, alpha, "beta", 20*time.Second)
	betaPeer = waitForRelayHandshake(t, beta, "alpha", 20*time.Second)
	alphaPeer = waitForRelayTransportQuiescent(t, alpha, "beta", 10*time.Second, time.Second)
	betaPeer = waitForRelayTransportQuiescent(t, beta, "alpha", 10*time.Second, time.Second)

	waitForRelayPacketDelivery(t, "alpha->beta", alphaNetif, betaCapture, alphaPacket, 10*time.Second)
	alphaPeer = waitForRelayTransportQuiescent(t, alpha, "beta", 10*time.Second, time.Second)
	betaPeer = waitForRelayTransportQuiescent(t, beta, "alpha", 10*time.Second, time.Second)
	waitForRelayPacketDelivery(t, "beta->alpha", betaNetif, alphaCapture, betaPacket, 10*time.Second)

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

func waitForRelayTransportQuiescent(t *testing.T, eng *engine, peerName string, timeout, quietPeriod time.Duration) *PeerStatus {
	t.Helper()

	deadline := time.Now().Add(timeout)
	var (
		last        *PeerStatus
		stableSince time.Time
	)
	for time.Now().Before(deadline) {
		current := findPeerStatusByName(eng.GetPeers(), peerName)
		if !isRelayPeerHandshakeReady(current) {
			last = current
			stableSince = time.Time{}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if relayPeerCountersEqual(last, current) {
			if stableSince.IsZero() {
				stableSince = time.Now()
			}
			if time.Since(stableSince) >= quietPeriod {
				return current
			}
		} else {
			stableSince = time.Time{}
		}
		last = current
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for relay transport %s on %s to quiesce; last=%+v peers=%+v", peerName, eng.cfg.Node.Name, last, eng.GetPeers())
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

type memoryPacketCapture struct {
	name    string
	packets chan []byte
	errs    chan error
}

func startMemoryPacketCapture(t *testing.T, name string, ni netif.MemoryTestInterface) *memoryPacketCapture {
	t.Helper()

	capture := &memoryPacketCapture{
		name:    name,
		packets: make(chan []byte, 32),
		errs:    make(chan error, 1),
	}
	go func() {
		for {
			buf := make([]byte, 2048)
			n, err := ni.ReceivePacket(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case capture.errs <- err:
				default:
				}
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			select {
			case capture.packets <- packet:
			default:
				select {
				case <-capture.packets:
				default:
				}
				capture.packets <- packet
			}
		}
	}()
	return capture
}

func waitForRelayPacketDelivery(t *testing.T, flow string, sender netif.MemoryTestInterface, receiver *memoryPacketCapture, packet []byte, timeout time.Duration) {
	t.Helper()

	drainCapturedPackets(receiver)

	send := func() {
		n, err := sender.InjectPacket(packet)
		if err != nil {
			t.Fatalf("%s InjectPacket() error = %v", flow, err)
		}
		if n != len(packet) {
			t.Fatalf("%s InjectPacket() = %d bytes, want %d", flow, n, len(packet))
		}
	}

	send()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case got := <-receiver.packets:
			if bytes.Equal(got, packet) {
				return
			}
		case err := <-receiver.errs:
			t.Fatalf("%s ReceivePacket() error = %v", flow, err)
		case <-ticker.C:
			send()
		}
	}
	t.Fatalf("timed out waiting for %s packet delivery", flow)
}

func relayPeerCountersEqual(left, right *PeerStatus) bool {
	if left == nil || right == nil {
		return false
	}
	return left.TxBytes == right.TxBytes &&
		left.RxBytes == right.RxBytes &&
		left.TransportTxBytes == right.TransportTxBytes &&
		left.TransportRxBytes == right.TransportRxBytes &&
		left.TransportTxPackets == right.TransportTxPackets &&
		left.TransportRxPackets == right.TransportRxPackets &&
		left.LastHandshake.Equal(right.LastHandshake)
}

func drainCapturedPackets(capture *memoryPacketCapture) {
	if capture == nil {
		return
	}
	for {
		select {
		case <-capture.packets:
		default:
			return
		}
	}
}

func dumpRelayWGGoTestDiagnostics(t *testing.T, relayAddr string, engines ...*engine) {
	t.Helper()

	t.Logf("relay diagnostics: relay=%s", relayAddr)
	for _, eng := range engines {
		if eng == nil {
			continue
		}
		status := eng.Status()
		t.Logf("relay diagnostics: node=%s engine_status=%+v client_peers=%s", eng.cfg.Node.Name, status, formatClientPeerDiagnostics(eng.GetPeers()))
		if eng.tun != nil {
			t.Logf("relay diagnostics: node=%s tunnel_peers=%s", eng.cfg.Node.Name, formatTunnelPeerDiagnostics(eng.tun.GetPeers()))
		}
		state, err := LoadRuntimeState(eng.statePath)
		if err != nil {
			t.Logf("relay diagnostics: node=%s runtime_state_error=%v", eng.cfg.Node.Name, err)
			continue
		}
		t.Logf("relay diagnostics: node=%s runtime_state=%+v", eng.cfg.Node.Name, state)
	}
}

func formatClientPeerDiagnostics(peers []*PeerStatus) string {
	if len(peers) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer == nil {
			parts = append(parts, "<nil>")
			continue
		}
		parts = append(parts, fmt.Sprintf("{name=%s state=%s conn=%s endpoint=%s handshake=%s ice=%s local=%s remote=%s tx=%d/%d rx=%d/%d xerr=%q}",
			peer.Name,
			peer.State,
			peer.ConnectionType,
			formatUDPAddr(peer.Endpoint),
			formatHandshake(peer.LastHandshake),
			peer.ICEState,
			peer.LocalCandidate,
			peer.RemoteCandidate,
			peer.TxBytes,
			peer.TransportTxBytes,
			peer.RxBytes,
			peer.TransportRxBytes,
			peer.TransportLastError,
		))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func formatTunnelPeerDiagnostics(peers []*tunnel.PeerStatus) string {
	if len(peers) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(peers))
	for _, peer := range peers {
		if peer == nil {
			parts = append(parts, "<nil>")
			continue
		}
		allowedIPs := make([]string, 0, len(peer.AllowedIPs))
		for _, ipn := range peer.AllowedIPs {
			allowedIPs = append(allowedIPs, ipn.String())
		}
		parts = append(parts, fmt.Sprintf("{pub=%s endpoint=%s handshake=%s allowed=%v tx=%d/%d rx=%d/%d xerr=%q}",
			peer.PublicKey.String(),
			formatUDPAddr(peer.Endpoint),
			formatHandshake(peer.LastHandshake),
			allowedIPs,
			peer.TxBytes,
			peer.TransportTxBytes,
			peer.RxBytes,
			peer.TransportRxBytes,
			peer.TransportLastError,
		))
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func formatHandshake(ts time.Time) string {
	if ts.IsZero() {
		return "-"
	}
	return ts.Format(time.RFC3339Nano)
}

func formatUDPAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return "-"
	}
	return addr.String()
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
