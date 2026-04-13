package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type wggoTunnel struct {
	cfg     Config
	adapter *netifAdapter
	events  chan TunnelEvent

	mu         sync.RWMutex
	started    bool
	stopped    bool
	listenPort int
	peers      map[PublicKey]*PeerStatus

	runCmd commandRunner
	now    func() time.Time
}

type netifAdapter struct {
	ifaceName string
	mtu       int
	ni        interface {
		Name() string
		MTU() int
		Read([]byte) (int, error)
		Write([]byte) (int, error)
	}
}

func newNetifAdapter(ni interface {
	Name() string
	MTU() int
	Read([]byte) (int, error)
	Write([]byte) (int, error)
}) *netifAdapter {
	if ni == nil {
		return nil
	}
	return &netifAdapter{ifaceName: ni.Name(), mtu: ni.MTU(), ni: ni}
}

func newWGGoTunnel(cfg Config) *wggoTunnel {
	return &wggoTunnel{
		cfg:     cfg,
		adapter: newNetifAdapter(cfg.Interface),
		events:  make(chan TunnelEvent, 64),
		peers:   make(map[PublicKey]*PeerStatus),
		runCmd:  defaultCommandRunner,
		now:     time.Now,
	}
}

func (w *wggoTunnel) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.started {
		return errors.New("tunnel: already started")
	}
	if w.cfg.Interface == nil {
		return errors.New("tunnel: interface is nil")
	}
	if w.cfg.PrivateKey == (PrivateKey{}) {
		return errors.New("tunnel: private key is empty")
	}

	listenPort, err := chooseListenPort(w.cfg.ListenPort)
	if err != nil {
		return err
	}
	if err := w.configureBaseLocked(listenPort); err != nil {
		return err
	}

	w.listenPort = listenPort
	w.started = true
	w.stopped = false
	return nil
}

func (w *wggoTunnel) Stop() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.started = false
	w.stopped = true
	return nil
}

func (w *wggoTunnel) AddPeer(peer *PeerConfig) error {
	if peer == nil {
		return errors.New("tunnel: peer config is nil")
	}
	if peer.PublicKey == (PublicKey{}) {
		return errors.New("tunnel: peer public key is empty")
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.peers[peer.PublicKey]; exists {
		return fmt.Errorf("tunnel: peer %s already exists", peer.PublicKey)
	}
	if err := w.configurePeerLocked(peer, false); err != nil {
		return err
	}

	w.peers[peer.PublicKey] = peerConfigToStatus(peer)
	w.emitLocked(TunnelEvent{Type: EventPeerAdded, PeerKey: peer.PublicKey, Timestamp: w.now()})
	return nil
}

func (w *wggoTunnel) RemovePeer(publicKey PublicKey) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if _, exists := w.peers[publicKey]; !exists {
		return fmt.Errorf("tunnel: peer %s not found", publicKey)
	}
	if err := w.runWGLocked("set", w.cfg.Interface.Name(), "peer", publicKey.String(), "remove"); err != nil {
		return err
	}
	delete(w.peers, publicKey)
	w.emitLocked(TunnelEvent{Type: EventPeerRemoved, PeerKey: publicKey, Timestamp: w.now()})
	return nil
}

func (w *wggoTunnel) UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	ps, exists := w.peers[publicKey]
	if !exists {
		return fmt.Errorf("tunnel: peer %s not found", publicKey)
	}

	endpointArg := "0.0.0.0:0"
	if endpoint != nil {
		endpointArg = endpoint.String()
	}
	if err := w.runWGLocked("set", w.cfg.Interface.Name(), "peer", publicKey.String(), "endpoint", endpointArg); err != nil {
		return err
	}

	if endpoint != nil {
		ps.Endpoint = &net.UDPAddr{IP: append(net.IP(nil), endpoint.IP...), Port: endpoint.Port, Zone: endpoint.Zone}
	} else {
		ps.Endpoint = nil
	}
	w.emitLocked(TunnelEvent{Type: EventPeerEndpointChanged, PeerKey: publicKey, Timestamp: w.now()})
	return nil
}

func (w *wggoTunnel) GetPeers() []*PeerStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refreshPeerStatsLocked()

	result := make([]*PeerStatus, 0, len(w.peers))
	for _, ps := range w.peers {
		result = append(result, clonePeerStatus(ps))
	}
	sort.Slice(result, func(i, j int) bool {
		ki := result[i].PublicKey
		kj := result[j].PublicKey
		for b := 0; b < len(ki); b++ {
			if ki[b] != kj[b] {
				return ki[b] < kj[b]
			}
		}
		return false
	})
	return result
}

func (w *wggoTunnel) GetStats() *TunnelStats {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refreshPeerStatsLocked()

	stats := &TunnelStats{Peers: len(w.peers)}
	for _, ps := range w.peers {
		stats.TxBytes += ps.TxBytes
		stats.RxBytes += ps.RxBytes
	}
	return stats
}

func (w *wggoTunnel) Events() <-chan TunnelEvent { return w.events }

func (w *wggoTunnel) emitLocked(ev TunnelEvent) {
	select {
	case w.events <- ev:
	default:
		select {
		case <-w.events:
		default:
		}
		select {
		case w.events <- ev:
		default:
		}
	}
}

func (w *wggoTunnel) configureBaseLocked(listenPort int) error {
	keyFile, err := writeSecretFile(w.cfg.PrivateKey.String())
	if err != nil {
		return err
	}
	defer os.Remove(keyFile)

	args := []string{"set", w.cfg.Interface.Name(), "private-key", keyFile, "listen-port", strconv.Itoa(listenPort)}
	return w.runWGLocked(args...)
}

func (w *wggoTunnel) configurePeerLocked(peer *PeerConfig, replaceAllowed bool) error {
	args := []string{"set", w.cfg.Interface.Name(), "peer", peer.PublicKey.String()}

	if peer.PresharedKey != nil {
		pskFile, err := writeSecretFile(peer.PresharedKey.String())
		if err != nil {
			return err
		}
		defer os.Remove(pskFile)
		args = append(args, "preshared-key", pskFile)
	}
	if replaceAllowed {
		args = append(args, "replace-allowed-ips", "true")
	}
	if len(peer.AllowedIPs) > 0 {
		allowed := make([]string, 0, len(peer.AllowedIPs))
		for _, ipn := range peer.AllowedIPs {
			allowed = append(allowed, ipn.String())
		}
		args = append(args, "allowed-ips", strings.Join(allowed, ","))
	}
	if peer.Endpoint != nil {
		args = append(args, "endpoint", peer.Endpoint.String())
	}
	if peer.Keepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(int(peer.Keepalive/time.Second)))
	}

	return w.runWGLocked(args...)
}

func (w *wggoTunnel) runWGLocked(args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := w.runCmd(ctx, "wg", args...)
	if err != nil {
		return fmt.Errorf("tunnel: wg %s: %w", strings.Join(args, " "), withOutput(err, out))
	}
	return nil
}

func (w *wggoTunnel) refreshPeerStatsLocked() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	out, err := w.runCmd(ctx, "wg", "show", w.cfg.Interface.Name(), "dump")
	if err != nil {
		return
	}

	parsed, err := parseWGDump(out)
	if err != nil {
		return
	}

	for key, snap := range parsed {
		cur, ok := w.peers[key]
		if !ok {
			continue
		}
		prevHandshake := cur.LastHandshake
		cur.LastHandshake = snap.LastHandshake
		cur.RxBytes = snap.RxBytes
		cur.TxBytes = snap.TxBytes
		if snap.Endpoint != nil {
			cur.Endpoint = snap.Endpoint
		}
		if !snap.LastHandshake.IsZero() && snap.LastHandshake.After(prevHandshake) {
			w.emitLocked(TunnelEvent{Type: EventPeerHandshake, PeerKey: key, Timestamp: w.now()})
		}
	}
}

func chooseListenPort(port int) (int, error) {
	if port > 0 {
		return port, nil
	}
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, fmt.Errorf("tunnel: allocate listen port: %w", err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port, nil
}

func writeSecretFile(content string) (string, error) {
	f, err := os.CreateTemp("", "winkyou-wg-key-*")
	if err != nil {
		return "", fmt.Errorf("tunnel: create temp key file: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("tunnel: write temp key file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("tunnel: close temp key file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("tunnel: chmod temp key file: %w", err)
	}
	return path, nil
}

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return out, err
}

func withOutput(err error, out []byte) error {
	if len(out) == 0 {
		return err
	}
	return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
}

func peerConfigToStatus(peer *PeerConfig) *PeerStatus {
	ps := &PeerStatus{PublicKey: peer.PublicKey}
	if peer.Endpoint != nil {
		ps.Endpoint = &net.UDPAddr{IP: append(net.IP(nil), peer.Endpoint.IP...), Port: peer.Endpoint.Port, Zone: peer.Endpoint.Zone}
	}
	for _, ipn := range peer.AllowedIPs {
		cp := net.IPNet{IP: append(net.IP(nil), ipn.IP...), Mask: append(net.IPMask(nil), ipn.Mask...)}
		ps.AllowedIPs = append(ps.AllowedIPs, cp)
	}
	return ps
}

func parseWGDump(out []byte) (map[PublicKey]*PeerStatus, error) {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	result := make(map[PublicKey]*PeerStatus)
	if len(lines) <= 1 {
		return result, nil
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		key, err := ParsePublicKey(fields[0])
		if err != nil {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rxBytes, _ := strconv.ParseUint(fields[5], 10, 64)
		txBytes, _ := strconv.ParseUint(fields[6], 10, 64)

		ps := &PeerStatus{PublicKey: key, RxBytes: rxBytes, TxBytes: txBytes}
		if handshake > 0 {
			ps.LastHandshake = time.Unix(handshake, 0)
		}
		if fields[2] != "(none)" && fields[2] != "" {
			if ep, err := net.ResolveUDPAddr("udp", fields[2]); err == nil {
				ps.Endpoint = ep
			}
		}
		if fields[3] != "(none)" && fields[3] != "" {
			parts := strings.Split(fields[3], ",")
			for _, cidr := range parts {
				cidr = strings.TrimSpace(cidr)
				if cidr == "" {
					continue
				}
				if _, ipn, err := net.ParseCIDR(cidr); err == nil {
					ps.AllowedIPs = append(ps.AllowedIPs, *ipn)
				}
			}
		}

		result[key] = ps
	}
	return result, nil
}

func allowMemoryTunnelForTest() bool {
	if os.Getenv("WINKYOU_TUNNEL_FORCE_WGGO") == "1" {
		return false
	}
	if os.Getenv("WINKYOU_TUNNEL_ALLOW_MEMORY") == "1" {
		return true
	}
	return strings.HasSuffix(os.Args[0], ".test")
}
