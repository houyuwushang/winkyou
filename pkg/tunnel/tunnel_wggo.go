package tunnel

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	wgconn "golang.zx2c4.com/wireguard/conn"
	wgdevice "golang.zx2c4.com/wireguard/device"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const (
	transportEndpointPrefix = "transport:"
	statsRefreshInterval    = 500 * time.Millisecond
	readPollInterval        = 200 * time.Millisecond
)

type wggoTunnel struct {
	cfg    Config
	events chan TunnelEvent

	mu         sync.RWMutex
	started    bool
	stopped    bool
	listenPort int
	peers      map[PublicKey]*PeerStatus

	device    *wgdevice.Device
	tunDevice *netifDevice
	bind      *peerTransportBind
	closeCh   chan struct{}
	wg        sync.WaitGroup

	now func() time.Time
}

func newWGGoTunnel(cfg Config) *wggoTunnel {
	return &wggoTunnel{
		cfg:    cfg,
		events: make(chan TunnelEvent, 64),
		peers:  make(map[PublicKey]*PeerStatus),
		now:    time.Now,
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

	w.tunDevice = newNetifDevice(w.cfg.Interface)
	w.bind = newPeerTransportBind()
	w.device = wgdevice.NewDevice(w.tunDevice, w.bind, wgdevice.NewLogger(wgdevice.LogLevelSilent, "winkyou"))

	if err := w.device.IpcSet(buildDeviceIPC(w.cfg.PrivateKey, w.cfg.ListenPort)); err != nil {
		w.device.Close()
		w.device = nil
		w.bind = nil
		w.tunDevice = nil
		return fmt.Errorf("tunnel: configure device: %w", err)
	}
	if err := w.device.Up(); err != nil {
		w.device.Close()
		w.device = nil
		w.bind = nil
		w.tunDevice = nil
		return fmt.Errorf("tunnel: bring device up: %w", err)
	}

	w.started = true
	w.stopped = false
	w.closeCh = make(chan struct{})
	w.refreshPeerStatsLocked()
	w.wg.Add(1)
	go w.statsLoop()
	return nil
}

func (w *wggoTunnel) Stop() error {
	w.mu.Lock()
	if !w.started && w.stopped {
		w.mu.Unlock()
		return nil
	}
	closeCh := w.closeCh
	device := w.device
	w.started = false
	w.stopped = true
	w.closeCh = nil
	w.mu.Unlock()

	if closeCh != nil {
		close(closeCh)
	}
	if device != nil {
		device.Close()
	}
	w.wg.Wait()

	w.mu.Lock()
	w.device = nil
	w.bind = nil
	w.tunDevice = nil
	w.mu.Unlock()
	return nil
}

func (w *wggoTunnel) AddPeer(peer *PeerConfig) error {
	if peer == nil {
		return errors.New("tunnel: peer config is nil")
	}
	if peer.PublicKey == (PublicKey{}) {
		return errors.New("tunnel: peer public key is empty")
	}

	w.mu.RLock()
	if !w.started || w.device == nil || w.bind == nil {
		w.mu.RUnlock()
		return errors.New("tunnel: not started")
	}
	if _, exists := w.peers[peer.PublicKey]; exists {
		w.mu.RUnlock()
		return fmt.Errorf("tunnel: peer %s already exists", peer.PublicKey)
	}
	device := w.device
	bind := w.bind
	w.mu.RUnlock()

	endpointArg := ""
	if peer.Transport != nil {
		var err error
		endpointArg, err = bind.AttachTransport(peer.PublicKey, peer.Transport)
		if err != nil {
			return err
		}
	} else if peer.Endpoint != nil {
		endpointArg = peer.Endpoint.String()
	}

	if err := device.IpcSet(buildPeerIPC(peer, endpointArg)); err != nil {
		if peer.Transport != nil {
			bind.DetachTransport(peer.PublicKey)
		}
		return fmt.Errorf("tunnel: configure peer %s: %w", peer.PublicKey, err)
	}

	status := peerConfigToStatus(peer)
	if peer.Transport != nil {
		status.Endpoint = bind.TransportRemoteAddr(peer.PublicKey)
	}

	w.mu.Lock()
	w.peers[peer.PublicKey] = status
	w.emitLocked(TunnelEvent{Type: EventPeerAdded, PeerKey: peer.PublicKey, Timestamp: w.now()})
	w.mu.Unlock()
	return nil
}

func (w *wggoTunnel) RemovePeer(publicKey PublicKey) error {
	w.mu.RLock()
	if !w.started || w.device == nil || w.bind == nil {
		w.mu.RUnlock()
		return errors.New("tunnel: not started")
	}
	if _, exists := w.peers[publicKey]; !exists {
		w.mu.RUnlock()
		return fmt.Errorf("tunnel: peer %s not found", publicKey)
	}
	device := w.device
	bind := w.bind
	w.mu.RUnlock()

	if err := device.IpcSet(buildRemovePeerIPC(publicKey)); err != nil {
		return fmt.Errorf("tunnel: remove peer %s: %w", publicKey, err)
	}
	bind.DetachTransport(publicKey)

	w.mu.Lock()
	delete(w.peers, publicKey)
	w.emitLocked(TunnelEvent{Type: EventPeerRemoved, PeerKey: publicKey, Timestamp: w.now()})
	w.mu.Unlock()
	return nil
}

func (w *wggoTunnel) UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error {
	w.mu.RLock()
	if !w.started || w.device == nil || w.bind == nil {
		w.mu.RUnlock()
		return errors.New("tunnel: not started")
	}
	ps, exists := w.peers[publicKey]
	if !exists {
		w.mu.RUnlock()
		return fmt.Errorf("tunnel: peer %s not found", publicKey)
	}
	device := w.device
	bind := w.bind
	hasTransport := bind.HasTransport(publicKey)
	w.mu.RUnlock()

	if hasTransport {
		bind.UpdateTransportEndpoint(publicKey, endpoint)
	} else {
		endpointArg := "0.0.0.0:0"
		if endpoint != nil {
			endpointArg = endpoint.String()
		}
		if err := device.IpcSet(buildUpdateEndpointIPC(publicKey, endpointArg)); err != nil {
			return fmt.Errorf("tunnel: update endpoint for %s: %w", publicKey, err)
		}
	}

	w.mu.Lock()
	if endpoint != nil {
		ps.Endpoint = cloneUDPAddr(endpoint)
	} else {
		ps.Endpoint = nil
	}
	w.emitLocked(TunnelEvent{Type: EventPeerEndpointChanged, PeerKey: publicKey, Timestamp: w.now()})
	w.mu.Unlock()
	return nil
}

func (w *wggoTunnel) GetPeers() []*PeerStatus {
	w.refreshPeerStats()

	w.mu.RLock()
	defer w.mu.RUnlock()
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
	w.refreshPeerStats()

	w.mu.RLock()
	defer w.mu.RUnlock()
	stats := &TunnelStats{Peers: len(w.peers)}
	for _, ps := range w.peers {
		stats.TxBytes += ps.TxBytes
		stats.RxBytes += ps.RxBytes
	}
	return stats
}

func (w *wggoTunnel) Events() <-chan TunnelEvent { return w.events }

func (w *wggoTunnel) statsLoop() {
	defer w.wg.Done()
	ticker := time.NewTicker(statsRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			w.refreshPeerStats()
		case <-w.closeCh:
			return
		}
	}
}

func (w *wggoTunnel) refreshPeerStats() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.refreshPeerStatsLocked()
}

func (w *wggoTunnel) refreshPeerStatsLocked() {
	if w.device == nil || w.bind == nil {
		return
	}

	snapshot, err := readDeviceSnapshot(w.device, w.bind)
	if err != nil {
		return
	}
	if snapshot.ListenPort != 0 {
		w.listenPort = snapshot.ListenPort
	}
	for key, snap := range snapshot.Peers {
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
		if len(snap.AllowedIPs) > 0 {
			cur.AllowedIPs = snap.AllowedIPs
		}
		if !snap.LastHandshake.IsZero() && snap.LastHandshake.After(prevHandshake) {
			w.emitLocked(TunnelEvent{Type: EventPeerHandshake, PeerKey: key, Timestamp: w.now()})
		}
	}
}

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

type netifDevice struct {
	ni interface {
		Name() string
		MTU() int
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		Close() error
	}
	events    chan wgtun.Event
	closeOnce sync.Once
}

func newNetifDevice(ni interface {
	Name() string
	MTU() int
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}) *netifDevice {
	d := &netifDevice{
		ni:     ni,
		events: make(chan wgtun.Event, 2),
	}
	d.events <- wgtun.EventUp
	d.events <- wgtun.EventMTUUpdate
	return d
}

func (d *netifDevice) File() *os.File { return nil }

func (d *netifDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	if offset > len(bufs[0]) {
		return 0, fmt.Errorf("tunnel: invalid tun read offset %d", offset)
	}
	n, err := d.ni.Read(bufs[0][offset:])
	if n > 0 {
		sizes[0] = n
		return 1, nil
	}
	return 0, err
}

func (d *netifDevice) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if offset > len(buf) {
			continue
		}
		if _, err := d.ni.Write(buf[offset:]); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func (d *netifDevice) MTU() (int, error) { return d.ni.MTU(), nil }

func (d *netifDevice) Name() (string, error) { return d.ni.Name(), nil }

func (d *netifDevice) Events() <-chan wgtun.Event { return d.events }

func (d *netifDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.ni.Close()
		close(d.events)
	})
	return err
}

func (d *netifDevice) BatchSize() int { return 1 }

type transportPacket struct {
	data     []byte
	endpoint *transportEndpoint
}

type peerTransportBind struct {
	mu         sync.RWMutex
	base       wgconn.Bind
	closeOnce  sync.Once
	closeCh    chan struct{}
	recvCh     chan transportPacket
	transports map[PublicKey]*boundTransport
}

type boundTransport struct {
	conn      net.Conn
	endpoint  *transportEndpoint
	stopCh    chan struct{}
	closeOnce sync.Once
}

type transportEndpoint struct {
	key PublicKey

	mu         sync.RWMutex
	id         string
	remoteAddr *net.UDPAddr
	localAddr  *net.UDPAddr
}

func newPeerTransportBind() *peerTransportBind {
	return &peerTransportBind{
		base:       wgconn.NewDefaultBind(),
		closeCh:    make(chan struct{}),
		recvCh:     make(chan transportPacket, 1024),
		transports: make(map[PublicKey]*boundTransport),
	}
}

func (b *peerTransportBind) Open(port uint16) ([]wgconn.ReceiveFunc, uint16, error) {
	baseFns, actualPort, err := b.base.Open(port)
	if err != nil {
		return nil, 0, err
	}
	fns := make([]wgconn.ReceiveFunc, 0, len(baseFns)+1)
	fns = append(fns, b.receiveFromTransports)
	fns = append(fns, baseFns...)
	return fns, actualPort, nil
}

func (b *peerTransportBind) Close() error {
	var err error
	b.closeOnce.Do(func() {
		close(b.closeCh)
		b.mu.Lock()
		for _, transport := range b.transports {
			_ = transport.Close()
		}
		b.transports = map[PublicKey]*boundTransport{}
		b.mu.Unlock()
		err = b.base.Close()
	})
	return err
}

func (b *peerTransportBind) SetMark(mark uint32) error {
	return b.base.SetMark(mark)
}

func (b *peerTransportBind) Send(bufs [][]byte, ep wgconn.Endpoint) error {
	transportEndpoint, ok := ep.(*transportEndpoint)
	if !ok {
		return b.base.Send(bufs, ep)
	}

	b.mu.RLock()
	transport := b.transports[transportEndpoint.key]
	b.mu.RUnlock()
	if transport == nil {
		return fmt.Errorf("tunnel: no transport for peer %s", transportEndpoint.key)
	}

	for _, buf := range bufs {
		if len(buf) == 0 {
			continue
		}
		if _, err := transport.conn.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *peerTransportBind) ParseEndpoint(s string) (wgconn.Endpoint, error) {
	if strings.HasPrefix(s, transportEndpointPrefix) {
		key, err := parseHexPublicKey(strings.TrimPrefix(s, transportEndpointPrefix))
		if err != nil {
			return nil, err
		}
		b.mu.RLock()
		transport := b.transports[key]
		b.mu.RUnlock()
		if transport == nil {
			return nil, fmt.Errorf("tunnel: unknown transport endpoint %q", s)
		}
		return transport.endpoint, nil
	}
	return b.base.ParseEndpoint(s)
}

func (b *peerTransportBind) BatchSize() int {
	baseSize := b.base.BatchSize()
	if baseSize < 1 {
		return 1
	}
	return baseSize
}

func (b *peerTransportBind) AttachTransport(publicKey PublicKey, transport net.Conn) (string, error) {
	if transport == nil {
		return "", fmt.Errorf("tunnel: peer transport is nil")
	}

	remoteAddr := udpAddrFromNetAddr(transport.RemoteAddr())
	localAddr := udpAddrFromNetAddr(transport.LocalAddr())
	endpoint := &transportEndpoint{
		key:        publicKey,
		id:         transportEndpointID(publicKey),
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}
	bound := &boundTransport{
		conn:     transport,
		endpoint: endpoint,
		stopCh:   make(chan struct{}),
	}

	b.mu.Lock()
	if existing := b.transports[publicKey]; existing != nil {
		_ = existing.Close()
	}
	b.transports[publicKey] = bound
	b.mu.Unlock()

	go b.readTransportLoop(bound)
	return endpoint.id, nil
}

func (b *peerTransportBind) DetachTransport(publicKey PublicKey) {
	b.mu.Lock()
	transport := b.transports[publicKey]
	delete(b.transports, publicKey)
	b.mu.Unlock()
	if transport != nil {
		_ = transport.Close()
	}
}

func (b *peerTransportBind) HasTransport(publicKey PublicKey) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.transports[publicKey] != nil
}

func (b *peerTransportBind) UpdateTransportEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) {
	b.mu.RLock()
	transport := b.transports[publicKey]
	b.mu.RUnlock()
	if transport == nil {
		return
	}
	transport.endpoint.SetRemoteAddr(endpoint)
}

func (b *peerTransportBind) TransportRemoteAddr(publicKey PublicKey) *net.UDPAddr {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if transport := b.transports[publicKey]; transport != nil {
		return transport.endpoint.RemoteAddr()
	}
	return nil
}

func (b *peerTransportBind) ResolveEndpoint(endpoint string) *net.UDPAddr {
	if !strings.HasPrefix(endpoint, transportEndpointPrefix) {
		addr, err := net.ResolveUDPAddr("udp", endpoint)
		if err != nil {
			return nil
		}
		return addr
	}
	key, err := parseHexPublicKey(strings.TrimPrefix(endpoint, transportEndpointPrefix))
	if err != nil {
		return nil
	}
	return b.TransportRemoteAddr(key)
}

func (b *peerTransportBind) readTransportLoop(transport *boundTransport) {
	buffer := make([]byte, 65535)
	for {
		_ = transport.conn.SetReadDeadline(time.Now().Add(readPollInterval))
		n, err := transport.conn.Read(buffer)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				select {
				case <-transport.stopCh:
					return
				case <-b.closeCh:
					return
				default:
					continue
				}
			}
			return
		}
		if n == 0 {
			continue
		}

		packet := transportPacket{
			data:     append([]byte(nil), buffer[:n]...),
			endpoint: transport.endpoint,
		}
		select {
		case b.recvCh <- packet:
		case <-transport.stopCh:
			return
		case <-b.closeCh:
			return
		}
	}
}

func (b *peerTransportBind) receiveFromTransports(packets [][]byte, sizes []int, eps []wgconn.Endpoint) (int, error) {
	if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
		return 0, nil
	}

	select {
	case <-b.closeCh:
		return 0, net.ErrClosed
	case packet := <-b.recvCh:
		n := copy(packets[0], packet.data)
		sizes[0] = n
		eps[0] = packet.endpoint
		count := 1
		for count < len(packets) {
			select {
			case packet := <-b.recvCh:
				n = copy(packets[count], packet.data)
				sizes[count] = n
				eps[count] = packet.endpoint
				count++
			default:
				return count, nil
			}
		}
		return count, nil
	}
}

func (e *transportEndpoint) ClearSrc() {}

func (e *transportEndpoint) SrcToString() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.localAddr == nil {
		return ""
	}
	return e.localAddr.String()
}

func (e *transportEndpoint) DstToString() string { return e.id }

func (e *transportEndpoint) DstToBytes() []byte {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.remoteAddr == nil {
		return []byte(e.id)
	}
	if addrPort, ok := udpAddrToAddrPort(e.remoteAddr); ok {
		b, _ := addrPort.MarshalBinary()
		return b
	}
	return []byte(e.id)
}

func (e *transportEndpoint) DstIP() netip.Addr {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.remoteAddr == nil {
		return netip.Addr{}
	}
	addr, _ := netip.AddrFromSlice(e.remoteAddr.IP)
	return addr
}

func (e *transportEndpoint) SrcIP() netip.Addr {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.localAddr == nil {
		return netip.Addr{}
	}
	addr, _ := netip.AddrFromSlice(e.localAddr.IP)
	return addr
}

func (e *transportEndpoint) RemoteAddr() *net.UDPAddr {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return cloneUDPAddr(e.remoteAddr)
}

func (e *transportEndpoint) SetRemoteAddr(addr *net.UDPAddr) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.remoteAddr = cloneUDPAddr(addr)
}

type deviceSnapshot struct {
	ListenPort int
	Peers      map[PublicKey]*PeerStatus
}

func (t *boundTransport) Close() error {
	if t == nil {
		return nil
	}

	var err error
	t.closeOnce.Do(func() {
		if t.stopCh != nil {
			close(t.stopCh)
		}
		if t.conn != nil {
			err = t.conn.Close()
		}
	})
	return err
}

func readDeviceSnapshot(device *wgdevice.Device, bind *peerTransportBind) (*deviceSnapshot, error) {
	dump, err := device.IpcGet()
	if err != nil {
		return nil, err
	}
	return parseDeviceSnapshot(dump, bind)
}

func parseDeviceSnapshot(dump string, bind *peerTransportBind) (*deviceSnapshot, error) {
	snapshot := &deviceSnapshot{Peers: make(map[PublicKey]*PeerStatus)}
	lines := strings.Split(strings.ReplaceAll(dump, "\r\n", "\n"), "\n")

	var current *PeerStatus
	var currentKey PublicKey
	flush := func() {
		if current != nil {
			snapshot.Peers[currentKey] = current
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}

		switch key {
		case "listen_port":
			port, _ := strconv.Atoi(value)
			snapshot.ListenPort = port
		case "public_key":
			flush()
			parsed, err := parseHexPublicKey(value)
			if err != nil {
				return nil, err
			}
			currentKey = parsed
			current = &PeerStatus{PublicKey: parsed}
		case "endpoint":
			if current != nil {
				current.Endpoint = bind.ResolveEndpoint(value)
			}
		case "last_handshake_time_sec":
			if current != nil {
				sec, _ := strconv.ParseInt(value, 10, 64)
				if sec > 0 {
					if current.LastHandshake.IsZero() {
						current.LastHandshake = time.Unix(sec, 0)
					} else {
						current.LastHandshake = time.Unix(sec, int64(current.LastHandshake.Nanosecond()))
					}
				}
			}
		case "last_handshake_time_nsec":
			if current != nil {
				nsec, _ := strconv.ParseInt(value, 10, 64)
				if !current.LastHandshake.IsZero() {
					current.LastHandshake = time.Unix(current.LastHandshake.Unix(), nsec)
				}
			}
		case "tx_bytes":
			if current != nil {
				current.TxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "rx_bytes":
			if current != nil {
				current.RxBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "allowed_ip":
			if current != nil {
				if _, ipn, err := net.ParseCIDR(value); err == nil {
					current.AllowedIPs = append(current.AllowedIPs, *ipn)
				}
			}
		}
	}
	flush()
	return snapshot, nil
}

func buildDeviceIPC(privateKey PrivateKey, listenPort int) string {
	return fmt.Sprintf("private_key=%s\nlisten_port=%d\n\n", encodeKeyHex(privateKey[:]), listenPort)
}

func buildPeerIPC(peer *PeerConfig, endpoint string) string {
	var builder strings.Builder
	builder.WriteString("public_key=")
	builder.WriteString(encodeKeyHex(peer.PublicKey[:]))
	builder.WriteByte('\n')
	if peer.PresharedKey != nil {
		builder.WriteString("preshared_key=")
		builder.WriteString(encodeKeyHex(peer.PresharedKey[:]))
		builder.WriteByte('\n')
	}
	builder.WriteString("replace_allowed_ips=true\n")
	for _, ipn := range peer.AllowedIPs {
		builder.WriteString("allowed_ip=")
		builder.WriteString(ipn.String())
		builder.WriteByte('\n')
	}
	if endpoint != "" {
		builder.WriteString("endpoint=")
		builder.WriteString(endpoint)
		builder.WriteByte('\n')
	}
	if peer.Keepalive > 0 {
		builder.WriteString("persistent_keepalive_interval=")
		builder.WriteString(strconv.Itoa(int(peer.Keepalive / time.Second)))
		builder.WriteByte('\n')
	}
	builder.WriteByte('\n')
	return builder.String()
}

func buildRemovePeerIPC(publicKey PublicKey) string {
	return fmt.Sprintf("public_key=%s\nremove=true\n\n", encodeKeyHex(publicKey[:]))
}

func buildUpdateEndpointIPC(publicKey PublicKey, endpoint string) string {
	return fmt.Sprintf("public_key=%s\nendpoint=%s\n\n", encodeKeyHex(publicKey[:]), endpoint)
}

func peerConfigToStatus(peer *PeerConfig) *PeerStatus {
	ps := &PeerStatus{PublicKey: peer.PublicKey}
	if peer.Endpoint != nil {
		ps.Endpoint = cloneUDPAddr(peer.Endpoint)
	}
	for _, ipn := range peer.AllowedIPs {
		cp := net.IPNet{IP: append(net.IP(nil), ipn.IP...), Mask: append(net.IPMask(nil), ipn.Mask...)}
		ps.AllowedIPs = append(ps.AllowedIPs, cp)
	}
	return ps
}

func encodeKeyHex(key []byte) string {
	return hex.EncodeToString(key)
}

func parseHexPublicKey(value string) (PublicKey, error) {
	var key PublicKey
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return key, fmt.Errorf("tunnel: parse hex public key: %w", err)
	}
	if len(decoded) != len(key) {
		return key, fmt.Errorf("tunnel: public key must be %d bytes", len(key))
	}
	copy(key[:], decoded)
	return key, nil
}

func transportEndpointID(publicKey PublicKey) string {
	return transportEndpointPrefix + encodeKeyHex(publicKey[:])
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func udpAddrFromNetAddr(addr net.Addr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return cloneUDPAddr(udpAddr)
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{IP: ip, Port: port}
}

func udpAddrToAddrPort(addr *net.UDPAddr) (netip.AddrPort, bool) {
	if addr == nil || addr.IP == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(ip, uint16(addr.Port)), true
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
