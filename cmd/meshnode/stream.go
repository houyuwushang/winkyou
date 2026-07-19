package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/mesh"
)

const (
	bootstrapProtocol = "wink-mesh-bootstrap/1"
	maxBootstrapHello = 4096
)

type bootstrapHello struct {
	Protocol string `json:"protocol"`
	NodeID   string `json:"node_id"`
}

func exchangeBootstrapHello(conn net.Conn, localID, expectedPeer string, timeout time.Duration) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("bootstrap connection is required")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	defer conn.SetDeadline(time.Time{})

	raw, err := json.Marshal(bootstrapHello{Protocol: bootstrapProtocol, NodeID: strings.TrimSpace(localID)})
	if err != nil {
		return "", err
	}
	if len(raw) == 0 || len(raw) > maxBootstrapHello {
		return "", fmt.Errorf("bootstrap hello has invalid length %d", len(raw))
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(raw)))
	if err := writeAll(conn, header); err != nil {
		return "", fmt.Errorf("write bootstrap hello header: %w", err)
	}
	if err := writeAll(conn, raw); err != nil {
		return "", fmt.Errorf("write bootstrap hello: %w", err)
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read bootstrap hello header: %w", err)
	}
	length := int(binary.BigEndian.Uint32(header))
	if length <= 0 || length > maxBootstrapHello {
		return "", fmt.Errorf("remote bootstrap hello has invalid length %d", length)
	}
	remoteRaw := make([]byte, length)
	if _, err := io.ReadFull(conn, remoteRaw); err != nil {
		return "", fmt.Errorf("read bootstrap hello: %w", err)
	}
	var remote bootstrapHello
	if err := json.Unmarshal(remoteRaw, &remote); err != nil {
		return "", fmt.Errorf("decode bootstrap hello: %w", err)
	}
	remote.NodeID = strings.TrimSpace(remote.NodeID)
	if remote.Protocol != bootstrapProtocol || remote.NodeID == "" || remote.NodeID == localID {
		return "", fmt.Errorf("invalid bootstrap peer protocol=%q node_id=%q", remote.Protocol, remote.NodeID)
	}
	if expectedPeer = strings.TrimSpace(expectedPeer); expectedPeer != "" && remote.NodeID != expectedPeer {
		return "", fmt.Errorf("bootstrap peer identity %q does not match expected %q", remote.NodeID, expectedPeer)
	}
	return remote.NodeID, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

type bootstrapServer struct {
	node      *mesh.Node
	listener  net.Listener
	timeout   time.Duration
	log       *eventLog
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func startBootstrapServer(parent context.Context, node *mesh.Node, address string, timeout time.Duration, log *eventLog) (*bootstrapServer, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	server := &bootstrapServer{node: node, listener: listener, timeout: timeout, log: log, ctx: ctx, cancel: cancel}
	server.wg.Add(1)
	go server.acceptLoop()
	return server, nil
}

func (s *bootstrapServer) Addr() string {
	if s == nil || s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *bootstrapServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.ctx.Err() == nil {
				s.log.write("bootstrap_accept_failed", map[string]any{"error": err.Error()})
			}
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			peerID, helloErr := exchangeBootstrapHello(conn, s.node.NodeID(), "", s.timeout)
			if helloErr != nil {
				_ = conn.Close()
				s.log.write("bootstrap_handshake_failed", map[string]any{"remote": conn.RemoteAddr().String(), "error": helloErr.Error()})
				return
			}
			if err := s.node.AttachStream(peerID, conn); err != nil {
				_ = conn.Close()
				s.log.write("bootstrap_attach_failed", map[string]any{"peer_id": peerID, "error": err.Error()})
				return
			}
			s.log.write("bootstrap_inbound_attached", map[string]any{"peer_id": peerID, "remote": conn.RemoteAddr().String()})
		}()
	}
}

func (s *bootstrapServer) Close() error {
	if s == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		s.cancel()
		closeErr = s.listener.Close()
		s.wg.Wait()
	})
	return closeErr
}

type desiredPeer struct {
	id      string
	address string
	cancel  context.CancelFunc

	mu     sync.Mutex
	active net.Conn
}

func (p *desiredPeer) setActive(conn net.Conn) {
	p.mu.Lock()
	p.active = conn
	p.mu.Unlock()
}

func (p *desiredPeer) clearActive(conn net.Conn) {
	p.mu.Lock()
	if p.active == conn {
		p.active = nil
	}
	p.mu.Unlock()
}

func (p *desiredPeer) closeActive() {
	p.mu.Lock()
	conn := p.active
	p.active = nil
	p.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

type bootstrapConnectors struct {
	node    *mesh.Node
	log     *eventLog
	retry   time.Duration
	timeout time.Duration
	ctx     context.Context
	cancel  context.CancelFunc

	mu    sync.Mutex
	peers map[string]*desiredPeer
	wg    sync.WaitGroup
}

func newBootstrapConnectors(parent context.Context, node *mesh.Node, retry, timeout time.Duration, log *eventLog) *bootstrapConnectors {
	if retry <= 0 {
		retry = time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	return &bootstrapConnectors{
		node: node, log: log, retry: retry, timeout: timeout,
		ctx: ctx, cancel: cancel, peers: make(map[string]*desiredPeer),
	}
}

func (c *bootstrapConnectors) Add(peerID, address string) error {
	peerID = strings.TrimSpace(peerID)
	address = strings.TrimSpace(address)
	if peerID == "" || peerID == c.node.NodeID() || address == "" {
		return fmt.Errorf("bootstrap peer requires a distinct node ID and address")
	}
	c.mu.Lock()
	if existing := c.peers[peerID]; existing != nil {
		if existing.address == address {
			c.mu.Unlock()
			return nil
		}
		delete(c.peers, peerID)
		existing.cancel()
		existing.closeActive()
	}
	peerCtx, cancel := context.WithCancel(c.ctx)
	peer := &desiredPeer{id: peerID, address: address, cancel: cancel}
	c.peers[peerID] = peer
	c.wg.Add(1)
	c.mu.Unlock()
	go c.runPeer(peerCtx, peer)
	c.log.write("bootstrap_peer_desired", map[string]any{"peer_id": peerID, "address": address})
	return nil
}

func (c *bootstrapConnectors) Remove(peerID string) bool {
	peerID = strings.TrimSpace(peerID)
	c.mu.Lock()
	peer := c.peers[peerID]
	if peer != nil {
		delete(c.peers, peerID)
	}
	c.mu.Unlock()
	if peer == nil {
		return false
	}
	peer.cancel()
	peer.closeActive()
	c.log.write("bootstrap_peer_removed", map[string]any{"peer_id": peerID})
	return true
}

func (c *bootstrapConnectors) Snapshot() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string]string, len(c.peers))
	for peerID, peer := range c.peers {
		result[peerID] = peer.address
	}
	return result
}

func (c *bootstrapConnectors) runPeer(ctx context.Context, peer *desiredPeer) {
	defer c.wg.Done()
	ticker := time.NewTicker(c.retry)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		// A desired bootstrap is a seed of last resort, not a competing direct
		// edge. If the graph already reaches the peer through another neighbor,
		// leave the peer slot free for protected-direct recovery.
		_, routed := c.node.Route(peer.id)
		if !c.node.HasNeighbor(peer.id) && !routed {
			dialer := net.Dialer{Timeout: c.timeout}
			conn, err := dialer.DialContext(ctx, "tcp", peer.address)
			if err == nil {
				_, err = exchangeBootstrapHello(conn, c.node.NodeID(), peer.id, c.timeout)
			}
			if err == nil {
				err = c.node.AttachStream(peer.id, conn)
			}
			if err != nil {
				if conn != nil {
					_ = conn.Close()
				}
				if ctx.Err() == nil {
					c.log.write("bootstrap_dial_failed", map[string]any{"peer_id": peer.id, "address": peer.address, "error": err.Error()})
				}
			} else {
				peer.setActive(conn)
				c.log.write("bootstrap_outbound_attached", map[string]any{"peer_id": peer.id, "address": peer.address, "local": conn.LocalAddr().String()})
			}
		}
		select {
		case <-ctx.Done():
			peer.closeActive()
			return
		case <-ticker.C:
			if !c.node.HasNeighbor(peer.id) {
				peer.mu.Lock()
				old := peer.active
				peer.mu.Unlock()
				if old != nil {
					peer.clearActive(old)
					_ = old.Close()
				}
			}
		}
	}
}

func (c *bootstrapConnectors) Close() {
	if c == nil {
		return
	}
	c.cancel()
	c.mu.Lock()
	peers := make([]*desiredPeer, 0, len(c.peers))
	for _, peer := range c.peers {
		peers = append(peers, peer)
	}
	c.peers = make(map[string]*desiredPeer)
	c.mu.Unlock()
	for _, peer := range peers {
		peer.cancel()
		peer.closeActive()
	}
	c.wg.Wait()
}

func parsePeerSpec(spec string) (string, string, error) {
	peerID, address, ok := strings.Cut(strings.TrimSpace(spec), "=")
	peerID = strings.TrimSpace(peerID)
	address = strings.TrimSpace(address)
	if !ok || peerID == "" || address == "" {
		return "", "", fmt.Errorf("peer %q must be NODE_ID=HOST:PORT", spec)
	}
	return peerID, address, nil
}

func sortedPeerIDs(peers map[string]string) []string {
	ids := make([]string, 0, len(peers))
	for id := range peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
