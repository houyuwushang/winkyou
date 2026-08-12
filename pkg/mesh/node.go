package mesh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/peercontrol"
	"winkyou/pkg/transport"
)

const (
	defaultTopologyLease   = 30 * time.Second
	defaultTopologyRefresh = 10 * time.Second
	defaultLinkRTTMillis   = 1
)

type NodeConfig struct {
	NodeID          string
	VirtualIP       string
	Endpoints       []string
	Capabilities    []string
	NATProfile      string
	Lease           time.Duration
	RefreshInterval time.Duration
	HopLimit        uint8
	DisableTransit  bool
	OnMessage       LocalHandler
	OnEvent         EventHandler
	OnData          DataHandler
	OnDataEvent     DataEventHandler
}

// Node combines the transport-neutral Router with member flooding, a
// link-state database, and local shortest-path calculation.
type Node struct {
	nodeID   string
	router   *Router
	topology *Topology

	member             peercontrol.MemberRecord
	links              map[string]peercontrol.LinkStateLink
	neighborHandles    map[string]NeighborHandle
	lsaRevision        uint64
	leaseMillis        uint32
	hopLimit           uint8
	transitAllowed     bool
	onMessage          LocalHandler
	dataHandler        DataHandler
	messageHandlers    map[uint64]LocalHandler
	messageHandlerSeq  uint64
	topologyHandlers   map[uint64]func()
	topologyHandlerSeq uint64
	refreshInterval    time.Duration

	mu         sync.Mutex
	routeMu    sync.Mutex
	neighborMu sync.Mutex
	started    bool
	closing    bool
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func NewNode(cfg NodeConfig) (*Node, error) {
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		return nil, fmt.Errorf("mesh: node id is required")
	}
	lease := cfg.Lease
	if lease <= 0 {
		lease = defaultTopologyLease
	}
	leaseMillis := lease.Milliseconds()
	if leaseMillis <= 0 || leaseMillis > peercontrol.MaxLeaseMillis {
		return nil, fmt.Errorf("mesh: topology lease %s is outside 1ms..%dms", lease, peercontrol.MaxLeaseMillis)
	}
	refresh := cfg.RefreshInterval
	if refresh <= 0 {
		refresh = defaultTopologyRefresh
	}
	if refresh >= lease {
		refresh = lease / 3
		if refresh <= 0 {
			refresh = time.Millisecond
		}
	}
	hopLimit := cfg.HopLimit
	if hopLimit == 0 {
		hopLimit = peercontrol.DefaultHopLimit
	}
	if hopLimit > peercontrol.MaxHopLimit {
		return nil, fmt.Errorf("mesh: hop limit %d exceeds maximum %d", hopLimit, peercontrol.MaxHopLimit)
	}
	revisionBase := nextBootCounterBase()

	topology, err := NewTopology(nodeID)
	if err != nil {
		return nil, err
	}
	node := &Node{
		nodeID:   nodeID,
		topology: topology,
		member: peercontrol.MemberRecord{
			NodeID:       nodeID,
			Revision:     revisionBase,
			LeaseMillis:  uint32(leaseMillis),
			VirtualIP:    strings.TrimSpace(cfg.VirtualIP),
			Endpoints:    append([]string(nil), cfg.Endpoints...),
			Capabilities: append([]string(nil), cfg.Capabilities...),
			NATProfile:   strings.TrimSpace(cfg.NATProfile),
		},
		links:            make(map[string]peercontrol.LinkStateLink),
		neighborHandles:  make(map[string]NeighborHandle),
		lsaRevision:      revisionBase,
		leaseMillis:      uint32(leaseMillis),
		hopLimit:         hopLimit,
		transitAllowed:   !cfg.DisableTransit,
		onMessage:        cfg.OnMessage,
		dataHandler:      cfg.OnData,
		messageHandlers:  make(map[uint64]LocalHandler),
		topologyHandlers: make(map[uint64]func()),
		refreshInterval:  refresh,
	}
	router, err := NewRouter(Config{
		NodeID:           nodeID,
		OnMessage:        node.handleMessage,
		OnEvent:          cfg.OnEvent,
		OnData:           node.handleData,
		OnDataEvent:      cfg.OnDataEvent,
		OnNeighborChange: node.handleNeighborChange,
	})
	if err != nil {
		return nil, err
	}
	node.router = router
	if err := topology.SetLocalMember(node.member); err != nil {
		_ = router.Close()
		return nil, err
	}
	if err := topology.SetLocalLinkState(node.localLinkState()); err != nil {
		_ = router.Close()
		return nil, err
	}
	return node, nil
}

func (n *Node) Start(ctx context.Context) error {
	if n == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return ErrClosed
	}
	if n.started {
		n.mu.Unlock()
		return fmt.Errorf("mesh: node %q already started", n.nodeID)
	}
	n.ctx, n.cancel = context.WithCancel(ctx)
	n.started = true
	runCtx := n.ctx
	n.mu.Unlock()

	if err := n.publishMember(runCtx); err != nil {
		n.rollbackStart()
		return err
	}
	if err := n.publishLinkState(runCtx); err != nil {
		n.rollbackStart()
		return err
	}
	n.wg.Add(1)
	go n.runMaintenance(runCtx)
	return nil
}

func (n *Node) rollbackStart() {
	n.mu.Lock()
	cancel := n.cancel
	n.started = false
	n.ctx = nil
	n.cancel = nil
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (n *Node) runMaintenance(ctx context.Context) {
	defer n.wg.Done()
	ticker := time.NewTicker(n.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			_ = n.publishMember(ctx)
			_ = n.publishLinkState(ctx)
			if n.topology.Expire(now) {
				n.syncRoutes()
				n.notifyTopologyHandlers()
			}
		}
	}
}

func (n *Node) AttachStream(peerID string, conn net.Conn) error {
	if n == nil || n.router == nil {
		if conn != nil {
			_ = conn.Close()
		}
		return ErrClosed
	}
	return n.router.AttachStream(peerID, conn)
}

func (n *Node) AttachStreams(peerID string, controlConn, dataConn net.Conn) error {
	if n == nil || n.router == nil {
		closeConns(controlConn, dataConn)
		return ErrClosed
	}
	return n.router.AttachStreams(peerID, controlConn, dataConn)
}

func (n *Node) AttachPacketTransport(peerID string, packetTransport transport.PacketTransport, config PacketNeighborConfig) error {
	_, err := n.AttachPacketTransportWithHandle(peerID, packetTransport, config)
	return err
}

func (n *Node) AttachPacketTransportWithHandle(
	peerID string,
	packetTransport transport.PacketTransport,
	config PacketNeighborConfig,
) (NeighborHandle, error) {
	if n == nil || n.router == nil {
		if packetTransport != nil {
			_ = packetTransport.Close()
		}
		return NeighborHandle{}, ErrClosed
	}
	return n.router.AttachPacketTransportWithHandle(peerID, packetTransport, config)
}

func (n *Node) HasNeighbor(peerID string) bool {
	return n != nil && n.router != nil && n.router.hasNeighbor(strings.TrimSpace(peerID))
}

// Neighbors returns the currently attached direct peer IDs in stable order.
// It is an operational snapshot; callers must still use topology routes for
// reachability because a neighbor may disappear immediately after the call.
func (n *Node) Neighbors() []string {
	if n == nil || n.router == nil {
		return nil
	}
	return n.router.neighborIDs()
}

func (n *Node) Neighbor(peerID string) (NeighborInfo, bool) {
	if n == nil || n.router == nil {
		return NeighborInfo{}, false
	}
	return n.router.neighbor(peerID)
}

func (n *Node) RemoveNeighbor(peerID string) error {
	if n == nil || n.router == nil {
		return ErrClosed
	}
	return n.router.RemoveNeighbor(peerID)
}

func (n *Node) RemoveNeighborHandle(handle NeighborHandle) error {
	if n == nil || n.router == nil {
		return nil
	}
	return n.router.RemoveNeighborHandle(handle)
}

// PromoteNeighborHandle publishes one exact, previously deferred neighbor as
// a routable graph edge. A stale handle can never promote its replacement.
func (n *Node) PromoteNeighborHandle(handle NeighborHandle) bool {
	return n != nil && n.router != nil && n.router.PromoteNeighborHandle(handle)
}

// WaitPacketNeighborReady waits for the exact packet session represented by
// handle to receive its first valid peer frame.
func (n *Node) WaitPacketNeighborReady(ctx context.Context, handle NeighborHandle) error {
	if n == nil || n.router == nil {
		return ErrClosed
	}
	return n.router.WaitPacketNeighborReady(ctx, handle)
}

func (n *Node) Send(ctx context.Context, msg peercontrol.Message) error {
	if n == nil || n.router == nil {
		return ErrClosed
	}
	return n.router.Send(ctx, msg)
}

func (n *Node) SendData(ctx context.Context, frame DataFrame) error {
	if n == nil || n.router == nil {
		return ErrClosed
	}
	return n.router.SendData(ctx, frame)
}

func (n *Node) NodeID() string {
	if n == nil {
		return ""
	}
	return n.nodeID
}

func (n *Node) SetDataHandler(handler DataHandler) error {
	if n == nil {
		return ErrClosed
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closing {
		return ErrClosed
	}
	if n.dataHandler != nil && handler != nil {
		return fmt.Errorf("mesh: node %q already has a data handler", n.nodeID)
	}
	n.dataHandler = handler
	return nil
}

// RegisterMessageHandler adds a composable application-control consumer.
// Topology records remain owned by Node; registered handlers receive the same
// non-topology messages as NodeConfig.OnMessage in registration order.
func (n *Node) RegisterMessageHandler(handler LocalHandler) (func(), error) {
	if n == nil || handler == nil {
		return nil, fmt.Errorf("mesh: message handler is required")
	}
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return nil, ErrClosed
	}
	n.messageHandlerSeq++
	id := n.messageHandlerSeq
	n.messageHandlers[id] = handler
	n.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			n.mu.Lock()
			delete(n.messageHandlers, id)
			n.mu.Unlock()
		})
	}, nil
}

// RegisterTopologyHandler adds a coalescing wake-up callback for actual
// membership, link-state, neighbor, or expiry changes. The callback runs only
// after the router has been synchronized and never while Node holds its lock.
func (n *Node) RegisterTopologyHandler(handler func()) (func(), error) {
	if n == nil || handler == nil {
		return nil, fmt.Errorf("mesh: topology handler is required")
	}
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return nil, ErrClosed
	}
	n.topologyHandlerSeq++
	id := n.topologyHandlerSeq
	n.topologyHandlers[id] = handler
	n.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			n.mu.Lock()
			delete(n.topologyHandlers, id)
			n.mu.Unlock()
		})
	}, nil
}

func (n *Node) Member(nodeID string) (peercontrol.MemberRecord, bool) {
	if n == nil {
		return peercontrol.MemberRecord{}, false
	}
	return n.topology.Member(nodeID)
}

func (n *Node) Members() map[string]peercontrol.MemberRecord {
	if n == nil {
		return nil
	}
	return n.topology.Members()
}

func (n *Node) Route(destination string) (Route, bool) {
	if n == nil {
		return Route{}, false
	}
	return n.topology.Route(destination)
}

// DataRoute returns the current route whose every hop can carry binary user
// data. It can lag the control route briefly while a dual-stream neighbor is
// being attached, so system-facing listeners must gate on this view.
func (n *Node) DataRoute(destination string) (Route, bool) {
	if n == nil || n.router == nil {
		return Route{}, false
	}
	route, ok := n.topology.DataRoute(destination)
	if !ok || !n.router.dataRouteAvailable(destination) {
		return Route{}, false
	}
	return route, true
}

func (n *Node) AlternateRoute(destination string) (Route, bool) {
	if n == nil {
		return Route{}, false
	}
	return n.topology.AlternateRoute(destination)
}

func (n *Node) Routes() map[string]Route {
	if n == nil {
		return nil
	}
	return n.topology.Routes()
}

func (n *Node) DataRoutes() map[string]Route {
	if n == nil || n.router == nil {
		return nil
	}
	routes := n.topology.DataRoutes()
	for destination := range routes {
		if !n.router.dataRouteAvailable(destination) {
			delete(routes, destination)
		}
	}
	return routes
}

func (n *Node) handleMessage(ctx context.Context, msg peercontrol.Message) error {
	switch msg.Type {
	case peercontrol.TypeMemberAnnounce:
		if msg.MemberRecord == nil {
			return fmt.Errorf("mesh: member announcement has no record")
		}
		changed, err := n.topology.ApplyMember(*msg.MemberRecord, time.Now())
		if err != nil {
			return err
		}
		if changed {
			n.syncRoutes()
			n.notifyTopologyHandlers()
		}
		return nil
	case peercontrol.TypeLinkState:
		if msg.LinkState == nil {
			return fmt.Errorf("mesh: link-state announcement has no record")
		}
		changed, err := n.topology.ApplyLinkState(*msg.LinkState, time.Now())
		if err != nil {
			return err
		}
		if changed {
			n.syncRoutes()
			n.notifyTopologyHandlers()
		}
		return nil
	default:
		n.mu.Lock()
		base := n.onMessage
		ids := make([]uint64, 0, len(n.messageHandlers))
		for id := range n.messageHandlers {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		handlers := make([]LocalHandler, 0, len(ids))
		for _, id := range ids {
			handlers = append(handlers, n.messageHandlers[id])
		}
		n.mu.Unlock()
		var handlerErr error
		if base != nil {
			handlerErr = errors.Join(handlerErr, base(ctx, msg))
		}
		for _, handler := range handlers {
			handlerErr = errors.Join(handlerErr, handler(ctx, msg))
		}
		return handlerErr
	}
}

func (n *Node) handleData(ctx context.Context, frame DataFrame) error {
	n.mu.Lock()
	handler := n.dataHandler
	n.mu.Unlock()
	if handler == nil {
		return nil
	}
	return handler(ctx, frame)
}

func (n *Node) handleNeighborChange(event NeighborEvent) {
	if n == nil || strings.TrimSpace(event.PeerID) == "" {
		return
	}
	n.neighborMu.Lock()
	// Neighbor notifications are emitted outside Router's lock. Re-read the
	// current entry so an older Down event cannot overwrite a replacement
	// session that attached under the same peer ID in the meantime.
	neighbor, up := n.router.neighbor(event.PeerID)
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		n.neighborMu.Unlock()
		return
	}
	link, linked := n.links[event.PeerID]
	trackedHandle, tracked := n.neighborHandles[event.PeerID]
	identityChanged := up != tracked || (up && trackedHandle != neighbor.Handle)
	shouldLink := up && neighbor.Advertised
	controlOnly := shouldLink && !neighbor.DataCapable
	capabilityChanged := shouldLink && linked && link.ControlOnly != controlOnly
	changed := shouldLink != linked || (shouldLink && (identityChanged || capabilityChanged))
	if !changed {
		if up {
			n.neighborHandles[event.PeerID] = neighbor.Handle
		} else {
			delete(n.neighborHandles, event.PeerID)
		}
		n.mu.Unlock()
		// detachNeighborHandle removes every route using the old next hop before
		// it emits Down. If a replacement attached first, both the stale Down and
		// the later Up can observe an unchanged logical LSA. Always rebuild the
		// router tables from the current topology/capability snapshot so that
		// this event ordering cannot leave permanent route holes.
		n.syncRoutes()
		n.neighborMu.Unlock()
		return
	}
	if shouldLink {
		n.links[event.PeerID] = peercontrol.LinkStateLink{
			PeerID:      event.PeerID,
			RTTMillis:   defaultLinkRTTMillis,
			ControlOnly: controlOnly,
		}
	} else {
		delete(n.links, event.PeerID)
	}
	if up {
		n.neighborHandles[event.PeerID] = neighbor.Handle
	} else {
		delete(n.neighborHandles, event.PeerID)
	}
	n.lsaRevision++
	state := n.localLinkStateLocked()
	started := n.started
	ctx := n.ctx
	n.mu.Unlock()

	if err := n.topology.SetLocalLinkState(state); err != nil {
		n.neighborMu.Unlock()
		return
	}
	n.syncRoutes()
	n.neighborMu.Unlock()
	n.notifyTopologyHandlers()
	if started && ctx != nil {
		_ = n.router.Send(ctx, peercontrol.NewLinkState(n.nodeID, state, n.hopLimit))
	}
}

func (n *Node) publishMember(ctx context.Context) error {
	n.mu.Lock()
	record := cloneMemberRecord(n.member)
	n.mu.Unlock()
	return n.router.Send(ctx, peercontrol.NewMemberAnnounce(n.nodeID, record, n.hopLimit))
}

func (n *Node) publishLinkState(ctx context.Context) error {
	n.mu.Lock()
	state := n.localLinkStateLocked()
	n.mu.Unlock()
	return n.router.Send(ctx, peercontrol.NewLinkState(n.nodeID, state, n.hopLimit))
}

func (n *Node) localLinkState() peercontrol.LinkStateAdvertisement {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.localLinkStateLocked()
}

func (n *Node) localLinkStateLocked() peercontrol.LinkStateAdvertisement {
	links := make([]peercontrol.LinkStateLink, 0, len(n.links))
	for _, link := range n.links {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool { return links[i].PeerID < links[j].PeerID })
	return peercontrol.LinkStateAdvertisement{
		NodeID:         n.nodeID,
		Revision:       n.lsaRevision,
		LeaseMillis:    n.leaseMillis,
		TransitAllowed: n.transitAllowed,
		Links:          links,
	}
}

func (n *Node) syncRoutes() {
	if n == nil || n.router == nil || n.topology == nil {
		return
	}
	n.routeMu.Lock()
	defer n.routeMu.Unlock()
	routes := n.topology.NextHops()
	dataRoutes := n.topology.DataNextHops()
	capabilities := n.router.neighborDataCapabilities()
	for destination, nextHop := range dataRoutes {
		if !capabilities[nextHop] {
			delete(dataRoutes, destination)
		}
	}
	_ = n.router.replaceRouteTables(routes, dataRoutes)
}

func (n *Node) notifyTopologyHandlers() {
	if n == nil {
		return
	}
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return
	}
	ids := make([]uint64, 0, len(n.topologyHandlers))
	for id := range n.topologyHandlers {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	handlers := make([]func(), 0, len(ids))
	for _, id := range ids {
		handlers = append(handlers, n.topologyHandlers[id])
	}
	n.mu.Unlock()
	for _, handler := range handlers {
		handler()
	}
}

func (n *Node) Close() error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	if n.closing {
		n.mu.Unlock()
		return nil
	}
	n.closing = true
	cancel := n.cancel
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	closeErr := n.router.Close()
	n.wg.Wait()
	return closeErr
}
