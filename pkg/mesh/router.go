// Package mesh routes WinkYou control messages across already-established
// neighbor sessions and builds an autonomous topology from flooded membership
// and link-state records.
package mesh

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/pkg/peercontrol"
)

const defaultSeenTTL = 2 * time.Minute

var (
	ErrClosed           = errors.New("mesh: router closed")
	ErrDuplicate        = errors.New("mesh: duplicate routed message")
	ErrHopLimitExceeded = errors.New("mesh: routed message hop limit exhausted")
	ErrLoopDetected     = errors.New("mesh: routed message path loop detected")
	ErrNoRoute          = errors.New("mesh: no route to destination")
	ErrRevisionConflict = errors.New("mesh: equal topology revision has different content")
	ErrUnknownNeighbor  = errors.New("mesh: unknown neighbor")
)

type EventKind string

const (
	EventForwarded EventKind = "forwarded"
	EventDelivered EventKind = "delivered"
	EventDropped   EventKind = "dropped"
)

// Event makes forwarding and rejection decisions observable without coupling
// the routing core to logging or the client runtime.
type Event struct {
	At          time.Time
	Kind        EventKind
	NodeID      string
	InboundPeer string
	NextHop     string
	Message     peercontrol.Message
	DecisionErr error
}

type LocalHandler func(context.Context, peercontrol.Message) error
type EventHandler func(Event)
type NeighborHandler func(NeighborEvent)
type DataHandler func(context.Context, DataFrame) error
type DataEventHandler func(DataEvent)

type NeighborEvent struct {
	At     time.Time
	NodeID string
	PeerID string
	Up     bool
}

type NeighborKind string

const (
	NeighborKindStream  NeighborKind = "stream"
	NeighborKindPacket  NeighborKind = "packet"
	NeighborKindUnknown NeighborKind = "unknown"
)

// NeighborHandle is an opaque identity for one specific attached neighbor
// session. Copies remain valid for conditional cleanup, but a handle never
// matches a replacement session attached later under the same peer ID.
type NeighborHandle struct {
	router *Router
	peerID string
	entry  *neighborEntry
}

type NeighborInfo struct {
	PeerID      string         `json:"peer_id"`
	Kind        NeighborKind   `json:"kind"`
	DataCapable bool           `json:"data_capable"`
	Advertised  bool           `json:"advertised"`
	Handle      NeighborHandle `json:"-"`
}

type DataEvent struct {
	At          time.Time
	Kind        EventKind
	NodeID      string
	InboundPeer string
	NextHop     string
	Frame       DataFrame
	DecisionErr error
}

type Config struct {
	NodeID           string
	SeenTTL          time.Duration
	OnMessage        LocalHandler
	OnEvent          EventHandler
	OnData           DataHandler
	OnDataEvent      DataEventHandler
	OnNeighborChange NeighborHandler
}

// NeighborSession is the transport-neutral control side of one direct graph
// edge. QUIC streams can implement the same contract after the static stream
// slice proves routing behavior.
type NeighborSession interface {
	PeerID() string
	Send(context.Context, peercontrol.Message) error
	Close() error
}

type DataNeighborSession interface {
	NeighborSession
	SendData(context.Context, DataFrame) error
}

// dataChannelProvider lets a session that implements DataNeighborSession for
// both of its modes report that a particular instance is control-only.
type dataChannelProvider interface {
	dataChannelAvailable() bool
}

type seenKey struct {
	origin string
	seq    uint64
}

type neighborEntry struct {
	session    NeighborSession
	kind       NeighborKind
	advertised bool
}

type neighborKindProvider interface {
	neighborKind() NeighborKind
}

// Router forwards logical messages by final node ID. Static routes map a final
// destination to an already-attached next-hop NeighborSession.
type Router struct {
	nodeID           string
	seenTTL          time.Duration
	onMessage        LocalHandler
	onEvent          EventHandler
	onData           DataHandler
	onDataEvent      DataEventHandler
	onNeighborChange NeighborHandler

	ctx    context.Context
	cancel context.CancelFunc
	seq    atomic.Uint64

	mu         sync.RWMutex
	closed     bool
	neighbors  map[string]*neighborEntry
	routes     map[string]string
	dataRoutes map[string]string
	// dataRoutesAuthoritative is set once a complete graph-derived data view
	// has been installed. Before that happens, a raw Router keeps its original
	// direct-neighbor fallback for low-level/static uses. Once authoritative,
	// even a physically data-capable direct neighbor must be selected by the
	// data table so a remote ControlOnly advertisement can exclude that edge.
	dataRoutesAuthoritative bool
	seen                    map[seenKey]time.Time
}

func NewRouter(cfg Config) (*Router, error) {
	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		return nil, fmt.Errorf("mesh: node id is required")
	}
	seenTTL := cfg.SeenTTL
	if seenTTL <= 0 {
		seenTTL = defaultSeenTTL
	}
	ctx, cancel := context.WithCancel(context.Background())
	router := &Router{
		nodeID:           nodeID,
		seenTTL:          seenTTL,
		onMessage:        cfg.OnMessage,
		onEvent:          cfg.OnEvent,
		onData:           cfg.OnData,
		onDataEvent:      cfg.OnDataEvent,
		onNeighborChange: cfg.OnNeighborChange,
		ctx:              ctx,
		cancel:           cancel,
		neighbors:        make(map[string]*neighborEntry),
		routes:           make(map[string]string),
		dataRoutes:       make(map[string]string),
		seen:             make(map[seenKey]time.Time),
	}
	router.seq.Store(nextBootCounterBase())
	return router, nil
}

func (r *Router) NodeID() string {
	if r == nil {
		return ""
	}
	return r.nodeID
}

func (r *Router) neighborIDs() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	ids := make([]string, 0, len(r.neighbors))
	for peerID := range r.neighbors {
		ids = append(ids, peerID)
	}
	r.mu.RUnlock()
	sort.Strings(ids)
	return ids
}

func (r *Router) neighbor(peerID string) (NeighborInfo, bool) {
	if r == nil {
		return NeighborInfo{}, false
	}
	peerID = strings.TrimSpace(peerID)
	r.mu.RLock()
	entry := r.neighbors[peerID]
	closed := r.closed
	advertised := entry != nil && entry.advertised
	r.mu.RUnlock()
	if closed || entry == nil {
		return NeighborInfo{}, false
	}
	return NeighborInfo{
		PeerID:      peerID,
		Kind:        entry.kind,
		DataCapable: neighborSupportsData(entry.session),
		Advertised:  advertised,
		Handle:      NeighborHandle{router: r, peerID: peerID, entry: entry},
	}, true
}

func kindOfNeighbor(session NeighborSession) NeighborKind {
	if provider, ok := session.(neighborKindProvider); ok {
		switch kind := provider.neighborKind(); kind {
		case NeighborKindStream, NeighborKindPacket:
			return kind
		}
	}
	return NeighborKindUnknown
}

func (r *Router) AddNeighbor(session NeighborSession) error {
	_, err := r.addNeighbor(session)
	return err
}

func (r *Router) addNeighbor(session NeighborSession) (NeighborHandle, error) {
	return r.addNeighborWithAdvertisement(session, true)
}

func (r *Router) addNeighborWithAdvertisement(session NeighborSession, advertised bool) (NeighborHandle, error) {
	if r == nil || session == nil {
		return NeighborHandle{}, fmt.Errorf("mesh: neighbor session is required")
	}
	peerID := strings.TrimSpace(session.PeerID())
	if peerID == "" {
		return NeighborHandle{}, fmt.Errorf("mesh: neighbor peer id is required")
	}
	if peerID == r.nodeID {
		return NeighborHandle{}, fmt.Errorf("mesh: node %q cannot be its own neighbor", r.nodeID)
	}
	entry := &neighborEntry{
		session:    session,
		kind:       kindOfNeighbor(session),
		advertised: advertised,
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return NeighborHandle{}, ErrClosed
	}
	if _, exists := r.neighbors[peerID]; exists {
		r.mu.Unlock()
		return NeighborHandle{}, fmt.Errorf("mesh: neighbor %q already attached", peerID)
	}
	r.neighbors[peerID] = entry
	r.mu.Unlock()
	r.emitNeighbor(peerID, true)
	return NeighborHandle{router: r, peerID: peerID, entry: entry}, nil
}

// PromoteNeighborHandle makes one exact attached session eligible for local
// link-state advertisement. Zero, foreign, stale, and already-detached
// handles return false; an already-promoted current handle returns true.
func (r *Router) PromoteNeighborHandle(handle NeighborHandle) bool {
	if r == nil || handle.router != r || handle.entry == nil || handle.peerID == "" {
		return false
	}
	r.mu.Lock()
	if r.closed || r.neighbors[handle.peerID] != handle.entry {
		r.mu.Unlock()
		return false
	}
	if handle.entry.advertised {
		r.mu.Unlock()
		return true
	}
	handle.entry.advertised = true
	r.mu.Unlock()
	r.emitNeighbor(handle.peerID, true)
	return true
}

// WaitPacketNeighborReady waits until the exact attached packet session has
// received a valid frame from its peer. A stale handle never observes a
// replacement session that later attaches under the same peer ID.
func (r *Router) WaitPacketNeighborReady(ctx context.Context, handle NeighborHandle) error {
	if r == nil || handle.router != r || handle.entry == nil || handle.peerID == "" {
		return fmt.Errorf("%w: packet neighbor handle", ErrUnknownNeighbor)
	}
	r.mu.RLock()
	entry := r.neighbors[handle.peerID]
	closed := r.closed
	r.mu.RUnlock()
	if closed {
		return ErrClosed
	}
	if entry != handle.entry {
		return fmt.Errorf("%w: %s", ErrUnknownNeighbor, handle.peerID)
	}
	session, ok := entry.session.(*PacketNeighborSession)
	if !ok {
		return fmt.Errorf("mesh: neighbor %q is not a packet session", handle.peerID)
	}
	return session.waitReady(ctx)
}

// RemoveNeighbor withdraws a direct edge immediately. Dynamic control-plane
// users publish a newer LSA from the neighbor-change callback.
func (r *Router) RemoveNeighbor(peerID string) error {
	if r == nil {
		return ErrClosed
	}
	peerID = strings.TrimSpace(peerID)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	entry := r.neighbors[peerID]
	if entry == nil {
		r.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknownNeighbor, peerID)
	}
	delete(r.neighbors, peerID)
	for destination, nextHop := range r.routes {
		if nextHop == peerID {
			delete(r.routes, destination)
		}
	}
	for destination, nextHop := range r.dataRoutes {
		if nextHop == peerID {
			delete(r.dataRoutes, destination)
		}
	}
	r.mu.Unlock()
	closeErr := entry.session.Close()
	r.emitNeighbor(peerID, false)
	return closeErr
}

// RemoveNeighborHandle conditionally removes the exact session represented by
// handle. Zero, foreign, and stale handles are successful no-ops.
func (r *Router) RemoveNeighborHandle(handle NeighborHandle) error {
	if r == nil || handle.router != r || handle.entry == nil || handle.peerID == "" {
		return nil
	}
	entry, removed := r.detachNeighborHandle(handle)
	if !removed {
		return nil
	}
	closeErr := entry.session.Close()
	r.emitNeighbor(handle.peerID, false)
	return closeErr
}

// withdrawNeighborHandle is used by a session that has already closed itself.
// It must not call Close again, but otherwise performs the same identity check.
func (r *Router) withdrawNeighborHandle(handle NeighborHandle) {
	if r == nil || handle.router != r || handle.entry == nil || handle.peerID == "" {
		return
	}
	_, removed := r.detachNeighborHandle(handle)
	if removed {
		r.emitNeighbor(handle.peerID, false)
	}
}

func (r *Router) detachNeighborHandle(handle NeighborHandle) (*neighborEntry, bool) {
	r.mu.Lock()
	if r.closed || r.neighbors[handle.peerID] != handle.entry {
		r.mu.Unlock()
		return nil, false
	}
	delete(r.neighbors, handle.peerID)
	for destination, nextHop := range r.routes {
		if nextHop == handle.peerID {
			delete(r.routes, destination)
		}
	}
	for destination, nextHop := range r.dataRoutes {
		if nextHop == handle.peerID {
			delete(r.dataRoutes, destination)
		}
	}
	r.mu.Unlock()
	return handle.entry, true
}

func (r *Router) SetRoute(destination, nextHop string) error {
	if r == nil {
		return ErrClosed
	}
	destination = strings.TrimSpace(destination)
	nextHop = strings.TrimSpace(nextHop)
	if destination == "" || nextHop == "" {
		return fmt.Errorf("mesh: route destination and next hop are required")
	}
	if destination == r.nodeID {
		return fmt.Errorf("mesh: local destination %q does not need a route", destination)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	r.routes[destination] = nextHop
	r.dataRoutes[destination] = nextHop
	return nil
}

func (r *Router) RemoveRoute(destination string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	destination = strings.TrimSpace(destination)
	delete(r.routes, destination)
	delete(r.dataRoutes, destination)
	r.mu.Unlock()
}

// ReplaceRoutes atomically installs a graph solver's destination-to-next-hop
// view. Directly attached destinations still take precedence for control;
// data forwarding treats the installed view as authoritative.
func (r *Router) ReplaceRoutes(routes map[string]string) error {
	return r.replaceRouteTables(routes, routes)
}

// replaceRouteTables atomically installs control and data next-hop views. The
// Node uses a distinct data view when a directly attached bootstrap stream is
// control-only but an alternate packet route exists.
func (r *Router) replaceRouteTables(routes, dataRoutes map[string]string) error {
	if r == nil {
		return ErrClosed
	}
	next := normalizedNextHops(r.nodeID, routes)
	nextData := normalizedNextHops(r.nodeID, dataRoutes)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	r.routes = next
	r.dataRoutes = nextData
	r.dataRoutesAuthoritative = true
	return nil
}

func normalizedNextHops(nodeID string, routes map[string]string) map[string]string {
	next := make(map[string]string, len(routes))
	for destination, nextHop := range routes {
		destination = strings.TrimSpace(destination)
		nextHop = strings.TrimSpace(nextHop)
		if destination == "" || nextHop == "" || destination == nodeID {
			continue
		}
		next[destination] = nextHop
	}
	return next
}

func (r *Router) Routes() map[string]string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	routes := make(map[string]string, len(r.routes))
	for destination, nextHop := range r.routes {
		routes[destination] = nextHop
	}
	return routes
}

// Send originates a routed message at this node. A zero sequence and missing
// route header are filled here so message constructors do not need router state.
func (r *Router) Send(ctx context.Context, msg peercontrol.Message) error {
	if r == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	msg = cloneMessage(msg)
	if strings.TrimSpace(msg.From) == "" {
		msg.From = r.nodeID
	}
	if msg.From != r.nodeID {
		return fmt.Errorf("mesh: local node %q cannot originate message from %q", r.nodeID, msg.From)
	}
	if msg.Seq == 0 {
		msg.Seq = r.seq.Add(1)
	}
	if msg.HopLimit == 0 {
		msg.HopLimit = peercontrol.DefaultHopLimit
	}
	if len(msg.PathVector) == 0 {
		msg.PathVector = []string{r.nodeID}
	} else if msg.PathVector[len(msg.PathVector)-1] != r.nodeID {
		if containsNode(msg.PathVector, r.nodeID) {
			return ErrLoopDetected
		}
		msg.PathVector = append(msg.PathVector, r.nodeID)
	}
	if err := peercontrol.Validate(msg); err != nil {
		return err
	}
	if err := r.markSeen(msg, time.Now()); err != nil {
		return err
	}
	if msg.To == peercontrol.BroadcastNodeID {
		if err := r.deliver(ctx, "", msg); err != nil {
			return err
		}
		return r.flood(ctx, "", msg)
	}
	if msg.To == r.nodeID {
		return r.deliver(ctx, "", msg)
	}
	return r.forward(ctx, "", msg)
}

// HandleInbound consumes or forwards a decoded message received from one
// immediate neighbor. Alternate NeighborSession implementations call this same
// method, so routing remains independent from TCP, QUIC, or another underlay.
func (r *Router) HandleInbound(ctx context.Context, inboundPeer string, msg peercontrol.Message) error {
	if r == nil {
		return ErrClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	inboundPeer = strings.TrimSpace(inboundPeer)
	if !r.hasNeighbor(inboundPeer) {
		return r.drop(inboundPeer, msg, ErrUnknownNeighbor)
	}
	msg = cloneMessage(msg)
	if msg.Seq == 0 {
		return r.drop(inboundPeer, msg, fmt.Errorf("mesh: routed message sequence is required"))
	}
	if msg.HopLimit == 0 {
		return r.drop(inboundPeer, msg, ErrHopLimitExceeded)
	}
	if err := peercontrol.Validate(msg); err != nil {
		return r.drop(inboundPeer, msg, err)
	}
	if err := r.markSeen(msg, time.Now()); err != nil {
		return r.drop(inboundPeer, msg, err)
	}
	if containsNode(msg.PathVector, r.nodeID) {
		return r.drop(inboundPeer, msg, ErrLoopDetected)
	}
	msg.PathVector = append(msg.PathVector, r.nodeID)
	if len(msg.PathVector) > peercontrol.MaxPathVectorLength {
		return r.drop(inboundPeer, msg, ErrHopLimitExceeded)
	}
	if msg.To == peercontrol.BroadcastNodeID {
		if err := r.deliver(ctx, inboundPeer, msg); err != nil {
			return err
		}
		if msg.HopLimit <= 1 {
			return nil
		}
		msg.HopLimit--
		return r.flood(ctx, inboundPeer, msg)
	}
	if msg.To == r.nodeID {
		return r.deliver(ctx, inboundPeer, msg)
	}
	if msg.HopLimit <= 1 {
		return r.drop(inboundPeer, msg, ErrHopLimitExceeded)
	}
	msg.HopLimit--
	return r.forward(ctx, inboundPeer, msg)
}

func (r *Router) flood(ctx context.Context, inboundPeer string, msg peercontrol.Message) error {
	neighbors := r.neighborSnapshot()
	var sendErr error
	for peerID, session := range neighbors {
		if peerID == inboundPeer || containsNode(msg.PathVector, peerID) {
			continue
		}
		if err := session.Send(ctx, msg); err != nil {
			sendErr = errors.Join(sendErr, fmt.Errorf("mesh: flood to neighbor %q: %w", peerID, err))
			continue
		}
		r.emit(Event{
			At:          time.Now().UTC(),
			Kind:        EventForwarded,
			NodeID:      r.nodeID,
			InboundPeer: inboundPeer,
			NextHop:     peerID,
			Message:     cloneMessage(msg),
		})
	}
	return sendErr
}

func (r *Router) forward(ctx context.Context, inboundPeer string, msg peercontrol.Message) error {
	nextHop, session, err := r.lookup(msg.To)
	if err != nil {
		return r.drop(inboundPeer, msg, err)
	}
	if err := session.Send(ctx, msg); err != nil {
		return r.drop(inboundPeer, msg, fmt.Errorf("mesh: send to next hop %q: %w", nextHop, err))
	}
	r.emit(Event{
		At:          time.Now().UTC(),
		Kind:        EventForwarded,
		NodeID:      r.nodeID,
		InboundPeer: inboundPeer,
		NextHop:     nextHop,
		Message:     cloneMessage(msg),
	})
	return nil
}

func (r *Router) deliver(ctx context.Context, inboundPeer string, msg peercontrol.Message) error {
	r.emit(Event{
		At:          time.Now().UTC(),
		Kind:        EventDelivered,
		NodeID:      r.nodeID,
		InboundPeer: inboundPeer,
		Message:     cloneMessage(msg),
	})
	if r.onMessage == nil {
		return nil
	}
	return r.onMessage(ctx, cloneMessage(msg))
}

func (r *Router) drop(inboundPeer string, msg peercontrol.Message, err error) error {
	r.emit(Event{
		At:          time.Now().UTC(),
		Kind:        EventDropped,
		NodeID:      r.nodeID,
		InboundPeer: inboundPeer,
		Message:     cloneMessage(msg),
		DecisionErr: err,
	})
	return err
}

func (r *Router) lookup(destination string) (string, NeighborSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return "", nil, ErrClosed
	}
	if direct := r.neighbors[destination]; direct != nil {
		return destination, direct.session, nil
	}
	nextHop := r.routes[destination]
	if nextHop == "" {
		return "", nil, fmt.Errorf("%w: %s", ErrNoRoute, destination)
	}
	entry := r.neighbors[nextHop]
	if entry == nil {
		return "", nil, fmt.Errorf("%w: route to %s uses %s", ErrUnknownNeighbor, destination, nextHop)
	}
	return nextHop, entry.session, nil
}

func (r *Router) lookupData(destination string) (string, DataNeighborSession, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return "", nil, ErrClosed
	}
	if !r.dataRoutesAuthoritative {
		if direct := r.neighbors[destination]; direct != nil && neighborSupportsData(direct.session) {
			return destination, direct.session.(DataNeighborSession), nil
		}
	}
	nextHop := r.dataRoutes[destination]
	if nextHop == "" {
		if direct := r.neighbors[destination]; direct != nil {
			return "", nil, fmt.Errorf("%w: %s", ErrDataChannelUnavailable, destination)
		}
		return "", nil, fmt.Errorf("%w: %s", ErrNoRoute, destination)
	}
	entry := r.neighbors[nextHop]
	if entry == nil {
		return "", nil, fmt.Errorf("%w: route to %s uses %s", ErrUnknownNeighbor, destination, nextHop)
	}
	if !neighborSupportsData(entry.session) {
		return "", nil, fmt.Errorf("%w: %s", ErrDataChannelUnavailable, nextHop)
	}
	return nextHop, entry.session.(DataNeighborSession), nil
}

func (r *Router) dataRouteAvailable(destination string) bool {
	_, _, err := r.lookupData(destination)
	return err == nil
}

func neighborSupportsData(session NeighborSession) bool {
	if _, ok := session.(DataNeighborSession); !ok {
		return false
	}
	if provider, ok := session.(dataChannelProvider); ok {
		return provider.dataChannelAvailable()
	}
	return true
}

func (r *Router) neighborDataCapabilities() map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil
	}
	result := make(map[string]bool, len(r.neighbors))
	for peerID, entry := range r.neighbors {
		result[peerID] = neighborSupportsData(entry.session)
	}
	return result
}

func (r *Router) hasNeighbor(peerID string) bool {
	if peerID == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return !r.closed && r.neighbors[peerID] != nil
}

func (r *Router) neighborSnapshot() map[string]NeighborSession {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil
	}
	neighbors := make(map[string]NeighborSession, len(r.neighbors))
	for peerID, entry := range r.neighbors {
		neighbors[peerID] = entry.session
	}
	return neighbors
}

func (r *Router) markSeen(msg peercontrol.Message, now time.Time) error {
	key := seenKey{origin: msg.From, seq: msg.Seq}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	for candidate, expiresAt := range r.seen {
		if !expiresAt.After(now) {
			delete(r.seen, candidate)
		}
	}
	if _, exists := r.seen[key]; exists {
		return ErrDuplicate
	}
	r.seen[key] = now.Add(r.seenTTL)
	return nil
}

func (r *Router) emit(event Event) {
	if r != nil && r.onEvent != nil {
		r.onEvent(event)
	}
}

func (r *Router) emitNeighbor(peerID string, up bool) {
	if r != nil && r.onNeighborChange != nil {
		r.onNeighborChange(NeighborEvent{
			At:     time.Now().UTC(),
			NodeID: r.nodeID,
			PeerID: peerID,
			Up:     up,
		})
	}
}

func (r *Router) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	sessions := make([]NeighborSession, 0, len(r.neighbors))
	for _, entry := range r.neighbors {
		sessions = append(sessions, entry.session)
	}
	r.neighbors = make(map[string]*neighborEntry)
	r.routes = make(map[string]string)
	r.dataRoutes = make(map[string]string)
	r.mu.Unlock()
	r.cancel()

	var closeErr error
	for _, session := range sessions {
		if err := session.Close(); err != nil {
			closeErr = errors.Join(closeErr, err)
		}
	}
	return closeErr
}

func containsNode(path []string, nodeID string) bool {
	for _, candidate := range path {
		if candidate == nodeID {
			return true
		}
	}
	return false
}

func cloneMessage(msg peercontrol.Message) peercontrol.Message {
	raw, err := peercontrol.Marshal(msg)
	if err == nil {
		if clone, decodeErr := peercontrol.Unmarshal(raw); decodeErr == nil {
			return clone
		}
	}
	// Invalid messages still need observable drop events. Copy the routed slices
	// that the router may mutate; payload pointers remain read-only on that path.
	clone := msg
	clone.PathVector = append([]string(nil), msg.PathVector...)
	return clone
}
