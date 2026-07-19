package mesh

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"winkyou/pkg/peercontrol"
)

type Route struct {
	Destination string
	NextHop     string
	HopCount    int
	RTT         time.Duration
	Path        []string
}

type memberState struct {
	record    peercontrol.MemberRecord
	expiresAt time.Time
	local     bool
}

type linkState struct {
	record    peercontrol.LinkStateAdvertisement
	expiresAt time.Time
	local     bool
}

// Topology stores flooded member and link-state records and calculates routes
// from confirmed bidirectional edges. It contains no transport or NAT logic.
type Topology struct {
	localID string

	mu         sync.RWMutex
	members    map[string]memberState
	lsas       map[string]linkState
	routes     map[string]Route
	dataRoutes map[string]Route
}

func NewTopology(localID string) (*Topology, error) {
	localID = strings.TrimSpace(localID)
	if localID == "" {
		return nil, fmt.Errorf("mesh: topology local node id is required")
	}
	return &Topology{
		localID:    localID,
		members:    make(map[string]memberState),
		lsas:       make(map[string]linkState),
		routes:     make(map[string]Route),
		dataRoutes: make(map[string]Route),
	}, nil
}

func (t *Topology) SetLocalMember(record peercontrol.MemberRecord) error {
	if t == nil {
		return ErrClosed
	}
	if record.NodeID != t.localID {
		return fmt.Errorf("mesh: local member id %q does not match %q", record.NodeID, t.localID)
	}
	if record.Revision == 0 {
		return fmt.Errorf("mesh: local member revision is required")
	}
	t.mu.Lock()
	t.members[t.localID] = memberState{record: cloneMemberRecord(record), local: true}
	t.recomputeLocked()
	t.mu.Unlock()
	return nil
}

func (t *Topology) SetLocalLinkState(record peercontrol.LinkStateAdvertisement) error {
	if t == nil {
		return ErrClosed
	}
	if record.NodeID != t.localID {
		return fmt.Errorf("mesh: local link-state id %q does not match %q", record.NodeID, t.localID)
	}
	if record.Revision == 0 {
		return fmt.Errorf("mesh: local link-state revision is required")
	}
	t.mu.Lock()
	t.lsas[t.localID] = linkState{record: cloneLinkState(record), local: true}
	t.recomputeLocked()
	t.mu.Unlock()
	return nil
}

// ApplyMember accepts newer state and lets an equal revision refresh its lease.
func (t *Topology) ApplyMember(record peercontrol.MemberRecord, receivedAt time.Time) (bool, error) {
	if t == nil {
		return false, ErrClosed
	}
	if strings.TrimSpace(record.NodeID) == "" || record.Revision == 0 || record.LeaseMillis == 0 {
		return false, fmt.Errorf("mesh: invalid member record")
	}
	if record.NodeID == t.localID {
		return false, nil
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	expiresAt := receivedAt.Add(time.Duration(record.LeaseMillis) * time.Millisecond)

	t.mu.Lock()
	defer t.mu.Unlock()
	current, exists := t.members[record.NodeID]
	if exists && current.local {
		return false, nil
	}
	if exists && record.Revision < current.record.Revision {
		return false, nil
	}
	if exists && record.Revision == current.record.Revision && !memberRecordsEqual(current.record, record) {
		return false, fmt.Errorf("%w: member %s revision %d", ErrRevisionConflict, record.NodeID, record.Revision)
	}
	changed := !exists || record.Revision > current.record.Revision || !memberRecordsEqual(current.record, record)
	t.members[record.NodeID] = memberState{
		record:    cloneMemberRecord(record),
		expiresAt: expiresAt,
	}
	if changed {
		t.recomputeLocked()
	}
	return changed, nil
}

// ApplyLinkState accepts newer state and treats omission from a newer link list
// as immediate withdrawal. Equal revisions refresh the lease.
func (t *Topology) ApplyLinkState(record peercontrol.LinkStateAdvertisement, receivedAt time.Time) (bool, error) {
	if t == nil {
		return false, ErrClosed
	}
	if strings.TrimSpace(record.NodeID) == "" || record.Revision == 0 || record.LeaseMillis == 0 {
		return false, fmt.Errorf("mesh: invalid link-state record")
	}
	if record.NodeID == t.localID {
		return false, nil
	}
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	expiresAt := receivedAt.Add(time.Duration(record.LeaseMillis) * time.Millisecond)

	t.mu.Lock()
	defer t.mu.Unlock()
	current, exists := t.lsas[record.NodeID]
	if exists && current.local {
		return false, nil
	}
	if exists && record.Revision < current.record.Revision {
		return false, nil
	}
	if exists && record.Revision == current.record.Revision && !linkStatesEqual(current.record, record) {
		return false, fmt.Errorf("%w: link state %s revision %d", ErrRevisionConflict, record.NodeID, record.Revision)
	}
	changed := !exists || record.Revision > current.record.Revision || !linkStatesEqual(current.record, record)
	t.lsas[record.NodeID] = linkState{
		record:    cloneLinkState(record),
		expiresAt: expiresAt,
	}
	if changed {
		t.recomputeLocked()
	}
	return changed, nil
}

// Expire removes remote records whose leases were not refreshed. Local state
// never expires and is withdrawn only by a local neighbor event.
func (t *Topology) Expire(now time.Time) bool {
	if t == nil {
		return false
	}
	if now.IsZero() {
		now = time.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	changed := false
	for nodeID, member := range t.members {
		if !member.local && !member.expiresAt.After(now) {
			delete(t.members, nodeID)
			delete(t.lsas, nodeID)
			changed = true
		}
	}
	for nodeID, lsa := range t.lsas {
		if !lsa.local && !lsa.expiresAt.After(now) {
			delete(t.lsas, nodeID)
			changed = true
		}
	}
	if changed {
		t.recomputeLocked()
	}
	return changed
}

func (t *Topology) Member(nodeID string) (peercontrol.MemberRecord, bool) {
	if t == nil {
		return peercontrol.MemberRecord{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	member, ok := t.members[nodeID]
	if !ok {
		return peercontrol.MemberRecord{}, false
	}
	return cloneMemberRecord(member.record), true
}

func (t *Topology) Members() map[string]peercontrol.MemberRecord {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	members := make(map[string]peercontrol.MemberRecord, len(t.members))
	for nodeID, member := range t.members {
		members[nodeID] = cloneMemberRecord(member.record)
	}
	return members
}

func (t *Topology) Route(destination string) (Route, bool) {
	if t == nil {
		return Route{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	route, ok := t.routes[destination]
	if !ok {
		return Route{}, false
	}
	return cloneRoute(route), true
}

// DataRoute returns the shortest route whose every confirmed bidirectional
// edge carries user data. A link is excluded when either endpoint advertises
// it as control-only, which gives every node the same packet-forwarding graph.
func (t *Topology) DataRoute(destination string) (Route, bool) {
	if t == nil {
		return Route{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	route, ok := t.dataRoutes[destination]
	if !ok {
		return Route{}, false
	}
	return cloneRoute(route), true
}

// AlternateRoute returns the shortest route to destination after excluding the
// direct localID<->destination edge. It does not mutate the installed topology
// or route table, so callers can safely use it to choose a coordinator before
// replacing an existing direct neighbor.
func (t *Topology) AlternateRoute(destination string) (Route, bool) {
	if t == nil {
		return Route{}, false
	}
	destination = strings.TrimSpace(destination)
	if destination == "" || destination == t.localID {
		return Route{}, false
	}
	t.mu.RLock()
	route, ok := t.computeRoutesLocked(map[string]struct{}{destination: {}}, false)[destination]
	t.mu.RUnlock()
	if !ok {
		return Route{}, false
	}
	return cloneRoute(route), true
}

func (t *Topology) Routes() map[string]Route {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	routes := make(map[string]Route, len(t.routes))
	for destination, route := range t.routes {
		routes[destination] = cloneRoute(route)
	}
	return routes
}

func (t *Topology) DataRoutes() map[string]Route {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	routes := make(map[string]Route, len(t.dataRoutes))
	for destination, route := range t.dataRoutes {
		routes[destination] = cloneRoute(route)
	}
	return routes
}

func (t *Topology) NextHops() map[string]string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	nextHops := make(map[string]string, len(t.routes))
	for destination, route := range t.routes {
		nextHops[destination] = route.NextHop
	}
	return nextHops
}

func (t *Topology) DataNextHops() map[string]string {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	nextHops := make(map[string]string, len(t.dataRoutes))
	for destination, route := range t.dataRoutes {
		nextHops[destination] = route.NextHop
	}
	return nextHops
}

type graphEdge struct {
	to  string
	rtt time.Duration
}

type pathCost struct {
	hops int
	rtt  time.Duration
}

func (t *Topology) recomputeLocked() {
	t.routes = t.computeRoutesLocked(nil, false)
	t.dataRoutes = t.computeRoutesLocked(nil, true)
}

// computeRoutesLocked calculates a fresh route table while the caller holds
// t.mu for reading or writing. excludedDirectPeers removes the undirected edge
// between the local node and every named peer; all other graph edges remain.
func (t *Topology) computeRoutesLocked(excludedDirectPeers map[string]struct{}, dataOnly bool) map[string]Route {
	adjacency := make(map[string][]graphEdge)
	for origin, state := range t.lsas {
		if _, exists := t.members[origin]; !exists {
			continue
		}
		for _, link := range state.record.Links {
			_, excludeForward := excludedDirectPeers[link.PeerID]
			_, excludeReverse := excludedDirectPeers[origin]
			if (origin == t.localID && excludeForward) ||
				(link.PeerID == t.localID && excludeReverse) {
				continue
			}
			if _, exists := t.members[link.PeerID]; !exists {
				continue
			}
			reverseState, exists := t.lsas[link.PeerID]
			if !exists {
				continue
			}
			reverse, ok := findLink(reverseState.record.Links, origin)
			if !ok {
				continue
			}
			if dataOnly && (link.ControlOnly || reverse.ControlOnly) {
				continue
			}
			adjacency[origin] = append(adjacency[origin], graphEdge{
				to:  link.PeerID,
				rtt: combinedRTT(link.RTTMillis, reverse.RTTMillis),
			})
		}
	}
	for nodeID := range adjacency {
		sort.Slice(adjacency[nodeID], func(i, j int) bool {
			return adjacency[nodeID][i].to < adjacency[nodeID][j].to
		})
	}

	dist := map[string]pathCost{t.localID: {}}
	paths := map[string][]string{t.localID: {t.localID}}
	visited := make(map[string]bool)
	for {
		current := ""
		for candidate := range dist {
			if visited[candidate] {
				continue
			}
			if current == "" || costLess(dist[candidate], dist[current]) ||
				(dist[candidate] == dist[current] && candidate < current) {
				current = candidate
			}
		}
		if current == "" {
			break
		}
		visited[current] = true
		if current != t.localID {
			state, exists := t.lsas[current]
			if !exists || !state.record.TransitAllowed {
				continue
			}
		}
		for _, edge := range adjacency[current] {
			if visited[edge.to] {
				continue
			}
			candidateCost := pathCost{
				hops: dist[current].hops + 1,
				rtt:  dist[current].rtt + edge.rtt,
			}
			candidatePath := append(append([]string(nil), paths[current]...), edge.to)
			knownCost, exists := dist[edge.to]
			if !exists || costLess(candidateCost, knownCost) ||
				(candidateCost == knownCost && pathLess(candidatePath, paths[edge.to])) {
				dist[edge.to] = candidateCost
				paths[edge.to] = candidatePath
			}
		}
	}

	routes := make(map[string]Route)
	for destination, path := range paths {
		if destination == t.localID || len(path) < 2 {
			continue
		}
		cost := dist[destination]
		routes[destination] = Route{
			Destination: destination,
			NextHop:     path[1],
			HopCount:    cost.hops,
			RTT:         cost.rtt,
			Path:        append([]string(nil), path...),
		}
	}
	return routes
}

func findLink(links []peercontrol.LinkStateLink, peerID string) (peercontrol.LinkStateLink, bool) {
	for _, link := range links {
		if link.PeerID == peerID {
			return link, true
		}
	}
	return peercontrol.LinkStateLink{}, false
}

func combinedRTT(left, right uint32) time.Duration {
	switch {
	case left == 0 && right == 0:
		return time.Millisecond
	case left == 0:
		return time.Duration(right) * time.Millisecond
	case right == 0:
		return time.Duration(left) * time.Millisecond
	default:
		return time.Duration((uint64(left)+uint64(right))/2) * time.Millisecond
	}
}

func costLess(left, right pathCost) bool {
	if left.hops != right.hops {
		return left.hops < right.hops
	}
	return left.rtt < right.rtt
}

func pathLess(left, right []string) bool {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}

func cloneMemberRecord(record peercontrol.MemberRecord) peercontrol.MemberRecord {
	record.Endpoints = append([]string(nil), record.Endpoints...)
	record.Capabilities = append([]string(nil), record.Capabilities...)
	return record
}

func cloneLinkState(record peercontrol.LinkStateAdvertisement) peercontrol.LinkStateAdvertisement {
	record.Links = append([]peercontrol.LinkStateLink(nil), record.Links...)
	return record
}

func cloneRoute(route Route) Route {
	route.Path = append([]string(nil), route.Path...)
	return route
}

func memberRecordsEqual(left, right peercontrol.MemberRecord) bool {
	return left.NodeID == right.NodeID &&
		left.Revision == right.Revision &&
		left.LeaseMillis == right.LeaseMillis &&
		left.VirtualIP == right.VirtualIP &&
		left.NATProfile == right.NATProfile &&
		slices.Equal(left.Endpoints, right.Endpoints) &&
		slices.Equal(left.Capabilities, right.Capabilities)
}

func linkStatesEqual(left, right peercontrol.LinkStateAdvertisement) bool {
	return left.NodeID == right.NodeID &&
		left.Revision == right.Revision &&
		left.LeaseMillis == right.LeaseMillis &&
		left.TransitAllowed == right.TransitAllowed &&
		slices.Equal(left.Links, right.Links)
}
