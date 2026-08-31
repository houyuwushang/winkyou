package natsim

import (
	"fmt"
	"net/netip"
	"sync"
)

const (
	defaultMaxPacketConns = 64
	defaultMaxMappings    = 1024
	defaultQueueCapacity  = 64
	defaultMaxDatagram    = 65507
)

// Config bounds every in-memory resource owned by one Network.
type Config struct {
	MaxPacketConns int
	MaxMappings    int
	QueueCapacity  int
	MaxDatagram    int
}

func normalizeConfig(config Config) (Config, error) {
	if config.MaxPacketConns == 0 {
		config.MaxPacketConns = defaultMaxPacketConns
	}
	if config.MaxMappings == 0 {
		config.MaxMappings = defaultMaxMappings
	}
	if config.QueueCapacity == 0 {
		config.QueueCapacity = defaultQueueCapacity
	}
	if config.MaxDatagram == 0 {
		config.MaxDatagram = defaultMaxDatagram
	}
	if config.MaxPacketConns < 1 || config.MaxMappings < 1 || config.QueueCapacity < 1 || config.MaxDatagram < 1 || config.MaxDatagram > 65535 {
		return Config{}, fmt.Errorf("%w: network resource limits must be positive and max_datagram <= 65535", ErrInvalidConfig)
	}
	return config, nil
}

// Counters is a race-safe resource and packet snapshot.
type Counters struct {
	ActivePacketConns int
	ActiveMappings    int
	QueuedPackets     int
	PeakPacketConns   int
	PeakMappings      int
	PeakQueuedPackets int
	PacketsWritten    uint64
	PacketsDelivered  uint64
	PacketsDropped    uint64
	PacketsRejected   uint64
}

// NATSnapshot describes one deterministic virtual NAT generation.
type NATSnapshot struct {
	Name            string
	PublicAddr      netip.Addr
	Model           Model
	OutboundPackets uint64
	ActiveMappings  int
	AppliedChanges  int
}

// EndpointConfig attaches one local UDP endpoint to an inner-to-outer NAT
// chain. An empty chain is a directly routed in-memory endpoint.
type EndpointConfig struct {
	LocalAddr netip.AddrPort
	NATChain  []*NAT
}

type endpointKey struct {
	inner *NAT
	local netip.AddrPort
}

type mappingKey struct {
	internal    netip.AddrPort
	destination netip.AddrPort
}

type natMapping struct {
	key              mappingKey
	internal         netip.AddrPort
	external         netip.AddrPort
	connection       *PacketConn
	chainIndex       int
	allowedAddresses map[netip.Addr]struct{}
	allowedEndpoints map[netip.AddrPort]struct{}
}

type externalRoute struct {
	connection *PacketConn
	chainIndex int
	nat        *NAT
}

type externalRouteKey struct {
	external    netip.AddrPort
	destination netip.AddrPort
}

type allocatedPortKey struct {
	port        uint16
	destination netip.AddrPort
}

// NAT is an opaque virtual translation layer owned by one Network.
type NAT struct {
	network         *Network
	name            string
	publicAddr      netip.Addr
	model           Model
	changes         []BehaviorChange
	nextChange      int
	outboundPackets uint64
	mappings        map[mappingKey]*natMapping
	usedPorts       map[allocatedPortKey]struct{}
	portCursor      int
	randomState     uint64
}

// Network is a deterministic in-memory datagram router. It never opens a
// socket, starts a listener, resolves DNS, or performs operating-system I/O.
type Network struct {
	mu sync.Mutex

	config       Config
	closed       bool
	nats         []*NAT
	natNames     map[string]*NAT
	publicOwners map[netip.Addr]*NAT
	connections  map[*PacketConn]struct{}
	endpoints    map[endpointKey]*PacketConn
	directRoutes map[netip.AddrPort]*PacketConn
	routes       map[externalRouteKey]externalRoute
	counters     Counters
}

// NewNetwork creates one empty deterministic simulation universe.
func NewNetwork(config Config) (*Network, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Network{
		config:       normalized,
		natNames:     make(map[string]*NAT),
		publicOwners: make(map[netip.Addr]*NAT),
		connections:  make(map[*PacketConn]struct{}),
		endpoints:    make(map[endpointKey]*PacketConn),
		directRoutes: make(map[netip.AddrPort]*PacketConn),
		routes:       make(map[externalRouteKey]externalRoute),
	}, nil
}

// NewNAT adds one translation layer. NATs may later be composed into a chain
// to model CGNAT.
func (network *Network) NewNAT(config NATConfig) (*NAT, error) {
	if network == nil {
		return nil, ErrClosed
	}
	validated, err := validateNATConfig(config)
	if err != nil {
		return nil, err
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.closed {
		return nil, ErrClosed
	}
	if _, exists := network.natNames[validated.Name]; exists {
		return nil, fmt.Errorf("%w: duplicate NAT name %q", ErrAddressInUse, validated.Name)
	}
	if owner := network.publicOwners[validated.PublicAddr]; owner != nil {
		return nil, fmt.Errorf("%w: public address %s belongs to NAT %q", ErrAddressInUse, validated.PublicAddr, owner.name)
	}
	nat := &NAT{
		network:     network,
		name:        validated.Name,
		publicAddr:  validated.PublicAddr,
		model:       validated.Model,
		changes:     validated.Changes,
		mappings:    make(map[mappingKey]*natMapping),
		usedPorts:   make(map[allocatedPortKey]struct{}),
		portCursor:  validated.Model.PortMin,
		randomState: validated.Model.RandomSeed,
	}
	network.nats = append(network.nats, nat)
	network.natNames[nat.name] = nat
	network.publicOwners[nat.publicAddr] = nat
	return nat, nil
}

// NewPacketConn creates an injectable net.PacketConn-compatible endpoint.
func (network *Network) NewPacketConn(config EndpointConfig) (*PacketConn, error) {
	if network == nil {
		return nil, ErrClosed
	}
	if err := validateEndpoint(config.LocalAddr); err != nil {
		return nil, err
	}
	chain := append([]*NAT(nil), config.NATChain...)
	seen := make(map[*NAT]struct{}, len(chain))
	for index, nat := range chain {
		if nat == nil || nat.network != network {
			return nil, fmt.Errorf("%w: NAT chain entry %d belongs to another network", ErrInvalidConfig, index)
		}
		if _, duplicate := seen[nat]; duplicate {
			return nil, fmt.Errorf("%w: NAT chain repeats %q", ErrInvalidConfig, nat.name)
		}
		seen[nat] = struct{}{}
	}
	var inner *NAT
	if len(chain) > 0 {
		inner = chain[0]
	}
	key := endpointKey{inner: inner, local: config.LocalAddr}

	network.mu.Lock()
	defer network.mu.Unlock()
	if network.closed {
		return nil, ErrClosed
	}
	if network.counters.ActivePacketConns >= network.config.MaxPacketConns {
		return nil, ErrResourceLimit
	}
	if _, exists := network.endpoints[key]; exists {
		return nil, fmt.Errorf("%w: endpoint %s is already registered behind this inner NAT", ErrAddressInUse, config.LocalAddr)
	}
	if len(chain) == 0 {
		if _, exists := network.directRoutes[config.LocalAddr]; exists {
			return nil, fmt.Errorf("%w: direct endpoint %s", ErrAddressInUse, config.LocalAddr)
		}
	}
	connection := newPacketConn(network, config.LocalAddr, chain, network.config.QueueCapacity)
	network.connections[connection] = struct{}{}
	network.endpoints[key] = connection
	if len(chain) == 0 {
		network.directRoutes[config.LocalAddr] = connection
	}
	network.counters.ActivePacketConns++
	if network.counters.ActivePacketConns > network.counters.PeakPacketConns {
		network.counters.PeakPacketConns = network.counters.ActivePacketConns
	}
	return connection, nil
}

// MappedAddr returns the current outermost mapping created for destination.
// It never creates a mapping; callers create one through PacketConn.WriteTo.
func (network *Network) MappedAddr(connection *PacketConn, destination netip.AddrPort) (netip.AddrPort, error) {
	if network == nil || connection == nil {
		return netip.AddrPort{}, ErrClosed
	}
	if err := validateEndpoint(destination); err != nil {
		return netip.AddrPort{}, err
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.closed || connection.closed.Load() {
		return netip.AddrPort{}, ErrClosed
	}
	if _, exists := network.connections[connection]; !exists {
		return netip.AddrPort{}, ErrClosed
	}
	current := connection.localAddr
	for _, nat := range connection.natChain {
		key := nat.mappingKey(current, destination)
		mapping := nat.mappings[key]
		if mapping == nil {
			return netip.AddrPort{}, ErrNoMapping
		}
		current = mapping.external
	}
	return current, nil
}

// Snapshot returns current and peak resource counts.
func (network *Network) Snapshot() Counters {
	if network == nil {
		return Counters{}
	}
	network.mu.Lock()
	defer network.mu.Unlock()
	return network.counters
}

// Snapshot returns one NAT's current model and generation counters.
func (nat *NAT) Snapshot() NATSnapshot {
	if nat == nil || nat.network == nil {
		return NATSnapshot{}
	}
	nat.network.mu.Lock()
	defer nat.network.mu.Unlock()
	return NATSnapshot{
		Name:            nat.name,
		PublicAddr:      nat.publicAddr,
		Model:           nat.model,
		OutboundPackets: nat.outboundPackets,
		ActiveMappings:  len(nat.mappings),
		AppliedChanges:  nat.nextChange,
	}
}

// Close closes every virtual PacketConn and releases all mappings. It never
// touches operating-system network state.
func (network *Network) Close() error {
	if network == nil {
		return nil
	}
	network.mu.Lock()
	if network.closed {
		network.mu.Unlock()
		return nil
	}
	network.closed = true
	connections := make([]*PacketConn, 0, len(network.connections))
	for connection := range network.connections {
		connections = append(connections, connection)
	}
	network.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	return nil
}

func (network *Network) transmit(connection *PacketConn, packet []byte, destination netip.AddrPort) (int, error) {
	network.mu.Lock()
	defer network.mu.Unlock()
	if network.closed || connection.closed.Load() {
		return 0, ErrClosed
	}
	if _, exists := network.connections[connection]; !exists {
		return 0, ErrClosed
	}
	network.counters.PacketsWritten++
	if len(packet) > network.config.MaxDatagram {
		network.counters.PacketsRejected++
		return 0, ErrMessageTooLarge
	}

	source := connection.localAddr
	for index, nat := range connection.natChain {
		translated, err := nat.translateOutboundLocked(connection, index, source, destination)
		if err != nil {
			network.counters.PacketsRejected++
			return 0, err
		}
		source = translated
	}

	if direct := network.directRoutes[destination]; direct != nil {
		network.deliverLocked(direct, packet, source)
		return len(packet), nil
	}
	route, exists := network.routes[externalRouteKey{external: destination, destination: source}]
	if !exists {
		route, exists = network.routes[externalRouteKey{external: destination}]
	}
	if !exists || route.connection == nil || route.connection.closed.Load() {
		network.counters.PacketsDropped++
		return len(packet), nil
	}
	internalDestination := destination
	for index := route.chainIndex; index >= 0; index-- {
		translated, allowed := route.connection.natChain[index].translateInboundLocked(internalDestination, source)
		if !allowed {
			network.counters.PacketsDropped++
			return len(packet), nil
		}
		internalDestination = translated
	}
	if internalDestination != route.connection.localAddr {
		network.counters.PacketsDropped++
		return len(packet), nil
	}
	network.deliverLocked(route.connection, packet, source)
	return len(packet), nil
}

func (network *Network) deliverLocked(destination *PacketConn, packet []byte, source netip.AddrPort) {
	if destination == nil || destination.closed.Load() {
		network.counters.PacketsDropped++
		return
	}
	datagram := virtualDatagram{packet: append([]byte(nil), packet...), source: source}
	select {
	case destination.inbound <- datagram:
		network.counters.QueuedPackets++
		network.counters.PacketsDelivered++
		if network.counters.QueuedPackets > network.counters.PeakQueuedPackets {
			network.counters.PeakQueuedPackets = network.counters.QueuedPackets
		}
	default:
		network.counters.PacketsDropped++
	}
}

func (network *Network) consumeQueued() {
	network.mu.Lock()
	if network.counters.QueuedPackets > 0 {
		network.counters.QueuedPackets--
	}
	network.mu.Unlock()
}

func (network *Network) closePacketConn(connection *PacketConn) {
	network.mu.Lock()
	defer network.mu.Unlock()
	if _, exists := network.connections[connection]; !exists {
		return
	}
	delete(network.connections, connection)
	var inner *NAT
	if len(connection.natChain) > 0 {
		inner = connection.natChain[0]
	}
	delete(network.endpoints, endpointKey{inner: inner, local: connection.localAddr})
	if len(connection.natChain) == 0 && network.directRoutes[connection.localAddr] == connection {
		delete(network.directRoutes, connection.localAddr)
	}
	for _, nat := range network.nats {
		network.removeConnectionMappingsLocked(nat, connection)
	}
	for {
		select {
		case <-connection.inbound:
			if network.counters.QueuedPackets > 0 {
				network.counters.QueuedPackets--
			}
		default:
			if network.counters.ActivePacketConns > 0 {
				network.counters.ActivePacketConns--
			}
			return
		}
	}
}

func (network *Network) removeConnectionMappingsLocked(nat *NAT, connection *PacketConn) {
	for key, mapping := range nat.mappings {
		if mapping.connection != connection {
			continue
		}
		network.removeMappingLocked(nat, key, mapping)
	}
}

func (network *Network) removeMappingLocked(nat *NAT, key mappingKey, mapping *natMapping) {
	delete(nat.mappings, key)
	delete(nat.usedPorts, nat.allocatedPortKey(mapping.external.Port(), mapping.key.destination))
	routeKey := nat.externalRouteKey(mapping.external, mapping.key.destination)
	if route, exists := network.routes[routeKey]; exists && route.nat == nat && route.connection == mapping.connection && route.chainIndex == mapping.chainIndex {
		delete(network.routes, routeKey)
	}
	if network.counters.ActiveMappings > 0 {
		network.counters.ActiveMappings--
	}
}

func (network *Network) clearNATMappingsLocked(nat *NAT) {
	for key, mapping := range nat.mappings {
		network.removeMappingLocked(nat, key, mapping)
	}
	nat.mappings = make(map[mappingKey]*natMapping)
	nat.usedPorts = make(map[allocatedPortKey]struct{})
}

func (nat *NAT) mappingKey(internal, destination netip.AddrPort) mappingKey {
	key := mappingKey{internal: internal}
	if nat.model.Mapping == MappingEndpointDependent {
		key.destination = destination
	}
	return key
}

func (nat *NAT) translateOutboundLocked(connection *PacketConn, chainIndex int, internal, destination netip.AddrPort) (netip.AddrPort, error) {
	if err := nat.applyChangesLocked(); err != nil {
		return netip.AddrPort{}, err
	}
	nat.outboundPackets++
	if nat.model.UDPBlocked {
		return netip.AddrPort{}, ErrUDPBlocked
	}
	key := nat.mappingKey(internal, destination)
	mapping := nat.mappings[key]
	if mapping == nil {
		if nat.network.counters.ActiveMappings >= nat.network.config.MaxMappings {
			return netip.AddrPort{}, ErrResourceLimit
		}
		port, err := nat.allocatePortLocked(internal.Port(), destination)
		if err != nil {
			return netip.AddrPort{}, err
		}
		mapping = &natMapping{
			key:              key,
			internal:         internal,
			external:         netip.AddrPortFrom(nat.publicAddr, port),
			connection:       connection,
			chainIndex:       chainIndex,
			allowedAddresses: make(map[netip.Addr]struct{}),
			allowedEndpoints: make(map[netip.AddrPort]struct{}),
		}
		nat.mappings[key] = mapping
		nat.network.routes[nat.externalRouteKey(mapping.external, destination)] = externalRoute{connection: connection, chainIndex: chainIndex, nat: nat}
		nat.network.counters.ActiveMappings++
		if nat.network.counters.ActiveMappings > nat.network.counters.PeakMappings {
			nat.network.counters.PeakMappings = nat.network.counters.ActiveMappings
		}
	}
	mapping.allowedAddresses[destination.Addr()] = struct{}{}
	mapping.allowedEndpoints[destination] = struct{}{}
	return mapping.external, nil
}

func (nat *NAT) translateInboundLocked(external, source netip.AddrPort) (netip.AddrPort, bool) {
	var mapping *natMapping
	for _, candidate := range nat.mappings {
		if candidate.external == external && (!nat.model.EndpointDependentPortReuse || candidate.key.destination == source) {
			mapping = candidate
			break
		}
	}
	if mapping == nil {
		return netip.AddrPort{}, false
	}
	switch nat.model.Filtering {
	case FilterEndpointIndependent:
		return mapping.internal, true
	case FilterAddressDependent:
		_, allowed := mapping.allowedAddresses[source.Addr()]
		return mapping.internal, allowed
	case FilterAddressPortDependent:
		_, allowed := mapping.allowedEndpoints[source]
		return mapping.internal, allowed
	default:
		return netip.AddrPort{}, false
	}
}

func (nat *NAT) applyChangesLocked() error {
	for nat.nextChange < len(nat.changes) && nat.outboundPackets >= nat.changes[nat.nextChange].AfterOutboundPackets {
		change := nat.changes[nat.nextChange]
		newPublic := nat.publicAddr
		if change.PublicAddr.IsValid() {
			newPublic = change.PublicAddr
		}
		if owner := nat.network.publicOwners[newPublic]; owner != nil && owner != nat {
			return fmt.Errorf("%w: changed public address %s belongs to NAT %q", ErrAddressInUse, newPublic, owner.name)
		}
		nat.network.clearNATMappingsLocked(nat)
		if newPublic != nat.publicAddr {
			delete(nat.network.publicOwners, nat.publicAddr)
			nat.publicAddr = newPublic
			nat.network.publicOwners[nat.publicAddr] = nat
		}
		nat.model = change.Model
		nat.portCursor = nat.model.PortMin
		nat.randomState = nat.model.RandomSeed
		nat.nextChange++
	}
	return nil
}

func (nat *NAT) allocatePortLocked(internalPort uint16, destination netip.AddrPort) (uint16, error) {
	if nat.model.Allocation == PortPreserving {
		internal := int(internalPort)
		key := nat.allocatedPortKey(internalPort, destination)
		if _, used := nat.usedPorts[key]; internal >= nat.model.PortMin && internal <= nat.model.PortMax && !used {
			nat.usedPorts[key] = struct{}{}
			return internalPort, nil
		}
	}
	span := nat.model.PortMax - nat.model.PortMin + 1
	randomStart := 0
	if nat.model.Allocation == PortRandom {
		nat.randomState = nat.randomState*6364136223846793005 + 1442695040888963407
		randomStart = int(nat.randomState % uint64(span))
	}
	for attempts := 0; attempts < span; attempts++ {
		var candidate int
		switch nat.model.Allocation {
		case PortRandom:
			candidate = nat.model.PortMin + (randomStart+attempts)%span
		default:
			candidate = nat.portCursor
			nat.portCursor++
			if nat.portCursor > nat.model.PortMax {
				nat.portCursor = nat.model.PortMin
			}
		}
		port := uint16(candidate)
		key := nat.allocatedPortKey(port, destination)
		if _, used := nat.usedPorts[key]; used {
			continue
		}
		nat.usedPorts[key] = struct{}{}
		return port, nil
	}
	return 0, ErrResourceLimit
}

func (nat *NAT) allocatedPortKey(port uint16, destination netip.AddrPort) allocatedPortKey {
	key := allocatedPortKey{port: port}
	if nat.model.EndpointDependentPortReuse {
		key.destination = destination
	}
	return key
}

func (nat *NAT) externalRouteKey(external, destination netip.AddrPort) externalRouteKey {
	key := externalRouteKey{external: external}
	if nat.model.EndpointDependentPortReuse {
		key.destination = destination
	}
	return key
}
