//go:build linux && natlab

package natlab

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"winkyou/internal/v2/hardnatcontrol"
	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

const (
	gateB2TUNTable         = "102"
	gateB2TUNRulePriority  = "102"
	gateB2MappingPortMin   = uint16(40000)
	gateB2MappingPortMax   = uint16(49000)
	gateB2RouterDrain      = 2 * time.Second
	gateB2NATQueueDefault  = 1_024
	gateB3PerNATMappingCap = 40_000
)

var (
	errGateB2NATOutbound   = errors.New("Gate B2 isolated NAT outbound forwarding failed")
	errGateB2NATInbound    = errors.New("Gate B2 isolated NAT inbound injection failed")
	errGateB2NATTUNRead    = errors.New("Gate B2 isolated NAT TUN read failed")
	errGateB2NATNamespace  = errors.New("Gate B2 isolated NAT namespace runner failed")
	errGateB2NATDrain      = errors.New("Gate B2 isolated NAT drain timed out")
	errGateB3NATMappingCap = errors.New("Gate B3 isolated NAT mapping hard cap reached")
)

type gateB2NATMode uint8

const (
	gateB2NATAPDM gateB2NATMode = iota + 1
	gateB2NATEIM
)

// gateB2FavorablePorts fixes one favorable 128x512 collision sample for the
// required asymmetric executor proof. It does not estimate probability: the
// independent natsim repetition matrix owns that evidence. The target-set NAT
// records its already-frozen destination set before the delayed mapping-set
// schedule begins, and the APDM test allocator consumes a non-repeating prefix.
type gateB2FavorablePorts struct {
	mu    sync.Mutex
	seen  map[uint16]struct{}
	ports []uint16
	next  int
}

func newGateB2FavorablePorts() *gateB2FavorablePorts {
	return &gateB2FavorablePorts{seen: make(map[uint16]struct{}, 512)}
}

func (ports *gateB2FavorablePorts) record(port uint16) {
	if ports == nil || port == 0 {
		return
	}
	ports.mu.Lock()
	defer ports.mu.Unlock()
	if _, exists := ports.seen[port]; exists {
		return
	}
	ports.seen[port] = struct{}{}
	ports.ports = append(ports.ports, port)
}

func (ports *gateB2FavorablePorts) take() (uint16, bool) {
	if ports == nil {
		return 0, false
	}
	ports.mu.Lock()
	defer ports.mu.Unlock()
	if ports.next >= len(ports.ports) {
		return 0, false
	}
	port := ports.ports[ports.next]
	ports.next++
	return port, true
}

func (ports *gateB2FavorablePorts) count() int {
	if ports == nil {
		return 0
	}
	ports.mu.Lock()
	defer ports.mu.Unlock()
	return len(ports.ports)
}

type gateB2NATConfig struct {
	namespace                 string
	tunName                   string
	private                   netip.Addr
	public                    netip.Addr
	peerPublic                netip.Addr
	mode                      gateB2NATMode
	recordTargets             *gateB2FavorablePorts
	useFavorable              *gateB2FavorablePorts
	mappingPortMin            uint16
	mappingPortMax            uint16
	randomSeed                uint64
	reusePortsByTarget        bool
	dropAllCandidateInbound   bool
	dropEveryCandidateInbound uint64
	mappingHardCap            int
	packetQueueCapacity       int
	gateB3MappingPlan         interface {
		preferred(context.Context, bool, uint16) (uint16, error)
	}
	gateB3MappingPlanLeft bool
	// Test-only read-only observation of the reverse kernel pinhole before
	// forwarding the sole winner. The callback must not create/refresh a flow.
	gateB3BeforeWinner func(netip.AddrPort, netip.AddrPort) error
}

type gateB2UsedPort struct {
	port   uint16
	target netip.AddrPort
}

type gateB2NATKey struct {
	internalPort uint16
	target       netip.AddrPort
}

type gateB2NATMapping struct {
	connection *net.UDPConn
	internal   netip.AddrPort
	public     netip.AddrPort
	allowed    map[netip.AddrPort]struct{}
	createdAt  time.Time
}

type gateB2TUNPacket struct {
	source      netip.AddrPort
	destination netip.AddrPort
	payload     []byte
}

type gateB2MappedReply struct {
	mapping *gateB2NATMapping
	source  netip.AddrPort
	payload []byte
}

type gateB2NATWitness struct {
	Mappings           int
	Outbound           uint64
	Inbound            uint64
	DroppedInbound     uint64
	PeakMappings       int
	MappingHardCap     int
	MappingCapHit      bool
	CandidateInbound   uint64
	WinnerOutbound     uint64
	WinnerInbound      uint64
	WinnerMappingAgeMS int64
}

type gateB2NATRouter struct {
	config gateB2NATConfig

	ctx    context.Context
	cancel context.CancelFunc
	ready  chan error
	done   chan error

	tunMu sync.Mutex
	tun   *os.File

	mappingsMu  sync.Mutex
	mappings    map[gateB2NATKey]*gateB2NATMapping
	all         []*gateB2NATMapping
	pending     int
	nextPort    uint16
	randomState uint64
	usedPorts   map[gateB2UsedPort]struct{}

	readers sync.WaitGroup
	close   sync.Once

	outbound           atomic.Uint64
	inbound            atomic.Uint64
	droppedInbound     atomic.Uint64
	candidateInbound   atomic.Uint64
	winnerOutbound     atomic.Uint64
	winnerInbound      atomic.Uint64
	winnerMappingAgeMS atomic.Int64
	peakMappings       atomic.Int64
	mappingCapHit      atomic.Bool
}

func startGateB2NATRouter(t testing.TB, config gateB2NATConfig) *gateB2NATRouter {
	t.Helper()
	if config.mappingPortMin == 0 {
		config.mappingPortMin = gateB2MappingPortMin
	}
	if config.mappingPortMax == 0 {
		config.mappingPortMax = gateB2MappingPortMax
	}
	if config.randomSeed == 0 {
		config.randomSeed = 1
	}
	if config.packetQueueCapacity == 0 {
		config.packetQueueCapacity = gateB2NATQueueDefault
	}
	if config.namespace == "" || config.tunName == "" || !config.private.Is4() || !config.public.Is4() ||
		!config.peerPublic.Is4() || (config.mode != gateB2NATAPDM && config.mode != gateB2NATEIM) ||
		config.mappingPortMin > config.mappingPortMax || config.mappingHardCap < 0 ||
		config.packetQueueCapacity < 1 || config.packetQueueCapacity > gateB3PerNATMappingCap ||
		(config.reusePortsByTarget && config.mode != gateB2NATAPDM) ||
		(config.gateB3MappingPlan != nil && (!config.reusePortsByTarget || config.mode != gateB2NATAPDM)) {
		t.Fatal("Gate B2 isolated NAT configuration rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	router := &gateB2NATRouter{
		config: config, ctx: ctx, cancel: cancel, ready: make(chan error, 1), done: make(chan error, 1),
		mappings: make(map[gateB2NATKey]*gateB2NATMapping), nextPort: config.mappingPortMin,
		randomState: config.randomSeed, usedPorts: make(map[gateB2UsedPort]struct{}),
	}
	go func() {
		router.done <- RunInNamespace(config.namespace, router.run)
	}()
	select {
	case err := <-router.ready:
		if err != nil {
			cancel()
			t.Fatal("Gate B2 isolated NAT TUN startup failed")
		}
	case <-time.After(gateB2RouterDrain):
		cancel()
		t.Fatal("Gate B2 isolated NAT TUN startup timed out")
	}
	if err := router.configureNamespace(); err != nil {
		_ = router.Close()
		t.Fatal("Gate B2 isolated NAT route setup failed")
	}
	t.Cleanup(func() { _ = router.Close() })
	return router
}

func (router *gateB2NATRouter) run() error {
	tun, err := openGateB2TUN(router.config.tunName)
	if err != nil {
		router.ready <- err
		return err
	}
	router.tunMu.Lock()
	router.tun = tun
	router.tunMu.Unlock()
	router.ready <- nil

	outbound := make(chan gateB2TUNPacket, router.config.packetQueueCapacity)
	replies := make(chan gateB2MappedReply, router.config.packetQueueCapacity)
	readErr := make(chan error, 1)
	router.readers.Add(1)
	go router.readTUN(tun, outbound, readErr)

	var runErr error
	for runErr == nil {
		select {
		case packet := <-outbound:
			if err := router.forwardOutbound(packet, replies); err != nil {
				runErr = errors.Join(errGateB2NATOutbound, err)
			}
			clear(packet.payload)
		case reply := <-replies:
			if err := router.forwardInbound(tun, reply); err != nil {
				runErr = errors.Join(errGateB2NATInbound, err)
			}
			clear(reply.payload)
		case err := <-readErr:
			if router.ctx.Err() == nil {
				runErr = errors.Join(errGateB2NATTUNRead, err)
			}
		case <-router.ctx.Done():
			runErr = router.ctx.Err()
		}
	}
	router.closeDescriptors()
	router.readers.Wait()
	if errors.Is(runErr, context.Canceled) || errors.Is(runErr, net.ErrClosed) || errors.Is(runErr, os.ErrClosed) {
		return nil
	}
	return runErr
}

func (router *gateB2NATRouter) configureNamespace() error {
	commands := [][]string{
		{"link", "set", "dev", router.config.tunName, "up"},
		{"route", "replace", "table", gateB2TUNTable, "default", "dev", router.config.tunName},
		{"rule", "add", "priority", gateB2TUNRulePriority, "iif", "lan0", "lookup", gateB2TUNTable},
	}
	for _, args := range commands {
		command := append([]string{"ip", "-n", router.config.namespace}, args...)
		if _, err := runCommand(command[0], command[1:]...); err != nil {
			return err
		}
	}
	if _, err := runNamespaced(router.config.namespace, "sysctl", nil,
		"-qw", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0"); err != nil {
		return err
	}
	_, err := runNamespaced(router.config.namespace, "iptables", nil,
		"-w", "5", "-I", "INPUT", "1", "-i", "wan0", "-p", "udp", "-d", router.config.public.String(),
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	return err
}

func openGateB2TUN(name string) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, request); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "gate-b2-isolated-tun")
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("Gate B2 TUN descriptor wrapping failed")
	}
	return file, nil
}

func (router *gateB2NATRouter) readTUN(tun *os.File, packets chan<- gateB2TUNPacket, failures chan<- error) {
	defer router.readers.Done()
	buffer := make([]byte, 65535)
	defer clear(buffer)
	for {
		n, err := tun.Read(buffer)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-timer.C:
				case <-router.ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					return
				}
				continue
			}
			select {
			case failures <- err:
			case <-router.ctx.Done():
			}
			return
		}
		packet, err := parseGateB2IPv4UDP(buffer[:n])
		if err != nil || packet.source.Addr() != router.config.private {
			continue
		}
		select {
		case packets <- packet:
		case <-router.ctx.Done():
			clear(packet.payload)
			return
		}
	}
}

func (router *gateB2NATRouter) forwardOutbound(packet gateB2TUNPacket, replies chan<- gateB2MappedReply) error {
	key := gateB2NATKey{internalPort: packet.source.Port()}
	if router.config.mode == gateB2NATAPDM {
		key.target = packet.destination
	}
	router.mappingsMu.Lock()
	mapping := router.mappings[key]
	router.mappingsMu.Unlock()
	if mapping == nil {
		var err error
		mapping, err = router.newMapping(key, packet.source, packet.destination, replies)
		if err != nil {
			return err
		}
	}
	mapping.allowed[packet.destination] = struct{}{}
	if router.config.recordTargets != nil && packet.destination.Addr() == router.config.peerPublic {
		router.config.recordTargets.record(packet.destination.Port())
	}
	if metadata, err := hardnatcontrol.InspectFrame(packet.payload); err == nil && metadata.Type == hardnatcontrol.FrameWinner && router.config.gateB3BeforeWinner != nil {
		if err := router.config.gateB3BeforeWinner(mapping.public, packet.destination); err != nil {
			return err
		}
	}
	var _, err = mapping.connection.WriteToUDPAddrPort(packet.payload, packet.destination)
	if router.config.reusePortsByTarget {
		_, err = mapping.connection.Write(packet.payload)
	}
	if err != nil {
		return err
	}
	router.outbound.Add(1)
	if metadata, inspectErr := hardnatcontrol.InspectFrame(packet.payload); inspectErr == nil && metadata.Type == hardnatcontrol.FrameWinner {
		router.winnerOutbound.Add(1)
		router.winnerMappingAgeMS.Store(time.Since(mapping.createdAt).Milliseconds())
	}
	return nil
}

func (router *gateB2NATRouter) newMapping(key gateB2NATKey, internal, target netip.AddrPort,
	replies chan<- gateB2MappedReply,
) (*gateB2NATMapping, error) {
	router.mappingsMu.Lock()
	if existing := router.mappings[key]; existing != nil {
		router.mappingsMu.Unlock()
		return existing, nil
	}
	reserved := router.config.mappingHardCap > 0
	if reserved && len(router.all)+router.pending >= router.config.mappingHardCap {
		router.mappingCapHit.Store(true)
		router.mappingsMu.Unlock()
		return nil, errGateB3NATMappingCap
	}
	if reserved {
		router.pending++
	}
	router.mappingsMu.Unlock()
	releaseReservation := func() {
		if !reserved {
			return
		}
		router.mappingsMu.Lock()
		router.pending--
		router.mappingsMu.Unlock()
	}

	var preferred uint16
	if router.config.useFavorable != nil && target.Addr() == router.config.peerPublic {
		var ok bool
		preferred, ok = router.config.useFavorable.take()
		if !ok {
			releaseReservation()
			return nil, errors.New("Gate B2 favorable allocation was not ready before mapping schedule")
		}
	}
	connection, public, err := router.openMappedSocket(preferred, target)
	if err != nil {
		releaseReservation()
		return nil, err
	}
	mapping := &gateB2NATMapping{
		connection: connection, internal: internal, public: public,
		allowed:   make(map[netip.AddrPort]struct{}, 512),
		createdAt: time.Now(),
	}
	router.mappingsMu.Lock()
	if reserved {
		router.pending--
	}
	if existing := router.mappings[key]; existing != nil {
		router.mappingsMu.Unlock()
		_ = connection.Close()
		return existing, nil
	}
	router.mappings[key] = mapping
	router.all = append(router.all, mapping)
	count := len(router.all)
	router.mappingsMu.Unlock()
	for {
		peak := router.peakMappings.Load()
		if int64(count) <= peak || router.peakMappings.CompareAndSwap(peak, int64(count)) {
			break
		}
	}
	router.readers.Add(1)
	go router.readMapped(mapping, replies)
	return mapping, nil
}

func (router *gateB2NATRouter) openMappedSocket(preferred uint16, target netip.AddrPort) (*net.UDPConn, netip.AddrPort, error) {
	try := func(port uint16) (*net.UDPConn, netip.AddrPort, error) {
		endpoint := netip.AddrPortFrom(router.config.public, port)
		if router.config.reusePortsByTarget {
			key := gateB2UsedPort{port: port, target: target}
			if _, exists := router.usedPorts[key]; exists {
				return nil, netip.AddrPort{}, errors.New("Gate B3 isolated NAT four-tuple already allocated")
			}
			connection, err := dialGateB3MappedSocket(router.ctx, endpoint, target)
			if err == nil {
				router.usedPorts[key] = struct{}{}
			}
			return connection, endpoint, err
		}
		connection, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
		return connection, endpoint, err
	}
	planned := false
	if router.config.gateB3MappingPlan != nil && target.Addr() == router.config.peerPublic {
		var err error
		preferred, err = router.config.gateB3MappingPlan.preferred(
			router.ctx, router.config.gateB3MappingPlanLeft, target.Port(),
		)
		if err != nil || preferred < router.config.mappingPortMin || preferred > router.config.mappingPortMax {
			return nil, netip.AddrPort{}, errors.Join(errors.New("Gate B3 isolated NAT mapping plan failed"), err)
		}
		planned = true
	}
	if preferred != 0 {
		connection, endpoint, err := try(preferred)
		if err == nil {
			return connection, endpoint, nil
		}
		if planned {
			return nil, netip.AddrPort{}, err
		}
		// A favorable set has ample disjoint ports. Skip a local collision but
		// never synthesize a port outside the peer's committed target set.
		for router.config.useFavorable != nil {
			next, ok := router.config.useFavorable.take()
			if !ok {
				return nil, netip.AddrPort{}, err
			}
			connection, endpoint, nextErr := try(next)
			if nextErr == nil {
				return connection, endpoint, nil
			}
			err = nextErr
		}
	}
	span := uint64(router.config.mappingPortMax-router.config.mappingPortMin) + 1
	randomStart := uint64(0)
	if router.config.reusePortsByTarget {
		router.randomState = router.randomState*6364136223846793005 + 1442695040888963407
		randomStart = router.randomState % span
	}
	for attempts := uint64(0); attempts < span; attempts++ {
		port := router.nextPort
		if router.config.reusePortsByTarget {
			port = router.config.mappingPortMin + uint16((randomStart+attempts)%span)
		} else {
			router.nextPort++
			if router.nextPort > router.config.mappingPortMax {
				router.nextPort = router.config.mappingPortMin
			}
		}
		connection, endpoint, err := try(port)
		if err == nil {
			return connection, endpoint, nil
		}
	}
	return nil, netip.AddrPort{}, errors.New("Gate B2 isolated NAT mapping range exhausted")
}

func dialGateB3MappedSocket(ctx context.Context, local, remote netip.AddrPort) (*net.UDPConn, error) {
	dialer := net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(local),
		Control: func(_, _ string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(descriptor uintptr) {
				if err := unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					controlErr = err
					return
				}
				controlErr = unix.SetsockoptInt(int(descriptor), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	connection, err := dialer.DialContext(ctx, "udp4", remote.String())
	if err != nil {
		return nil, err
	}
	udp, ok := connection.(*net.UDPConn)
	if !ok {
		_ = connection.Close()
		return nil, errors.New("Gate B3 isolated NAT dial did not return UDP")
	}
	return udp, nil
}

func (router *gateB2NATRouter) readMapped(mapping *gateB2NATMapping, replies chan<- gateB2MappedReply) {
	defer router.readers.Done()
	buffer := make([]byte, 65535)
	defer clear(buffer)
	for {
		n, source, err := mapping.connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return
		}
		payload := append([]byte(nil), buffer[:n]...)
		select {
		case replies <- gateB2MappedReply{mapping: mapping, source: source, payload: payload}:
		case <-router.ctx.Done():
			clear(payload)
			return
		}
	}
}

func (router *gateB2NATRouter) forwardInbound(tun *os.File, reply gateB2MappedReply) error {
	if reply.mapping == nil {
		return errors.New("Gate B2 isolated NAT reply lacked a mapping")
	}
	if _, allowed := reply.mapping.allowed[reply.source]; !allowed {
		router.droppedInbound.Add(1)
		return nil
	}
	if metadata, err := hardnatcontrol.InspectFrame(reply.payload); err == nil && metadata.Type == hardnatcontrol.FrameCandidate {
		ordinal := router.candidateInbound.Add(1)
		if router.config.dropAllCandidateInbound ||
			(router.config.dropEveryCandidateInbound > 0 && ordinal%router.config.dropEveryCandidateInbound == 0) {
			router.droppedInbound.Add(1)
			return nil
		}
	}
	packet, err := buildGateB2IPv4UDP(reply.source, reply.mapping.internal, reply.payload)
	if err != nil {
		return err
	}
	defer clear(packet)
	n, err := tun.Write(packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return errors.New("Gate B2 isolated NAT short TUN write")
	}
	router.inbound.Add(1)
	if metadata, err := hardnatcontrol.InspectFrame(reply.payload); err == nil && metadata.Type == hardnatcontrol.FrameWinner {
		router.winnerInbound.Add(1)
	}
	return nil
}

func (router *gateB2NATRouter) Witness() gateB2NATWitness {
	if router == nil {
		return gateB2NATWitness{}
	}
	router.mappingsMu.Lock()
	mappings := len(router.all)
	router.mappingsMu.Unlock()
	return gateB2NATWitness{
		Mappings: mappings, Outbound: router.outbound.Load(), Inbound: router.inbound.Load(),
		DroppedInbound: router.droppedInbound.Load(), PeakMappings: int(router.peakMappings.Load()),
		MappingHardCap: router.config.mappingHardCap, MappingCapHit: router.mappingCapHit.Load(),
		CandidateInbound: router.candidateInbound.Load(), WinnerOutbound: router.winnerOutbound.Load(),
		WinnerInbound: router.winnerInbound.Load(), WinnerMappingAgeMS: router.winnerMappingAgeMS.Load(),
	}
}

func (router *gateB2NATRouter) closeDescriptors() {
	if router == nil {
		return
	}
	router.tunMu.Lock()
	if router.tun != nil {
		_ = router.tun.Close()
		router.tun = nil
	}
	router.tunMu.Unlock()
	router.mappingsMu.Lock()
	for _, mapping := range router.all {
		_ = mapping.connection.Close()
	}
	router.mappingsMu.Unlock()
}

func (router *gateB2NATRouter) Close() error {
	if router == nil {
		return nil
	}
	var closeErr error
	router.close.Do(func() {
		router.cancel()
		router.closeDescriptors()
		select {
		case closeErr = <-router.done:
			if closeErr != nil && !errors.Is(closeErr, errGateB2NATOutbound) &&
				!errors.Is(closeErr, errGateB2NATInbound) && !errors.Is(closeErr, errGateB2NATTUNRead) {
				closeErr = errors.Join(errGateB2NATNamespace, closeErr)
			}
		case <-time.After(gateB2RouterDrain):
			closeErr = errGateB2NATDrain
		}
	})
	return closeErr
}

func gateB2NATDrainClass(err error) string {
	switch {
	case err == nil:
		return "clean"
	case errors.Is(err, errGateB2NATOutbound):
		return "outbound_forward"
	case errors.Is(err, errGateB2NATInbound):
		return "inbound_inject"
	case errors.Is(err, errGateB2NATTUNRead):
		return "tun_read"
	case errors.Is(err, errGateB2NATNamespace):
		return "namespace_runner"
	case errors.Is(err, errGateB2NATDrain):
		return "drain_timeout"
	default:
		return "unknown"
	}
}

func parseGateB2IPv4UDP(packet []byte) (gateB2TUNPacket, error) {
	var result gateB2TUNPacket
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 17 {
		return result, errors.New("not an IPv4 UDP packet")
	}
	header := int(packet[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if header < 20 || total < header+8 || total > len(packet) || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return result, errors.New("invalid IPv4 UDP framing")
	}
	udp := packet[header:total]
	udpLength := int(binary.BigEndian.Uint16(udp[4:6]))
	if udpLength < 8 || udpLength > len(udp) {
		return result, errors.New("invalid UDP length")
	}
	var sourceAddress, destinationAddress [4]byte
	copy(sourceAddress[:], packet[12:16])
	copy(destinationAddress[:], packet[16:20])
	result.source = netip.AddrPortFrom(netip.AddrFrom4(sourceAddress), binary.BigEndian.Uint16(udp[0:2]))
	result.destination = netip.AddrPortFrom(netip.AddrFrom4(destinationAddress), binary.BigEndian.Uint16(udp[2:4]))
	if result.source.Port() == 0 || result.destination.Port() == 0 {
		return gateB2TUNPacket{}, errors.New("zero UDP port")
	}
	result.payload = append([]byte(nil), udp[8:udpLength]...)
	return result, nil
}

func buildGateB2IPv4UDP(source, destination netip.AddrPort, payload []byte) ([]byte, error) {
	if !source.IsValid() || !destination.IsValid() || !source.Addr().Is4() || !destination.Addr().Is4() ||
		source.Port() == 0 || destination.Port() == 0 || len(payload) > 65507 {
		return nil, errors.New("invalid IPv4 UDP injection")
	}
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	sourceAddress, destinationAddress := source.Addr().As4(), destination.Addr().As4()
	copy(packet[12:16], sourceAddress[:])
	copy(packet[16:20], destinationAddress[:])
	binary.BigEndian.PutUint16(packet[10:12], gateB2Checksum(packet[:20]))
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	// IPv4 explicitly permits a zero UDP checksum. The test router does not
	// weaken any product path; it only injects isolated TEST-NET packets.
	copy(udp[8:], payload)
	return packet, nil
}

func gateB2Checksum(packet []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(packet); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	if len(packet)%2 != 0 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

type gateB2ObserverSet struct {
	topology hardnatobserve.Topology
	sockets  [4]*net.UDPConn
	cancel   context.CancelFunc
	readers  sync.WaitGroup
	close    sync.Once
	packets  atomic.Uint64
}

func startGateB2ObserverSet(t testing.TB, namespace string) *gateB2ObserverSet {
	t.Helper()
	set := &gateB2ObserverSet{}
	err := RunInNamespace(namespace, func() error {
		first, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(n2dPublicA), 0)))
		if err != nil {
			return err
		}
		set.sockets[0] = first
		second, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr(n2dPublicA), 0)))
		if err != nil {
			return err
		}
		set.sockets[1] = second
		firstPort := first.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		secondPort := second.LocalAddr().(*net.UDPAddr).AddrPort().Port()
		if firstPort == secondPort {
			return errors.New("Gate B2 observer ports collided")
		}
		set.sockets[2], err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("%s:%d", n2dPublicB, firstPort))))
		if err != nil {
			return err
		}
		set.sockets[3], err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.MustParseAddrPort(fmt.Sprintf("%s:%d", n2dPublicB, secondPort))))
		if err != nil {
			return err
		}
		set.topology = hardnatobserve.Topology{
			Primary: netip.MustParseAddrPort(fmt.Sprintf("%s:%d", n2dPublicA, firstPort)),
			Other:   netip.MustParseAddrPort(fmt.Sprintf("%s:%d", n2dPublicB, secondPort)),
		}
		return nil
	})
	if err != nil {
		_ = set.Close()
		t.Fatal("Gate B2 RFC 5780 observer startup failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	set.cancel = cancel
	endpoints, err := set.topology.Endpoints()
	if err != nil {
		_ = set.Close()
		t.Fatal("Gate B2 RFC 5780 topology rejected")
	}
	for index := range set.sockets {
		set.readers.Add(1)
		go set.serve(ctx, index, endpoints)
	}
	t.Cleanup(func() { _ = set.Close() })
	return set
}

func (set *gateB2ObserverSet) serve(ctx context.Context, index int, endpoints [4]netip.AddrPort) {
	defer set.readers.Done()
	buffer := make([]byte, 1024)
	defer clear(buffer)
	for {
		_ = set.sockets[index].SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, source, err := set.sockets[index].ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		transaction, change, err := hardnatplan.ParseBehaviorBindingRequest(buffer[:n])
		if err != nil {
			continue
		}
		writer := index
		if change.ChangeIP && change.ChangePort {
			writer = 3
		} else if change.ChangePort {
			writer = 1
		}
		response, err := hardnatplan.BuildBehaviorBindingSuccess(transaction, hardnatplan.BehaviorAttributes{
			Mapped: gateB2PlanEndpoint(source), HasMapped: true,
			ResponseOrigin: gateB2PlanEndpoint(endpoints[writer]), HasResponseOrigin: true,
			OtherAddress: gateB2PlanEndpoint(endpoints[3]), HasOtherAddress: true,
		})
		if err == nil {
			_, err = set.sockets[writer].WriteToUDPAddrPort(response, source)
		}
		clear(response)
		if err == nil {
			set.packets.Add(1)
		}
	}
}

func gateB2PlanEndpoint(endpoint netip.AddrPort) hardnatplan.AddressPort {
	address := endpoint.Addr().Unmap()
	if address.Is4() {
		return hardnatplan.AddressPort{Address: hardnatplan.Address4(address.As4()), Port: endpoint.Port()}
	}
	return hardnatplan.AddressPort{Address: hardnatplan.Address6(address.As16()), Port: endpoint.Port()}
}

func (set *gateB2ObserverSet) Close() error {
	if set == nil {
		return nil
	}
	var closeErr error
	set.close.Do(func() {
		if set.cancel != nil {
			set.cancel()
		}
		for _, socket := range set.sockets {
			if socket != nil {
				closeErr = errors.Join(closeErr, socket.Close())
			}
		}
		set.readers.Wait()
	})
	return closeErr
}

func gateB2TUNName(namespace string) string {
	value := "gb2" + namespace
	if len(value) > 15 {
		value = value[len(value)-15:]
	}
	return value
}
