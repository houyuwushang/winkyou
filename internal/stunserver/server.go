package stunserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/internal/stunwire"
)

const (
	DefaultMaxPPS     = 200
	HardMaxPPS        = 200
	PerSourceMaxPPS   = 20
	MaxSourceBuckets  = 4096
	MaxLoggedPrefixes = 256
	SourceIdleLimit   = 5 * time.Minute
)

var (
	ErrInvalidConfig = errors.New("stunserver: invalid configuration")
	ErrAlreadyServed = errors.New("stunserver: Serve may be called only once")
)

// Config fixes every server-side resource bound. MaxPPS may be lowered from
// HardMaxPPS but never raised. ListenAddr port zero is accepted only so tests
// can obtain an OS-selected loopback port; cmd/wink-stund rejects it.
type Config struct {
	ListenAddr  netip.AddrPort
	MaxPPS      int
	LogPrefixes bool
}

// Server owns one UDP socket and a single synchronous receive/respond loop.
// There is no worker queue and no outbound target-selection API.
type Server struct {
	connection   *net.UDPConn
	listenAddr   netip.AddrPort
	maxPPS       int
	perSourcePPS int
	admission    *admissionController
	counters     *counters
	served       atomic.Bool
	closed       atomic.Bool
	closeOnce    sync.Once
}

// Open creates the sole response-only socket owned by wink-stund.
func Open(config Config) (*Server, error) {
	address, maxPPS, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	network := "udp6"
	if address.Addr().Is4() {
		network = "udp4"
	}
	connection, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(address))
	if err != nil {
		return nil, fmt.Errorf("stunserver: listen: %w", err)
	}
	actual, err := udpAddrPort(connection.LocalAddr())
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	perSourcePPS := PerSourceMaxPPS
	if maxPPS < perSourcePPS {
		perSourcePPS = maxPPS
	}
	now := time.Now()
	return &Server{
		connection:   connection,
		listenAddr:   actual,
		maxPPS:       maxPPS,
		perSourcePPS: perSourcePPS,
		admission:    newAdmissionController(maxPPS, perSourcePPS, MaxSourceBuckets, SourceIdleLimit, now),
		counters:     newCounters(config.LogPrefixes),
	}, nil
}

func normalizeConfig(config Config) (netip.AddrPort, int, error) {
	if !config.ListenAddr.IsValid() || config.ListenAddr.Addr().Zone() != "" {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: literal IPv4 or bracketed IPv6 listen address is required", ErrInvalidConfig)
	}
	address := config.ListenAddr.Addr().Unmap()
	if !(address.IsUnspecified() || address.IsLoopback() || address.IsGlobalUnicast()) {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: listen address must be unicast, loopback, or unspecified", ErrInvalidConfig)
	}
	maxPPS := config.MaxPPS
	if maxPPS == 0 {
		maxPPS = DefaultMaxPPS
	}
	if maxPPS < 1 || maxPPS > HardMaxPPS {
		return netip.AddrPort{}, 0, fmt.Errorf("%w: max PPS must be between 1 and %d", ErrInvalidConfig, HardMaxPPS)
	}
	return netip.AddrPortFrom(address, config.ListenAddr.Port()), maxPPS, nil
}

func udpAddrPort(address net.Addr) (netip.AddrPort, error) {
	udpAddress, ok := address.(*net.UDPAddr)
	if !ok || udpAddress == nil {
		return netip.AddrPort{}, fmt.Errorf("%w: UDP listener returned an unexpected address", ErrInvalidConfig)
	}
	endpoint := udpAddress.AddrPort()
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("%w: UDP listener returned an invalid endpoint", ErrInvalidConfig)
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()), nil
}

func (server *Server) ListenAddr() netip.AddrPort {
	if server == nil {
		return netip.AddrPort{}
	}
	return server.listenAddr
}

func (server *Server) MaxPPS() int {
	if server == nil {
		return 0
	}
	return server.maxPPS
}

func (server *Server) PerSourcePPS() int {
	if server == nil {
		return 0
	}
	return server.perSourcePPS
}

func (server *Server) Snapshot() Stats {
	if server == nil || server.counters == nil {
		return Stats{}
	}
	return server.counters.snapshot()
}

// Serve processes requests synchronously. Cancellation wakes the one blocked
// read; no per-request goroutine or queue is created.
func (server *Server) Serve(ctx context.Context) error {
	if server == nil || server.connection == nil || ctx == nil {
		return ErrInvalidConfig
	}
	if !server.served.CompareAndSwap(false, true) {
		return ErrAlreadyServed
	}
	wakeDone := make(chan struct{})
	defer close(wakeDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-wakeDone:
		}
	}()

	buffer := make([]byte, stunwire.MaxRequestBytes+1)
	for {
		n, source, err := server.connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || server.closed.Load() || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("stunserver: read: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		server.handlePacket(buffer[:n], source, time.Now())
	}
}

func (server *Server) handlePacket(packet []byte, source netip.AddrPort, now time.Time) {
	server.counters.received.Add(1)
	switch server.admission.allow(source.Addr(), now) {
	case admissionInvalidSource:
		server.counters.invalidSource.Add(1)
		return
	case admissionGlobalRate:
		server.counters.globalRateLimit.Add(1)
		return
	case admissionSourceRate:
		server.counters.sourceRateLimit.Add(1)
		return
	case admissionSourceTableFull:
		server.counters.sourceTableFull.Add(1)
		return
	}

	transaction, err := stunwire.ParseBindingRequest(packet)
	if err != nil {
		server.countRequestError(err)
		return
	}
	mapped := netip.AddrPortFrom(source.Addr().Unmap(), source.Port())
	response, err := stunwire.BindingSuccess(transaction, mapped)
	if err != nil {
		server.counters.invalidMappedEndpoint.Add(1)
		return
	}
	written, err := server.connection.WriteToUDPAddrPort(response, source)
	if err != nil || written != len(response) {
		server.counters.writeFailure.Add(1)
		return
	}
	server.counters.responseFrom(mapped.Addr())
}

func (server *Server) countRequestError(err error) {
	switch {
	case errors.Is(err, stunwire.ErrMessageTooLarge):
		server.counters.messageTooLarge.Add(1)
	case errors.Is(err, stunwire.ErrTruncatedMessage):
		server.counters.truncatedMessage.Add(1)
	case errors.Is(err, stunwire.ErrUnexpectedMessage):
		server.counters.unexpectedMessage.Add(1)
	case errors.Is(err, stunwire.ErrMagicCookieMismatch):
		server.counters.magicCookieMismatch.Add(1)
	case errors.Is(err, stunwire.ErrAttributeLength):
		server.counters.attributeLength.Add(1)
	case errors.Is(err, stunwire.ErrUnknownRequiredAttribute):
		server.counters.unknownRequiredAttribute.Add(1)
	default:
		server.counters.unexpectedMessage.Add(1)
	}
}

func (server *Server) Close() error {
	if server == nil {
		return nil
	}
	var err error
	server.closeOnce.Do(func() {
		server.closed.Store(true)
		if server.connection != nil {
			err = server.connection.Close()
		}
	})
	return err
}
