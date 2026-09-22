//go:build linux && fieldc1c

package c1crouter

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"winkyou/internal/v2/hardnatplan"
)

// The observer has no protocol initiator and no resolver. All four response
// sockets bind only inside the pre-validated, exclusive transit namespace.
type observerSet struct {
	connections [4]*net.UDPConn
	endpoints   [4]netip.AddrPort
	sources     [2]netip.Addr
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	replies     atomic.Uint64
	received    atomic.Uint64
	done        chan struct{}
	failure     chan error
}

func newObserver(ctx context.Context, ns *os.File, endpoints [4]netip.AddrPort, sources [2]netip.Addr) (*observerSet, error) {
	child, cancel := context.WithCancel(ctx)
	o := &observerSet{ctx: child, cancel: cancel, endpoints: endpoints, sources: sources, done: make(chan struct{}), failure: make(chan error, 1)}
	e := inNamespace(ns, func() error {
		for i, endpoint := range endpoints {
			// owner=sealed-router-observer; response-only, four fixed bindings.
			conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(endpoint))
			if err != nil {
				return errIO
			}
			o.connections[i] = conn
		}
		return nil
	})
	if e != nil {
		o.closeSockets()
		cancel()
		return nil, e
	}
	for i := range o.connections {
		o.wg.Add(1)
		go o.serve(i)
	}
	go func() { o.wg.Wait(); close(o.done) }()
	return o, nil
}

func (o *observerSet) serve(index int) {
	defer o.wg.Done()
	buf := make([]byte, 1025)
	defer clear(buf)
	for {
		n, source, e := o.connections[index].ReadFromUDPAddrPort(buf)
		if e != nil {
			return
		}
		if o.ctx.Err() != nil {
			return
		}
		if source.Addr() != o.sources[0] && source.Addr() != o.sources[1] {
			o.fail(ErrResource)
			return
		}
		if o.received.Add(1) > ObserverPacketCap || n > 1024 {
			o.fail(ErrResource)
			return
		}
		transaction, change, e := hardnatplan.ParseBehaviorBindingRequest(buf[:n])
		if e != nil {
			o.fail(ErrInvalid)
			return
		}
		reply := index
		if change.ChangeIP {
			reply ^= 2
		}
		if change.ChangePort {
			reply ^= 1
		}
		payload, e := hardnatplan.BuildBehaviorBindingSuccess(transaction, hardnatplan.BehaviorAttributes{Mapped: planAddress(source), HasMapped: true, ResponseOrigin: planAddress(o.endpoints[reply]), HasResponseOrigin: true, OtherAddress: planAddress(o.endpoints[reply^3]), HasOtherAddress: true})
		if e != nil {
			o.fail(ErrInvalid)
			return
		}
		if o.ctx.Err() != nil {
			clear(payload)
			return
		}
		_ = o.connections[reply].SetWriteDeadline(time.Now().Add(QueryTimeout))
		n, e = o.connections[reply].WriteToUDPAddrPort(payload, source)
		size := len(payload)
		clear(payload)
		if e != nil || n != size {
			o.fail(errIO)
			return
		}
		o.replies.Add(1)
	}
}

func planAddress(p netip.AddrPort) hardnatplan.AddressPort {
	return hardnatplan.AddressPort{Address: hardnatplan.Address4(p.Addr().As4()), Port: p.Port()}
}
func (o *observerSet) fail(err error) {
	select {
	case o.failure <- err:
	default:
	}
	o.cancel()
	o.closeSockets()
}
func (o *observerSet) closeSockets() {
	for _, c := range o.connections {
		if c != nil {
			_ = c.Close()
		}
	}
}
func (o *observerSet) close() error {
	o.cancel()
	o.closeSockets()
	select {
	case <-o.done:
		return nil
	case <-time.After(DrainTimeout):
		return ErrDrain
	}
}
