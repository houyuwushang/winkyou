package tunnel

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
)

// InnerTuple matches one exact decrypted transport tuple, never a wildcard.
type InnerTuple struct {
	Src, Dst         netip.Addr
	Proto            uint8
	SrcPort, DstPort uint16
}

// InnerTap must synchronously copy or discard the packet without blocking.
// It may not retain packet memory. False reports a local drop; matched packets
// NEVER fall through to the interface, including on a drop.
type InnerTap interface{ Deliver([]byte) bool }

// InnerTapRegistrar is optional, single-use and limited to caller-owned binds.
// There is one owner and at most two exact tuples, not two registrations.
type InnerTapRegistrar interface {
	SetInnerTap([]InnerTuple, InnerTap) error
}

var ErrInnerTap = errors.New("tunnel: inner tap registration rejected")

type innerTapSlot struct {
	mu                 sync.RWMutex
	tuples             [2]InnerTuple
	count              int
	tap                InnerTap
	registered, closed bool
}

func (w *wggoTunnel) SetInnerTap(tuples []InnerTuple, tap InnerTap) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if !w.started || w.stopped || !w.memoryOnly || w.tunDevice == nil {
		return ErrInnerTap
	}
	return w.tunDevice.innerTap.register(tuples, tap)
}

func (s *innerTapSlot) register(tuples []InnerTuple, tap InnerTap) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.registered || tap == nil || len(tuples) == 0 || len(tuples) > 2 {
		return ErrInnerTap
	}
	for i, tuple := range tuples {
		if !tuple.Src.Is4() || !tuple.Dst.Is4() || tuple.Src == tuple.Dst ||
			tuple.Src.IsUnspecified() || tuple.Dst.IsUnspecified() || tuple.SrcPort == 0 || tuple.DstPort == 0 ||
			(tuple.Proto != 6 && tuple.Proto != 17) || (i > 0 && tuple == tuples[0]) {
			return ErrInnerTap
		}
	}
	copy(s.tuples[:], tuples)
	s.count, s.tap, s.registered = len(tuples), tap, true
	return nil
}

func (s *innerTapSlot) consume(packet []byte) bool {
	if len(packet) < 24 || packet[0]>>4 != 4 {
		return false
	}
	offset := int(packet[0]&15) * 4
	if offset < 20 || offset+4 > len(packet) {
		return false
	}
	tuple := InnerTuple{
		Src: netip.AddrFrom4([4]byte(packet[12:16])), Dst: netip.AddrFrom4([4]byte(packet[16:20])),
		Proto: packet[9], SrcPort: binary.BigEndian.Uint16(packet[offset:]), DstPort: binary.BigEndian.Uint16(packet[offset+2:]),
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed || s.tap == nil {
		return false
	}
	for i := 0; i < s.count; i++ {
		if tuple == s.tuples[i] {
			s.tap.Deliver(packet)
			return true
		}
	}
	return false
}

func (s *innerTapSlot) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed, s.tap, s.count = true, nil, 0
	s.tuples = [2]InnerTuple{}
}
