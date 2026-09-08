package tunnel

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"testing"
)

type tapTestFunc func([]byte) bool

func (f tapTestFunc) Deliver(b []byte) bool { return f(b) }

type tapTestInterface struct{ writes int }

func (*tapTestInterface) Name() string                  { return "tap-test" }
func (*tapTestInterface) MTU() int                      { return 1280 }
func (*tapTestInterface) Read([]byte) (int, error)      { return 0, nil }
func (n *tapTestInterface) Write(b []byte) (int, error) { n.writes++; return len(b), nil }
func (*tapTestInterface) Close() error                  { return nil }

func tapTuple() InnerTuple {
	return InnerTuple{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), 17, 32113, 32113}
}
func tapPacket(tuple InnerTuple) []byte {
	b := make([]byte, 92)
	b[0], b[9] = 0x45, tuple.Proto
	src, dst := tuple.Src.As4(), tuple.Dst.As4()
	copy(b[12:16], src[:])
	copy(b[16:20], dst[:])
	binary.BigEndian.PutUint16(b[20:], tuple.SrcPort)
	binary.BigEndian.PutUint16(b[22:], tuple.DstPort)
	return b
}

func TestInnerTapExactOnceAndDropDoesNotFallThrough(t *testing.T) {
	ni := &tapTestInterface{}
	d := newNetifDevice(ni)
	tuple := tapTuple()
	old := tuple
	old.SrcPort, old.DstPort = 32112, 32112
	seen := 0
	if err := d.innerTap.register([]InnerTuple{tuple, old}, tapTestFunc(func(b []byte) bool { seen++; return false })); err != nil {
		t.Fatal(err)
	}
	business := tuple
	business.DstPort++
	packets := [][]byte{tapPacket(tuple), tapPacket(old), tapPacket(business)}
	n, err := d.Write(packets, 0)
	if err != nil || n != 3 || ni.writes != 1 || seen != 2 {
		t.Fatalf("packets=%d interface=%d tap=%d err=%v", n, ni.writes, seen, err)
	}
	if err := d.innerTap.register([]InnerTuple{tuple}, tapTestFunc(func([]byte) bool { return true })); err == nil {
		t.Fatal("second owner")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if d.innerTap.tap != nil || d.innerTap.consume(tapPacket(tuple)) {
		t.Fatal("retained tap after close")
	}
}

func TestInnerTapRegistrationAuthority(t *testing.T) {
	for _, tc := range []struct {
		started, stopped, memory bool
		ok                       bool
	}{{false, false, true, false}, {true, false, false, false}, {true, true, true, false}, {true, false, true, true}} {
		w := newWGGoTunnel(Config{})
		w.started, w.stopped, w.memoryOnly = tc.started, tc.stopped, tc.memory
		w.tunDevice = newNetifDevice(&tapTestInterface{})
		err := w.SetInnerTap([]InnerTuple{tapTuple()}, tapTestFunc(func([]byte) bool { return true }))
		if (err == nil) != tc.ok {
			t.Fatalf("registration=%v want=%v", err, tc.ok)
		}
	}
	for _, tuples := range [][]InnerTuple{nil, {tapTuple(), tapTuple()}, {tapTuple(), tapTuple(), tapTuple()}, {{}}} {
		var slot innerTapSlot
		if slot.register(tuples, tapTestFunc(func([]byte) bool { return true })) == nil {
			t.Fatal("invalid tuple set")
		}
	}
}

func TestInnerTapCloseJoinsDeliveryAndRejectsRearm(t *testing.T) {
	var slot innerTapSlot
	if err := slot.register([]InnerTuple{tapTuple()}, tapTestFunc(func([]byte) bool { return false })); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	group.Add(1)
	go func() {
		defer group.Done()
		for i := 0; i < 100; i++ {
			slot.consume(tapPacket(tapTuple()))
		}
	}()
	slot.close()
	group.Wait()
	if slot.register([]InnerTuple{tapTuple()}, tapTestFunc(func([]byte) bool { return false })) == nil {
		t.Fatal("rearm after close")
	}
}
