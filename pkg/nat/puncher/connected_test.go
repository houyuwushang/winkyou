package puncher

import (
	"net"
	"testing"
	"time"
)

// TestConnectedConnWriteReadFilter verifies the peer-fixed wrapper writes to the
// peer and, on read, drops datagrams from other sources.
func TestConnectedConnWriteReadFilter(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	a, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lo})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lo})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	other, err := net.ListenUDP("udp4", &net.UDPAddr{IP: lo})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	aAddr := a.LocalAddr().(*net.UDPAddr)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	res := &Result{Conn: a, RemoteAddr: peerAddr}
	conn := res.Connected()

	// Write goes to the peer.
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 64)
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	n, src, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(buf[:n]) != "hello" || src.Port != aAddr.Port {
		t.Fatalf("peer got %q from %v, want hello from %d", buf[:n], src, aAddr.Port)
	}

	// A packet from an unrelated source must be dropped; the real peer's packet read.
	if _, err := other.WriteToUDP([]byte("spoof"), aAddr); err != nil {
		t.Fatalf("other write: %v", err)
	}
	if _, err := peer.WriteToUDP([]byte("real"), aAddr); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("conn read: %v", err)
	}
	if string(buf[:n]) != "real" {
		t.Fatalf("read %q, want real (spoof should be filtered)", buf[:n])
	}
}

func TestConnectedConnRejectsIncompleteResult(t *testing.T) {
	if conn := (*Result)(nil).Connected(); conn != nil {
		t.Fatalf("nil result produced connection %v", conn)
	}
	conn := (&Result{}).Connected()
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("incomplete connection Read unexpectedly succeeded")
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("incomplete connection Write unexpectedly succeeded")
	}
}
