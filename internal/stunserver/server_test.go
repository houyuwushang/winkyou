package stunserver

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"winkyou/internal/stunwire"
)

func TestListenValidatesLiteralBoundedConfiguration(t *testing.T) {
	for _, config := range []Config{
		{},
		{ListenAddr: netip.MustParseAddrPort("224.0.0.1:3478")},
		{ListenAddr: netip.MustParseAddrPort("127.0.0.1:3478"), MaxPPS: HardMaxPPS + 1},
	} {
		if server, err := Open(config); !errors.Is(err, ErrInvalidConfig) {
			if server != nil {
				_ = server.Close()
			}
			t.Fatalf("Listen(%+v) error = %v, want ErrInvalidConfig", config, err)
		}
	}

	server, err := Open(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0"), MaxPPS: 7})
	if err != nil {
		t.Fatalf("Listen(loopback): %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	if !server.ListenAddr().Addr().IsLoopback() || server.ListenAddr().Port() == 0 || server.MaxPPS() != 7 || server.PerSourcePPS() != 7 {
		t.Fatalf("server limits/address = %s max=%d source=%d", server.ListenAddr(), server.MaxPPS(), server.PerSourcePPS())
	}
}

func TestServeCancellationIsBoundedAndSingleUse(t *testing.T) {
	server, err := Open(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0")})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit after cancellation")
	}
	if err := server.Serve(context.Background()); !errors.Is(err, ErrAlreadyServed) {
		t.Fatalf("second Serve error = %v, want ErrAlreadyServed", err)
	}
}

func TestServeSilentlyDropsInvalidRequestAndCountsReason(t *testing.T) {
	server, err := Open(Config{ListenAddr: netip.MustParseAddrPort("127.0.0.1:0"), MaxPPS: 10})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("Serve did not exit")
		}
	})

	client, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(server.ListenAddr()))
	if err != nil {
		t.Fatalf("dial loopback responder: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	request := make([]byte, stunwire.HeaderBytes)
	binary.BigEndian.PutUint16(request[0:2], stunwire.BindingRequestType)
	// The zero cookie deliberately violates the profile.
	if _, err := client.Write(request); err != nil {
		t.Fatalf("write invalid request: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	if _, err := client.Read(make([]byte, 64)); err == nil {
		t.Fatal("invalid request received a response")
	} else if networkError, ok := err.(net.Error); !ok || !networkError.Timeout() {
		t.Fatalf("invalid request read error = %v, want timeout", err)
	}
	stats := server.Snapshot()
	if stats.Received != 1 || stats.Responded != 0 || stats.Dropped.MagicCookieMismatch != 1 {
		t.Fatalf("invalid request stats = %+v", stats)
	}
}
