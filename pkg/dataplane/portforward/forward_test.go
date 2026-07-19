package portforward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestRunClientServerForwardsTCPOverPunchedUDP(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer target.Close()
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			n, readErr := conn.Read(buf)
			if n > 0 {
				if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
					return
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	serverPacket := mustListenUDP(t)
	clientPacket := mustListenUDP(t)
	serverAddr := serverPacket.LocalAddr().(*net.UDPAddr)
	clientAddr := clientPacket.LocalAddr().(*net.UDPAddr)
	secret := bytes.Repeat([]byte{0x5a}, minimumSecretBytes)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- RunServer(ctx, ServerConfig{
			PacketConn: serverPacket,
			PeerAddr:   clientAddr,
			Secret:     secret,
			Target:     target.Addr().String(),
		})
	}()

	clientReady := make(chan net.Addr, 1)
	clientErr := make(chan error, 1)
	go func() {
		clientErr <- RunClient(ctx, ClientConfig{
			PacketConn: clientPacket,
			PeerAddr:   serverAddr,
			Secret:     secret,
			Listen:     "127.0.0.1:0",
			OnReady: func(listener, _, _ net.Addr) {
				clientReady <- listener
			},
		})
	}()

	var listener net.Addr
	select {
	case listener = <-clientReady:
	case err := <-clientErr:
		t.Fatalf("client stopped before ready: %v", err)
	case <-ctx.Done():
		t.Fatalf("client readiness timed out: %v", ctx.Err())
	}

	forwarded, err := net.DialTimeout("tcp", listener.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded listener: %v", err)
	}
	payload := []byte("winkyou-no-wintun-forward")
	if _, err := forwarded.Write(payload); err != nil {
		forwarded.Close()
		t.Fatalf("write forwarded payload: %v", err)
	}
	if err := forwarded.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		forwarded.Close()
		t.Fatalf("set forwarded read deadline: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(forwarded, got); err != nil {
		forwarded.Close()
		t.Fatalf("read forwarded payload: %v", err)
	}
	_ = forwarded.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("forwarded payload = %q, want %q", got, payload)
	}

	cancel()
	assertStopsCleanly(t, "client", clientErr)
	assertStopsCleanly(t, "server", serverErr)
}

func TestRunClientRejectsWrongSecret(t *testing.T) {
	serverPacket := mustListenUDP(t)
	clientPacket := mustListenUDP(t)
	serverAddr := serverPacket.LocalAddr().(*net.UDPAddr)
	clientAddr := clientPacket.LocalAddr().(*net.UDPAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- RunServer(ctx, ServerConfig{
			PacketConn: serverPacket,
			PeerAddr:   clientAddr,
			Secret:     bytes.Repeat([]byte{0x11}, minimumSecretBytes),
			Target:     "127.0.0.1:22",
		})
	}()

	err := RunClient(ctx, ClientConfig{
		PacketConn: clientPacket,
		PeerAddr:   serverAddr,
		Secret:     bytes.Repeat([]byte{0x22}, minimumSecretBytes),
		Listen:     "127.0.0.1:0",
	})
	if err == nil {
		t.Fatal("RunClient succeeded with the wrong secret")
	}
	cancel()
	select {
	case <-serverErr:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after authentication test")
	}
}

func TestStatusRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := writeStatus(&buf, statusDialFailed, "target unavailable"); err != nil {
		t.Fatalf("writeStatus: %v", err)
	}
	code, message, err := readStatus(&buf)
	if err != nil {
		t.Fatalf("readStatus: %v", err)
	}
	if code != statusDialFailed || message != "target unavailable" {
		t.Fatalf("status = (%d, %q), want (%d, %q)", code, message, statusDialFailed, "target unavailable")
	}
}

func TestWindowsConnectionResetIsBenignCopyCompletion(t *testing.T) {
	err := fmt.Errorf("read tcp: wsarecv: %w", syscall.Errno(10054))
	if !isBenignCopyError(err) {
		t.Fatalf("isBenignCopyError(%v) = false, want true", err)
	}
}

func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	return conn
}

func assertStopsCleanly(t *testing.T, name string, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("%s stopped with error: %v", name, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not stop", name)
	}
}
