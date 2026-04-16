package framedstream

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFramedStreamReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	a1 := New(c1, "path1")
	a2 := New(c2, "path2")

	payload := []byte("hello framed world")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- a1.WritePacket(ctx, payload)
	}()

	buf := make([]byte, 1024)
	n, meta, err := a2.ReadPacket(ctx, buf)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", string(buf[:n]), string(payload))
	}
	if meta.PathID != "path2" {
		t.Fatalf("meta.PathID = %q, want path2", meta.PathID)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
}

func TestFramedStreamOversizedFrame(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	a1 := NewWithMaxFrameSize(c1, "path1", 8)
	_ = NewWithMaxFrameSize(c2, "path2", 8)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := a1.WritePacket(ctx, []byte("this is too large"))
	if err == nil {
		t.Fatal("WritePacket() error = nil, want oversized frame error")
	}
}

func TestFramedStreamPartialReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	a1 := New(c1, "path1")
	a2 := New(c2, "path2")

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = a1.WritePacket(ctx, payload)
	}()

	buf := make([]byte, 8192)
	n, _, err := a2.ReadPacket(ctx, buf)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("ReadPacket() n = %d, want %d", n, len(payload))
	}
	for i := 0; i < n; i++ {
		if buf[i] != payload[i] {
			t.Fatalf("payload mismatch at %d: got %d want %d", i, buf[i], payload[i])
		}
	}
}

func TestFramedStreamClose(t *testing.T) {
	c1, _ := net.Pipe()
	a := New(c1, "path")
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
