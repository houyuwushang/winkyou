package iceadapter

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestPacketConnAdapterReadWriteAndClose(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()

	adapter := New(left, "legacyice:test")

	writeErr := make(chan error, 1)
	go func() {
		writeErr <- adapter.WritePacket(context.Background(), []byte("wink"))
	}()

	buf := make([]byte, 16)
	n, err := right.Read(buf)
	if err != nil {
		t.Fatalf("right.Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "wink" {
		t.Fatalf("right.Read() payload = %q, want wink", got)
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}

	readDone := make(chan struct {
		n      int
		pathID string
		err    error
	}, 1)
	go func() {
		packet := make([]byte, 16)
		n, meta, err := adapter.ReadPacket(context.Background(), packet)
		readDone <- struct {
			n      int
			pathID string
			err    error
		}{n: n, pathID: meta.PathID, err: err}
	}()

	if _, err := right.Write([]byte("pong")); err != nil {
		t.Fatalf("right.Write() error = %v", err)
	}

	select {
	case result := <-readDone:
		if result.err != nil {
			t.Fatalf("ReadPacket() error = %v", result.err)
		}
		if result.n != 4 {
			t.Fatalf("ReadPacket() n = %d, want 4", result.n)
		}
		if result.pathID != "legacyice:test" {
			t.Fatalf("ReadPacket() path_id = %q, want legacyice:test", result.pathID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ReadPacket()")
	}

	if err := adapter.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := adapter.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
}
