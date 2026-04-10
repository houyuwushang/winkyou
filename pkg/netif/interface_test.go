package netif

import (
	"errors"
	"testing"
)

func TestNewAutoBackend(t *testing.T) {
	ni, err := New(Config{Backend: "auto", MTU: 1400})
	if err != nil {
		t.Fatalf("New(auto) returned error: %v", err)
	}
	if ni == nil {
		t.Fatal("New(auto) returned nil interface")
	}
	if ni.MTU() != 1400 {
		t.Errorf("MTU() = %d, want 1400", ni.MTU())
	}
}

func TestNewDefaultMTU(t *testing.T) {
	ni, err := New(Config{})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if ni.MTU() != 1280 {
		t.Errorf("MTU() = %d, want 1280", ni.MTU())
	}
}

func TestNewUnknownBackend(t *testing.T) {
	_, err := New(Config{Backend: "magic"})
	if err == nil {
		t.Fatal("expected error for unknown backend")
	}
}

func TestNoopReturnsErrNotImplemented(t *testing.T) {
	ni, err := New(Config{})
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	buf := make([]byte, 1500)
	_, readErr := ni.Read(buf)
	if !errors.Is(readErr, ErrNotImplemented) {
		t.Errorf("Read() error = %v, want ErrNotImplemented", readErr)
	}

	_, writeErr := ni.Write(buf)
	if !errors.Is(writeErr, ErrNotImplemented) {
		t.Errorf("Write() error = %v, want ErrNotImplemented", writeErr)
	}

	if err := ni.SetIP(nil, nil); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("SetIP() error = %v, want ErrNotImplemented", err)
	}
}

func TestNoopClose(t *testing.T) {
	ni, _ := New(Config{})
	if err := ni.Close(); err != nil {
		t.Errorf("Close() returned unexpected error: %v", err)
	}
}

func TestInterfaceNameAndType(t *testing.T) {
	ni, _ := New(Config{Backend: "auto"})
	if ni.Name() == "" {
		t.Error("Name() returned empty string")
	}
	if ni.Type() == "" {
		t.Error("Type() returned empty string")
	}
}
