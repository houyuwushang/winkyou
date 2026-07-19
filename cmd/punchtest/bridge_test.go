package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBridgeSecretHex(t *testing.T) {
	want := bytes.Repeat([]byte{0x4d}, 32)
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(hex.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	got, err := loadBridgeSecret(path)
	if err != nil {
		t.Fatalf("loadBridgeSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("secret mismatch: got %x, want %x", got, want)
	}
}

func TestLoadBridgeSecretRawAndTooShort(t *testing.T) {
	dir := t.TempDir()
	rawPath := filepath.Join(dir, "raw")
	want := bytes.Repeat([]byte{0xa5}, 32)
	if err := os.WriteFile(rawPath, want, 0o600); err != nil {
		t.Fatalf("write raw secret: %v", err)
	}
	got, err := loadBridgeSecret(rawPath)
	if err != nil {
		t.Fatalf("load raw secret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("raw secret mismatch")
	}

	shortPath := filepath.Join(dir, "short")
	if err := os.WriteFile(shortPath, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write short secret: %v", err)
	}
	if _, err := loadBridgeSecret(shortPath); err == nil {
		t.Fatal("loadBridgeSecret accepted a short secret")
	}
}
