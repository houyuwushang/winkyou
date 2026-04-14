package netif

import (
	"encoding/binary"
	"testing"
)

func TestPacketIPVersion(t *testing.T) {
	tests := []struct {
		name    string
		packet  []byte
		want    byte
		wantErr bool
	}{
		{name: "ipv4", packet: []byte{0x45, 0x00}, want: 4},
		{name: "ipv6", packet: []byte{0x60, 0x00}, want: 6},
		{name: "empty", packet: nil, wantErr: true},
		{name: "invalid", packet: []byte{0x10, 0x00}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := packetIPVersion(tt.packet)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("packetIPVersion() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("packetIPVersion() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDarwinPacketHeaderUsesIPVersionNibble(t *testing.T) {
	tests := []struct {
		name   string
		packet []byte
		want   uint32
	}{
		{name: "ipv4", packet: []byte{0x45, 0x00, 0x00, 0x14}, want: darwinPacketAFInet},
		{name: "ipv6", packet: []byte{0x60, 0x00, 0x00, 0x00}, want: darwinPacketAFInet6},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hdr, err := darwinPacketHeader(tt.packet)
			if err != nil {
				t.Fatalf("darwinPacketHeader() error = %v", err)
			}
			if got := binary.BigEndian.Uint32(hdr[:]); got != tt.want {
				t.Fatalf("darwinPacketHeader() = %d, want %d", got, tt.want)
			}
		})
	}
}
