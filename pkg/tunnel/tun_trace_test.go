package tunnel

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDescribeTUNPacketIPv4UDP(t *testing.T) {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[9] = 17
	copy(packet[12:16], []byte{10, 88, 0, 9})
	copy(packet[16:20], []byte{10, 88, 0, 8})
	binary.BigEndian.PutUint16(packet[20:22], 57155)
	binary.BigEndian.PutUint16(packet[22:24], 33434)

	got := describeTUNPacket(packet)
	if !strings.Contains(got, "10.88.0.9:57155 -> 10.88.0.8:33434") || !strings.Contains(got, "proto=17") {
		t.Fatalf("describeTUNPacket() = %q, want UDP endpoints", got)
	}
}

func TestDescribeTUNPacketIPv4ICMP(t *testing.T) {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[9] = 1
	copy(packet[12:16], []byte{10, 88, 0, 9})
	copy(packet[16:20], []byte{10, 88, 0, 8})

	got := describeTUNPacket(packet)
	if !strings.Contains(got, "10.88.0.9 -> 10.88.0.8") || !strings.Contains(got, "proto=1") {
		t.Fatalf("describeTUNPacket() = %q, want ICMP endpoints", got)
	}
}

func TestDescribeTUNPacketUnknown(t *testing.T) {
	if got := describeTUNPacket([]byte{0xf0}); !strings.Contains(got, "unknown version=15") {
		t.Fatalf("describeTUNPacket() = %q, want unknown version", got)
	}
}
