package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
)

const tunPacketTraceEnv = "WINKYOU_TRACE_TUN_PACKETS"

func traceTUNPacket(direction string, packet []byte) {
	if os.Getenv(tunPacketTraceEnv) != "1" {
		return
	}
	fmt.Fprintf(os.Stderr, "wink tun %s %s\n", direction, describeTUNPacket(packet))
}

func describeTUNPacket(packet []byte) string {
	if len(packet) == 0 {
		return "empty"
	}
	version := packet[0] >> 4
	switch version {
	case 4:
		return describeIPv4Packet(packet)
	case 6:
		return fmt.Sprintf("ipv6 len=%d", len(packet))
	default:
		return fmt.Sprintf("unknown version=%d len=%d", version, len(packet))
	}
}

func describeIPv4Packet(packet []byte) string {
	if len(packet) < 20 {
		return fmt.Sprintf("ipv4 truncated len=%d", len(packet))
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return fmt.Sprintf("ipv4 invalid_ihl=%d len=%d", ihl, len(packet))
	}
	proto := packet[9]
	src := net.IP(packet[12:16]).String()
	dst := net.IP(packet[16:20]).String()
	if proto == 6 || proto == 17 {
		if len(packet) >= ihl+4 {
			srcPort := binary.BigEndian.Uint16(packet[ihl : ihl+2])
			dstPort := binary.BigEndian.Uint16(packet[ihl+2 : ihl+4])
			return fmt.Sprintf("ipv4 %s:%d -> %s:%d proto=%d len=%d", src, srcPort, dst, dstPort, proto, len(packet))
		}
		return fmt.Sprintf("ipv4 %s -> %s proto=%d truncated_l4 len=%d", src, dst, proto, len(packet))
	}
	return fmt.Sprintf("ipv4 %s -> %s proto=%d len=%d", src, dst, proto, len(packet))
}
