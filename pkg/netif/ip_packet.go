package netif

import (
	"encoding/binary"
	"fmt"
)

const (
	darwinPacketAFInet  = 2
	darwinPacketAFInet6 = 30
)

func packetIPVersion(buf []byte) (byte, error) {
	if len(buf) == 0 {
		return 0, fmt.Errorf("netif: empty ip packet")
	}

	switch version := buf[0] >> 4; version {
	case 4, 6:
		return version, nil
	default:
		return 0, fmt.Errorf("netif: unsupported ip version nibble %d", version)
	}
}

func darwinPacketHeader(buf []byte) ([4]byte, error) {
	var hdr [4]byte

	version, err := packetIPVersion(buf)
	if err != nil {
		return hdr, err
	}

	switch version {
	case 4:
		binary.BigEndian.PutUint32(hdr[:], darwinPacketAFInet)
	case 6:
		binary.BigEndian.PutUint32(hdr[:], darwinPacketAFInet6)
	}
	return hdr, nil
}
