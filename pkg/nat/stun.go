package nat

// STUN protocol constants and message encoding/decoding (RFC 5389).
//
// This file defines the wire format helpers. The actual UDP I/O lives
// in stun_native.go.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// STUN message type constants.
const (
	stunMethodBinding       = 0x0001
	stunClassRequest        = 0x0000
	stunClassSuccessResp    = 0x0100
	stunClassErrorResp      = 0x0110
	stunMsgTypeBindingReq   = stunMethodBinding | stunClassRequest     // 0x0001
	stunMsgTypeBindingResp  = stunMethodBinding | stunClassSuccessResp // 0x0101
	stunMsgTypeBindingError = stunMethodBinding | stunClassErrorResp   // 0x0111
)

// STUN attribute types.
const (
	stunAttrMappedAddress    = 0x0001
	stunAttrXORMappedAddress = 0x0020
)

// STUN magic cookie (RFC 5389 section 6).
const stunMagicCookie uint32 = 0x2112A442

// STUN header size: 20 bytes (type 2 + length 2 + cookie 4 + txID 12).
const stunHeaderSize = 20

// stunTransactionID is the 12-byte transaction identifier.
type stunTransactionID [12]byte

// stunMessage represents a decoded STUN message.
type stunMessage struct {
	msgType       uint16
	transactionID stunTransactionID
	attrs         []stunAttribute
}

type stunAttribute struct {
	typ  uint16
	data []byte
}

// newTransactionID generates a cryptographically random 12-byte ID.
func newTransactionID() (stunTransactionID, error) {
	var id stunTransactionID
	_, err := rand.Read(id[:])
	return id, err
}

// buildBindingRequest creates a STUN Binding Request packet.
func buildBindingRequest(txID stunTransactionID) []byte {
	buf := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], stunMsgTypeBindingReq)
	binary.BigEndian.PutUint16(buf[2:4], 0) // length = 0 (no attributes)
	binary.BigEndian.PutUint32(buf[4:8], stunMagicCookie)
	copy(buf[8:20], txID[:])
	return buf
}

// parseSTUNMessage parses a raw STUN packet into a stunMessage.
func parseSTUNMessage(data []byte) (*stunMessage, error) {
	if len(data) < stunHeaderSize {
		return nil, errors.New("stun: message too short")
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	msgLen := binary.BigEndian.Uint16(data[2:4])
	cookie := binary.BigEndian.Uint32(data[4:8])

	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("stun: bad magic cookie: 0x%08x", cookie)
	}

	if int(msgLen)+stunHeaderSize > len(data) {
		return nil, errors.New("stun: message length exceeds packet")
	}

	msg := &stunMessage{msgType: msgType}
	copy(msg.transactionID[:], data[8:20])

	// Parse attributes.
	pos := stunHeaderSize
	end := stunHeaderSize + int(msgLen)
	for pos+4 <= end {
		attrType := binary.BigEndian.Uint16(data[pos : pos+2])
		attrLen := binary.BigEndian.Uint16(data[pos+2 : pos+4])
		pos += 4
		if pos+int(attrLen) > end {
			return nil, errors.New("stun: attribute length exceeds message")
		}
		attr := stunAttribute{
			typ:  attrType,
			data: make([]byte, attrLen),
		}
		copy(attr.data, data[pos:pos+int(attrLen)])
		msg.attrs = append(msg.attrs, attr)
		// Attributes are padded to 4-byte boundaries.
		pos += int(attrLen)
		if pad := int(attrLen) % 4; pad != 0 {
			pos += 4 - pad
		}
	}

	return msg, nil
}

// extractMappedAddr extracts the mapped address from a STUN Binding Response.
// It prefers XOR-MAPPED-ADDRESS over MAPPED-ADDRESS.
func (m *stunMessage) extractMappedAddr() (*net.UDPAddr, error) {
	// Try XOR-MAPPED-ADDRESS first.
	for _, a := range m.attrs {
		if a.typ == stunAttrXORMappedAddress {
			return decodeXORMappedAddress(a.data, m.transactionID)
		}
	}
	// Fall back to MAPPED-ADDRESS.
	for _, a := range m.attrs {
		if a.typ == stunAttrMappedAddress {
			return decodeMappedAddress(a.data)
		}
	}
	return nil, errors.New("stun: no mapped address in response")
}

// decodeXORMappedAddress decodes an XOR-MAPPED-ADDRESS attribute (RFC 5389 section 15.2).
func decodeXORMappedAddress(data []byte, txID stunTransactionID) (*net.UDPAddr, error) {
	if len(data) < 8 {
		return nil, errors.New("stun: XOR-MAPPED-ADDRESS too short")
	}
	family := data[1]
	xport := binary.BigEndian.Uint16(data[2:4])
	port := xport ^ uint16(stunMagicCookie>>16)

	switch family {
	case 0x01: // IPv4
		if len(data) < 8 {
			return nil, errors.New("stun: XOR-MAPPED-ADDRESS IPv4 too short")
		}
		cookieBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(cookieBytes, stunMagicCookie)
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = data[4+i] ^ cookieBytes[i]
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	case 0x02: // IPv6 — not supported in MVP
		return nil, errors.New("stun: IPv6 not supported")
	default:
		return nil, fmt.Errorf("stun: unknown address family: 0x%02x", family)
	}
}

// decodeMappedAddress decodes a MAPPED-ADDRESS attribute (RFC 5389 section 15.1).
func decodeMappedAddress(data []byte) (*net.UDPAddr, error) {
	if len(data) < 8 {
		return nil, errors.New("stun: MAPPED-ADDRESS too short")
	}
	family := data[1]
	port := binary.BigEndian.Uint16(data[2:4])

	switch family {
	case 0x01: // IPv4
		ip := net.IP(make([]byte, 4))
		copy(ip, data[4:8])
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil
	case 0x02:
		return nil, errors.New("stun: IPv6 not supported")
	default:
		return nil, fmt.Errorf("stun: unknown address family: 0x%02x", family)
	}
}
