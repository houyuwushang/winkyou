// Package testkit builds synthetic STUN Binding responses for isolated tests.
// It owns no socket, resolver, goroutine, or network target.
package testkit

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	bindingRequestType        uint16 = 0x0001
	bindingSuccessType        uint16 = 0x0101
	attributeXORMappedAddress uint16 = 0x0020
	magicCookie               uint32 = 0x2112a442
	headerBytes                      = 20
)

var ErrInvalidBindingRequest = errors.New("stunobserve/testkit: invalid Binding request or mapped endpoint")

// BindingSuccess validates the minimal request emitted by stunobserve.Client
// and returns a matching XOR-MAPPED-ADDRESS success response.
func BindingSuccess(request []byte, mapped netip.AddrPort) ([]byte, error) {
	if len(request) < headerBytes || binary.BigEndian.Uint16(request[0:2]) != bindingRequestType || binary.BigEndian.Uint32(request[4:8]) != magicCookie {
		return nil, ErrInvalidBindingRequest
	}
	messageLength := int(binary.BigEndian.Uint16(request[2:4]))
	if messageLength%4 != 0 || messageLength != len(request)-headerBytes {
		return nil, ErrInvalidBindingRequest
	}
	if !mapped.IsValid() || mapped.Port() == 0 || mapped.Addr().IsUnspecified() || mapped.Addr().Zone() != "" {
		return nil, ErrInvalidBindingRequest
	}
	address := mapped.Addr().Unmap()
	valueLength := 20
	family := byte(0x02)
	if address.Is4() {
		valueLength = 8
		family = 0x01
	}
	response := make([]byte, headerBytes+4+valueLength)
	binary.BigEndian.PutUint16(response[0:2], bindingSuccessType)
	binary.BigEndian.PutUint16(response[2:4], uint16(4+valueLength))
	binary.BigEndian.PutUint32(response[4:8], magicCookie)
	copy(response[8:20], request[8:20])
	binary.BigEndian.PutUint16(response[20:22], attributeXORMappedAddress)
	binary.BigEndian.PutUint16(response[22:24], uint16(valueLength))
	response[25] = family
	binary.BigEndian.PutUint16(response[26:28], mapped.Port()^uint16(magicCookie>>16))
	if address.Is4() {
		bytes4 := address.As4()
		var cookie [4]byte
		binary.BigEndian.PutUint32(cookie[:], magicCookie)
		for index := range bytes4 {
			response[28+index] = bytes4[index] ^ cookie[index]
		}
		return response, nil
	}
	bytes16 := address.As16()
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[0:4], magicCookie)
	copy(mask[4:], request[8:20])
	for index := range bytes16 {
		response[28+index] = bytes16[index] ^ mask[index]
	}
	return response, nil
}
