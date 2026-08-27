package hardnatplan

import (
	"bytes"
	"encoding/binary"
)

func appendUint16(target *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	target.Write(encoded[:])
}

func appendUint32(target *bytes.Buffer, value uint32) {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	target.Write(encoded[:])
}

func appendUint64(target *bytes.Buffer, value uint64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	target.Write(encoded[:])
}

func appendInt64(target *bytes.Buffer, value int64) {
	appendUint64(target, uint64(value))
}

func appendString(target *bytes.Buffer, value string) {
	appendUint32(target, uint32(len(value)))
	target.WriteString(value)
}

func appendAddress(target *bytes.Buffer, address Address) {
	encoded := address.canonicalBytes()
	target.Write(encoded)
	clear(encoded)
}
