// Package puncher implements multi-socket UDP hole punching for hard NATs.
//
// It opens many source sockets at once (birthday-paradox) and/or targets a
// peer's predicted ports (for sequential/preserving NATs), sends small
// self-identifying punch packets, and returns the first source socket that
// achieves a verified bidirectional path. Punch methods are pluggable so
// path-aware techniques (TTL-scoped, ICMP-assisted, spoofed-source) can be
// added without changing the core loop. See docs/BIRTHDAY-PUNCH-DESIGN.md.
package puncher

import (
	"bytes"
	"crypto/rand"
)

// punchPacketLen is the fixed wire size: magic + kind + session + nonce.
const punchPacketLen = 4 + 1 + 8 + 8

// punchMagic identifies a winkyou punch datagram so a receiver can tell it apart
// from STUN and stray traffic immediately.
var punchMagic = [4]byte{'W', 'K', 'P', '1'}

type punchKind byte

const (
	// punchProbe means "I am trying to reach you"; the receiver learns the
	// sender's real post-NAT source address from it.
	punchProbe punchKind = 1
	// punchAck means "I received your probe"; receiving one proves the sender's
	// probe reached the peer. In legacy mode this is also the winner signal; in
	// coordinated mode it is only a candidate tuple.
	punchAck punchKind = 2
	// punchSelect asks the receiver to retain the exact local socket and remote
	// address on which this packet arrived. Nonce is the selection transaction.
	punchSelect punchKind = 3
	// punchSelectAck confirms that the receiver observed punchSelect on that
	// reciprocal tuple.
	punchSelectAck punchKind = 4
	// punchDone commits the selected tuple after punchSelectAck.
	punchDone punchKind = 5
	// punchDoneAck confirms that both endpoints committed the same tuple.
	punchDoneAck punchKind = 6
)

// punchPacket is the decoded form of a punch datagram.
type punchPacket struct {
	Kind    punchKind
	Session [8]byte // shared traffic discriminator; rejects cross-talk, not forgery
	Nonce   [8]byte // per-packet id echoed in acks for round-trip matching/diagnostics
}

func encodePunch(p punchPacket) []byte {
	buf := make([]byte, punchPacketLen)
	copy(buf[0:4], punchMagic[:])
	buf[4] = byte(p.Kind)
	copy(buf[5:13], p.Session[:])
	copy(buf[13:21], p.Nonce[:])
	return buf
}

func decodePunch(buf []byte) (punchPacket, bool) {
	if len(buf) < punchPacketLen {
		return punchPacket{}, false
	}
	if !bytes.Equal(buf[0:4], punchMagic[:]) {
		return punchPacket{}, false
	}
	p := punchPacket{Kind: punchKind(buf[4])}
	copy(p.Session[:], buf[5:13])
	copy(p.Nonce[:], buf[13:21])
	return p, true
}

func randNonce() [8]byte {
	var n [8]byte
	// crypto/rand.Read never returns a short read; ignore the error and fall
	// back to a zero nonce, which is still valid on the wire.
	_, _ = rand.Read(n[:])
	return n
}

func randSelectionToken() ([8]byte, error) {
	var token [8]byte
	_, err := rand.Read(token[:])
	return token, err
}
