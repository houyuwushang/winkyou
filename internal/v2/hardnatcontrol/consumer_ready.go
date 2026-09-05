package hardnatcontrol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"sync"

	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/noisecore"
)

const (
	ConsumerReadyFrameBytes    = 40
	ConsumerFinishedFrameBytes = 40
	consumerReadyHeaderBytes   = 24
	consumerReadyLabel         = "winkyou-gate-c-consumer-ready/1\x00"
	consumerFinishedLabel      = "winkyou-gate-c-consumer-finished/1\x00"
	consumerFinishedProfile    = "wireguard-direct-session/1"
)

// ConsumerReadiness is a one-shot, post-VERIFY product codec. It has no I/O or
// exported key material. The WYHB parser deliberately does not recognize WYCR.
type ConsumerReadiness struct {
	mu                     sync.Mutex
	role                   Role
	packets                *noisecore.PacketCipher
	binding                []byte
	sent, received, closed bool
	finished               bool
}

// NewProductProtocol differs only in post-VERIFY key ownership. The legacy
// constructor still zeroizes at VERIFY. The product owner must Close or Take.
func NewProductProtocol(role Role, plannerRole hardnatplan.Role, binding Binding, packets *noisecore.PacketCipher) (*Protocol, error) {
	protocol, err := NewProtocol(role, plannerRole, binding, packets)
	if err != nil {
		return nil, err
	}
	protocol.retainForConsumer = true
	return protocol, nil
}

// TakeConsumerReadiness transfers the original directional cipher, including
// its nonce ledger. Only the Gate C product handoff may call this method.
func (protocol *Protocol) TakeConsumerReadiness() (*ConsumerReadiness, error) {
	if protocol == nil {
		return nil, ErrInvalidTransition
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if !protocol.retainForConsumer || !protocol.state.success || !protocol.state.sentVerify || !protocol.state.receivedVerify ||
		!protocol.state.hasWinner || protocol.packets == nil || !protocol.packets.Ready() {
		return nil, ErrInvalidTransition
	}
	attempt, err := base64.RawURLEncoding.DecodeString(protocol.binding.AttemptID)
	if err != nil || len(attempt) != 16 {
		return nil, ErrInvalidBinding
	}
	binding := append([]byte(nil), attempt...)
	for _, digest := range [][32]byte{protocol.binding.ContextDigest, protocol.binding.HandshakeHash,
		protocol.binding.EnvelopeDigest, protocol.joint.JointDigest, protocol.executionDigest, protocol.state.winner.Digest} {
		binding = append(binding, digest[:]...)
	}
	codec := &ConsumerReadiness{role: protocol.role, packets: protocol.packets, binding: binding}
	protocol.packets = nil
	protocol.state.terminal = true
	return codec, nil
}

func consumerReadyHeader(role Role) []byte {
	header := make([]byte, consumerReadyHeaderBytes)
	copy(header, "WYCR")
	header[4] = 1
	if role == RoleInitiator {
		header[5], header[6] = 1, 1
	} else {
		header[5], header[6] = 2, 2
	}
	binary.BigEndian.PutUint64(header[8:16], uint64(7+header[5]))
	binary.BigEndian.PutUint64(header[16:24], Generation)
	return header
}

func (codec *ConsumerReadiness) ad(header []byte) []byte {
	ad := append([]byte(consumerReadyLabel), header...)
	return append(ad, codec.binding...)
}

func (codec *ConsumerReadiness) Seal() ([]byte, error) {
	if codec == nil {
		return nil, ErrInvalidTransition
	}
	codec.mu.Lock()
	defer codec.mu.Unlock()
	if codec.closed || codec.sent || (codec.role == RoleResponder && !codec.received) {
		return nil, codec.failLocked()
	}
	header := consumerReadyHeader(codec.role)
	ciphertext, err := codec.packets.Seal(binary.BigEndian.Uint64(header[8:16]), codec.ad(header), nil)
	if err != nil {
		return nil, codec.failLocked()
	}
	codec.sent = true
	return append(header, ciphertext...), nil
}

func (codec *ConsumerReadiness) Open(frame []byte) error {
	if codec == nil {
		return ErrInvalidTransition
	}
	codec.mu.Lock()
	defer codec.mu.Unlock()
	if codec.closed || codec.received || (codec.role == RoleInitiator && !codec.sent) || len(frame) != ConsumerReadyFrameBytes {
		return codec.failLocked()
	}
	peer := RoleInitiator
	if codec.role == RoleInitiator {
		peer = RoleResponder
	}
	header := consumerReadyHeader(peer)
	if !bytes.Equal(frame[:consumerReadyHeaderBytes], header) {
		return codec.failLocked()
	}
	plaintext, err := codec.packets.Open(binary.BigEndian.Uint64(header[8:16]), codec.ad(header), frame[consumerReadyHeaderBytes:])
	defer clear(plaintext)
	if err != nil || len(plaintext) != 0 {
		return codec.failLocked()
	}
	codec.received = true
	return nil
}

func (codec *ConsumerReadiness) failLocked() error {
	codec.closed = true
	if codec.packets != nil {
		_ = codec.packets.Close()
	}
	clear(codec.binding)
	return ErrInvalidFrame
}

func (codec *ConsumerReadiness) Close() error {
	if codec == nil {
		return nil
	}
	codec.mu.Lock()
	defer codec.mu.Unlock()
	_ = codec.failLocked()
	return nil
}

func consumerFinishedHeader() []byte {
	header := make([]byte, consumerReadyHeaderBytes)
	copy(header, "WYCF")
	header[4], header[5], header[6] = 1, 1, 2
	binary.BigEndian.PutUint64(header[8:16], 10)
	binary.BigEndian.PutUint64(header[16:24], Generation)
	return header
}

func (codec *ConsumerReadiness) finishedAD(header []byte) []byte {
	ad := append([]byte(consumerFinishedLabel), header...)
	ad = append(ad, codec.binding...)
	return append(ad, consumerFinishedProfile...)
}

// SealFinish is the responder's one post-durable-FINISH confirmation. The
// lease-owned gate, not the pure codec, enforces the journal-before-write order.
func (codec *ConsumerReadiness) SealFinish() ([]byte, error) {
	if codec == nil {
		return nil, ErrInvalidTransition
	}
	codec.mu.Lock()
	defer codec.mu.Unlock()
	if codec.closed || codec.finished || !codec.sent || !codec.received || codec.role != RoleResponder {
		return nil, codec.failLocked()
	}
	header := consumerFinishedHeader()
	ciphertext, err := codec.packets.Seal(10, codec.finishedAD(header), nil)
	if err != nil {
		return nil, codec.failLocked()
	}
	codec.finished = true
	return append(header, ciphertext...), nil
}

// OpenFinish authenticates peer durability before the initiator may FINISH or
// close OOB. It consumes the same cipher's original nonce ledger exactly once.
func (codec *ConsumerReadiness) OpenFinish(frame []byte) error {
	if codec == nil {
		return ErrInvalidTransition
	}
	codec.mu.Lock()
	defer codec.mu.Unlock()
	if codec.closed || codec.finished || !codec.sent || !codec.received || codec.role != RoleInitiator ||
		len(frame) != ConsumerFinishedFrameBytes {
		return codec.failLocked()
	}
	header := consumerFinishedHeader()
	if !bytes.Equal(frame[:consumerReadyHeaderBytes], header) {
		return codec.failLocked()
	}
	plaintext, err := codec.packets.Open(10, codec.finishedAD(header), frame[consumerReadyHeaderBytes:])
	defer clear(plaintext)
	if err != nil || len(plaintext) != 0 {
		return codec.failLocked()
	}
	codec.finished = true
	return nil
}
