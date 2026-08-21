package noisecore

import (
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// PacketCipher owns the two Split keys after an atomic transfer from Session.
// It is a constrained form of Noise revision 34 section 11.4: the application
// sends an explicit bounded nonce beside each datagram and tracks successful
// nonces to reject replay. Keys and mutable nonce state are never exposed.
type PacketCipher struct {
	send    packetDirection
	receive packetDirection
}

type packetDirection struct {
	mu          sync.Mutex
	key         [chacha20poly1305.KeySize]byte
	maxSequence uint64
	used        map[uint64]struct{}
	closed      bool
}

func newPacketCipher(sendKey, receiveKey [chacha20poly1305.KeySize]byte, maxSequence uint64) *PacketCipher {
	result := &PacketCipher{}
	result.send.initialize(sendKey, maxSequence)
	result.receive.initialize(receiveKey, maxSequence)
	return result
}

func (direction *packetDirection) initialize(key [chacha20poly1305.KeySize]byte, maxSequence uint64) {
	direction.key = key
	direction.maxSequence = maxSequence
	direction.used = make(map[uint64]struct{})
}

// Ready reports whether both packet directions still own usable keys.
func (cipher *PacketCipher) Ready() bool {
	if cipher == nil {
		return false
	}
	cipher.send.mu.Lock()
	defer cipher.send.mu.Unlock()
	cipher.receive.mu.Lock()
	defer cipher.receive.mu.Unlock()
	return !cipher.send.closed && !cipher.receive.closed
}

// Seal authenticates one sequence exactly once. Reusing or exceeding the
// admitted sequence permanently invalidates the sending direction.
func (cipher *PacketCipher) Seal(sequence uint64, additionalData, plaintext []byte) ([]byte, error) {
	if cipher == nil {
		return nil, ErrClosed
	}
	return cipher.send.seal(sequence, additionalData, plaintext)
}

func (direction *packetDirection) seal(sequence uint64, additionalData, plaintext []byte) ([]byte, error) {
	direction.mu.Lock()
	defer direction.mu.Unlock()
	if direction.closed {
		return nil, ErrClosed
	}
	if sequence > direction.maxSequence || sequence == math.MaxUint64 {
		direction.zeroizeLocked()
		return nil, ErrSequenceOutOfRange
	}
	if _, exists := direction.used[sequence]; exists {
		direction.zeroizeLocked()
		return nil, ErrSequenceReuse
	}
	if len(plaintext) > MaxTransportPlaintext {
		direction.zeroizeLocked()
		return nil, ErrInvalidMessage
	}
	aead, err := chacha20poly1305.New(direction.key[:])
	if err != nil {
		direction.zeroizeLocked()
		return nil, ErrClosed
	}
	nonce := noiseNonce(sequence)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, additionalData)
	zeroBytes(nonce[:])
	direction.used[sequence] = struct{}{}
	return ciphertext, nil
}

// Open accepts authenticated sequences in any order and rejects every replay.
// Authentication, range, or replay failure permanently invalidates receive.
func (cipher *PacketCipher) Open(sequence uint64, additionalData, ciphertext []byte) ([]byte, error) {
	if cipher == nil {
		return nil, ErrClosed
	}
	return cipher.receive.open(sequence, additionalData, ciphertext)
}

func (direction *packetDirection) open(sequence uint64, additionalData, ciphertext []byte) ([]byte, error) {
	direction.mu.Lock()
	defer direction.mu.Unlock()
	if direction.closed {
		return nil, ErrClosed
	}
	if sequence > direction.maxSequence || sequence == math.MaxUint64 {
		direction.zeroizeLocked()
		return nil, ErrSequenceOutOfRange
	}
	if _, exists := direction.used[sequence]; exists {
		direction.zeroizeLocked()
		return nil, ErrSequenceReuse
	}
	if len(ciphertext) < TagSize || len(ciphertext) > MaxNoiseMessageSize {
		direction.zeroizeLocked()
		return nil, ErrInvalidMessage
	}
	aead, err := chacha20poly1305.New(direction.key[:])
	if err != nil {
		direction.zeroizeLocked()
		return nil, ErrClosed
	}
	nonce := noiseNonce(sequence)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additionalData)
	zeroBytes(nonce[:])
	if err != nil {
		direction.zeroizeLocked()
		return nil, ErrAuthentication
	}
	direction.used[sequence] = struct{}{}
	return plaintext, nil
}

// Zeroize permanently closes both directions and best-effort overwrites keys.
func (cipher *PacketCipher) Zeroize() {
	_ = cipher.Close()
}

// Close permanently closes both packet directions.
func (cipher *PacketCipher) Close() error {
	if cipher == nil {
		return nil
	}
	cipher.send.mu.Lock()
	cipher.send.zeroizeLocked()
	cipher.send.mu.Unlock()
	cipher.receive.mu.Lock()
	cipher.receive.zeroizeLocked()
	cipher.receive.mu.Unlock()
	return nil
}

func (direction *packetDirection) zeroizeLocked() {
	zeroBytes(direction.key[:])
	clear(direction.used)
	direction.used = nil
	direction.maxSequence = 0
	direction.closed = true
}
