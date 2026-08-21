package noisecore

import (
	"encoding/binary"
	"math"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

type cipherStateCore struct {
	key    [chacha20poly1305.KeySize]byte
	nonce  uint64
	hasKey bool
	closed bool
}

func (state *cipherStateCore) initializeKey(key []byte) {
	zeroBytes(state.key[:])
	state.nonce = 0
	state.hasKey = false
	state.closed = false
	if len(key) == 0 {
		return
	}
	copy(state.key[:], key)
	state.hasKey = true
}

func (state *cipherStateCore) encryptWithAD(additionalData, plaintext []byte) ([]byte, error) {
	if state.closed {
		return nil, ErrClosed
	}
	if !state.hasKey {
		return append([]byte(nil), plaintext...), nil
	}
	if len(plaintext) > MaxTransportPlaintext {
		state.zeroize()
		return nil, ErrInvalidMessage
	}
	if state.nonce == math.MaxUint64 {
		state.zeroize()
		return nil, ErrNonceExhausted
	}
	aead, err := chacha20poly1305.New(state.key[:])
	if err != nil {
		state.zeroize()
		return nil, ErrClosed
	}
	nonce := noiseNonce(state.nonce)
	ciphertext := aead.Seal(nil, nonce[:], plaintext, additionalData)
	zeroBytes(nonce[:])
	state.nonce++
	return ciphertext, nil
}

func (state *cipherStateCore) decryptWithAD(additionalData, ciphertext []byte) ([]byte, error) {
	if state.closed {
		return nil, ErrClosed
	}
	if !state.hasKey {
		return append([]byte(nil), ciphertext...), nil
	}
	if len(ciphertext) < TagSize || len(ciphertext) > MaxNoiseMessageSize {
		state.zeroize()
		return nil, ErrInvalidMessage
	}
	if state.nonce == math.MaxUint64 {
		state.zeroize()
		return nil, ErrNonceExhausted
	}
	aead, err := chacha20poly1305.New(state.key[:])
	if err != nil {
		state.zeroize()
		return nil, ErrClosed
	}
	nonce := noiseNonce(state.nonce)
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, additionalData)
	zeroBytes(nonce[:])
	if err != nil {
		state.zeroize()
		return nil, ErrAuthentication
	}
	state.nonce++
	return plaintext, nil
}

func noiseNonce(counter uint64) [chacha20poly1305.NonceSize]byte {
	var nonce [chacha20poly1305.NonceSize]byte
	// Noise ChaChaPoly uses four zero bytes followed by a little-endian uint64.
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	return nonce
}

func (state *cipherStateCore) zeroize() {
	zeroBytes(state.key[:])
	state.nonce = 0
	state.hasKey = false
	state.closed = true
}

// CipherState owns one post-handshake key and monotonically increasing nonce.
// It intentionally exposes no SetNonce, Rekey, export, or import operation.
type CipherState struct {
	mu   sync.Mutex
	core cipherStateCore
}

func newCipherState(key [HashSize]byte) *CipherState {
	state := &CipherState{}
	state.core.closed = false
	state.core.initializeKey(key[:])
	return state
}

// Encrypt protects one message and advances the nonce only on success.
func (state *CipherState) Encrypt(additionalData, plaintext []byte) ([]byte, error) {
	if state == nil {
		return nil, ErrClosed
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.core.encryptWithAD(additionalData, plaintext)
}

// Decrypt authenticates one message and advances the nonce only on success.
// Authentication failure permanently invalidates this direction.
func (state *CipherState) Decrypt(additionalData, ciphertext []byte) ([]byte, error) {
	if state == nil {
		return nil, ErrClosed
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.core.decryptWithAD(additionalData, ciphertext)
}

// Zeroize permanently invalidates the direction and best-effort overwrites
// its reachable key bytes.
func (state *CipherState) Zeroize() {
	_ = state.Close()
}

// Close permanently invalidates the direction.
func (state *CipherState) Close() error {
	if state == nil {
		return nil
	}
	state.mu.Lock()
	state.core.zeroize()
	state.mu.Unlock()
	return nil
}
