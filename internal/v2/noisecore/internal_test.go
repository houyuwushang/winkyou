package noisecore

import (
	"errors"
	"math"
	"testing"
)

func TestChaChaPolyNonceEncodingIsNoiseLittleEndian(t *testing.T) {
	nonce := noiseNonce(0x0807060504030201)
	want := [12]byte{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	if nonce != want {
		t.Fatalf("nonce = %x, want %x", nonce, want)
	}
}

func TestNonceExhaustionPermanentlyInvalidatesDirection(t *testing.T) {
	var key [32]byte
	key[0] = 1
	state := newCipherState(key)
	state.core.nonce = math.MaxUint64 - 1
	if _, err := state.Encrypt(nil, nil); err != nil {
		t.Fatalf("last permitted nonce: %v", err)
	}
	if _, err := state.Encrypt(nil, nil); !errors.Is(err, ErrNonceExhausted) {
		t.Fatalf("exhaustion error = %v", err)
	}
	if _, err := state.Encrypt(nil, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-exhaustion error = %v", err)
	}
}

func TestX25519RejectsAllZeroPublicKey(t *testing.T) {
	var privateKey [32]byte
	privateKey[0] = 1
	var publicKey [32]byte
	if _, err := x25519(privateKey, publicKey); !errors.Is(err, ErrLowOrderPoint) {
		t.Fatalf("all-zero public key error = %v", err)
	}
}

func TestCipherStateZeroizeClearsReachableKey(t *testing.T) {
	var key [32]byte
	key[0] = 1
	state := newCipherState(key)
	state.Zeroize()
	if !allZero(state.core.key[:]) || state.core.hasKey || !state.core.closed {
		t.Fatalf("cipher state retained reachable key material: %+v", state.core)
	}
}
