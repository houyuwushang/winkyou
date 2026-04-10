package tunnel

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// PrivateKey represents a WireGuard private key (Curve25519, 32 bytes).
type PrivateKey [32]byte

// PublicKey represents a WireGuard public key (Curve25519, 32 bytes).
type PublicKey [32]byte

// PresharedKey represents an optional pre-shared key (32 bytes).
type PresharedKey [32]byte

// GeneratePrivateKey generates a new random WireGuard private key.
// It applies the Curve25519 clamping as specified by WireGuard.
func GeneratePrivateKey() (PrivateKey, error) {
	var key PrivateKey
	if _, err := rand.Read(key[:]); err != nil {
		return key, fmt.Errorf("tunnel: generate private key: %w", err)
	}
	// Curve25519 clamping
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return key, nil
}

// PublicKey derives the Curve25519 public key from the private key.
//
func (k PrivateKey) PublicKey() PublicKey {
	var pub PublicKey
	curve25519.ScalarBaseMult((*[32]byte)(&pub), (*[32]byte)(&k))
	return pub
}

// String returns the base64 standard encoding of the private key.
func (k PrivateKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// String returns the base64 standard encoding of the public key.
func (k PublicKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// String returns the base64 standard encoding of the preshared key.
func (k PresharedKey) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

// ParsePrivateKey decodes a base64-encoded private key string.
func ParsePrivateKey(s string) (PrivateKey, error) {
	var key PrivateKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("tunnel: parse private key: %w", err)
	}
	if len(b) != 32 {
		return key, errors.New("tunnel: private key must be 32 bytes")
	}
	copy(key[:], b)
	return key, nil
}

// ParsePublicKey decodes a base64-encoded public key string.
func ParsePublicKey(s string) (PublicKey, error) {
	var key PublicKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("tunnel: parse public key: %w", err)
	}
	if len(b) != 32 {
		return key, errors.New("tunnel: public key must be 32 bytes")
	}
	copy(key[:], b)
	return key, nil
}

// ParsePresharedKey decodes a base64-encoded preshared key string.
func ParsePresharedKey(s string) (PresharedKey, error) {
	var key PresharedKey
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("tunnel: parse preshared key: %w", err)
	}
	if len(b) != 32 {
		return key, errors.New("tunnel: preshared key must be 32 bytes")
	}
	copy(key[:], b)
	return key, nil
}
