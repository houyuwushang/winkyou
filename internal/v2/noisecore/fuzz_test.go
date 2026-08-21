package noisecore_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"winkyou/internal/v2/noisecore"
)

func FuzzReadMessage(f *testing.F) {
	firstVector, err := hex.DecodeString("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479b962b8aff8485742ac32f905ba45369e2465fb59e138a93d67a0d1266b6a54")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(firstVector)
	f.Add(make([]byte, PublicHandshakeMessageSize))
	f.Add([]byte{})
	prologue := []byte("fuzz-prologue")
	psk := repeatedKey(0x70)
	f.Fuzz(func(t *testing.T, message []byte) {
		responder, err := noisecore.NewResponder(noisecore.Config{
			Prologue: prologue,
			PSK:      fixedPSKSource{key: psk},
			Random:   bytes.NewReader(bytes.Repeat([]byte{0x71}, 32)),
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = responder.ReadMessage(message)
		_ = responder.Close()
	})
}

func FuzzDecrypt(f *testing.F) {
	prologue := []byte("fuzz-prologue")
	psk := repeatedKey(0x72)
	initiator, responder := completeHandshake(f, prologue, prologue, psk, psk)
	seed, err := initiator.Encrypt([]byte("ad"), []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	_ = initiator.Close()
	_ = responder.Close()
	f.Add(seed)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		initiator, responder := completeHandshake(t, prologue, prologue, psk, psk)
		decrypted, _ := responder.Decrypt([]byte("ad"), ciphertext)
		clear(decrypted)
		_ = initiator.Close()
		_ = responder.Close()
	})
}
