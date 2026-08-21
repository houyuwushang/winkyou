package noisecore_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/noisecore"
	"winkyou/internal/v2/testpairing"
)

func TestSelfInteropUsesExactPairingPrologueAndAdditionalData(t *testing.T) {
	prologue := pairingPrologue(t)
	psk := repeatedKey(0x41)
	initiator, responder := completeHandshake(t, prologue, prologue, psk, psk)
	defer initiator.Close()
	defer responder.Close()

	additionalData := []byte("attempt-bound-ad")
	plaintext := []byte("test-only transport payload")
	ciphertext, err := initiator.Encrypt(additionalData, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	opened, err := responder.Decrypt(additionalData, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %q, want %q", opened, plaintext)
	}

	returnCiphertext, err := responder.Encrypt(additionalData, []byte("return"))
	if err != nil {
		t.Fatalf("encrypt return: %v", err)
	}
	if _, err := initiator.Decrypt([]byte("wrong-ad"), returnCiphertext); !errors.Is(err, noisecore.ErrAuthentication) {
		t.Fatalf("wrong AD error = %v, want authentication", err)
	}
	if _, err := initiator.Decrypt(additionalData, returnCiphertext); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("decrypt after terminal failure = %v, want closed", err)
	}
}

func TestWrongPSKFailsOnFirstAuthenticatedNNpsk0Message(t *testing.T) {
	prologue := pairingPrologue(t)
	initiator, err := newInitiator(prologue, repeatedKey(0x10), 0x21)
	if err != nil {
		t.Fatalf("new initiator: %v", err)
	}
	defer initiator.Close()
	responder, err := newResponder(prologue, repeatedKey(0x11), 0x31)
	if err != nil {
		t.Fatalf("new responder: %v", err)
	}
	defer responder.Close()
	first, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatalf("write first: %v", err)
	}
	if _, err := responder.ReadMessage(first); !errors.Is(err, noisecore.ErrAuthentication) {
		t.Fatalf("wrong PSK error = %v, want authentication on first message", err)
	}
	if responder.Complete() {
		t.Fatal("wrong PSK completed responder handshake")
	}
}

func TestPrologueMismatchFailsAuthentication(t *testing.T) {
	prologue := pairingPrologue(t)
	wrong := append([]byte(nil), prologue...)
	wrong[len(wrong)-1] ^= 1
	initiator, err := newInitiator(prologue, repeatedKey(0x22), 0x41)
	if err != nil {
		t.Fatal(err)
	}
	defer initiator.Close()
	responder, err := newResponder(wrong, repeatedKey(0x22), 0x51)
	if err != nil {
		t.Fatal(err)
	}
	defer responder.Close()
	first, err := initiator.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.ReadMessage(first); !errors.Is(err, noisecore.ErrAuthentication) {
		t.Fatalf("prologue mismatch error = %v", err)
	}
}

func TestEveryHandshakeByteIsTranscriptBound(t *testing.T) {
	prologue := pairingPrologue(t)
	psk := repeatedKey(0x33)

	firstInitiator, err := newInitiator(prologue, psk, 0x61)
	if err != nil {
		t.Fatal(err)
	}
	first, err := firstInitiator.WriteMessage(nil)
	_ = firstInitiator.Close()
	if err != nil {
		t.Fatal(err)
	}
	for index := range first {
		mutated := append([]byte(nil), first...)
		mutated[index] ^= 1
		responder, err := newResponder(prologue, psk, 0x71)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := responder.ReadMessage(mutated)
		_ = responder.Close()
		if readErr == nil {
			t.Fatalf("first-message mutation at byte %d authenticated", index)
		}
	}

	for index := 0; index < PublicHandshakeMessageSize; index++ {
		initiator, responder, second := handshakeThroughSecondWrite(t, prologue, psk)
		mutated := append([]byte(nil), second...)
		mutated[index] ^= 1
		_, readErr := initiator.ReadMessage(mutated)
		_ = initiator.Close()
		_ = responder.Close()
		if readErr == nil {
			t.Fatalf("second-message mutation at byte %d authenticated", index)
		}
	}
}

const PublicHandshakeMessageSize = noisecore.PublicKeySize + noisecore.TagSize

func TestHandshakeRejectsTruncationOversizeOrderingAndReplay(t *testing.T) {
	prologue := pairingPrologue(t)
	psk := repeatedKey(0x44)
	initiator, err := newInitiator(prologue, psk, 0x12)
	if err != nil {
		t.Fatal(err)
	}
	first, err := initiator.WriteMessage(nil)
	_ = initiator.Close()
	if err != nil {
		t.Fatal(err)
	}
	for length := 0; length < len(first); length++ {
		responder, err := newResponder(prologue, psk, 0x13)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := responder.ReadMessage(first[:length])
		_ = responder.Close()
		if readErr == nil {
			t.Fatalf("truncated length %d accepted", length)
		}
	}
	responder, err := newResponder(prologue, psk, 0x14)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := responder.ReadMessage(make([]byte, noisecore.MaxNoiseMessageSize+1)); !errors.Is(err, noisecore.ErrInvalidMessage) {
		t.Fatalf("oversize error = %v", err)
	}
	_ = responder.Close()

	wrongOrder, err := newResponder(prologue, psk, 0x15)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongOrder.WriteMessage(nil); !errors.Is(err, noisecore.ErrUnexpectedMessage) {
		t.Fatalf("out-of-order error = %v", err)
	}
	if _, err := wrongOrder.ReadMessage(first); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("state after out-of-order call = %v", err)
	}
	_ = wrongOrder.Close()

	replayResponder, err := newResponder(prologue, psk, 0x16)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replayResponder.ReadMessage(first); err != nil {
		t.Fatalf("read original first: %v", err)
	}
	if _, err := replayResponder.ReadMessage(first); !errors.Is(err, noisecore.ErrUnexpectedMessage) {
		t.Fatalf("replay error = %v", err)
	}
	_ = replayResponder.Close()
}

func TestTransportNonceAdvancesAndCloseIsTerminal(t *testing.T) {
	prologue := pairingPrologue(t)
	psk := repeatedKey(0x55)
	initiator, responder := completeHandshake(t, prologue, prologue, psk, psk)
	first, err := initiator.Encrypt(nil, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := initiator.Encrypt(nil, []byte("same"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("successive nonces produced identical ciphertext")
	}
	if _, err := responder.Decrypt(nil, first); err != nil {
		t.Fatal(err)
	}
	if _, err := responder.Decrypt(nil, second); err != nil {
		t.Fatal(err)
	}
	initiator.Zeroize()
	if _, err := initiator.Encrypt(nil, nil); !errors.Is(err, noisecore.ErrClosed) {
		t.Fatalf("encrypt after zeroize = %v", err)
	}
	_ = responder.Close()
}

func TestTransportDirectionsProgressConcurrently(t *testing.T) {
	prologue := pairingPrologue(t)
	psk := repeatedKey(0x56)
	initiator, responder := completeHandshake(t, prologue, prologue, psk, psk)
	defer initiator.Close()
	defer responder.Close()

	const messages = 64
	errorsOut := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	go func() {
		defer workers.Done()
		for index := 0; index < messages; index++ {
			plaintext := []byte(fmt.Sprintf("initiator-%d", index))
			ciphertext, err := initiator.Encrypt(nil, plaintext)
			if err != nil {
				errorsOut <- err
				return
			}
			opened, err := responder.Decrypt(nil, ciphertext)
			if err != nil {
				errorsOut <- err
				return
			}
			if !bytes.Equal(opened, plaintext) {
				errorsOut <- fmt.Errorf("initiator direction %d: opened=%q", index, opened)
				return
			}
		}
	}()
	go func() {
		defer workers.Done()
		for index := 0; index < messages; index++ {
			plaintext := []byte(fmt.Sprintf("responder-%d", index))
			ciphertext, err := responder.Encrypt(nil, plaintext)
			if err != nil {
				errorsOut <- err
				return
			}
			opened, err := initiator.Decrypt(nil, ciphertext)
			if err != nil {
				errorsOut <- err
				return
			}
			if !bytes.Equal(opened, plaintext) {
				errorsOut <- fmt.Errorf("responder direction %d: opened=%q", index, opened)
				return
			}
		}
	}()
	workers.Wait()
	close(errorsOut)
	for err := range errorsOut {
		t.Fatal(err)
	}
}

type testingTB interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

func completeHandshake(t testingTB, initiatorPrologue, responderPrologue []byte, initiatorPSK, responderPSK [32]byte) (*noisecore.Session, *noisecore.Session) {
	t.Helper()
	initiator, err := newInitiator(initiatorPrologue, initiatorPSK, 0x81)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := newResponder(responderPrologue, responderPSK, 0x91)
	if err != nil {
		_ = initiator.Close()
		t.Fatal(err)
	}
	first, err := initiator.WriteMessage(nil)
	if err == nil {
		_, err = responder.ReadMessage(first)
	}
	if err != nil {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatalf("first handshake message: %v", err)
	}
	second, err := responder.WriteMessage(nil)
	if err == nil {
		_, err = initiator.ReadMessage(second)
	}
	if err != nil {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatalf("second handshake message: %v", err)
	}
	if !initiator.Complete() || !responder.Complete() || len(first) != PublicHandshakeMessageSize || len(second) != PublicHandshakeMessageSize {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatal("handshake did not complete with two 48-byte messages")
	}
	return initiator, responder
}

func handshakeThroughSecondWrite(t *testing.T, prologue []byte, psk [32]byte) (*noisecore.Session, *noisecore.Session, []byte) {
	t.Helper()
	initiator, err := newInitiator(prologue, psk, 0xa1)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := newResponder(prologue, psk, 0xb1)
	if err != nil {
		_ = initiator.Close()
		t.Fatal(err)
	}
	first, err := initiator.WriteMessage(nil)
	if err == nil {
		_, err = responder.ReadMessage(first)
	}
	if err != nil {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatal(err)
	}
	second, err := responder.WriteMessage(nil)
	if err != nil {
		_ = initiator.Close()
		_ = responder.Close()
		t.Fatal(err)
	}
	return initiator, responder, second
}

func newInitiator(prologue []byte, psk [32]byte, randomByte byte) (*noisecore.Session, error) {
	return noisecore.NewInitiator(noisecore.Config{
		Prologue: prologue,
		PSK:      fixedPSKSource{key: psk},
		Random:   bytes.NewReader(bytes.Repeat([]byte{randomByte}, 32)),
	})
}

func newResponder(prologue []byte, psk [32]byte, randomByte byte) (*noisecore.Session, error) {
	return noisecore.NewResponder(noisecore.Config{
		Prologue: prologue,
		PSK:      fixedPSKSource{key: psk},
		Random:   bytes.NewReader(bytes.Repeat([]byte{randomByte}, 32)),
	})
}

func pairingPrologue(t *testing.T) []byte {
	t.Helper()
	now := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	context := testpairing.PairingContext{
		Artifact:               testpairing.PairingArtifactAcceptance,
		Protocol:               testpairing.ProtocolVersion,
		AuthScope:              testpairing.AuthScope,
		CredentialID:           encodedID(1),
		AttemptID:              encodedID(2),
		ObservationGeneration:  "1",
		InitiatorParticipantID: encodedID(3),
		ResponderParticipantID: encodedID(4),
		InitiatorGovernorScope: string(testpairing.GovernorScopeMachine),
		ResponderGovernorScope: string(testpairing.GovernorScopeUserAcknowledged),
		SecureChannelProfile:   testpairing.SelectedSecureChannelProfile,
		IssuedAt:               now.Format(time.RFC3339),
		ExpiresAt:              now.Add(5 * time.Minute).Format(time.RFC3339),
		OfferFingerprint:       base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32)),
		InitiatorChannelRole:   testpairing.ChannelRoleInitiator,
		ResponderChannelRole:   testpairing.ChannelRoleResponder,
		EarlyData:              testpairing.FeatureDisabled,
		Resumption:             testpairing.FeatureDisabled,
		RuntimeFallback:        testpairing.FeatureDisabled,
	}
	prologue, err := testpairing.BuildNoisePrologue(context)
	if err != nil {
		t.Fatalf("build pairing prologue: %v", err)
	}
	return prologue
}

func encodedID(seed byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seed}, 16))
}

func repeatedKey(value byte) [32]byte {
	var key [32]byte
	for index := range key {
		key[index] = value
	}
	return key
}
