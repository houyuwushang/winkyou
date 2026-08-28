package noisecore

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const (
	ProtocolName          = "Noise_NNpsk0_25519_ChaChaPoly_SHA256"
	PSKSize               = 32
	PublicKeySize         = 32
	HashSize              = 32
	TagSize               = 16
	MaxNoiseMessageSize   = 65535
	MaxHandshakePayload   = MaxNoiseMessageSize - PublicKeySize - TagSize
	MaxTransportPlaintext = MaxNoiseMessageSize - TagSize
	MaxPrologueSize       = 64 * 1024
)

var (
	ErrInvalidConfig        = errors.New("noisecore: invalid configuration")
	ErrPSKUnavailable       = errors.New("noisecore: preshared key unavailable")
	ErrRandomSource         = errors.New("noisecore: random source failed")
	ErrUnexpectedMessage    = errors.New("noisecore: unexpected handshake message")
	ErrInvalidMessage       = errors.New("noisecore: invalid Noise message")
	ErrAuthentication       = errors.New("noisecore: authentication failed")
	ErrLowOrderPoint        = errors.New("noisecore: invalid low-order X25519 public key")
	ErrNonceExhausted       = errors.New("noisecore: nonce exhausted")
	ErrSequenceOutOfRange   = errors.New("noisecore: packet sequence out of range")
	ErrSequenceReuse        = errors.New("noisecore: packet sequence reused")
	ErrTransportAlreadyUsed = errors.New("noisecore: ordered transport state already used")
	ErrHandshakeIncomplete  = errors.New("noisecore: handshake incomplete")
	ErrClosed               = errors.New("noisecore: state closed")
)

// PSKSource supplies one already-derived 32-byte pairing secret. noisecore
// never derives, persists, or fetches pairing material itself.
type PSKSource interface {
	LoadPSK() ([PSKSize]byte, error)
}

// TakePacketCipher atomically moves both unused Split keys into a bounded
// explicit-sequence packet cipher. It is mutually exclusive with Encrypt and
// Decrypt: once called, Session is permanently closed and cannot be reused.
// This narrow simulation seam implements the out-of-order transport guidance
// in Noise revision 34 section 11.4 without exposing keys or mutable SetNonce.
func (session *Session) TakePacketCipher(maxSequence uint64) (*PacketCipher, error) {
	packetCipher, planner, err := session.takePacketCipher(maxSequence, false)
	if planner != nil {
		planner.Close()
	}
	return packetCipher, err
}

const maxPlannerContextBytes = 4096

// PlannerKeySource owns a domain-separated secret derived from the canonical
// ordered Noise Split keys. It cannot encrypt traffic or expose either
// transport key and exists only for Gate B's deterministic planner PRF.
type PlannerKeySource struct {
	mu     sync.Mutex
	secret [HashSize]byte
	closed bool
}

// TakePacketCipherAndPlannerKeySource atomically transfers the transport keys
// into PacketCipher and derives one narrow planner-key source. Initiator and
// responder canonicalize the two directional Split keys in the same order.
func (session *Session) TakePacketCipherAndPlannerKeySource(maxSequence uint64) (*PacketCipher, *PlannerKeySource, error) {
	return session.takePacketCipher(maxSequence, true)
}

func (session *Session) takePacketCipher(maxSequence uint64, withPlanner bool) (*PacketCipher, *PlannerKeySource, error) {
	if session == nil {
		return nil, nil, ErrClosed
	}
	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return nil, nil, ErrClosed
	}
	if !session.complete || session.send == nil || session.receive == nil {
		session.mu.Unlock()
		return nil, nil, ErrHandshakeIncomplete
	}
	if maxSequence == ^uint64(0) {
		session.mu.Unlock()
		return nil, nil, ErrSequenceOutOfRange
	}
	send := session.send
	receive := session.receive
	send.mu.Lock()
	receive.mu.Lock()
	if send.core.closed || receive.core.closed || !send.core.hasKey || !receive.core.hasKey || send.core.nonce != 0 || receive.core.nonce != 0 {
		receive.mu.Unlock()
		send.mu.Unlock()
		session.failLocked(ErrTransportAlreadyUsed)
		session.send = nil
		session.receive = nil
		session.mu.Unlock()
		closeCipherStates(send, receive)
		return nil, nil, ErrTransportAlreadyUsed
	}
	sendKey := send.core.key
	receiveKey := receive.core.key
	var planner *PlannerKeySource
	if withPlanner {
		first, second := sendKey, receiveKey
		if session.role == roleResponder {
			first, second = receiveKey, sendKey
		}
		mac := hmac.New(sha256.New, first[:])
		_, _ = mac.Write([]byte("winkyou-hardnat-planner-exporter-v1\x00"))
		_, _ = mac.Write(second[:])
		_, _ = mac.Write(session.handshakeHash[:])
		var secret [HashSize]byte
		copy(secret[:], mac.Sum(nil))
		planner = &PlannerKeySource{secret: secret}
		zeroBytes(secret[:])
	}
	send.core.zeroize()
	receive.core.zeroize()
	receive.mu.Unlock()
	send.mu.Unlock()
	session.closed = true
	session.complete = false
	session.send = nil
	session.receive = nil
	zeroBytes(session.handshakeHash[:])
	session.mu.Unlock()
	packetCipher := newPacketCipher(sendKey, receiveKey, maxSequence)
	zeroBytes(sendKey[:])
	zeroBytes(receiveKey[:])
	return packetCipher, planner, nil
}

// Derive deterministically expands the planner exporter for one canonical
// Gate B context. It does not consume the source, so both local recomputation
// passes can prove the same plan; Close invalidates all future derivations.
func (source *PlannerKeySource) Derive(context []byte) ([HashSize]byte, error) {
	if source == nil || len(context) == 0 || len(context) > maxPlannerContextBytes {
		return [HashSize]byte{}, ErrInvalidConfig
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || allZero(source.secret[:]) {
		return [HashSize]byte{}, ErrClosed
	}
	mac := hmac.New(sha256.New, source.secret[:])
	_, _ = mac.Write([]byte("winkyou-hardnat-planner-key-v1\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(context)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write(context)
	var result [HashSize]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func (source *PlannerKeySource) Close() {
	if source == nil {
		return
	}
	source.mu.Lock()
	zeroBytes(source.secret[:])
	source.closed = true
	source.mu.Unlock()
}

// Config contains only caller-owned in-memory inputs. Random defaults to
// crypto/rand.Reader; deterministic readers are intended only for vectors.
type Config struct {
	Prologue []byte
	PSK      PSKSource
	Random   io.Reader
}

type role uint8

const (
	roleInitiator role = iota + 1
	roleResponder
)

type phase uint8

const (
	phaseInitiatorWriteFirst phase = iota + 1
	phaseInitiatorReadSecond
	phaseResponderReadFirst
	phaseResponderWriteSecond
	phaseComplete
)

// Session owns one role of one NNpsk0 handshake and the two transport cipher
// directions produced by Split. It is not reusable across attempts.
type Session struct {
	mu sync.Mutex

	role   role
	phase  phase
	random io.Reader

	symmetric  symmetricState
	psk        [PSKSize]byte
	localE     [PublicKeySize]byte
	remoteE    [PublicKeySize]byte
	hasLocalE  bool
	hasRemoteE bool

	handshakeHash [HashSize]byte
	send          *CipherState
	receive       *CipherState
	complete      bool
	closed        bool
}

// NewInitiator constructs the first-message writer for one attempt.
func NewInitiator(config Config) (*Session, error) {
	return newSession(roleInitiator, config)
}

// NewResponder constructs the first-message reader for one attempt.
func NewResponder(config Config) (*Session, error) {
	return newSession(roleResponder, config)
}

func newSession(sessionRole role, config Config) (*Session, error) {
	if config.PSK == nil || len(config.Prologue) == 0 || len(config.Prologue) > MaxPrologueSize {
		return nil, ErrInvalidConfig
	}
	psk, err := config.PSK.LoadPSK()
	if err != nil {
		zeroBytes(psk[:])
		return nil, ErrPSKUnavailable
	}
	randomSource := config.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}

	session := &Session{
		role:   sessionRole,
		random: randomSource,
		psk:    psk,
	}
	zeroBytes(psk[:])
	session.symmetric.initialize(ProtocolName)
	session.symmetric.mixHash(config.Prologue)
	if sessionRole == roleInitiator {
		session.phase = phaseInitiatorWriteFirst
	} else {
		session.phase = phaseResponderReadFirst
	}
	return session, nil
}

// WriteMessage emits the next Noise handshake message. The core accepts a
// Noise payload so the upstream conformance vectors can be checked exactly;
// WinkYou's pairing profile must pass an empty payload at its adapter boundary.
func (session *Session) WriteMessage(payload []byte) ([]byte, error) {
	if session == nil {
		return nil, ErrClosed
	}
	session.mu.Lock()
	closeTransports := false
	defer func() {
		send := session.send
		receive := session.receive
		session.mu.Unlock()
		if closeTransports {
			closeCipherStates(send, receive)
		}
	}()
	if session.closed {
		return nil, ErrClosed
	}
	if len(payload) > MaxHandshakePayload {
		closeTransports = true
		return nil, session.failLocked(ErrInvalidMessage)
	}

	var (
		message []byte
		err     error
	)
	switch session.phase {
	case phaseInitiatorWriteFirst:
		message, err = session.writeFirst(payload)
		if err == nil {
			session.phase = phaseInitiatorReadSecond
		}
	case phaseResponderWriteSecond:
		message, err = session.writeSecond(payload)
		if err == nil {
			err = session.completeLocked()
		}
	default:
		err = ErrUnexpectedMessage
	}
	if err != nil {
		closeTransports = true
		return nil, session.failLocked(err)
	}
	return message, nil
}

// ReadMessage consumes the next Noise handshake message and returns its
// authenticated payload.
func (session *Session) ReadMessage(message []byte) ([]byte, error) {
	if session == nil {
		return nil, ErrClosed
	}
	session.mu.Lock()
	closeTransports := false
	defer func() {
		send := session.send
		receive := session.receive
		session.mu.Unlock()
		if closeTransports {
			closeCipherStates(send, receive)
		}
	}()
	if session.closed {
		return nil, ErrClosed
	}
	if len(message) < PublicKeySize+TagSize || len(message) > MaxNoiseMessageSize {
		closeTransports = true
		return nil, session.failLocked(ErrInvalidMessage)
	}

	var (
		payload []byte
		err     error
	)
	switch session.phase {
	case phaseResponderReadFirst:
		payload, err = session.readFirst(message)
		if err == nil {
			session.phase = phaseResponderWriteSecond
		}
	case phaseInitiatorReadSecond:
		payload, err = session.readSecond(message)
		if err == nil {
			err = session.completeLocked()
		}
	default:
		err = ErrUnexpectedMessage
	}
	if err != nil {
		zeroBytes(payload)
		closeTransports = true
		return nil, session.failLocked(err)
	}
	return payload, nil
}

func (session *Session) writeFirst(payload []byte) ([]byte, error) {
	session.mixPSK()
	publicKey, err := session.generateEphemeral()
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, PublicKeySize+len(payload)+TagSize)
	message = append(message, publicKey...)
	session.symmetric.mixHash(publicKey)
	session.symmetric.mixKey(publicKey)
	ciphertext, err := session.symmetric.encryptAndHash(payload)
	if err != nil {
		zeroBytes(message)
		return nil, err
	}
	message = append(message, ciphertext...)
	zeroBytes(ciphertext)
	return message, nil
}

func (session *Session) readFirst(message []byte) ([]byte, error) {
	session.mixPSK()
	if err := session.setRemoteEphemeral(message[:PublicKeySize]); err != nil {
		return nil, err
	}
	session.symmetric.mixHash(message[:PublicKeySize])
	session.symmetric.mixKey(message[:PublicKeySize])
	return session.symmetric.decryptAndHash(message[PublicKeySize:])
}

func (session *Session) writeSecond(payload []byte) ([]byte, error) {
	publicKey, err := session.generateEphemeral()
	if err != nil {
		return nil, err
	}
	message := make([]byte, 0, PublicKeySize+len(payload)+TagSize)
	message = append(message, publicKey...)
	session.symmetric.mixHash(publicKey)
	session.symmetric.mixKey(publicKey)
	shared, err := x25519(session.localE, session.remoteE)
	session.clearLocalEphemeral()
	if err != nil {
		zeroBytes(message)
		return nil, err
	}
	session.symmetric.mixKey(shared)
	zeroBytes(shared)
	ciphertext, err := session.symmetric.encryptAndHash(payload)
	if err != nil {
		zeroBytes(message)
		return nil, err
	}
	message = append(message, ciphertext...)
	zeroBytes(ciphertext)
	return message, nil
}

func (session *Session) readSecond(message []byte) ([]byte, error) {
	if err := session.setRemoteEphemeral(message[:PublicKeySize]); err != nil {
		return nil, err
	}
	session.symmetric.mixHash(message[:PublicKeySize])
	session.symmetric.mixKey(message[:PublicKeySize])
	shared, err := x25519(session.localE, session.remoteE)
	session.clearLocalEphemeral()
	if err != nil {
		return nil, err
	}
	session.symmetric.mixKey(shared)
	zeroBytes(shared)
	return session.symmetric.decryptAndHash(message[PublicKeySize:])
}

func (session *Session) mixPSK() {
	session.symmetric.mixKeyAndHash(session.psk[:])
	zeroBytes(session.psk[:])
}

func (session *Session) generateEphemeral() ([]byte, error) {
	if session.hasLocalE {
		return nil, ErrUnexpectedMessage
	}
	if _, err := io.ReadFull(session.random, session.localE[:]); err != nil {
		session.clearLocalEphemeral()
		return nil, ErrRandomSource
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(session.localE[:])
	if err != nil {
		session.clearLocalEphemeral()
		return nil, ErrRandomSource
	}
	publicKey := privateKey.PublicKey().Bytes()
	if len(publicKey) != PublicKeySize {
		zeroBytes(publicKey)
		session.clearLocalEphemeral()
		return nil, ErrRandomSource
	}
	session.hasLocalE = true
	return publicKey, nil
}

func (session *Session) setRemoteEphemeral(publicKey []byte) error {
	if session.hasRemoteE || len(publicKey) != PublicKeySize {
		return ErrUnexpectedMessage
	}
	copy(session.remoteE[:], publicKey)
	session.hasRemoteE = true
	return nil
}

func x25519(privateBytes, publicBytes [PublicKeySize]byte) ([]byte, error) {
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes[:])
	if err != nil {
		return nil, ErrLowOrderPoint
	}
	publicKey, err := ecdh.X25519().NewPublicKey(publicBytes[:])
	if err != nil {
		return nil, ErrLowOrderPoint
	}
	shared, err := privateKey.ECDH(publicKey)
	if err != nil || allZero(shared) {
		zeroBytes(shared)
		return nil, ErrLowOrderPoint
	}
	return shared, nil
}

func allZero(value []byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}

func (session *Session) completeLocked() error {
	first, second, err := session.symmetric.split()
	if err != nil {
		return err
	}
	session.handshakeHash = session.symmetric.handshakeHash()
	if session.role == roleInitiator {
		session.send = newCipherState(first)
		session.receive = newCipherState(second)
	} else {
		session.send = newCipherState(second)
		session.receive = newCipherState(first)
	}
	zeroBytes(first[:])
	zeroBytes(second[:])
	session.symmetric.zeroize()
	session.clearHandshakeSecretsLocked()
	session.phase = phaseComplete
	session.complete = true
	return nil
}

// Complete reports whether Split succeeded and transport keys are available.
func (session *Session) Complete() bool {
	if session == nil {
		return false
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.complete && !session.closed
}

// HandshakeHash returns a copy of the final transcript hash after completion.
func (session *Session) HandshakeHash() ([HashSize]byte, error) {
	if session == nil {
		return [HashSize]byte{}, ErrClosed
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return [HashSize]byte{}, ErrClosed
	}
	if !session.complete {
		return [HashSize]byte{}, ErrHandshakeIncomplete
	}
	return session.handshakeHash, nil
}

// Encrypt protects one post-handshake transport payload with the role's send
// CipherState. Additional data is authenticated but not encrypted.
func (session *Session) Encrypt(additionalData, plaintext []byte) ([]byte, error) {
	state, err := session.transportState(true)
	if err != nil {
		return nil, err
	}
	ciphertext, err := state.Encrypt(additionalData, plaintext)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return ciphertext, nil
}

// Decrypt authenticates and opens one post-handshake transport payload with
// the role's receive CipherState. Any failure permanently closes the session.
func (session *Session) Decrypt(additionalData, ciphertext []byte) ([]byte, error) {
	state, err := session.transportState(false)
	if err != nil {
		return nil, err
	}
	plaintext, err := state.Decrypt(additionalData, ciphertext)
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return plaintext, nil
}

func (session *Session) transportState(send bool) (*CipherState, error) {
	if session == nil {
		return nil, ErrClosed
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return nil, ErrClosed
	}
	if !session.complete {
		return nil, ErrHandshakeIncomplete
	}
	if send {
		return session.send, nil
	}
	return session.receive, nil
}

func (session *Session) failLocked(err error) error {
	session.closed = true
	session.complete = false
	session.symmetric.zeroize()
	session.clearHandshakeSecretsLocked()
	zeroBytes(session.handshakeHash[:])
	return err
}

func (session *Session) clearHandshakeSecretsLocked() {
	zeroBytes(session.psk[:])
	session.clearLocalEphemeral()
	zeroBytes(session.remoteE[:])
	session.hasRemoteE = false
	session.random = nil
}

func (session *Session) clearLocalEphemeral() {
	zeroBytes(session.localE[:])
	session.hasLocalE = false
}

// Zeroize closes the session and best-effort overwrites reachable key bytes.
func (session *Session) Zeroize() {
	_ = session.Close()
}

// Close permanently invalidates the handshake and both transport directions.
func (session *Session) Close() error {
	if session == nil {
		return nil
	}
	session.mu.Lock()
	if session.closed {
		send := session.send
		receive := session.receive
		session.mu.Unlock()
		closeCipherStates(send, receive)
		return nil
	}
	session.closed = true
	session.complete = false
	session.symmetric.zeroize()
	session.clearHandshakeSecretsLocked()
	zeroBytes(session.handshakeHash[:])
	send := session.send
	receive := session.receive
	session.mu.Unlock()
	closeCipherStates(send, receive)
	return nil
}

func closeCipherStates(send, receive *CipherState) {
	if send != nil {
		_ = send.Close()
	}
	if receive != nil {
		_ = receive.Close()
	}
}

func zeroBytes(value []byte) {
	clear(value)
}
