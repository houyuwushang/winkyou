package testpairing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	ProtocolVersion = "winkyou-test-pairing/1"
	AuthScope       = "test_only"

	MaxPairingLifetime     = 10 * time.Minute
	MaxControlLifetime     = 15 * time.Second
	MaxFrameBodyBytes      = 4096
	MaxPayloadBytes        = 2048
	MaxMessagesPerSide     = 5
	MaxMessagesTotal       = 9
	receiveTokensPerSecond = 4.0
	receiveBurst           = 2.0
)

var (
	ErrInvalidContext    = errors.New("testpairing: invalid attempt context")
	ErrExpired           = errors.New("testpairing: attempt expired")
	ErrClockRollback     = errors.New("testpairing: clock moved backwards")
	ErrCredentialUsed    = errors.New("testpairing: credential already burned")
	ErrClosed            = errors.New("testpairing: channel closed")
	ErrInvalidTransition = errors.New("testpairing: invalid state transition")
	ErrContextMismatch   = errors.New("testpairing: message context mismatch")
	ErrSequence          = errors.New("testpairing: invalid message sequence")
	ErrLimitExceeded     = errors.New("testpairing: hard limit exceeded")
	ErrRateLimited       = errors.New("testpairing: receive rate exceeded")
)

type Role string

const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
)

func (r Role) valid() bool {
	return r == RoleInitiator || r == RoleResponder
}

func (r Role) peer() Role {
	if r == RoleInitiator {
		return RoleResponder
	}
	return RoleInitiator
}

type GovernorScope string

const (
	GovernorScopeMachine          GovernorScope = "machine"
	GovernorScopeUserAcknowledged GovernorScope = "user_acknowledged"
)

func (s GovernorScope) valid() bool {
	return s == GovernorScopeMachine || s == GovernorScopeUserAcknowledged
}

type MessageType string

const (
	MessagePrepare MessageType = "prepare"
	MessageReady   MessageType = "ready"
	MessageFire    MessageType = "fire"
	MessageVerify  MessageType = "verify"
	MessageCancel  MessageType = "cancel"
)

func (m MessageType) valid() bool {
	switch m {
	case MessagePrepare, MessageReady, MessageFire, MessageVerify, MessageCancel:
		return true
	default:
		return false
	}
}

// AttemptContext is the non-secret context that a future reviewed handshake
// must bind. The fake transport never receives or derives a pairing secret.
type AttemptContext struct {
	Protocol               string
	AuthScope              string
	CredentialID           string
	AttemptID              string
	ObservationGeneration  uint64
	InitiatorParticipantID string
	ResponderParticipantID string
	InitiatorGovernorScope GovernorScope
	ResponderGovernorScope GovernorScope
	IssuedAt               time.Time
	ExpiresAt              time.Time
}

func (c AttemptContext) Validate(now time.Time) error {
	if c.Protocol != ProtocolVersion {
		return fmt.Errorf("%w: protocol", ErrInvalidContext)
	}
	if c.AuthScope != AuthScope {
		return fmt.Errorf("%w: auth scope", ErrInvalidContext)
	}
	identifiers := []struct {
		name  string
		value string
	}{
		{"credential id", c.CredentialID},
		{"attempt id", c.AttemptID},
		{"initiator participant id", c.InitiatorParticipantID},
		{"responder participant id", c.ResponderParticipantID},
	}
	seen := make(map[string]struct{}, len(identifiers))
	for _, identifier := range identifiers {
		if err := validateIdentifier(identifier.value); err != nil {
			return fmt.Errorf("%w: %s", ErrInvalidContext, identifier.name)
		}
		if _, exists := seen[identifier.value]; exists {
			return fmt.Errorf("%w: identifiers must be distinct", ErrInvalidContext)
		}
		seen[identifier.value] = struct{}{}
	}
	if c.ObservationGeneration == 0 {
		return fmt.Errorf("%w: observation generation", ErrInvalidContext)
	}
	if !c.InitiatorGovernorScope.valid() || !c.ResponderGovernorScope.valid() {
		return fmt.Errorf("%w: governor scope", ErrInvalidContext)
	}
	if !canonicalSecondUTC(c.IssuedAt) || !canonicalSecondUTC(c.ExpiresAt) {
		return fmt.Errorf("%w: timestamps must be UTC whole seconds", ErrInvalidContext)
	}
	lifetime := c.ExpiresAt.Sub(c.IssuedAt)
	if lifetime <= 0 || lifetime > MaxPairingLifetime {
		return fmt.Errorf("%w: pairing lifetime", ErrInvalidContext)
	}
	if now.Before(c.IssuedAt) || !now.Before(c.ExpiresAt) {
		return ErrExpired
	}
	return nil
}

func validateIdentifier(value string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 16 {
		return ErrInvalidContext
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return ErrInvalidContext
	}
	return nil
}

func canonicalSecondUTC(value time.Time) bool {
	name, offset := value.Zone()
	return name == "UTC" && offset == 0 && value.Nanosecond() == 0
}

func (c AttemptContext) participant(role Role) (string, GovernorScope) {
	if role == RoleInitiator {
		return c.InitiatorParticipantID, c.InitiatorGovernorScope
	}
	return c.ResponderParticipantID, c.ResponderGovernorScope
}

// Message is a simulation-domain envelope. It is not a wire encoding and its
// fields are not authenticated by this package.
type Message struct {
	Protocol              string
	AuthScope             string
	AttemptID             string
	ObservationGeneration uint64
	FromParticipantID     string
	ToParticipantID       string
	SenderRole            Role
	GovernorScope         GovernorScope
	Sequence              uint64
	Type                  MessageType
	Payload               []byte
}

type TerminalReason string

const (
	TerminalNone          TerminalReason = ""
	TerminalSuccess       TerminalReason = "success"
	TerminalCancelled     TerminalReason = "cancelled"
	TerminalExpired       TerminalReason = "expired"
	TerminalProtocolError TerminalReason = "protocol_error"
)

type Status struct {
	Role     Role
	Terminal bool
	Success  bool
	Reason   TerminalReason
	Sent     int
	Received int
}

// TestPairingChannel is the minimal attempt-control contract shared by the
// simulation and a possible future reviewed adapter. It carries no membership
// or network-opening capability.
type TestPairingChannel interface {
	Send(context.Context, MessageType, []byte) error
	Receive(context.Context) (Message, error)
	Status() Status
}

// SimulatedChannel is a bounded, in-memory model of TestPairingChannel. It has
// zero transport security and is suitable only for deterministic tests.
type SimulatedChannel struct {
	context  AttemptContext
	role     Role
	ledger   ReplayLedger
	now      func() time.Time
	incoming chan Message
	outgoing chan Message

	sendMu sync.Mutex
	recvMu sync.Mutex
	mu     sync.Mutex
	state  channelState
}

type channelState struct {
	startedAt time.Time
	lastNow   time.Time

	sendSequence    uint64
	receiveSequence uint64
	sentCount       int
	receivedCount   int

	sentPrepare     bool
	receivedPrepare bool
	sentReady       bool
	receivedReady   bool
	sentFire        bool
	receivedFire    bool
	sentVerify      bool
	receivedVerify  bool
	sentCancel      bool
	receivedCancel  bool

	terminal bool
	success  bool
	reason   TerminalReason

	receiveBucket tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// NewSimulatedPair burns the credential independently in each injected ledger
// and creates a one-frame-buffered, in-memory duplex pair. If the second burn
// fails, the first remains burned by design.
func NewSimulatedPair(
	attempt AttemptContext,
	initiatorLedger ReplayLedger,
	responderLedger ReplayLedger,
	now func() time.Time,
) (*SimulatedChannel, *SimulatedChannel, error) {
	if initiatorLedger == nil || responderLedger == nil || now == nil {
		return nil, nil, fmt.Errorf("%w: missing simulation dependency", ErrInvalidContext)
	}
	startedAt := now()
	if err := attempt.Validate(startedAt); err != nil {
		return nil, nil, err
	}
	if err := burn(attempt, RoleInitiator, initiatorLedger, startedAt); err != nil {
		return nil, nil, err
	}
	if err := burn(attempt, RoleResponder, responderLedger, startedAt); err != nil {
		return nil, nil, errors.Join(
			err,
			initiatorLedger.Finish(attempt.CredentialID, TerminalProtocolError),
		)
	}

	initiatorToResponder := make(chan Message, 1)
	responderToInitiator := make(chan Message, 1)
	initiator := newSimulatedChannel(
		attempt,
		RoleInitiator,
		initiatorLedger,
		now,
		responderToInitiator,
		initiatorToResponder,
		startedAt,
	)
	responder := newSimulatedChannel(
		attempt,
		RoleResponder,
		responderLedger,
		now,
		initiatorToResponder,
		responderToInitiator,
		startedAt,
	)
	return initiator, responder, nil
}

func burn(attempt AttemptContext, role Role, ledger ReplayLedger, now time.Time) error {
	_, scope := attempt.participant(role)
	return ledger.Burn(BurnRecord{
		CredentialID: attempt.CredentialID,
		AttemptID:    attempt.AttemptID,
		LocalRole:    role,
		LocalScope:   scope,
		BurnedAt:     now,
		ExpiresAt:    attempt.ExpiresAt,
	})
}

func newSimulatedChannel(
	attempt AttemptContext,
	role Role,
	ledger ReplayLedger,
	now func() time.Time,
	incoming chan Message,
	outgoing chan Message,
	startedAt time.Time,
) *SimulatedChannel {
	return &SimulatedChannel{
		context:  attempt,
		role:     role,
		ledger:   ledger,
		now:      now,
		incoming: incoming,
		outgoing: outgoing,
		state: channelState{
			startedAt: startedAt,
			lastNow:   startedAt,
			receiveBucket: tokenBucket{
				tokens: receiveBurst,
				last:   startedAt,
			},
		},
	}
}

func (c *SimulatedChannel) Send(ctx context.Context, messageType MessageType, payload []byte) error {
	if c == nil {
		return ErrClosed
	}
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidTransition)
	}
	c.sendMu.Lock()
	defer c.sendMu.Unlock()
	if err := ctx.Err(); err != nil {
		return c.fail(TerminalCancelled, err)
	}

	c.mu.Lock()
	if err := c.checkLiveLocked(); err != nil {
		c.mu.Unlock()
		return err
	}
	if err := c.validateSendLocked(messageType, payload); err != nil {
		err = c.failLocked(TerminalProtocolError, err)
		c.mu.Unlock()
		return err
	}
	localID, localScope := c.context.participant(c.role)
	peerID, _ := c.context.participant(c.role.peer())
	message := Message{
		Protocol:              ProtocolVersion,
		AuthScope:             AuthScope,
		AttemptID:             c.context.AttemptID,
		ObservationGeneration: c.context.ObservationGeneration,
		FromParticipantID:     localID,
		ToParticipantID:       peerID,
		SenderRole:            c.role,
		GovernorScope:         localScope,
		Sequence:              c.state.sendSequence + 1,
		Type:                  messageType,
		Payload:               append([]byte(nil), payload...),
	}
	timer := time.NewTimer(c.remainingLocked())
	defer stopTimer(timer)

	select {
	case c.outgoing <- message:
		c.applySendLocked(messageType)
		err := c.finishIfTerminalLocked()
		c.mu.Unlock()
		return err
	case <-ctx.Done():
		err := c.failLocked(TerminalCancelled, ctx.Err())
		c.mu.Unlock()
		return err
	case <-timer.C:
		err := c.failLocked(TerminalExpired, ErrExpired)
		c.mu.Unlock()
		return err
	}
}

func (c *SimulatedChannel) Receive(ctx context.Context) (Message, error) {
	if c == nil {
		return Message{}, ErrClosed
	}
	if ctx == nil {
		return Message{}, fmt.Errorf("%w: nil context", ErrInvalidTransition)
	}
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if err := ctx.Err(); err != nil {
		return Message{}, c.fail(TerminalCancelled, err)
	}

	c.mu.Lock()
	if err := c.checkLiveLocked(); err != nil {
		c.mu.Unlock()
		return Message{}, err
	}
	timer := time.NewTimer(c.remainingLocked())
	c.mu.Unlock()
	defer stopTimer(timer)

	var message Message
	select {
	case message = <-c.incoming:
	case <-ctx.Done():
		return Message{}, c.fail(TerminalCancelled, ctx.Err())
	case <-timer.C:
		return Message{}, c.fail(TerminalExpired, ErrExpired)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLiveLocked(); err != nil {
		return Message{}, err
	}
	if !c.allowReceiveLocked() {
		return Message{}, c.failLocked(TerminalProtocolError, ErrRateLimited)
	}
	if err := c.validateMessageLocked(message); err != nil {
		return Message{}, c.failLocked(TerminalProtocolError, err)
	}
	if err := c.validateReceiveTransitionLocked(message.Type); err != nil {
		return Message{}, c.failLocked(TerminalProtocolError, err)
	}
	c.applyReceiveLocked(message.Type)
	if err := c.finishIfTerminalLocked(); err != nil {
		return Message{}, err
	}
	message.Payload = append([]byte(nil), message.Payload...)
	return message, nil
}

func (c *SimulatedChannel) Status() Status {
	if c == nil {
		return Status{Terminal: true, Reason: TerminalProtocolError}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return Status{
		Role:     c.role,
		Terminal: c.state.terminal,
		Success:  c.state.success,
		Reason:   c.state.reason,
		Sent:     c.state.sentCount,
		Received: c.state.receivedCount,
	}
}

func (c *SimulatedChannel) validateSendLocked(messageType MessageType, payload []byte) error {
	if !messageType.valid() {
		return fmt.Errorf("%w: unknown message type", ErrInvalidTransition)
	}
	if len(payload) > MaxPayloadBytes {
		return fmt.Errorf("%w: payload", ErrLimitExceeded)
	}
	if c.state.sentCount >= MaxMessagesPerSide || c.state.sentCount+c.state.receivedCount >= MaxMessagesTotal {
		return fmt.Errorf("%w: message count", ErrLimitExceeded)
	}
	switch messageType {
	case MessagePrepare:
		if c.state.sentPrepare {
			return ErrInvalidTransition
		}
	case MessageReady:
		if !c.state.sentPrepare || !c.state.receivedPrepare || c.state.sentReady {
			return ErrInvalidTransition
		}
	case MessageFire:
		if c.role != RoleInitiator || !c.state.sentReady || !c.state.receivedReady || c.state.sentFire {
			return ErrInvalidTransition
		}
	case MessageVerify:
		if c.state.sentVerify {
			return ErrInvalidTransition
		}
		if c.role == RoleInitiator && !c.state.sentFire {
			return ErrInvalidTransition
		}
		if c.role == RoleResponder && !c.state.receivedFire {
			return ErrInvalidTransition
		}
	case MessageCancel:
		if c.state.sentCancel {
			return ErrInvalidTransition
		}
	}
	return nil
}

func (c *SimulatedChannel) validateMessageLocked(message Message) error {
	peerID, peerScope := c.context.participant(c.role.peer())
	localID, _ := c.context.participant(c.role)
	if message.Protocol != ProtocolVersion ||
		message.AuthScope != AuthScope ||
		message.AttemptID != c.context.AttemptID ||
		message.ObservationGeneration != c.context.ObservationGeneration ||
		message.FromParticipantID != peerID ||
		message.ToParticipantID != localID ||
		message.SenderRole != c.role.peer() ||
		message.GovernorScope != peerScope {
		return ErrContextMismatch
	}
	if message.Sequence != c.state.receiveSequence+1 {
		return ErrSequence
	}
	if !message.Type.valid() {
		return fmt.Errorf("%w: unknown message type", ErrInvalidTransition)
	}
	if len(message.Payload) > MaxPayloadBytes {
		return fmt.Errorf("%w: payload", ErrLimitExceeded)
	}
	if c.state.receivedCount >= MaxMessagesPerSide || c.state.sentCount+c.state.receivedCount >= MaxMessagesTotal {
		return fmt.Errorf("%w: message count", ErrLimitExceeded)
	}
	return nil
}

func (c *SimulatedChannel) validateReceiveTransitionLocked(messageType MessageType) error {
	switch messageType {
	case MessagePrepare:
		if c.state.receivedPrepare {
			return ErrInvalidTransition
		}
	case MessageReady:
		if !c.state.sentPrepare || !c.state.receivedPrepare || c.state.receivedReady {
			return ErrInvalidTransition
		}
	case MessageFire:
		if c.role != RoleResponder || !c.state.sentReady || !c.state.receivedReady || c.state.receivedFire {
			return ErrInvalidTransition
		}
	case MessageVerify:
		if c.state.receivedVerify {
			return ErrInvalidTransition
		}
		if c.role == RoleInitiator && !c.state.sentFire {
			return ErrInvalidTransition
		}
		if c.role == RoleResponder && !c.state.receivedFire {
			return ErrInvalidTransition
		}
	case MessageCancel:
		if c.state.receivedCancel {
			return ErrInvalidTransition
		}
	default:
		return ErrInvalidTransition
	}
	return nil
}

func (c *SimulatedChannel) applySendLocked(messageType MessageType) {
	c.state.sendSequence++
	c.state.sentCount++
	switch messageType {
	case MessagePrepare:
		c.state.sentPrepare = true
	case MessageReady:
		c.state.sentReady = true
	case MessageFire:
		c.state.sentFire = true
	case MessageVerify:
		c.state.sentVerify = true
		if c.state.receivedVerify {
			c.setTerminalLocked(TerminalSuccess)
		}
	case MessageCancel:
		c.state.sentCancel = true
		c.setTerminalLocked(TerminalCancelled)
	}
}

func (c *SimulatedChannel) applyReceiveLocked(messageType MessageType) {
	c.state.receiveSequence++
	c.state.receivedCount++
	switch messageType {
	case MessagePrepare:
		c.state.receivedPrepare = true
	case MessageReady:
		c.state.receivedReady = true
	case MessageFire:
		c.state.receivedFire = true
	case MessageVerify:
		c.state.receivedVerify = true
		if c.state.sentVerify {
			c.setTerminalLocked(TerminalSuccess)
		}
	case MessageCancel:
		c.state.receivedCancel = true
		c.setTerminalLocked(TerminalCancelled)
	}
}

func (c *SimulatedChannel) checkLiveLocked() error {
	if c.state.terminal {
		return ErrClosed
	}
	now := c.now()
	if now.Before(c.state.lastNow) {
		return c.failLocked(TerminalProtocolError, ErrClockRollback)
	}
	c.state.lastNow = now
	if now.Before(c.context.IssuedAt) || !now.Before(c.context.ExpiresAt) || now.Sub(c.state.startedAt) >= MaxControlLifetime {
		return c.failLocked(TerminalExpired, ErrExpired)
	}
	return nil
}

func (c *SimulatedChannel) allowReceiveLocked() bool {
	now := c.state.lastNow
	elapsed := now.Sub(c.state.receiveBucket.last).Seconds()
	if elapsed > 0 {
		c.state.receiveBucket.tokens += elapsed * receiveTokensPerSecond
		if c.state.receiveBucket.tokens > receiveBurst {
			c.state.receiveBucket.tokens = receiveBurst
		}
		c.state.receiveBucket.last = now
	}
	if c.state.receiveBucket.tokens < 1 {
		return false
	}
	c.state.receiveBucket.tokens--
	return true
}

func (c *SimulatedChannel) remainingLocked() time.Duration {
	controlDeadline := c.state.startedAt.Add(MaxControlLifetime)
	deadline := controlDeadline
	if c.context.ExpiresAt.Before(deadline) {
		deadline = c.context.ExpiresAt
	}
	remaining := deadline.Sub(c.state.lastNow)
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}

func stopTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (c *SimulatedChannel) fail(reason TerminalReason, cause error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state.terminal {
		return errors.Join(ErrClosed, cause)
	}
	return c.failLocked(reason, cause)
}

func (c *SimulatedChannel) failLocked(reason TerminalReason, cause error) error {
	c.setTerminalLocked(reason)
	return errors.Join(cause, c.finishIfTerminalLocked())
}

func (c *SimulatedChannel) setTerminalLocked(reason TerminalReason) {
	if c.state.terminal {
		return
	}
	c.state.terminal = true
	c.state.reason = reason
	c.state.success = reason == TerminalSuccess
}

func (c *SimulatedChannel) finishIfTerminalLocked() error {
	if !c.state.terminal {
		return nil
	}
	return c.ledger.Finish(c.context.CredentialID, c.state.reason)
}
