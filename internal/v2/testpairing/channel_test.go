package testpairing

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"
)

var _ TestPairingChannel = (*SimulatedChannel)(nil)

func TestCompiledLimitsMatchDraftMiniSpec(t *testing.T) {
	if MaxPairingLifetime != 10*time.Minute ||
		MaxControlLifetime != 15*time.Second ||
		MaxFrameBodyBytes != 4096 ||
		MaxPayloadBytes != 2048 ||
		MaxMessagesPerSide != 5 ||
		MaxMessagesTotal != 9 ||
		receiveTokensPerSecond != 4 ||
		receiveBurst != 2 {
		t.Fatal("compiled simulation limits drifted from TEST-ONLY-PAIRING-MINI-SPEC.md")
	}
}

func TestAttemptContextValidation(t *testing.T) {
	clock := newManualClock()
	valid := testAttempt(clock.Now())

	tests := []struct {
		name   string
		edit   func(*AttemptContext)
		now    func(AttemptContext) time.Time
		wanted error
	}{
		{
			name:   "protocol",
			edit:   func(attempt *AttemptContext) { attempt.Protocol = "winkyou-test-pairing/2" },
			wanted: ErrInvalidContext,
		},
		{
			name:   "auth scope",
			edit:   func(attempt *AttemptContext) { attempt.AuthScope = "mesh_member" },
			wanted: ErrInvalidContext,
		},
		{
			name:   "identifier length",
			edit:   func(attempt *AttemptContext) { attempt.AttemptID = "short" },
			wanted: ErrInvalidContext,
		},
		{
			name:   "identifier padding",
			edit:   func(attempt *AttemptContext) { attempt.AttemptID += "=" },
			wanted: ErrInvalidContext,
		},
		{
			name:   "duplicate identifier",
			edit:   func(attempt *AttemptContext) { attempt.ResponderParticipantID = attempt.InitiatorParticipantID },
			wanted: ErrInvalidContext,
		},
		{
			name:   "generation zero",
			edit:   func(attempt *AttemptContext) { attempt.ObservationGeneration = 0 },
			wanted: ErrInvalidContext,
		},
		{
			name:   "scope",
			edit:   func(attempt *AttemptContext) { attempt.ResponderGovernorScope = "container" },
			wanted: ErrInvalidContext,
		},
		{
			name:   "subsecond timestamp",
			edit:   func(attempt *AttemptContext) { attempt.IssuedAt = attempt.IssuedAt.Add(time.Nanosecond) },
			wanted: ErrInvalidContext,
		},
		{
			name: "non UTC timestamp",
			edit: func(attempt *AttemptContext) {
				attempt.IssuedAt = attempt.IssuedAt.In(time.FixedZone("CST", 8*60*60))
			},
			wanted: ErrInvalidContext,
		},
		{
			name: "lifetime too long",
			edit: func(attempt *AttemptContext) {
				attempt.ExpiresAt = attempt.IssuedAt.Add(MaxPairingLifetime + time.Second)
			},
			wanted: ErrInvalidContext,
		},
		{
			name:   "expired",
			now:    func(attempt AttemptContext) time.Time { return attempt.ExpiresAt },
			wanted: ErrExpired,
		},
		{
			name:   "not yet valid",
			now:    func(attempt AttemptContext) time.Time { return attempt.IssuedAt.Add(-time.Second) },
			wanted: ErrExpired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attempt := valid
			if test.edit != nil {
				test.edit(&attempt)
			}
			now := clock.Now()
			if test.now != nil {
				now = test.now(attempt)
			}
			if err := attempt.Validate(now); !errors.Is(err, test.wanted) {
				t.Fatalf("Validate() error = %v, want %v", err, test.wanted)
			}
		})
	}

	if err := valid.Validate(clock.Now()); err != nil {
		t.Fatalf("valid context rejected: %v", err)
	}
}

func TestSimulatedPairHappyPath(t *testing.T) {
	clock := newManualClock()
	attempt := testAttempt(clock.Now())
	initiatorLedger := NewMemoryLedger()
	responderLedger := NewMemoryLedger()
	initiator, responder, err := NewSimulatedPair(
		attempt,
		initiatorLedger,
		responderLedger,
		clock.Now,
	)
	if err != nil {
		t.Fatalf("NewSimulatedPair() error: %v", err)
	}

	sendMessage(t, initiator, MessagePrepare, []byte("initiator plan"))
	sendMessage(t, responder, MessagePrepare, []byte("responder plan"))
	receiveMessage(t, clock, responder, MessagePrepare, "initiator plan")
	receiveMessage(t, clock, initiator, MessagePrepare, "responder plan")

	sendMessage(t, initiator, MessageReady, nil)
	sendMessage(t, responder, MessageReady, nil)
	receiveMessage(t, clock, responder, MessageReady, "")
	receiveMessage(t, clock, initiator, MessageReady, "")

	sendMessage(t, initiator, MessageFire, nil)
	receiveMessage(t, clock, responder, MessageFire, "")

	sendMessage(t, initiator, MessageVerify, []byte("initiator result"))
	sendMessage(t, responder, MessageVerify, []byte("responder result"))
	receiveMessage(t, clock, initiator, MessageVerify, "responder result")
	receiveMessage(t, clock, responder, MessageVerify, "initiator result")

	assertStatus(t, initiator.Status(), Status{
		Role: RoleInitiator, Terminal: true, Success: true,
		Reason: TerminalSuccess, Sent: 4, Received: 3,
	})
	assertStatus(t, responder.Status(), Status{
		Role: RoleResponder, Terminal: true, Success: true,
		Reason: TerminalSuccess, Sent: 3, Received: 4,
	})
	assertLedgerReason(t, initiatorLedger, attempt.CredentialID, TerminalSuccess)
	assertLedgerReason(t, responderLedger, attempt.CredentialID, TerminalSuccess)
}

func TestSimulatedPairBurnsCredentialOnce(t *testing.T) {
	clock := newManualClock()
	attempt := testAttempt(clock.Now())
	initiatorLedger := NewMemoryLedger()
	responderLedger := NewMemoryLedger()

	if _, _, err := NewSimulatedPair(attempt, initiatorLedger, responderLedger, clock.Now); err != nil {
		t.Fatalf("first NewSimulatedPair() error: %v", err)
	}
	if _, _, err := NewSimulatedPair(attempt, initiatorLedger, responderLedger, clock.Now); !errors.Is(err, ErrCredentialUsed) {
		t.Fatalf("replayed NewSimulatedPair() error = %v, want ErrCredentialUsed", err)
	}

	record, exists := initiatorLedger.Record(attempt.CredentialID)
	if !exists || record.AttemptID != attempt.AttemptID || record.LocalRole != RoleInitiator || record.LocalScope != GovernorScopeMachine {
		t.Fatalf("initiator burn record = %#v, exists=%t", record, exists)
	}
}

func TestSecondLedgerFailureLeavesFirstCredentialBurned(t *testing.T) {
	clock := newManualClock()
	attempt := testAttempt(clock.Now())
	initiatorLedger := NewMemoryLedger()
	responderLedger := NewMemoryLedger()
	if err := responderLedger.Burn(BurnRecord{CredentialID: attempt.CredentialID}); err != nil {
		t.Fatalf("pre-burn responder credential: %v", err)
	}

	if _, _, err := NewSimulatedPair(attempt, initiatorLedger, responderLedger, clock.Now); !errors.Is(err, ErrCredentialUsed) {
		t.Fatalf("NewSimulatedPair() error = %v, want ErrCredentialUsed", err)
	}
	assertLedgerReason(t, initiatorLedger, attempt.CredentialID, TerminalProtocolError)
}

func TestSimulatedChannelRejectsBoundContextTampering(t *testing.T) {
	tests := []struct {
		name   string
		edit   func(*Message)
		wanted error
	}{
		{"attempt", func(message *Message) { message.AttemptID = testIdentifier(9) }, ErrContextMismatch},
		{"generation", func(message *Message) { message.ObservationGeneration++ }, ErrContextMismatch},
		{"participant", func(message *Message) { message.FromParticipantID = testIdentifier(9) }, ErrContextMismatch},
		{"role reflection", func(message *Message) { message.SenderRole = RoleResponder }, ErrContextMismatch},
		{"scope", func(message *Message) { message.GovernorScope = GovernorScopeUserAcknowledged }, ErrContextMismatch},
		{"sequence", func(message *Message) { message.Sequence++ }, ErrSequence},
		{"unknown type", func(message *Message) { message.Type = "unknown" }, ErrInvalidTransition},
		{"payload", func(message *Message) { message.Payload = make([]byte, MaxPayloadBytes+1) }, ErrLimitExceeded},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock()
			attempt := testAttempt(clock.Now())
			responderLedger := NewMemoryLedger()
			initiator, responder, err := NewSimulatedPair(
				attempt,
				NewMemoryLedger(),
				responderLedger,
				clock.Now,
			)
			if err != nil {
				t.Fatalf("NewSimulatedPair() error: %v", err)
			}
			sendMessage(t, initiator, MessagePrepare, nil)
			message := <-responder.incoming
			test.edit(&message)
			responder.incoming <- message
			clock.Advance(300 * time.Millisecond)
			if _, err := responder.Receive(context.Background()); !errors.Is(err, test.wanted) {
				t.Fatalf("Receive() error = %v, want %v", err, test.wanted)
			}
			status := responder.Status()
			if !status.Terminal || status.Success || status.Reason != TerminalProtocolError {
				t.Fatalf("responder status = %#v", status)
			}
			assertLedgerReason(t, responderLedger, attempt.CredentialID, TerminalProtocolError)
		})
	}
}

func TestSimulatedChannelRejectsInvalidTransitionsAndOversizedSend(t *testing.T) {
	tests := []struct {
		name        string
		role        Role
		messageType MessageType
		payload     []byte
		wanted      error
	}{
		{"ready before prepare", RoleInitiator, MessageReady, nil, ErrInvalidTransition},
		{"responder fire", RoleResponder, MessageFire, nil, ErrInvalidTransition},
		{"unknown", RoleInitiator, "unknown", nil, ErrInvalidTransition},
		{"oversized payload", RoleInitiator, MessagePrepare, make([]byte, MaxPayloadBytes+1), ErrLimitExceeded},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := newManualClock()
			attempt := testAttempt(clock.Now())
			initiator, responder, err := NewSimulatedPair(
				attempt,
				NewMemoryLedger(),
				NewMemoryLedger(),
				clock.Now,
			)
			if err != nil {
				t.Fatalf("NewSimulatedPair() error: %v", err)
			}
			channel := initiator
			if test.role == RoleResponder {
				channel = responder
			}
			if err := channel.Send(context.Background(), test.messageType, test.payload); !errors.Is(err, test.wanted) {
				t.Fatalf("Send() error = %v, want %v", err, test.wanted)
			}
			if status := channel.Status(); !status.Terminal || status.Reason != TerminalProtocolError {
				t.Fatalf("channel status = %#v", status)
			}
		})
	}
}

func TestReadyRequiresBothPrepareMessages(t *testing.T) {
	t.Run("send ready before local prepare", func(t *testing.T) {
		clock := newManualClock()
		initiator, responder, err := NewSimulatedPair(
			testAttempt(clock.Now()),
			NewMemoryLedger(),
			NewMemoryLedger(),
			clock.Now,
		)
		if err != nil {
			t.Fatalf("NewSimulatedPair() error: %v", err)
		}
		sendMessage(t, responder, MessagePrepare, nil)
		receiveMessage(t, clock, initiator, MessagePrepare, "")
		if err := initiator.Send(context.Background(), MessageReady, nil); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("Send(ready) error = %v, want ErrInvalidTransition", err)
		}
	})

	t.Run("receive ready before peer prepare", func(t *testing.T) {
		clock := newManualClock()
		attempt := testAttempt(clock.Now())
		initiator, _, err := NewSimulatedPair(
			attempt,
			NewMemoryLedger(),
			NewMemoryLedger(),
			clock.Now,
		)
		if err != nil {
			t.Fatalf("NewSimulatedPair() error: %v", err)
		}
		sendMessage(t, initiator, MessagePrepare, nil)
		initiator.incoming <- Message{
			Protocol:              ProtocolVersion,
			AuthScope:             AuthScope,
			AttemptID:             attempt.AttemptID,
			ObservationGeneration: attempt.ObservationGeneration,
			FromParticipantID:     attempt.ResponderParticipantID,
			ToParticipantID:       attempt.InitiatorParticipantID,
			SenderRole:            RoleResponder,
			GovernorScope:         attempt.ResponderGovernorScope,
			Sequence:              1,
			Type:                  MessageReady,
		}
		if _, err := initiator.Receive(context.Background()); !errors.Is(err, ErrInvalidTransition) {
			t.Fatalf("Receive(ready) error = %v, want ErrInvalidTransition", err)
		}
	})
}

func TestSimulatedChannelCancelIsTerminal(t *testing.T) {
	clock := newManualClock()
	attempt := testAttempt(clock.Now())
	initiatorLedger := NewMemoryLedger()
	responderLedger := NewMemoryLedger()
	initiator, responder, err := NewSimulatedPair(
		attempt,
		initiatorLedger,
		responderLedger,
		clock.Now,
	)
	if err != nil {
		t.Fatalf("NewSimulatedPair() error: %v", err)
	}

	if err := initiator.Send(context.Background(), MessageCancel, nil); err != nil {
		t.Fatalf("Send(cancel) error: %v", err)
	}
	message, err := responder.Receive(context.Background())
	if err != nil || message.Type != MessageCancel {
		t.Fatalf("Receive(cancel) = %#v, %v", message, err)
	}
	for name, status := range map[string]Status{
		"initiator": initiator.Status(),
		"responder": responder.Status(),
	} {
		if !status.Terminal || status.Success || status.Reason != TerminalCancelled {
			t.Fatalf("%s status = %#v", name, status)
		}
	}
	assertLedgerReason(t, initiatorLedger, attempt.CredentialID, TerminalCancelled)
	assertLedgerReason(t, responderLedger, attempt.CredentialID, TerminalCancelled)
}

func TestSimulatedChannelExpiresAndRejectsClockRollback(t *testing.T) {
	t.Run("control lifetime", func(t *testing.T) {
		clock := newManualClock()
		attempt := testAttempt(clock.Now())
		ledger := NewMemoryLedger()
		initiator, _, err := NewSimulatedPair(attempt, ledger, NewMemoryLedger(), clock.Now)
		if err != nil {
			t.Fatalf("NewSimulatedPair() error: %v", err)
		}
		clock.Advance(MaxControlLifetime)
		if err := initiator.Send(context.Background(), MessagePrepare, nil); !errors.Is(err, ErrExpired) {
			t.Fatalf("Send() error = %v, want ErrExpired", err)
		}
		if status := initiator.Status(); status.Reason != TerminalExpired {
			t.Fatalf("status = %#v", status)
		}
		assertLedgerReason(t, ledger, attempt.CredentialID, TerminalExpired)
	})

	t.Run("clock rollback", func(t *testing.T) {
		clock := newManualClock()
		attempt := testAttempt(clock.Now())
		initiator, _, err := NewSimulatedPair(attempt, NewMemoryLedger(), NewMemoryLedger(), clock.Now)
		if err != nil {
			t.Fatalf("NewSimulatedPair() error: %v", err)
		}
		clock.Advance(-time.Second)
		if err := initiator.Send(context.Background(), MessagePrepare, nil); !errors.Is(err, ErrClockRollback) {
			t.Fatalf("Send() error = %v, want ErrClockRollback", err)
		}
		if status := initiator.Status(); status.Reason != TerminalProtocolError {
			t.Fatalf("status = %#v", status)
		}
	})
}

func TestReceiveTokenBucketIsBounded(t *testing.T) {
	start := time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC)
	bucket := tokenBucket{tokens: receiveBurst, last: start}
	channel := &SimulatedChannel{state: channelState{lastNow: start, receiveBucket: bucket}}
	if !channel.allowReceiveLocked() || !channel.allowReceiveLocked() {
		t.Fatal("initial burst was not admitted")
	}
	if channel.allowReceiveLocked() {
		t.Fatal("third immediate receive exceeded burst")
	}
	channel.state.lastNow = start.Add(250 * time.Millisecond)
	if !channel.allowReceiveLocked() {
		t.Fatal("one token was not replenished after 250ms")
	}
	if channel.allowReceiveLocked() {
		t.Fatal("replenishment exceeded four messages per second")
	}
}

func TestSendCopiesPayloadBeforeQueueing(t *testing.T) {
	clock := newManualClock()
	initiator, responder, err := NewSimulatedPair(
		testAttempt(clock.Now()),
		NewMemoryLedger(),
		NewMemoryLedger(),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("NewSimulatedPair() error: %v", err)
	}
	payload := []byte("original")
	if err := initiator.Send(context.Background(), MessagePrepare, payload); err != nil {
		t.Fatalf("Send() error: %v", err)
	}
	copy(payload, "mutated!")
	message, err := responder.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}
	if string(message.Payload) != "original" {
		t.Fatalf("payload = %q, want original", message.Payload)
	}
}

func TestCancelledOperationClosesSimulation(t *testing.T) {
	clock := newManualClock()
	initiator, _, err := NewSimulatedPair(
		testAttempt(clock.Now()),
		NewMemoryLedger(),
		NewMemoryLedger(),
		clock.Now,
	)
	if err != nil {
		t.Fatalf("NewSimulatedPair() error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := initiator.Send(ctx, MessagePrepare, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("Send() error = %v, want context.Canceled", err)
	}
	if status := initiator.Status(); status.Reason != TerminalCancelled {
		t.Fatalf("status = %#v", status)
	}
}

func sendMessage(t *testing.T, channel TestPairingChannel, messageType MessageType, payload []byte) {
	t.Helper()
	if err := channel.Send(context.Background(), messageType, payload); err != nil {
		t.Fatalf("Send(%s) error: %v", messageType, err)
	}
}

func receiveMessage(t *testing.T, clock *manualClock, channel TestPairingChannel, wantedType MessageType, wantedPayload string) {
	t.Helper()
	clock.Advance(300 * time.Millisecond)
	message, err := channel.Receive(context.Background())
	if err != nil {
		t.Fatalf("Receive() error: %v", err)
	}
	if message.Type != wantedType || string(message.Payload) != wantedPayload {
		t.Fatalf("Receive() = type %q payload %q, want %q/%q", message.Type, message.Payload, wantedType, wantedPayload)
	}
}

func assertStatus(t *testing.T, actual, wanted Status) {
	t.Helper()
	if actual != wanted {
		t.Fatalf("status = %#v, want %#v", actual, wanted)
	}
}

func assertLedgerReason(t *testing.T, ledger *MemoryLedger, credentialID string, wanted TerminalReason) {
	t.Helper()
	record, exists := ledger.Record(credentialID)
	if !exists || record.Reason != wanted {
		t.Fatalf("ledger record = %#v, exists=%t, want reason %q", record, exists, wanted)
	}
}

func testAttempt(now time.Time) AttemptContext {
	now = now.UTC().Truncate(time.Second)
	return AttemptContext{
		Protocol:               ProtocolVersion,
		AuthScope:              AuthScope,
		CredentialID:           testIdentifier(1),
		AttemptID:              testIdentifier(2),
		ObservationGeneration:  7,
		InitiatorParticipantID: testIdentifier(3),
		ResponderParticipantID: testIdentifier(4),
		InitiatorGovernorScope: GovernorScopeMachine,
		ResponderGovernorScope: GovernorScopeUserAcknowledged,
		IssuedAt:               now,
		ExpiresAt:              now.Add(MaxPairingLifetime),
	}
}

func testIdentifier(value byte) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{value}, 16))
}

type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func newManualClock() *manualClock {
	return &manualClock{
		now: time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC),
	}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}
