package directsim

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sync"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/noisecore"
)

var (
	ErrRendezvousOrder = errors.New("directsim: invalid rendezvous order")
	ErrPresence        = errors.New("directsim: invalid presence witness")
	ErrFrameLimit      = errors.New("directsim: rendezvous frame limit exceeded")
	ErrQueueFull       = errors.New("directsim: rendezvous queue full")
)

type PresenceSlot string

const (
	PresenceSlotA PresenceSlot = "a"
	PresenceSlotB PresenceSlot = "b"
)

// Presence is deliberately transport-local and secret-free. It contains no
// credential, attempt, participant, generation, role, endpoint, or payload.
type Presence struct {
	Profile       string
	AssociationID string
	Slot          PresenceSlot
}

func (presence Presence) validate() error {
	decoded, err := base64.RawURLEncoding.DecodeString(presence.AssociationID)
	validAssociation := err == nil && len(decoded) == 16 &&
		base64.RawURLEncoding.EncodeToString(decoded) == presence.AssociationID
	clear(decoded)
	if presence.Profile != directattempt.RendezvousPresenceProfile || !validAssociation ||
		(presence.Slot != PresenceSlotA && presence.Slot != PresenceSlotB) {
		return ErrPresence
	}
	return nil
}

type frameKind uint8

const (
	frameHandshake frameKind = iota + 1
	frameControl
)

type memoryFrame struct {
	kind    frameKind
	payload []byte
}

// MemoryRendezvous is a one-frame-per-direction carrier model. Presence is
// separate from frame queues, and no handshake/control frame can be admitted
// until both endpoint-local durable burns have been acknowledged.
type MemoryRendezvous struct {
	mu sync.Mutex

	associationID string
	presence      map[PresenceSlot]struct{}
	burned        bool
	handshakeDone bool
	closed        bool
	handshakeSent map[directattempt.Role]int
	handshakeRead map[directattempt.Role]int
	toInitiator   *memoryFrame
	toResponder   *memoryFrame
}

func NewMemoryRendezvous(associationID string) (*MemoryRendezvous, error) {
	presence := Presence{Profile: directattempt.RendezvousPresenceProfile, AssociationID: associationID, Slot: PresenceSlotA}
	if err := presence.validate(); err != nil {
		return nil, err
	}
	return &MemoryRendezvous{
		associationID: associationID,
		presence:      make(map[PresenceSlot]struct{}, 2),
		handshakeSent: make(map[directattempt.Role]int, 2),
		handshakeRead: make(map[directattempt.Role]int, 2),
	}, nil
}

func (rendezvous *MemoryRendezvous) Arrive(presence Presence) (bool, error) {
	if rendezvous == nil {
		return false, ErrPresence
	}
	if err := presence.validate(); err != nil {
		return false, err
	}
	rendezvous.mu.Lock()
	defer rendezvous.mu.Unlock()
	if rendezvous.closed || rendezvous.burned || presence.AssociationID != rendezvous.associationID {
		return false, ErrRendezvousOrder
	}
	if _, duplicate := rendezvous.presence[presence.Slot]; duplicate {
		return false, ErrPresence
	}
	rendezvous.presence[presence.Slot] = struct{}{}
	return len(rendezvous.presence) == 2, nil
}

func (rendezvous *MemoryRendezvous) MarkDurablyBurned() error {
	if rendezvous == nil {
		return ErrRendezvousOrder
	}
	rendezvous.mu.Lock()
	defer rendezvous.mu.Unlock()
	if rendezvous.closed || rendezvous.burned || len(rendezvous.presence) != 2 {
		return ErrRendezvousOrder
	}
	rendezvous.burned = true
	return nil
}

func (rendezvous *MemoryRendezvous) MarkHandshakeComplete() error {
	if rendezvous == nil {
		return ErrRendezvousOrder
	}
	rendezvous.mu.Lock()
	defer rendezvous.mu.Unlock()
	if rendezvous.closed || !rendezvous.burned || rendezvous.handshakeDone || rendezvous.toInitiator != nil || rendezvous.toResponder != nil ||
		rendezvous.handshakeSent[directattempt.RoleInitiator] != 1 || rendezvous.handshakeSent[directattempt.RoleResponder] != 1 ||
		rendezvous.handshakeRead[directattempt.RoleInitiator] != 1 || rendezvous.handshakeRead[directattempt.RoleResponder] != 1 {
		return ErrRendezvousOrder
	}
	rendezvous.handshakeDone = true
	return nil
}

func (rendezvous *MemoryRendezvous) SendHandshake(sender directattempt.Role, payload []byte) error {
	return rendezvous.send(sender, frameHandshake, payload, false)
}

func (rendezvous *MemoryRendezvous) SendControl(sender directattempt.Role, payload []byte) error {
	return rendezvous.send(sender, frameControl, payload, false)
}

// injectControl models a carrier delivery fault. It copies an already emitted
// frame without increasing sender-emission counters.
func (rendezvous *MemoryRendezvous) injectControl(sender directattempt.Role, payload []byte) error {
	return rendezvous.send(sender, frameControl, payload, true)
}

func (rendezvous *MemoryRendezvous) send(sender directattempt.Role, kind frameKind, payload []byte, injected bool) error {
	if rendezvous == nil || !sender.Valid() || len(payload) == 0 {
		return ErrRendezvousOrder
	}
	if len(payload) > directattempt.MaxFrameBytes && kind == frameControl {
		return ErrFrameLimit
	}
	if kind == frameHandshake && len(payload) != noisecore.PublicKeySize+noisecore.TagSize {
		return ErrFrameLimit
	}
	rendezvous.mu.Lock()
	defer rendezvous.mu.Unlock()
	if rendezvous.closed || !rendezvous.burned || kind == frameControl && !rendezvous.handshakeDone {
		return ErrRendezvousOrder
	}
	if injected && kind != frameControl {
		return ErrRendezvousOrder
	}
	target := &rendezvous.toResponder
	if sender == directattempt.RoleResponder {
		target = &rendezvous.toInitiator
	}
	if *target != nil {
		return ErrQueueFull
	}
	if kind == frameHandshake && rendezvous.handshakeSent[sender] != 0 {
		return ErrRendezvousOrder
	}
	*target = &memoryFrame{kind: kind, payload: append([]byte(nil), payload...)}
	if kind == frameHandshake {
		rendezvous.handshakeSent[sender]++
	}
	return nil
}

func (rendezvous *MemoryRendezvous) ReceiveHandshake(receiver directattempt.Role) ([]byte, error) {
	return rendezvous.receive(receiver, frameHandshake)
}

func (rendezvous *MemoryRendezvous) ReceiveControl(receiver directattempt.Role) ([]byte, error) {
	return rendezvous.receive(receiver, frameControl)
}

func (rendezvous *MemoryRendezvous) receive(receiver directattempt.Role, kind frameKind) ([]byte, error) {
	if rendezvous == nil || !receiver.Valid() {
		return nil, ErrRendezvousOrder
	}
	rendezvous.mu.Lock()
	defer rendezvous.mu.Unlock()
	if rendezvous.closed || !rendezvous.burned || kind == frameControl && !rendezvous.handshakeDone {
		return nil, ErrRendezvousOrder
	}
	target := &rendezvous.toInitiator
	if receiver == directattempt.RoleResponder {
		target = &rendezvous.toResponder
	}
	if *target == nil || (*target).kind != kind {
		return nil, ErrRendezvousOrder
	}
	payload := (*target).payload
	*target = nil
	if kind == frameHandshake {
		rendezvous.handshakeRead[receiver]++
	}
	return payload, nil
}

func (rendezvous *MemoryRendezvous) Close() error {
	if rendezvous == nil {
		return nil
	}
	rendezvous.mu.Lock()
	defer rendezvous.mu.Unlock()
	rendezvous.closed = true
	for _, frame := range []*memoryFrame{rendezvous.toInitiator, rendezvous.toResponder} {
		if frame != nil {
			clear(frame.payload)
		}
	}
	rendezvous.toInitiator = nil
	rendezvous.toResponder = nil
	return nil
}

func (presence Presence) String() string {
	return fmt.Sprintf("presence profile=%s slot=%s", presence.Profile, presence.Slot)
}
