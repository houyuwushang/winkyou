package directattempt

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	"winkyou/internal/v2/noisecore"
)

const (
	FrameMagic       = "WYDA"
	FrameVersion     = 1
	FrameHeaderBytes = 18
	MaxFrameBytes    = 1024
	MaxSequence      = 7
	Generation       = 1
	// OOBDirectAttemptProfile is the Gate A control profile. Existing callers
	// continue to use DirectAttemptProfile through the legacy wrappers below.
	OOBDirectAttemptProfile = "winkyou-test-direct-oob-control/1"

	additionalDataLabel = "winkyou-test-direct-attempt-ad/1"
	readyPayloadMagic   = "WYRD\x01"
)

var (
	ErrInvalidBinding    = errors.New("directattempt: invalid session binding")
	ErrInvalidFrame      = errors.New("directattempt: invalid authenticated frame")
	ErrInvalidReady      = errors.New("directattempt: invalid READY payload")
	ErrInvalidSequence   = errors.New("directattempt: invalid role sequence")
	ErrInvalidTransition = errors.New("directattempt: invalid transition")
	ErrTerminal          = errors.New("directattempt: terminal state")
	ErrCancelled         = errors.New("directattempt: cancelled")
)

type Role string

const (
	RoleInitiator Role = "initiator"
	RoleResponder Role = "responder"
)

func (role Role) Valid() bool { return role == RoleInitiator || role == RoleResponder }

func (role Role) Peer() Role {
	if role == RoleInitiator {
		return RoleResponder
	}
	if role == RoleResponder {
		return RoleInitiator
	}
	return ""
}

type Domain string

const (
	DomainRendezvousControl Domain = "rendezvous-control"
	DomainDirectPunch       Domain = "direct-punch"
)

type FrameType uint8

const (
	FramePrepare FrameType = iota
	FrameReady
	FrameFire
	FrameSYN
	FrameSYNACK
	FrameACK
	FrameVerify
	FrameCancel
)

func (frameType FrameType) String() string {
	switch frameType {
	case FramePrepare:
		return "PREPARE"
	case FrameReady:
		return "READY"
	case FrameFire:
		return "FIRE"
	case FrameSYN:
		return "SYN"
	case FrameSYNACK:
		return "SYN_ACK"
	case FrameACK:
		return "ACK"
	case FrameVerify:
		return "VERIFY"
	case FrameCancel:
		return "CANCEL"
	default:
		return "UNKNOWN"
	}
}

func (frameType FrameType) Domain() (Domain, bool) {
	switch frameType {
	case FramePrepare, FrameReady, FrameFire, FrameVerify, FrameCancel:
		return DomainRendezvousControl, true
	case FrameSYN, FrameSYNACK, FrameACK:
		return DomainDirectPunch, true
	default:
		return "", false
	}
}

func (frameType FrameType) Sequence() (uint64, bool) {
	if frameType > FrameCancel {
		return 0, false
	}
	return uint64(frameType), true
}

func frameTypeAllowedForRole(frameType FrameType, role Role) bool {
	switch role {
	case RoleInitiator:
		return frameType == FramePrepare || frameType == FrameReady || frameType == FrameFire ||
			frameType == FrameSYN || frameType == FrameACK || frameType == FrameVerify || frameType == FrameCancel
	case RoleResponder:
		return frameType == FramePrepare || frameType == FrameReady || frameType == FrameSYNACK ||
			frameType == FrameVerify || frameType == FrameCancel
	default:
		return false
	}
}

type Binding struct {
	AttemptID     string
	ContextDigest [sha256.Size]byte
	HandshakeHash [sha256.Size]byte
	Generation    uint64
}

func (binding Binding) Validate() error {
	if !validBase64URL(binding.AttemptID, 16) || binding.Generation != Generation ||
		allZero(binding.ContextDigest[:]) || allZero(binding.HandshakeHash[:]) {
		return ErrInvalidBinding
	}
	return nil
}

type ReadyPayload struct {
	HandshakeHash [sha256.Size]byte
	SenderRole    Role
	ContextDigest [sha256.Size]byte
	Generation    uint64
	Endpoint      netip.AddrPort
	Profile       string
}

func NewReadyPayload(binding Binding, role Role, endpoint netip.AddrPort) (ReadyPayload, error) {
	return NewReadyPayloadForProfile(binding, role, endpoint, DirectAttemptProfile)
}

// NewReadyPayloadForProfile constructs READY for one exact, locally selected
// profile. It never negotiates or falls back between the N3b and Gate A
// profiles.
func NewReadyPayloadForProfile(binding Binding, role Role, endpoint netip.AddrPort, profile string) (ReadyPayload, error) {
	ready := ReadyPayload{
		HandshakeHash: binding.HandshakeHash,
		SenderRole:    role,
		ContextDigest: binding.ContextDigest,
		Generation:    binding.Generation,
		Endpoint:      endpoint,
		Profile:       profile,
	}
	if err := ready.validateForProfile(profile); err != nil {
		return ReadyPayload{}, err
	}
	return ready, nil
}

func (ready ReadyPayload) Validate() error {
	return ready.validateForProfile(DirectAttemptProfile)
}

func (ready ReadyPayload) validateForProfile(profile string) error {
	if allZero(ready.HandshakeHash[:]) || !ready.SenderRole.Valid() || allZero(ready.ContextDigest[:]) ||
		ready.Generation != Generation || !validControlProfile(profile) || ready.Profile != profile || !canonicalDirectEndpointForProfile(ready.Endpoint, profile) {
		return ErrInvalidReady
	}
	return nil
}

func (ready ReadyPayload) MarshalBinary() ([]byte, error) {
	return ready.MarshalBinaryForProfile(DirectAttemptProfile)
}

// MarshalBinaryForProfile preserves the legacy MarshalBinary acceptance while
// allowing the explicitly selected Gate A profile to use the same wire shape.
func (ready ReadyPayload) MarshalBinaryForProfile(profile string) ([]byte, error) {
	if err := ready.validateForProfile(profile); err != nil {
		return nil, err
	}
	address := ready.Endpoint.Addr()
	addressBytes := address.AsSlice()
	family := byte(6)
	if address.Is4() {
		family = 4
	}
	if len(ready.Profile) > 255 {
		return nil, ErrInvalidReady
	}
	payload := make([]byte, 0, len(readyPayloadMagic)+32+1+32+8+1+len(addressBytes)+2+1+len(ready.Profile))
	payload = append(payload, readyPayloadMagic...)
	payload = append(payload, ready.HandshakeHash[:]...)
	payload = append(payload, roleCode(ready.SenderRole))
	payload = append(payload, ready.ContextDigest[:]...)
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], ready.Generation)
	payload = append(payload, generation[:]...)
	clear(generation[:])
	payload = append(payload, family)
	payload = append(payload, addressBytes...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], ready.Endpoint.Port())
	payload = append(payload, port[:]...)
	clear(port[:])
	payload = append(payload, byte(len(ready.Profile)))
	payload = append(payload, ready.Profile...)
	return payload, nil
}

func ParseReadyPayload(payload []byte) (ReadyPayload, error) {
	return ParseReadyPayloadForProfile(payload, DirectAttemptProfile)
}

// ParseReadyPayloadForProfile accepts exactly one caller-selected profile.
func ParseReadyPayloadForProfile(payload []byte, profile string) (ReadyPayload, error) {
	if !validControlProfile(profile) {
		return ReadyPayload{}, ErrInvalidReady
	}
	minimum := len(readyPayloadMagic) + 32 + 1 + 32 + 8 + 1 + 4 + 2 + 1
	if len(payload) < minimum || !bytes.HasPrefix(payload, []byte(readyPayloadMagic)) {
		return ReadyPayload{}, ErrInvalidReady
	}
	offset := len(readyPayloadMagic)
	var ready ReadyPayload
	copy(ready.HandshakeHash[:], payload[offset:offset+32])
	offset += 32
	ready.SenderRole = roleFromCode(payload[offset])
	offset++
	copy(ready.ContextDigest[:], payload[offset:offset+32])
	offset += 32
	ready.Generation = binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	family := payload[offset]
	offset++
	addressSize := 0
	switch family {
	case 4:
		addressSize = 4
	case 6:
		addressSize = 16
	default:
		return ReadyPayload{}, ErrInvalidReady
	}
	if len(payload) < offset+addressSize+3 {
		return ReadyPayload{}, ErrInvalidReady
	}
	address, ok := netip.AddrFromSlice(payload[offset : offset+addressSize])
	if !ok {
		return ReadyPayload{}, ErrInvalidReady
	}
	offset += addressSize
	port := binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	profileLength := int(payload[offset])
	offset++
	if profileLength == 0 || len(payload) != offset+profileLength {
		return ReadyPayload{}, ErrInvalidReady
	}
	ready.Endpoint = netip.AddrPortFrom(address, port)
	ready.Profile = string(payload[offset:])
	if err := ready.validateForProfile(profile); err != nil {
		return ReadyPayload{}, err
	}
	return ready, nil
}

type OpenedFrame struct {
	Type  FrameType
	Ready *ReadyPayload
}

// FrameMetadata is the authenticated-header shape needed by reviewed carrier
// adapters. InspectFrame validates the complete public header and frame length
// but deliberately does not authenticate or decrypt the ciphertext.
type FrameMetadata struct {
	Domain          Domain
	Type            FrameType
	Sender          Role
	Sequence        uint64
	CiphertextBytes int
}

// InspectFrame returns validated, non-secret routing metadata without
// exposing ciphertext internals or cipher state. A carrier must still pass the
// frame to Protocol.Open before treating any field as authenticated.
func InspectFrame(frame []byte) (FrameMetadata, error) {
	_, ciphertext, sender, frameType, sequence, err := parseFrame(frame)
	if err != nil {
		return FrameMetadata{}, err
	}
	domain, ok := frameType.Domain()
	if !ok {
		return FrameMetadata{}, ErrInvalidFrame
	}
	return FrameMetadata{
		Domain:          domain,
		Type:            frameType,
		Sender:          sender,
		Sequence:        sequence,
		CiphertextBytes: len(ciphertext),
	}, nil
}

type Status struct {
	Terminal  bool
	Success   bool
	Cancelled bool
	Sent      int
	Received  int
}

type protocolState struct {
	sentPrepare, receivedPrepare bool
	sentReady, receivedReady     bool
	sentFire, receivedFire       bool
	sentSYN, receivedSYN         bool
	sentSYNACK, receivedSYNACK   bool
	sentACK, receivedACK         bool
	sentVerify, receivedVerify   bool
	sentCancel, receivedCancel   bool
	terminal, success, cancelled bool
	sent, received               int
}

// Protocol owns one PacketCipher and admits only the frozen role/type/sequence
// table. Any malformed, replayed, or invalid transition closes the full state.
type Protocol struct {
	mu      sync.Mutex
	role    Role
	binding Binding
	profile string
	packets *noisecore.PacketCipher
	state   protocolState
}

func NewProtocol(role Role, binding Binding, packets *noisecore.PacketCipher) (*Protocol, error) {
	return NewProtocolForProfile(role, binding, packets, DirectAttemptProfile)
}

// NewProtocolForProfile selects one exact local profile. Unknown profiles are
// rejected without negotiation or fallback.
func NewProtocolForProfile(role Role, binding Binding, packets *noisecore.PacketCipher, profile string) (*Protocol, error) {
	if !role.Valid() || binding.Validate() != nil || packets == nil || !packets.Ready() || !validControlProfile(profile) {
		return nil, ErrInvalidBinding
	}
	return &Protocol{role: role, binding: binding, profile: profile, packets: packets}, nil
}

func (protocol *Protocol) Seal(frameType FrameType, ready *ReadyPayload) ([]byte, error) {
	if protocol == nil {
		return nil, ErrTerminal
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal {
		return nil, ErrTerminal
	}
	if !frameTypeAllowedForRole(frameType, protocol.role) {
		return nil, protocol.failLocked(ErrInvalidSequence)
	}
	if err := protocol.validateSendLocked(frameType); err != nil {
		return nil, protocol.failLocked(err)
	}
	payload, err := protocol.payloadForSend(frameType, ready)
	if err != nil {
		return nil, protocol.failLocked(err)
	}
	defer clear(payload)
	sequence, _ := frameType.Sequence()
	header, err := BuildFrameHeader(protocol.role, frameType, len(payload)+noisecore.TagSize)
	if err != nil {
		return nil, protocol.failLocked(err)
	}
	additionalData, err := BuildAdditionalDataForProfile(protocol.binding, header, protocol.profile)
	if err != nil {
		clear(header)
		return nil, protocol.failLocked(err)
	}
	ciphertext, err := protocol.packets.Seal(sequence, additionalData, payload)
	clear(additionalData)
	if err != nil {
		clear(header)
		return nil, protocol.failLocked(err)
	}
	frame := make([]byte, 0, len(header)+len(ciphertext))
	frame = append(frame, header...)
	frame = append(frame, ciphertext...)
	clear(header)
	clear(ciphertext)
	protocol.applySendLocked(frameType)
	return frame, nil
}

func (protocol *Protocol) Open(frame []byte) (OpenedFrame, error) {
	if protocol == nil {
		return OpenedFrame{}, ErrTerminal
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal {
		return OpenedFrame{}, ErrTerminal
	}
	header, ciphertext, sender, frameType, sequence, err := parseFrame(frame)
	if err != nil {
		return OpenedFrame{}, protocol.failLocked(err)
	}
	if sender != protocol.role.Peer() || !frameTypeAllowedForRole(frameType, sender) {
		return OpenedFrame{}, protocol.failLocked(ErrInvalidSequence)
	}
	expectedSequence, _ := frameType.Sequence()
	if sequence != expectedSequence {
		return OpenedFrame{}, protocol.failLocked(ErrInvalidSequence)
	}
	if err := protocol.validateReceiveLocked(frameType); err != nil {
		return OpenedFrame{}, protocol.failLocked(err)
	}
	additionalData, err := BuildAdditionalDataForProfile(protocol.binding, header, protocol.profile)
	if err != nil {
		return OpenedFrame{}, protocol.failLocked(err)
	}
	plaintext, err := protocol.packets.Open(sequence, additionalData, ciphertext)
	clear(additionalData)
	if err != nil {
		return OpenedFrame{}, protocol.failLocked(errors.Join(ErrInvalidFrame, err))
	}
	defer clear(plaintext)
	opened := OpenedFrame{Type: frameType}
	if frameType == FrameReady {
		ready, err := ParseReadyPayloadForProfile(plaintext, protocol.profile)
		if err != nil || ready.SenderRole != sender || ready.HandshakeHash != protocol.binding.HandshakeHash ||
			ready.ContextDigest != protocol.binding.ContextDigest || ready.Generation != protocol.binding.Generation ||
			ready.Profile != protocol.profile {
			return OpenedFrame{}, protocol.failLocked(ErrInvalidReady)
		}
		opened.Ready = &ready
	} else if len(plaintext) != 0 {
		return OpenedFrame{}, protocol.failLocked(ErrInvalidFrame)
	}
	protocol.applyReceiveLocked(frameType)
	return opened, nil
}

func (protocol *Protocol) Status() Status {
	if protocol == nil {
		return Status{Terminal: true}
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	return Status{
		Terminal:  protocol.state.terminal,
		Success:   protocol.state.success,
		Cancelled: protocol.state.cancelled,
		Sent:      protocol.state.sent,
		Received:  protocol.state.received,
	}
}

func (protocol *Protocol) Close() error {
	if protocol == nil {
		return nil
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if !protocol.state.terminal {
		protocol.state.terminal = true
	}
	if protocol.packets != nil {
		return protocol.packets.Close()
	}
	return nil
}

func (protocol *Protocol) payloadForSend(frameType FrameType, ready *ReadyPayload) ([]byte, error) {
	if frameType != FrameReady {
		if ready != nil {
			return nil, ErrInvalidFrame
		}
		return nil, nil
	}
	if ready == nil || ready.SenderRole != protocol.role || ready.HandshakeHash != protocol.binding.HandshakeHash ||
		ready.ContextDigest != protocol.binding.ContextDigest || ready.Generation != protocol.binding.Generation ||
		ready.Profile != protocol.profile {
		return nil, ErrInvalidReady
	}
	return ready.MarshalBinaryForProfile(protocol.profile)
}

func (protocol *Protocol) validateSendLocked(frameType FrameType) error {
	s := &protocol.state
	switch frameType {
	case FramePrepare:
		if s.sentPrepare {
			return ErrInvalidTransition
		}
	case FrameReady:
		if !s.sentPrepare || !s.receivedPrepare || s.sentReady {
			return ErrInvalidTransition
		}
	case FrameFire:
		if protocol.role != RoleInitiator || !s.sentReady || !s.receivedReady || s.sentFire {
			return ErrInvalidTransition
		}
	case FrameSYN:
		if protocol.role != RoleInitiator || !s.sentFire || s.sentSYN {
			return ErrInvalidTransition
		}
	case FrameSYNACK:
		// Deliberately blind: receiving SYN is not a prerequisite.
		if protocol.role != RoleResponder || !s.receivedFire || s.sentSYNACK {
			return ErrInvalidTransition
		}
	case FrameACK:
		if protocol.role != RoleInitiator || !s.sentSYN || !s.receivedSYNACK || s.sentACK {
			return ErrInvalidTransition
		}
	case FrameVerify:
		complete := protocol.role == RoleInitiator && s.sentACK || protocol.role == RoleResponder && s.receivedACK
		if !complete || s.sentVerify {
			return ErrInvalidTransition
		}
	case FrameCancel:
		if s.sentCancel {
			return ErrInvalidTransition
		}
	default:
		return ErrInvalidSequence
	}
	return nil
}

func (protocol *Protocol) validateReceiveLocked(frameType FrameType) error {
	s := &protocol.state
	switch frameType {
	case FramePrepare:
		if s.receivedPrepare {
			return ErrInvalidTransition
		}
	case FrameReady:
		if !s.sentPrepare || !s.receivedPrepare || s.receivedReady {
			return ErrInvalidTransition
		}
	case FrameFire:
		if protocol.role != RoleResponder || !s.sentReady || !s.receivedReady || s.receivedFire {
			return ErrInvalidTransition
		}
	case FrameSYN:
		if protocol.role != RoleResponder || !s.receivedFire || s.receivedSYN {
			return ErrInvalidTransition
		}
	case FrameSYNACK:
		if protocol.role != RoleInitiator || !s.sentFire || !s.sentSYN || s.receivedSYNACK {
			return ErrInvalidTransition
		}
	case FrameACK:
		if protocol.role != RoleResponder || !s.receivedFire || !s.sentSYNACK || s.receivedACK {
			return ErrInvalidTransition
		}
	case FrameVerify:
		complete := protocol.role == RoleInitiator && s.sentACK || protocol.role == RoleResponder && s.receivedACK
		if !complete || s.receivedVerify {
			return ErrInvalidTransition
		}
	case FrameCancel:
		if s.receivedCancel {
			return ErrInvalidTransition
		}
	default:
		return ErrInvalidSequence
	}
	return nil
}

func (protocol *Protocol) applySendLocked(frameType FrameType) {
	s := &protocol.state
	s.sent++
	switch frameType {
	case FramePrepare:
		s.sentPrepare = true
	case FrameReady:
		s.sentReady = true
	case FrameFire:
		s.sentFire = true
	case FrameSYN:
		s.sentSYN = true
	case FrameSYNACK:
		s.sentSYNACK = true
	case FrameACK:
		s.sentACK = true
	case FrameVerify:
		s.sentVerify = true
		protocol.completeIfVerifiedLocked()
	case FrameCancel:
		s.sentCancel = true
		s.cancelled = true
		s.terminal = true
		_ = protocol.packets.Close()
	}
}

func (protocol *Protocol) applyReceiveLocked(frameType FrameType) {
	s := &protocol.state
	s.received++
	switch frameType {
	case FramePrepare:
		s.receivedPrepare = true
	case FrameReady:
		s.receivedReady = true
	case FrameFire:
		s.receivedFire = true
	case FrameSYN:
		s.receivedSYN = true
	case FrameSYNACK:
		s.receivedSYNACK = true
	case FrameACK:
		s.receivedACK = true
	case FrameVerify:
		s.receivedVerify = true
		protocol.completeIfVerifiedLocked()
	case FrameCancel:
		s.receivedCancel = true
		s.cancelled = true
		s.terminal = true
		_ = protocol.packets.Close()
	}
}

func (protocol *Protocol) completeIfVerifiedLocked() {
	if protocol.state.sentVerify && protocol.state.receivedVerify {
		protocol.state.success = true
		protocol.state.terminal = true
		_ = protocol.packets.Close()
	}
}

func (protocol *Protocol) failLocked(cause error) error {
	protocol.state.terminal = true
	protocol.state.success = false
	if protocol.packets != nil {
		_ = protocol.packets.Close()
	}
	return cause
}

// BuildFrameHeader freezes the 18-byte frame header. Every integer uses
// unsigned big-endian encoding. ciphertextLength includes the 16-byte tag.
func BuildFrameHeader(sender Role, frameType FrameType, ciphertextLength int) ([]byte, error) {
	sequence, ok := frameType.Sequence()
	domain, domainOK := frameType.Domain()
	if !sender.Valid() || !ok || !domainOK || !frameTypeAllowedForRole(frameType, sender) ||
		ciphertextLength < noisecore.TagSize || FrameHeaderBytes+ciphertextLength > MaxFrameBytes {
		return nil, ErrInvalidFrame
	}
	header := make([]byte, FrameHeaderBytes)
	copy(header[:4], FrameMagic)
	header[4] = FrameVersion
	header[5] = domainCode(domain)
	header[6] = byte(frameType)
	header[7] = roleCode(sender)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	binary.BigEndian.PutUint16(header[16:18], uint16(ciphertextLength))
	return header, nil
}

// BuildAdditionalData returns the exact authenticated bytes for a frame.
func BuildAdditionalData(binding Binding, header []byte) ([]byte, error) {
	return BuildAdditionalDataForProfile(binding, header, DirectAttemptProfile)
}

// BuildAdditionalDataForProfile binds one exact direct-attempt profile into
// every authenticated frame while keeping the N3b byte sequence unchanged.
func BuildAdditionalDataForProfile(binding Binding, header []byte, profile string) ([]byte, error) {
	if binding.Validate() != nil || len(header) != FrameHeaderBytes || !validControlProfile(profile) {
		return nil, ErrInvalidBinding
	}
	if err := validateFrameHeader(header); err != nil {
		return nil, err
	}
	attempt, err := base64.RawURLEncoding.DecodeString(binding.AttemptID)
	if err != nil || len(attempt) != 16 {
		clear(attempt)
		return nil, ErrInvalidBinding
	}
	domain := domainFromCode(header[5])
	if domain == "" {
		clear(attempt)
		return nil, ErrInvalidFrame
	}
	additionalData := make([]byte, 0, len(additionalDataLabel)+1+len(profile)+1+len(domain)+1+16+32+len(header))
	additionalData = append(additionalData, additionalDataLabel...)
	additionalData = append(additionalData, 0)
	additionalData = append(additionalData, profile...)
	additionalData = append(additionalData, 0)
	additionalData = append(additionalData, domain...)
	additionalData = append(additionalData, 0)
	additionalData = append(additionalData, attempt...)
	additionalData = append(additionalData, binding.ContextDigest[:]...)
	additionalData = append(additionalData, header...)
	clear(attempt)
	return additionalData, nil
}

func validControlProfile(profile string) bool {
	return profile == DirectAttemptProfile || profile == OOBDirectAttemptProfile
}

func validateFrameHeader(header []byte) error {
	if len(header) != FrameHeaderBytes || !bytes.Equal(header[:4], []byte(FrameMagic)) || header[4] != FrameVersion {
		return ErrInvalidFrame
	}
	domain := domainFromCode(header[5])
	frameType := FrameType(header[6])
	sender := roleFromCode(header[7])
	sequence := binary.BigEndian.Uint64(header[8:16])
	ciphertextLength := int(binary.BigEndian.Uint16(header[16:18]))
	expectedDomain, domainOK := frameType.Domain()
	expectedSequence, sequenceOK := frameType.Sequence()
	if domain == "" || !domainOK || domain != expectedDomain || !sequenceOK || sequence != expectedSequence ||
		!sender.Valid() || !frameTypeAllowedForRole(frameType, sender) || ciphertextLength < noisecore.TagSize ||
		FrameHeaderBytes+ciphertextLength > MaxFrameBytes {
		return ErrInvalidFrame
	}
	return nil
}

func parseFrame(frame []byte) (header, ciphertext []byte, sender Role, frameType FrameType, sequence uint64, err error) {
	if len(frame) < FrameHeaderBytes+noisecore.TagSize || len(frame) > MaxFrameBytes || !bytes.Equal(frame[:4], []byte(FrameMagic)) || frame[4] != FrameVersion {
		err = ErrInvalidFrame
		return
	}
	header = frame[:FrameHeaderBytes]
	if err = validateFrameHeader(header); err != nil {
		return
	}
	domain := domainFromCode(header[5])
	frameType = FrameType(header[6])
	sender = roleFromCode(header[7])
	sequence = binary.BigEndian.Uint64(header[8:16])
	length := int(binary.BigEndian.Uint16(header[16:18]))
	expectedDomain, ok := frameType.Domain()
	if domain == "" || !ok || domain != expectedDomain || !sender.Valid() || length < noisecore.TagSize || len(frame) != FrameHeaderBytes+length {
		err = ErrInvalidFrame
		return
	}
	ciphertext = frame[FrameHeaderBytes:]
	return
}

func canonicalDirectEndpoint(endpoint netip.AddrPort) bool {
	if !endpoint.IsValid() || endpoint.Port() == 0 {
		return false
	}
	address := endpoint.Addr()
	return address.IsValid() && address.Zone() == "" && address.Unmap() == address &&
		!address.IsUnspecified() && !address.IsMulticast() && !address.IsLoopback()
}

func canonicalDirectEndpointForProfile(endpoint netip.AddrPort, profile string) bool {
	if canonicalDirectEndpoint(endpoint) {
		return true
	}
	if profile != OOBDirectAttemptProfile || !endpoint.IsValid() || endpoint.Port() == 0 {
		return false
	}
	address := endpoint.Addr()
	return address.Zone() == "" && address.Unmap() == address && address.IsLoopback()
}

func domainCode(domain Domain) byte {
	if domain == DomainRendezvousControl {
		return 1
	}
	if domain == DomainDirectPunch {
		return 2
	}
	return 0
}

func domainFromCode(code byte) Domain {
	if code == 1 {
		return DomainRendezvousControl
	}
	if code == 2 {
		return DomainDirectPunch
	}
	return ""
}

func roleCode(role Role) byte {
	if role == RoleInitiator {
		return 1
	}
	if role == RoleResponder {
		return 2
	}
	return 0
}

func roleFromCode(code byte) Role {
	if code == 1 {
		return RoleInitiator
	}
	if code == 2 {
		return RoleResponder
	}
	return ""
}

func allZero(value []byte) bool {
	var aggregate byte
	for _, current := range value {
		aggregate |= current
	}
	return aggregate == 0
}

func (binding Binding) String() string {
	return fmt.Sprintf("direct-attempt binding generation=%d", binding.Generation)
}
