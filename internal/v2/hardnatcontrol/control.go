package hardnatcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"winkyou/internal/v2/directattempt"
	"winkyou/internal/v2/hardnatattempt"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/noisecore"
)

const (
	FrameMagic       = "WYHB"
	FrameVersion     = 1
	FrameHeaderBytes = 24
	MaxFrameBytes    = 1024
	MaxSequence      = uint64(530)
	Generation       = uint64(1)

	CandidateSequenceBase = uint64(16)
	WinnerSequence        = uint64(528)
	VerifySequence        = uint64(529)
	CancelSequence        = uint64(530)
)

var (
	ErrInvalidBinding    = errors.New("hardnatcontrol: invalid binding")
	ErrInvalidFrame      = errors.New("hardnatcontrol: invalid frame")
	ErrInvalidPayload    = errors.New("hardnatcontrol: invalid payload")
	ErrInvalidSequence   = errors.New("hardnatcontrol: invalid sequence")
	ErrInvalidTransition = errors.New("hardnatcontrol: invalid transition")
	ErrPlanMismatch      = errors.New("hardnatcontrol: plan mismatch")
	ErrTerminal          = errors.New("hardnatcontrol: terminal")
)

type Role = directattempt.Role

const (
	RoleInitiator = directattempt.RoleInitiator
	RoleResponder = directattempt.RoleResponder
)

type Domain uint8

const (
	DomainRendezvousControl Domain = 1
	DomainDirectPunch       Domain = 2
)

type FrameType uint8

const (
	FramePrepare FrameType = iota
	FrameSource
	FrameReady
	FrameFire
	FrameCandidate
	FrameWinner
	FrameVerify
	FrameCancel
)

func (frameType FrameType) domain() (Domain, bool) {
	switch frameType {
	case FramePrepare, FrameSource, FrameReady, FrameFire, FrameVerify, FrameCancel:
		return DomainRendezvousControl, true
	case FrameCandidate, FrameWinner:
		return DomainDirectPunch, true
	default:
		return 0, false
	}
}

type Binding struct {
	AttemptID      string
	ContextDigest  [32]byte
	HandshakeHash  [32]byte
	Generation     uint64
	Profile        hardnatplan.Profile
	ResourceClass  hardnatplan.ResourceClass
	EnvelopeDigest [32]byte
}

func (binding Binding) Validate() error {
	decoded, err := base64.RawURLEncoding.DecodeString(binding.AttemptID)
	validID := err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == binding.AttemptID
	clear(decoded)
	if !validID || binding.Generation != Generation || allZero(binding.ContextDigest[:]) ||
		allZero(binding.HandshakeHash[:]) || allZero(binding.EnvelopeDigest[:]) {
		return ErrInvalidBinding
	}
	if (binding.Profile != hardnatplan.ProfilePredictiveEdm || binding.ResourceClass != hardnatplan.ResourcePredictive) &&
		(binding.Profile != hardnatplan.ProfileAsymmetricBirthday || binding.ResourceClass != hardnatplan.ResourceAsymmetric) {
		return ErrInvalidBinding
	}
	return nil
}

type FrameMetadata struct {
	Domain          Domain
	Type            FrameType
	Sender          Role
	Sequence        uint64
	SocketSlot      uint16
	Ordinal         uint32
	CiphertextBytes int
}

type SourcePayload struct {
	Compact       hardnatplan.CompactSourceInput
	PublicAddress hardnatplan.Address
}

func NewSourcePayload(commitment hardnatplan.LocalSourceCommitment, publicAddress hardnatplan.Address) (SourcePayload, error) {
	compact, err := hardnatplan.CompactSourceInputFor(commitment)
	payload := SourcePayload{Compact: compact, PublicAddress: publicAddress}
	if err != nil || !publicAddress.Valid() ||
		(compact.Role == hardnatplan.RoleTargetSet && compact.ReceiveEndpoint.Address != publicAddress) {
		return SourcePayload{}, ErrInvalidPayload
	}
	return payload, nil
}

func (payload SourcePayload) Commitment(profile hardnatplan.Profile, resource hardnatplan.ResourceClass) (hardnatplan.LocalSourceCommitment, error) {
	if payload.Compact.Profile != profile || payload.Compact.ResourceClass != resource || !payload.PublicAddress.Valid() ||
		(payload.Compact.Role == hardnatplan.RoleTargetSet && payload.Compact.ReceiveEndpoint.Address != payload.PublicAddress) {
		return hardnatplan.LocalSourceCommitment{}, ErrInvalidPayload
	}
	commitment, err := hardnatplan.ReconstructLocalCommitment(payload.Compact)
	if err != nil {
		return hardnatplan.LocalSourceCommitment{}, errors.Join(ErrInvalidPayload, err)
	}
	return commitment, nil
}

type ReadyPayload struct {
	JointDigest     [32]byte
	ExecutionDigest [32]byte
}

type Winner struct {
	CandidateSender    Role
	CandidateOrdinal   uint32
	ReceiverSocketSlot uint16
	Digest             [32]byte
}

type OpenedFrame struct {
	Metadata FrameMetadata
	Source   *SourcePayload
	Ready    *ReadyPayload
	Winner   *Winner
}

type ExecutionSource struct {
	CarrierRole   Role
	PlannerRole   hardnatplan.Role
	SourceDigest  [32]byte
	PublicAddress hardnatplan.Address
}

func BuildExecutionDigest(joint hardnatplan.JointPlanCommitment, envelopeDigest [32]byte, left, right ExecutionSource) ([32]byte, error) {
	if left.CarrierRole == RoleResponder && right.CarrierRole == RoleInitiator {
		left, right = right, left
	}
	if left.CarrierRole != RoleInitiator || right.CarrierRole != RoleResponder ||
		!left.PublicAddress.Valid() || !right.PublicAddress.Valid() || allZero(envelopeDigest[:]) ||
		allZero(left.SourceDigest[:]) || allZero(right.SourceDigest[:]) || left.PlannerRole == right.PlannerRole ||
		joint.JointDigest == ([32]byte{}) {
		return [32]byte{}, ErrPlanMismatch
	}
	var encoded bytes.Buffer
	encoded.WriteString("winkyou-hardnat-execution-commitment-v1\x00")
	encoded.Write(joint.JointDigest[:])
	encoded.Write(envelopeDigest[:])
	appendExecutionSource(&encoded, left)
	appendExecutionSource(&encoded, right)
	return sha256.Sum256(encoded.Bytes()), nil
}

func appendExecutionSource(encoded *bytes.Buffer, source ExecutionSource) {
	appendString(encoded, string(source.CarrierRole))
	appendString(encoded, string(source.PlannerRole))
	encoded.Write(source.SourceDigest[:])
	appendAddress(encoded, source.PublicAddress)
}

// NoisePlannerKeySource adapts only the domain-separated Noise planner
// exporter to B1's pure PlannerKeySource interface.
type NoisePlannerKeySource struct{ Source *noisecore.PlannerKeySource }

func (source NoisePlannerKeySource) DerivePlannerKey(context hardnatplan.PlannerKeyContext) ([32]byte, error) {
	if source.Source == nil {
		return [32]byte{}, ErrInvalidBinding
	}
	encoded, err := EncodePlannerKeyContext(context)
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(encoded)
	return source.Source.Derive(encoded)
}

func EncodePlannerKeyContext(context hardnatplan.PlannerKeyContext) ([]byte, error) {
	if context.Generation == 0 || allZero(context.AttemptDigest[:]) || allZero(context.FirstEvidenceDigest[:]) ||
		allZero(context.SecondEvidenceDigest[:]) ||
		(context.Profile != hardnatplan.ProfilePredictiveEdm && context.Profile != hardnatplan.ProfileAsymmetricBirthday) {
		return nil, ErrInvalidBinding
	}
	var encoded bytes.Buffer
	encoded.WriteString("winkyou-hardnat-planner-context-v1\x00")
	encoded.Write(context.AttemptDigest[:])
	appendUint64(&encoded, context.Generation)
	appendString(&encoded, string(context.Profile))
	appendString(&encoded, string(context.ResourceClass))
	encoded.Write(context.FirstEvidenceDigest[:])
	encoded.Write(context.SecondEvidenceDigest[:])
	return encoded.Bytes(), nil
}

type protocolState struct {
	sentPrepare, receivedPrepare bool
	sentSource, receivedSource   bool
	bound                        bool
	sentReady, receivedReady     bool
	sentFire, receivedFire       bool
	sentWinner, receivedWinner   bool
	sentVerify, receivedVerify   bool
	sentCancel, receivedCancel   bool
	sentCandidates               map[uint32]struct{}
	receivedCandidates           map[uint32]struct{}
	winner                       Winner
	hasWinner                    bool
	terminal, success            bool
}

type Protocol struct {
	mu              sync.Mutex
	role            Role
	plannerRole     hardnatplan.Role
	binding         Binding
	packets         *noisecore.PacketCipher
	state           protocolState
	localPlan       hardnatplan.Plan
	peerPlan        hardnatplan.Plan
	joint           hardnatplan.JointPlanCommitment
	executionDigest [32]byte
}

func NewProtocol(role Role, plannerRole hardnatplan.Role, binding Binding, packets *noisecore.PacketCipher) (*Protocol, error) {
	if !role.Valid() || binding.Validate() != nil || packets == nil || !packets.Ready() || !plannerRoleMatches(binding.Profile, role, plannerRole) {
		return nil, ErrInvalidBinding
	}
	return &Protocol{role: role, plannerRole: plannerRole, binding: binding, packets: packets,
		state: protocolState{sentCandidates: map[uint32]struct{}{}, receivedCandidates: map[uint32]struct{}{}}}, nil
}

func plannerRoleMatches(profile hardnatplan.Profile, carrier Role, planner hardnatplan.Role) bool {
	if profile == hardnatplan.ProfilePredictiveEdm {
		return carrier == RoleInitiator && planner == hardnatplan.RoleInitiator || carrier == RoleResponder && planner == hardnatplan.RoleResponder
	}
	return profile == hardnatplan.ProfileAsymmetricBirthday && (planner == hardnatplan.RoleMappingSet || planner == hardnatplan.RoleTargetSet)
}

func (protocol *Protocol) chooser() bool {
	return protocol.binding.Profile == hardnatplan.ProfilePredictiveEdm && protocol.role == RoleInitiator ||
		protocol.binding.Profile == hardnatplan.ProfileAsymmetricBirthday && protocol.plannerRole == hardnatplan.RoleTargetSet
}

func (protocol *Protocol) SealPrepare() ([]byte, error) {
	return protocol.sealControl(FramePrepare, nil)
}
func (protocol *Protocol) SealSource(payload SourcePayload) ([]byte, error) {
	encoded, err := marshalSource(payload)
	if err != nil {
		return nil, protocol.fail(err)
	}
	defer clear(encoded)
	return protocol.sealControl(FrameSource, encoded)
}
func (protocol *Protocol) SealReady() ([]byte, error) {
	protocol.mu.Lock()
	ready := ReadyPayload{JointDigest: protocol.joint.JointDigest, ExecutionDigest: protocol.executionDigest}
	protocol.mu.Unlock()
	payload := make([]byte, 64)
	copy(payload[:32], ready.JointDigest[:])
	copy(payload[32:], ready.ExecutionDigest[:])
	defer clear(payload)
	return protocol.sealControl(FrameReady, payload)
}
func (protocol *Protocol) SealFire() ([]byte, error) { return protocol.sealControl(FrameFire, nil) }
func (protocol *Protocol) SealVerify() ([]byte, error) {
	protocol.mu.Lock()
	winner := protocol.state.winner
	has := protocol.state.hasWinner
	protocol.mu.Unlock()
	if !has {
		return nil, protocol.fail(ErrInvalidTransition)
	}
	payload := append([]byte(nil), winner.Digest[:]...)
	defer clear(payload)
	return protocol.sealControl(FrameVerify, payload)
}
func (protocol *Protocol) SealCancel() ([]byte, error) { return protocol.sealControl(FrameCancel, nil) }

func (protocol *Protocol) sealControl(frameType FrameType, payload []byte) ([]byte, error) {
	if protocol == nil {
		return nil, ErrTerminal
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal {
		return nil, ErrTerminal
	}
	if err := protocol.validateSendLocked(frameType, 0); err != nil {
		return nil, protocol.failLocked(err)
	}
	sequence, ok := fixedSequence(frameType)
	if !ok {
		return nil, protocol.failLocked(ErrInvalidSequence)
	}
	frame, err := protocol.sealLocked(frameType, sequence, 0, 0, payload)
	if err != nil {
		return nil, protocol.failLocked(err)
	}
	protocol.applySendLocked(frameType, 0)
	return frame, nil
}

func (protocol *Protocol) SealCandidate(candidate hardnatplan.Candidate) ([]byte, error) {
	if protocol == nil {
		return nil, ErrTerminal
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal || !protocol.state.bound {
		return nil, ErrTerminal
	}
	if int(candidate.Ordinal) >= len(protocol.localPlan.Candidates) || protocol.localPlan.Candidates[candidate.Ordinal] != candidate {
		return nil, protocol.failLocked(ErrPlanMismatch)
	}
	if err := protocol.validateSendLocked(FrameCandidate, candidate.Ordinal); err != nil {
		return nil, protocol.failLocked(err)
	}
	sequence := CandidateSequenceBase + uint64(candidate.Ordinal)
	frame, err := protocol.sealLocked(FrameCandidate, sequence, candidate.SocketSlot, candidate.Ordinal, nil)
	if err != nil {
		return nil, protocol.failLocked(err)
	}
	protocol.applySendLocked(FrameCandidate, candidate.Ordinal)
	return frame, nil
}

func (protocol *Protocol) ChooseWinner(candidate OpenedFrame, receiverSocketSlot uint16) (Winner, error) {
	if protocol == nil || candidate.Metadata.Type != FrameCandidate {
		return Winner{}, ErrInvalidTransition
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal || !protocol.chooser() || protocol.state.hasWinner {
		return Winner{}, protocol.failLocked(ErrInvalidTransition)
	}
	if _, ok := protocol.state.receivedCandidates[candidate.Metadata.Ordinal]; !ok {
		return Winner{}, protocol.failLocked(ErrInvalidTransition)
	}
	winner := Winner{CandidateSender: candidate.Metadata.Sender, CandidateOrdinal: candidate.Metadata.Ordinal, ReceiverSocketSlot: receiverSocketSlot}
	winner.Digest = digestWinner(protocol.executionDigest, winner)
	protocol.state.winner, protocol.state.hasWinner = winner, true
	return winner, nil
}

func (protocol *Protocol) SealWinner(winner Winner) ([]byte, error) {
	if protocol == nil {
		return nil, ErrTerminal
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal || !protocol.chooser() || !protocol.state.hasWinner || protocol.state.winner != winner ||
		winner.Digest != digestWinner(protocol.executionDigest, winner) {
		return nil, protocol.failLocked(ErrInvalidTransition)
	}
	if err := protocol.validateSendLocked(FrameWinner, winner.CandidateOrdinal); err != nil {
		return nil, protocol.failLocked(err)
	}
	payload := marshalWinner(winner)
	defer clear(payload)
	frame, err := protocol.sealLocked(FrameWinner, WinnerSequence, winner.ReceiverSocketSlot, winner.CandidateOrdinal, payload)
	if err != nil {
		return nil, protocol.failLocked(err)
	}
	protocol.applySendLocked(FrameWinner, winner.CandidateOrdinal)
	return frame, nil
}

func (protocol *Protocol) BindExecution(localPlan, peerPlan hardnatplan.Plan, joint hardnatplan.JointPlanCommitment, executionDigest [32]byte) error {
	if protocol == nil {
		return ErrTerminal
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	if protocol.state.terminal || protocol.state.bound || !protocol.state.sentSource || !protocol.state.receivedSource ||
		localPlan.Profile != protocol.binding.Profile || peerPlan.Profile != protocol.binding.Profile ||
		localPlan.ResourceClass != protocol.binding.ResourceClass || peerPlan.ResourceClass != protocol.binding.ResourceClass ||
		localPlan.Role != protocol.plannerRole || localPlan.Generation != protocol.binding.Generation ||
		peerPlan.Role == localPlan.Role || joint.JointDigest == ([32]byte{}) || allZero(executionDigest[:]) {
		return protocol.failLocked(ErrPlanMismatch)
	}
	foundLocal, foundPeer := false, false
	for _, direction := range joint.Directions {
		if direction.Role == localPlan.Role && direction.Triple == localPlan.Digests() {
			foundLocal = true
		}
		if direction.Role == peerPlan.Role && direction.Triple == peerPlan.Digests() {
			foundPeer = true
		}
	}
	if !foundLocal || !foundPeer {
		return protocol.failLocked(ErrPlanMismatch)
	}
	protocol.localPlan, protocol.peerPlan, protocol.joint, protocol.executionDigest = localPlan.Clone(), peerPlan.Clone(), joint, executionDigest
	protocol.state.bound = true
	return nil
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
	metadata, header, ciphertext, err := parseFrame(frame)
	if err != nil || metadata.Sender != protocol.role.Peer() {
		return OpenedFrame{}, protocol.failLocked(ErrInvalidFrame)
	}
	if err := protocol.validateReceiveLocked(metadata); err != nil {
		return OpenedFrame{}, protocol.failLocked(err)
	}
	ad, err := protocol.additionalDataLocked(metadata, header)
	if err != nil {
		return OpenedFrame{}, protocol.failLocked(err)
	}
	plaintext, err := protocol.packets.Open(metadata.Sequence, ad, ciphertext)
	clear(ad)
	if err != nil {
		return OpenedFrame{}, protocol.failLocked(errors.Join(ErrInvalidFrame, err))
	}
	defer clear(plaintext)
	opened := OpenedFrame{Metadata: metadata}
	switch metadata.Type {
	case FramePrepare, FrameFire, FrameCancel:
		if len(plaintext) != 0 {
			return OpenedFrame{}, protocol.failLocked(ErrInvalidPayload)
		}
	case FrameSource:
		source, parseErr := parseSource(plaintext, protocol.binding.Profile, protocol.binding.ResourceClass)
		if parseErr != nil {
			return OpenedFrame{}, protocol.failLocked(parseErr)
		}
		if source.Compact.Role == protocol.plannerRole {
			return OpenedFrame{}, protocol.failLocked(ErrPlanMismatch)
		}
		opened.Source = &source
	case FrameReady:
		if len(plaintext) != 64 {
			return OpenedFrame{}, protocol.failLocked(ErrInvalidPayload)
		}
		var ready ReadyPayload
		copy(ready.JointDigest[:], plaintext[:32])
		copy(ready.ExecutionDigest[:], plaintext[32:])
		if ready.JointDigest != protocol.joint.JointDigest || ready.ExecutionDigest != protocol.executionDigest {
			return OpenedFrame{}, protocol.failLocked(ErrPlanMismatch)
		}
		opened.Ready = &ready
	case FrameCandidate:
		if len(plaintext) != 0 || int(metadata.Ordinal) >= len(protocol.peerPlan.Candidates) ||
			protocol.peerPlan.Candidates[metadata.Ordinal].SocketSlot != metadata.SocketSlot {
			return OpenedFrame{}, protocol.failLocked(ErrPlanMismatch)
		}
	case FrameWinner:
		winner, parseErr := parseWinner(plaintext)
		if parseErr != nil || protocol.chooser() || winner.CandidateSender != protocol.role ||
			int(winner.CandidateOrdinal) >= len(protocol.localPlan.Candidates) ||
			winner.Digest != digestWinner(protocol.executionDigest, winner) || metadata.Ordinal != winner.CandidateOrdinal ||
			metadata.SocketSlot != winner.ReceiverSocketSlot {
			return OpenedFrame{}, protocol.failLocked(ErrPlanMismatch)
		}
		protocol.state.winner, protocol.state.hasWinner = winner, true
		opened.Winner = &winner
	case FrameVerify:
		if len(plaintext) != 32 || !protocol.state.hasWinner || !bytes.Equal(plaintext, protocol.state.winner.Digest[:]) {
			return OpenedFrame{}, protocol.failLocked(ErrPlanMismatch)
		}
	default:
		return OpenedFrame{}, protocol.failLocked(ErrInvalidSequence)
	}
	protocol.applyReceiveLocked(metadata)
	return opened, nil
}

func (protocol *Protocol) sealLocked(frameType FrameType, sequence uint64, socketSlot uint16, ordinal uint32, plaintext []byte) ([]byte, error) {
	header, metadata, err := buildHeader(protocol.role, frameType, sequence, socketSlot, ordinal, len(plaintext)+noisecore.TagSize)
	if err != nil {
		return nil, err
	}
	ad, err := protocol.additionalDataLocked(metadata, header)
	if err != nil {
		clear(header)
		return nil, err
	}
	ciphertext, err := protocol.packets.Seal(sequence, ad, plaintext)
	clear(ad)
	if err != nil {
		clear(header)
		return nil, err
	}
	frame := append(header, ciphertext...)
	clear(ciphertext)
	return frame, nil
}

func (protocol *Protocol) additionalDataLocked(metadata FrameMetadata, header []byte) ([]byte, error) {
	if protocol.binding.Validate() != nil || len(header) != FrameHeaderBytes {
		return nil, ErrInvalidBinding
	}
	var encoded bytes.Buffer
	encoded.WriteString("winkyou-hardnat-frame-ad-v1\x00")
	appendString(&encoded, hardnatattempt.DirectAttemptProfile)
	decoded, _ := base64.RawURLEncoding.DecodeString(protocol.binding.AttemptID)
	encoded.Write(decoded)
	clear(decoded)
	encoded.Write(protocol.binding.ContextDigest[:])
	encoded.Write(protocol.binding.HandshakeHash[:])
	appendUint64(&encoded, protocol.binding.Generation)
	appendString(&encoded, string(protocol.binding.Profile))
	appendString(&encoded, string(protocol.binding.ResourceClass))
	encoded.Write(protocol.binding.EnvelopeDigest[:])
	if metadata.Type == FrameReady || metadata.Type == FrameFire || metadata.Type == FrameCandidate ||
		metadata.Type == FrameWinner || metadata.Type == FrameVerify {
		if !protocol.state.bound || allZero(protocol.executionDigest[:]) {
			return nil, ErrInvalidTransition
		}
		encoded.Write(protocol.joint.JointDigest[:])
		encoded.Write(protocol.executionDigest[:])
		if metadata.Type == FrameCandidate {
			plan := protocol.localPlan
			if metadata.Sender != protocol.role {
				plan = protocol.peerPlan
			}
			encoded.Write(plan.PlanDigest[:])
		}
	}
	encoded.Write(header)
	return encoded.Bytes(), nil
}

func (protocol *Protocol) validateSendLocked(frameType FrameType, ordinal uint32) error {
	s := &protocol.state
	switch frameType {
	case FramePrepare:
		if s.sentPrepare {
			return ErrInvalidTransition
		}
	case FrameSource:
		if !s.sentPrepare || !s.receivedPrepare || s.sentSource {
			return ErrInvalidTransition
		}
	case FrameReady:
		if !s.bound || s.sentReady {
			return ErrInvalidTransition
		}
	case FrameFire:
		if !s.sentReady || !s.receivedReady || s.sentFire {
			return ErrInvalidTransition
		}
	case FrameCandidate:
		if !protocol.fireSeenLocked() {
			return ErrInvalidTransition
		}
		if _, exists := s.sentCandidates[ordinal]; exists {
			return ErrInvalidTransition
		}
	case FrameWinner:
		if !protocol.chooser() || !s.hasWinner || s.sentWinner {
			return ErrInvalidTransition
		}
	case FrameVerify:
		if !s.hasWinner || (protocol.chooser() && !s.sentWinner) || (!protocol.chooser() && !s.receivedWinner) || s.sentVerify {
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

func (protocol *Protocol) validateReceiveLocked(metadata FrameMetadata) error {
	s := &protocol.state
	switch metadata.Type {
	case FramePrepare:
		if s.receivedPrepare || metadata.Sequence != 0 {
			return ErrInvalidTransition
		}
	case FrameSource:
		if !s.sentPrepare || !s.receivedPrepare || s.receivedSource || metadata.Sequence != 1 {
			return ErrInvalidTransition
		}
	case FrameReady:
		if !s.bound || s.receivedReady || metadata.Sequence != 2 {
			return ErrInvalidTransition
		}
	case FrameFire:
		if !s.sentReady || !s.receivedReady || s.receivedFire || metadata.Sequence != 3 {
			return ErrInvalidTransition
		}
	case FrameCandidate:
		if !protocol.fireSeenLocked() || metadata.Sequence != CandidateSequenceBase+uint64(metadata.Ordinal) {
			return ErrInvalidTransition
		}
		if _, exists := s.receivedCandidates[metadata.Ordinal]; exists {
			return ErrInvalidTransition
		}
	case FrameWinner:
		if protocol.chooser() || s.receivedWinner || metadata.Sequence != WinnerSequence {
			return ErrInvalidTransition
		}
	case FrameVerify:
		if !s.hasWinner || s.receivedVerify || metadata.Sequence != VerifySequence {
			return ErrInvalidTransition
		}
	case FrameCancel:
		if s.receivedCancel || metadata.Sequence != CancelSequence {
			return ErrInvalidTransition
		}
	default:
		return ErrInvalidSequence
	}
	return nil
}

func (protocol *Protocol) fireSeenLocked() bool {
	return protocol.state.sentFire && protocol.state.receivedFire
}

func (protocol *Protocol) applySendLocked(frameType FrameType, ordinal uint32) {
	s := &protocol.state
	switch frameType {
	case FramePrepare:
		s.sentPrepare = true
	case FrameSource:
		s.sentSource = true
	case FrameReady:
		s.sentReady = true
	case FrameFire:
		s.sentFire = true
	case FrameCandidate:
		s.sentCandidates[ordinal] = struct{}{}
	case FrameWinner:
		s.sentWinner = true
	case FrameVerify:
		s.sentVerify = true
		protocol.completeLocked()
	case FrameCancel:
		s.sentCancel, s.terminal = true, true
		_ = protocol.packets.Close()
	}
}

func (protocol *Protocol) applyReceiveLocked(metadata FrameMetadata) {
	s := &protocol.state
	switch metadata.Type {
	case FramePrepare:
		s.receivedPrepare = true
	case FrameSource:
		s.receivedSource = true
	case FrameReady:
		s.receivedReady = true
	case FrameFire:
		s.receivedFire = true
	case FrameCandidate:
		s.receivedCandidates[metadata.Ordinal] = struct{}{}
	case FrameWinner:
		s.receivedWinner = true
	case FrameVerify:
		s.receivedVerify = true
		protocol.completeLocked()
	case FrameCancel:
		s.receivedCancel, s.terminal = true, true
		_ = protocol.packets.Close()
	}
}

func (protocol *Protocol) completeLocked() {
	if protocol.state.sentVerify && protocol.state.receivedVerify {
		protocol.state.success, protocol.state.terminal = true, true
		_ = protocol.packets.Close()
	}
}

func (protocol *Protocol) fail(err error) error {
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	return protocol.failLocked(err)
}
func (protocol *Protocol) failLocked(err error) error {
	protocol.state.terminal = true
	protocol.state.success = false
	if protocol.packets != nil {
		_ = protocol.packets.Close()
	}
	return err
}
func (protocol *Protocol) Close() error {
	if protocol == nil {
		return nil
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	protocol.state.terminal = true
	if protocol.packets != nil {
		return protocol.packets.Close()
	}
	return nil
}

func (protocol *Protocol) Success() bool {
	if protocol == nil {
		return false
	}
	protocol.mu.Lock()
	defer protocol.mu.Unlock()
	return protocol.state.success
}

func InspectFrame(frame []byte) (FrameMetadata, error) {
	metadata, _, _, err := parseFrame(frame)
	return metadata, err
}

func buildHeader(sender Role, frameType FrameType, sequence uint64, socketSlot uint16, ordinal uint32, ciphertextLength int) ([]byte, FrameMetadata, error) {
	domain, ok := frameType.domain()
	if !sender.Valid() || !ok || ciphertextLength < noisecore.TagSize || FrameHeaderBytes+ciphertextLength > MaxFrameBytes || sequence > MaxSequence {
		return nil, FrameMetadata{}, ErrInvalidFrame
	}
	header := make([]byte, FrameHeaderBytes)
	copy(header[:4], FrameMagic)
	header[4] = FrameVersion
	header[5], header[6], header[7] = byte(domain), byte(frameType), roleCode(sender)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	binary.BigEndian.PutUint16(header[16:18], socketSlot)
	binary.BigEndian.PutUint32(header[18:22], ordinal)
	binary.BigEndian.PutUint16(header[22:24], uint16(ciphertextLength))
	return header, FrameMetadata{Domain: domain, Type: frameType, Sender: sender, Sequence: sequence,
		SocketSlot: socketSlot, Ordinal: ordinal, CiphertextBytes: ciphertextLength}, nil
}

func parseFrame(frame []byte) (FrameMetadata, []byte, []byte, error) {
	if len(frame) < FrameHeaderBytes+noisecore.TagSize || len(frame) > MaxFrameBytes || !bytes.Equal(frame[:4], []byte(FrameMagic)) || frame[4] != FrameVersion {
		return FrameMetadata{}, nil, nil, ErrInvalidFrame
	}
	header := frame[:FrameHeaderBytes]
	metadata := FrameMetadata{Domain: Domain(header[5]), Type: FrameType(header[6]), Sender: roleFromCode(header[7]),
		Sequence: binary.BigEndian.Uint64(header[8:16]), SocketSlot: binary.BigEndian.Uint16(header[16:18]),
		Ordinal: binary.BigEndian.Uint32(header[18:22]), CiphertextBytes: int(binary.BigEndian.Uint16(header[22:24]))}
	domain, ok := metadata.Type.domain()
	if !ok || domain != metadata.Domain || !metadata.Sender.Valid() || metadata.Sequence > MaxSequence ||
		metadata.CiphertextBytes < noisecore.TagSize || len(frame) != FrameHeaderBytes+metadata.CiphertextBytes {
		return FrameMetadata{}, nil, nil, ErrInvalidFrame
	}
	if metadata.Type != FrameCandidate && metadata.Type != FrameWinner && (metadata.SocketSlot != 0 || metadata.Ordinal != 0) {
		return FrameMetadata{}, nil, nil, ErrInvalidFrame
	}
	return metadata, header, frame[FrameHeaderBytes:], nil
}

func fixedSequence(frameType FrameType) (uint64, bool) {
	switch frameType {
	case FramePrepare:
		return 0, true
	case FrameSource:
		return 1, true
	case FrameReady:
		return 2, true
	case FrameFire:
		return 3, true
	case FrameVerify:
		return VerifySequence, true
	case FrameCancel:
		return CancelSequence, true
	default:
		return 0, false
	}
}

func marshalSource(payload SourcePayload) ([]byte, error) {
	if _, err := payload.Commitment(payload.Compact.Profile, payload.Compact.ResourceClass); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	encoded.WriteString("WYSC\x01")
	encoded.WriteByte(plannerRoleCode(payload.Compact.Role))
	encoded.Write(payload.Compact.AttemptDigest[:])
	appendUint64(&encoded, payload.Compact.Generation)
	encoded.Write(payload.Compact.EvidenceDigest[:])
	encoded.Write(payload.Compact.ValidationDigest[:])
	appendAddress(&encoded, payload.PublicAddress)
	appendAddressPort(&encoded, payload.Compact.ReceiveEndpoint)
	appendUint16(&encoded, payload.Compact.ReceiveSocketSlot)
	if len(payload.Compact.ModelCoverage) > hardnatplan.MaxModelCoverageBytes {
		return nil, ErrInvalidPayload
	}
	appendUint16(&encoded, uint16(len(payload.Compact.ModelCoverage)))
	encoded.WriteString(payload.Compact.ModelCoverage)
	if len(payload.Compact.PredictedPorts) > 32 {
		return nil, ErrInvalidPayload
	}
	encoded.WriteByte(byte(len(payload.Compact.PredictedPorts)))
	for _, port := range payload.Compact.PredictedPorts {
		appendUint16(&encoded, port)
	}
	if encoded.Len() > MaxFrameBytes-FrameHeaderBytes-noisecore.TagSize {
		return nil, ErrInvalidPayload
	}
	return encoded.Bytes(), nil
}

func parseSource(payload []byte, profile hardnatplan.Profile, resource hardnatplan.ResourceClass) (SourcePayload, error) {
	const fixed = 5 + 1 + 32 + 8 + 32 + 32 + 17 + 19 + 2 + 2 + 1
	if len(payload) < fixed || !bytes.Equal(payload[:5], []byte("WYSC\x01")) {
		return SourcePayload{}, ErrInvalidPayload
	}
	offset := 5
	role := plannerRoleFromCode(payload[offset])
	offset++
	var compact hardnatplan.CompactSourceInput
	compact.Profile, compact.ResourceClass, compact.Role = profile, resource, role
	copy(compact.AttemptDigest[:], payload[offset:offset+32])
	offset += 32
	compact.Generation = binary.BigEndian.Uint64(payload[offset : offset+8])
	offset += 8
	copy(compact.EvidenceDigest[:], payload[offset:offset+32])
	offset += 32
	copy(compact.ValidationDigest[:], payload[offset:offset+32])
	offset += 32
	public, next, err := parseAddress(payload, offset)
	if err != nil {
		return SourcePayload{}, err
	}
	offset = next
	receive, next, err := parseAddressPort(payload, offset)
	if err != nil {
		return SourcePayload{}, err
	}
	offset = next
	if len(payload) < offset+4 {
		return SourcePayload{}, ErrInvalidPayload
	}
	compact.ReceiveEndpoint = receive
	compact.ReceiveSocketSlot = binary.BigEndian.Uint16(payload[offset : offset+2])
	offset += 2
	coverageLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if coverageLength == 0 || coverageLength > hardnatplan.MaxModelCoverageBytes || len(payload) < offset+coverageLength+1 {
		return SourcePayload{}, ErrInvalidPayload
	}
	compact.ModelCoverage = string(payload[offset : offset+coverageLength])
	offset += coverageLength
	count := int(payload[offset])
	offset++
	if count > 32 || len(payload) != offset+count*2 {
		return SourcePayload{}, ErrInvalidPayload
	}
	compact.PredictedPorts = make([]uint16, count)
	for index := range compact.PredictedPorts {
		compact.PredictedPorts[index] = binary.BigEndian.Uint16(payload[offset : offset+2])
		offset += 2
	}
	result := SourcePayload{Compact: compact, PublicAddress: public}
	if _, err := result.Commitment(profile, resource); err != nil {
		return SourcePayload{}, err
	}
	return result, nil
}

func marshalWinner(winner Winner) []byte {
	result := make([]byte, 1+4+2+32)
	result[0] = roleCode(winner.CandidateSender)
	binary.BigEndian.PutUint32(result[1:5], winner.CandidateOrdinal)
	binary.BigEndian.PutUint16(result[5:7], winner.ReceiverSocketSlot)
	copy(result[7:], winner.Digest[:])
	return result
}
func parseWinner(payload []byte) (Winner, error) {
	if len(payload) != 39 {
		return Winner{}, ErrInvalidPayload
	}
	winner := Winner{CandidateSender: roleFromCode(payload[0]), CandidateOrdinal: binary.BigEndian.Uint32(payload[1:5]), ReceiverSocketSlot: binary.BigEndian.Uint16(payload[5:7])}
	copy(winner.Digest[:], payload[7:])
	if !winner.CandidateSender.Valid() || allZero(winner.Digest[:]) {
		return Winner{}, ErrInvalidPayload
	}
	return winner, nil
}
func digestWinner(execution [32]byte, winner Winner) [32]byte {
	var encoded bytes.Buffer
	encoded.WriteString("winkyou-hardnat-winner-v1\x00")
	encoded.Write(execution[:])
	encoded.WriteByte(roleCode(winner.CandidateSender))
	appendUint32(&encoded, winner.CandidateOrdinal)
	appendUint16(&encoded, winner.ReceiverSocketSlot)
	return sha256.Sum256(encoded.Bytes())
}

// ValidateCandidateArrival proves the authenticated peer candidate arrived on
// a socket/source tuple that belongs to the reciprocal frozen plans.
func ValidateCandidateArrival(localPlan, peerPlan hardnatplan.Plan, opened OpenedFrame, receiverSocketSlot uint16, sourcePort uint16) error {
	if opened.Metadata.Type != FrameCandidate || sourcePort == 0 || int(opened.Metadata.Ordinal) >= len(peerPlan.Candidates) ||
		peerPlan.Candidates[opened.Metadata.Ordinal].SocketSlot != opened.Metadata.SocketSlot {
		return ErrPlanMismatch
	}
	peer := peerPlan.Candidates[opened.Metadata.Ordinal]
	switch localPlan.Profile {
	case hardnatplan.ProfilePredictiveEdm:
		if sourcePort != peer.ExpectedSourcePort {
			return ErrPlanMismatch
		}
		for _, local := range localPlan.Candidates {
			if local.SocketSlot == receiverSocketSlot && local.ExpectedSourcePort == peer.TargetPort {
				return nil
			}
		}
	case hardnatplan.ProfileAsymmetricBirthday:
		if localPlan.Role == hardnatplan.RoleTargetSet && peerPlan.Role == hardnatplan.RoleMappingSet {
			if len(localPlan.Candidates) == 0 || receiverSocketSlot != localPlan.Candidates[0].SocketSlot {
				return ErrPlanMismatch
			}
			for _, local := range localPlan.Candidates {
				if local.TargetPort == sourcePort {
					return nil
				}
			}
		}
		if localPlan.Role == hardnatplan.RoleMappingSet && peerPlan.Role == hardnatplan.RoleTargetSet && sourcePort == peer.ExpectedSourcePort {
			for _, local := range localPlan.Candidates {
				if local.SocketSlot == receiverSocketSlot {
					return nil
				}
			}
		}
	}
	return ErrPlanMismatch
}

func appendAddress(target *bytes.Buffer, address hardnatplan.Address) {
	target.WriteByte(byte(address.Family))
	target.Write(address.Bytes[:])
}
func appendAddressPort(target *bytes.Buffer, endpoint hardnatplan.AddressPort) {
	if endpoint == (hardnatplan.AddressPort{}) {
		target.Write(make([]byte, 17))
		appendUint16(target, 0)
		return
	}
	appendAddress(target, endpoint.Address)
	appendUint16(target, endpoint.Port)
}
func parseAddress(payload []byte, offset int) (hardnatplan.Address, int, error) {
	if len(payload) < offset+17 {
		return hardnatplan.Address{}, offset, ErrInvalidPayload
	}
	var address hardnatplan.Address
	address.Family = hardnatplan.AddressFamily(payload[offset])
	copy(address.Bytes[:], payload[offset+1:offset+17])
	offset += 17
	if !address.Valid() {
		return hardnatplan.Address{}, offset, ErrInvalidPayload
	}
	return address, offset, nil
}
func parseAddressPort(payload []byte, offset int) (hardnatplan.AddressPort, int, error) {
	if len(payload) < offset+19 {
		return hardnatplan.AddressPort{}, offset, ErrInvalidPayload
	}
	allEmpty := true
	for _, value := range payload[offset : offset+19] {
		allEmpty = allEmpty && value == 0
	}
	if allEmpty {
		return hardnatplan.AddressPort{}, offset + 19, nil
	}
	address, next, err := parseAddress(payload, offset)
	if err != nil {
		return hardnatplan.AddressPort{}, offset, err
	}
	port := binary.BigEndian.Uint16(payload[next : next+2])
	endpoint := hardnatplan.AddressPort{Address: address, Port: port}
	if !endpoint.Valid() {
		return hardnatplan.AddressPort{}, offset, ErrInvalidPayload
	}
	return endpoint, next + 2, nil
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
func plannerRoleCode(role hardnatplan.Role) byte {
	switch role {
	case hardnatplan.RoleInitiator:
		return 1
	case hardnatplan.RoleResponder:
		return 2
	case hardnatplan.RoleMappingSet:
		return 3
	case hardnatplan.RoleTargetSet:
		return 4
	}
	return 0
}
func plannerRoleFromCode(code byte) hardnatplan.Role {
	switch code {
	case 1:
		return hardnatplan.RoleInitiator
	case 2:
		return hardnatplan.RoleResponder
	case 3:
		return hardnatplan.RoleMappingSet
	case 4:
		return hardnatplan.RoleTargetSet
	}
	return ""
}
func appendString(target *bytes.Buffer, value string) {
	appendUint32(target, uint32(len(value)))
	target.WriteString(value)
}
func appendUint16(target *bytes.Buffer, value uint16) {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], value)
	target.Write(raw[:])
}
func appendUint32(target *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	target.Write(raw[:])
}
func appendUint64(target *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	target.Write(raw[:])
}
func allZero(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}
func (metadata FrameMetadata) String() string {
	return fmt.Sprintf("type=%d sequence=%d", metadata.Type, metadata.Sequence)
}
