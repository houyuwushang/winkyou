package hardnatcontrol

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
	"winkyou/internal/v2/noisecore"
)

type fixedPSK [32]byte

func (source fixedPSK) LoadPSK() ([32]byte, error) { return source, nil }

func TestCandidateHeaderByteGolden(t *testing.T) {
	header, metadata, err := buildHeader(RoleInitiator, FrameCandidate, CandidateSequenceBase, 7, 42, noisecore.TagSize)
	if err != nil {
		t.Fatal(err)
	}
	const want = "5759484201020401000000000000001000070000002a0010"
	if got := hex.EncodeToString(header); got != want {
		t.Fatalf("candidate header=%s, want=%s", got, want)
	}
	frame := append(append([]byte(nil), header...), make([]byte, noisecore.TagSize)...)
	parsed, parsedHeader, ciphertext, err := parseFrame(frame)
	if err != nil || parsed != metadata || !bytes.Equal(parsedHeader, header) || len(ciphertext) != noisecore.TagSize {
		t.Fatalf("parse golden metadata=%+v header=%x ciphertext=%d err=%v", parsed, parsedHeader, len(ciphertext), err)
	}
}

func TestHardCampaignBarrierAndSelectionHeaderByteGolden(t *testing.T) {
	tests := []struct {
		role      Role
		frameType FrameType
		sequence  uint64
		want      string
	}{
		{RoleInitiator, FrameReadyFire, 2, "575948420101090100000000000000020000000000000010"},
		{RoleResponder, FrameWinnerSelection, HardCampaignSelectionSequence, "575948420101080200000000000040110000000000000010"},
		{RoleResponder, FrameExhausted, HardCampaignVerifySequence, "5759484201010a0200000000000040120000000000000010"},
	}
	for _, test := range tests {
		header, metadata, err := buildHeader(test.role, test.frameType, test.sequence, 0, 0, noisecore.TagSize)
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(header); got != test.want {
			t.Fatalf("hard header type=%d = %s, want %s", test.frameType, got, test.want)
		}
		frame := append(append([]byte(nil), header...), make([]byte, noisecore.TagSize)...)
		parsed, _, _, err := parseFrame(frame)
		if err != nil || parsed != metadata {
			t.Fatalf("hard header parse type=%d = %+v/%v", test.frameType, parsed, err)
		}
	}
}

func TestProtocolBindsBilateralPlanAndWinner(t *testing.T) {
	attempt := sha256.Sum256([]byte("attempt"))
	leftSource := compactPredictive(t, hardnatplan.RoleInitiator, attempt, 50000, "left")
	rightSource := compactPredictive(t, hardnatplan.RoleResponder, attempt, 60000, "right")
	leftPayload, err := NewSourcePayload(leftSource, hardnatplan.Address4([4]byte{192, 0, 2, 10}))
	if err != nil {
		t.Fatal(err)
	}
	rightPayload, err := NewSourcePayload(rightSource, hardnatplan.Address4([4]byte{192, 0, 2, 20}))
	if err != nil {
		t.Fatal(err)
	}

	leftSession, rightSession := completeNoise(t)
	leftPackets, leftPlanner, err := leftSession.TakePacketCipherAndPlannerKeySource(MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	rightPackets, rightPlanner, err := rightSession.TakePacketCipherAndPlannerKeySource(MaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	defer leftPlanner.Close()
	defer rightPlanner.Close()
	leftBilateral, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{First: leftSource, Second: rightSource, KeySource: NoisePlannerKeySource{leftPlanner}})
	if err != nil {
		t.Fatal(err)
	}
	rightBilateral, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{First: rightSource, Second: leftSource, KeySource: NoisePlannerKeySource{rightPlanner}})
	if err != nil {
		t.Fatal(err)
	}
	if leftBilateral.JointDigest != rightBilateral.JointDigest {
		t.Fatal("Noise planner keys produced different joint plans")
	}
	joint := leftBilateral.Commitment()
	leftPlan, _ := leftBilateral.PlanForRole(hardnatplan.RoleInitiator)
	rightPlan, _ := leftBilateral.PlanForRole(hardnatplan.RoleResponder)
	envelope, _ := hardnatbudget.For(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
	envelopeDigest, _ := hardnatbudget.Digest(envelope)
	handshakeHash, _ := sha256Bytes("handshake")
	contextDigest, _ := sha256Bytes("context")
	binding := Binding{AttemptID: "AAECAwQFBgcICQoLDA0ODw", ContextDigest: contextDigest, HandshakeHash: handshakeHash,
		Generation: 1, Profile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive, EnvelopeDigest: envelopeDigest}
	leftProtocol, err := NewProtocol(RoleInitiator, hardnatplan.RoleInitiator, binding, leftPackets)
	if err != nil {
		t.Fatal(err)
	}
	rightProtocol, err := NewProtocol(RoleResponder, hardnatplan.RoleResponder, binding, rightPackets)
	if err != nil {
		t.Fatal(err)
	}
	defer leftProtocol.Close()
	defer rightProtocol.Close()
	exchange := func(sender, receiver *Protocol, frame []byte) OpenedFrame {
		t.Helper()
		opened, err := receiver.Open(frame)
		if err != nil {
			t.Fatal(err)
		}
		return opened
	}
	frame, _ := leftProtocol.SealPrepare()
	exchange(leftProtocol, rightProtocol, frame)
	frame, _ = rightProtocol.SealPrepare()
	exchange(rightProtocol, leftProtocol, frame)
	frame, err = leftProtocol.SealSource(leftPayload)
	if err != nil {
		t.Fatal(err)
	}
	openedRightSource := exchange(leftProtocol, rightProtocol, frame)
	frame, err = rightProtocol.SealSource(rightPayload)
	if err != nil {
		t.Fatal(err)
	}
	openedLeftSource := exchange(rightProtocol, leftProtocol, frame)
	if openedRightSource.Source == nil || openedLeftSource.Source == nil {
		t.Fatal("source payload missing")
	}
	execution, err := BuildExecutionDigest(joint, envelopeDigest,
		ExecutionSource{CarrierRole: RoleInitiator, PlannerRole: leftPlan.Role, SourceDigest: leftSource.SourceDigest, PublicAddress: leftPayload.PublicAddress},
		ExecutionSource{CarrierRole: RoleResponder, PlannerRole: rightPlan.Role, SourceDigest: rightSource.SourceDigest, PublicAddress: rightPayload.PublicAddress})
	if err != nil {
		t.Fatal(err)
	}
	if err := leftProtocol.BindExecution(leftPlan, rightPlan, joint, execution); err != nil {
		t.Fatal(err)
	}
	if err := rightProtocol.BindExecution(rightPlan, leftPlan, joint, execution); err != nil {
		t.Fatal(err)
	}
	frame, _ = leftProtocol.SealReady()
	exchange(leftProtocol, rightProtocol, frame)
	frame, _ = rightProtocol.SealReady()
	exchange(rightProtocol, leftProtocol, frame)
	frame, _ = leftProtocol.SealFire()
	exchange(leftProtocol, rightProtocol, frame)
	frame, _ = rightProtocol.SealFire()
	exchange(rightProtocol, leftProtocol, frame)
	peerCandidate := rightPlan.Candidates[0]
	frame, err = rightProtocol.SealCandidate(peerCandidate)
	if err != nil {
		t.Fatal(err)
	}
	openedCandidate := exchange(rightProtocol, leftProtocol, frame)
	receiverSlot := uint16(0xffff)
	for _, candidate := range leftPlan.Candidates {
		if candidate.ExpectedSourcePort == peerCandidate.TargetPort {
			receiverSlot = candidate.SocketSlot
			break
		}
	}
	if err := ValidateCandidateArrival(leftPlan, rightPlan, openedCandidate, receiverSlot, peerCandidate.ExpectedSourcePort); err != nil {
		t.Fatal(err)
	}
	winner, err := leftProtocol.ChooseWinner(openedCandidate, receiverSlot)
	if err != nil {
		t.Fatal(err)
	}
	frame, err = leftProtocol.SealWinner(winner)
	if err != nil {
		t.Fatal(err)
	}
	openedWinner := exchange(leftProtocol, rightProtocol, frame)
	if openedWinner.Winner == nil || *openedWinner.Winner != winner {
		t.Fatal("winner mismatch")
	}
	frame, _ = leftProtocol.SealVerify()
	exchange(leftProtocol, rightProtocol, frame)
	frame, _ = rightProtocol.SealVerify()
	exchange(rightProtocol, leftProtocol, frame)
	if !leftProtocol.Success() || !rightProtocol.Success() {
		t.Fatal("bidirectional VERIFY did not terminate successfully")
	}
}

func TestCandidateReplayAndCrossDomainMutationAreTerminal(t *testing.T) {
	left, right, leftPlan, _, _, _ := preparedProtocols(t, true)
	defer left.Close()
	defer right.Close()
	frame, err := left.SealCandidate(leftPlan.Candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := right.Open(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := right.Open(frame); err == nil {
		t.Fatal("candidate replay accepted")
	}
	left2, right2, leftPlan2, _, _, _ := preparedProtocols(t, true)
	defer left2.Close()
	defer right2.Close()
	frame, _ = left2.SealCandidate(leftPlan2.Candidates[0])
	frame[5] = byte(DomainRendezvousControl)
	if _, err := right2.Open(frame); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("cross-domain mutation = %v", err)
	}
}

func TestUnilateralFireCannotAuthorizeDirectPacket(t *testing.T) {
	left, right, leftPlan, _, _, _ := preparedProtocols(t, false)
	defer left.Close()
	defer right.Close()
	if _, err := left.SealCandidate(leftPlan.Candidates[0]); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("candidate after unilateral FIRE = %v, want invalid transition", err)
	}
}

func TestB2ProtocolRejectsHardCampaignSequenceWithoutWidening(t *testing.T) {
	left, right, leftPlan, _, _, _ := preparedProtocols(t, true)
	defer left.Close()
	defer right.Close()
	frame, err := left.SealCandidate(leftPlan.Candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(frame[8:16], HardCampaignWinnerSequence)
	if _, err := right.Open(frame); err == nil {
		t.Fatal("B2 protocol accepted a hard-campaign sequence")
	}
}

func TestHardCampaignLastOrdinalWinnerUsesFrozenSequence(t *testing.T) {
	left, right, leftPlan, rightPlan := preparedHardProtocols(t)
	defer left.Close()
	defer right.Close()
	for _, candidate := range leftPlan.Candidates {
		frame, err := left.SealCandidate(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := right.Open(frame); err != nil {
			t.Fatal(err)
		}
	}
	var opened OpenedFrame
	for _, candidate := range rightPlan.Candidates {
		frame, err := right.SealCandidate(candidate)
		if err != nil {
			t.Fatal(err)
		}
		opened, err = left.Open(frame)
		if err != nil {
			t.Fatal(err)
		}
	}
	if opened.Metadata.Sequence != CandidateSequenceBase+uint64(len(rightPlan.Candidates)-1) ||
		opened.Metadata.Ordinal != uint32(len(rightPlan.Candidates)-1) {
		t.Fatalf("last hard candidate = %+v", opened.Metadata)
	}
	winner, err := left.RecordWinnerCandidate(opened, leftPlan.Candidates[0].SocketSlot)
	if err != nil {
		t.Fatal(err)
	}
	frame, status, err := right.SealWinnerSelection()
	if err != nil || status.HasWinner {
		t.Fatalf("hard responder status = %+v/%v", status, err)
	}
	metadata, err := InspectFrame(frame)
	if err != nil || metadata.Sequence != HardCampaignSelectionSequence {
		t.Fatalf("hard selection sequence = %+v/%v", metadata, err)
	}
	if _, err := left.Open(frame); err != nil {
		t.Fatal(err)
	}
	frame, decision, err := left.SealWinnerSelection()
	if err != nil || !decision.HasWinner || decision.Winner != winner {
		t.Fatalf("hard initiator decision = %+v/%v", decision, err)
	}
	if _, err := right.Open(frame); err != nil {
		t.Fatal(err)
	}
	frame, err = left.SealWinner(winner)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err = InspectFrame(frame)
	if err != nil || metadata.Sequence != HardCampaignWinnerSequence {
		t.Fatalf("hard winner sequence = %+v/%v", metadata, err)
	}
	if _, err := right.Open(frame); err != nil {
		t.Fatal(err)
	}
	frame, err = left.SealVerify()
	if err != nil {
		t.Fatal(err)
	}
	metadata, _ = InspectFrame(frame)
	if metadata.Sequence != HardCampaignVerifySequence {
		t.Fatalf("hard verify sequence = %d", metadata.Sequence)
	}
	if _, err := right.Open(frame); err != nil {
		t.Fatal(err)
	}
	frame, err = right.SealVerify()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.Open(frame); err != nil {
		t.Fatal(err)
	}
	if !left.Success() || !right.Success() {
		t.Fatal("hard campaign did not reach bidirectional VERIFY")
	}
}

func TestHardCampaignCandidateReorderIsBoundedAndReplayIsTerminal(t *testing.T) {
	left, right, _, rightPlan := preparedHardProtocols(t)
	defer left.Close()
	defer right.Close()
	lastFrame, err := right.SealCandidate(rightPlan.Candidates[len(rightPlan.Candidates)-1])
	if err != nil {
		t.Fatal(err)
	}
	firstFrame, err := right.SealCandidate(rightPlan.Candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := left.Open(lastFrame); err != nil || opened.Metadata.Ordinal != uint32(len(rightPlan.Candidates)-1) {
		t.Fatalf("reordered last candidate = %+v/%v", opened.Metadata, err)
	}
	if opened, err := left.Open(firstFrame); err != nil || opened.Metadata.Ordinal != 0 {
		t.Fatalf("reordered first candidate = %+v/%v", opened.Metadata, err)
	}
	if _, err := left.Open(lastFrame); err == nil {
		t.Fatal("hard campaign candidate replay was accepted")
	}
	if _, err := left.SealCancel(); err == nil {
		t.Fatal("hard campaign protocol remained usable after replay")
	}
}

func TestHardCampaignCandidateArrivalRequiresReciprocalSocketTuple(t *testing.T) {
	left, right, leftPlan, rightPlan := preparedHardProtocols(t)
	defer left.Close()
	defer right.Close()
	peer := rightPlan.Candidates[0]
	opened := OpenedFrame{Metadata: FrameMetadata{
		Type: FrameCandidate, Sender: RoleResponder, Ordinal: peer.Ordinal, SocketSlot: peer.SocketSlot,
	}}
	receiverSlot := leftPlan.Candidates[0].SocketSlot
	if err := ValidateCandidateArrival(leftPlan, rightPlan, opened, receiverSlot, leftPlan.Candidates[0].TargetPort); err != nil {
		t.Fatalf("reciprocal hard tuple rejected: %v", err)
	}
	foreignPort := leftPlan.Candidates[1024].TargetPort
	if err := ValidateCandidateArrival(leftPlan, rightPlan, opened, receiverSlot, foreignPort); !errors.Is(err, ErrPlanMismatch) {
		t.Fatalf("same-universe foreign socket tuple = %v, want plan mismatch", err)
	}
}

func TestHardCampaignMutualHitSelectsOnlyInitiator(t *testing.T) {
	left, right, leftPlan, rightPlan := preparedHardProtocols(t)
	defer left.Close()
	defer right.Close()
	var leftOpened, rightOpened OpenedFrame
	for index := range leftPlan.Candidates {
		leftFrame, err := left.SealCandidate(leftPlan.Candidates[index])
		if err != nil {
			t.Fatal(err)
		}
		rightOpened, err = right.Open(leftFrame)
		if err != nil {
			t.Fatal(err)
		}
		rightFrame, err := right.SealCandidate(rightPlan.Candidates[index])
		if err != nil {
			t.Fatal(err)
		}
		leftOpened, err = left.Open(rightFrame)
		if err != nil {
			t.Fatal(err)
		}
	}
	leftProposal, err := left.RecordWinnerCandidate(leftOpened, leftPlan.Candidates[0].SocketSlot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := right.RecordWinnerCandidate(rightOpened, rightPlan.Candidates[0].SocketSlot); err != nil {
		t.Fatal(err)
	}
	statusFrame, _, err := right.SealWinnerSelection()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := left.Open(statusFrame); err != nil {
		t.Fatal(err)
	}
	decisionFrame, decision, err := left.SealWinnerSelection()
	if err != nil || !decision.HasWinner || decision.Winner != leftProposal {
		t.Fatalf("mutual-hit decision = %+v/%v", decision, err)
	}
	if _, err := right.Open(decisionFrame); err != nil {
		t.Fatal(err)
	}
	leftWinner, leftHas, leftSends := left.SelectedWinner()
	rightWinner, rightHas, rightSends := right.SelectedWinner()
	if !leftHas || !rightHas || !leftSends || rightSends || leftWinner != rightWinner || leftWinner != leftProposal {
		t.Fatalf("mutual-hit selected winner = %+v/%t/%t %+v/%t/%t",
			leftWinner, leftHas, leftSends, rightWinner, rightHas, rightSends)
	}
	if _, err := right.SealWinner(rightWinner); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("non-selected responder winner = %v", err)
	}
}

func TestHardCampaignResponderOnlyHitRemainsSelectable(t *testing.T) {
	left, right, leftPlan, rightPlan := preparedHardProtocols(t)
	defer left.Close()
	defer right.Close()
	var rightOpened OpenedFrame
	for index := range leftPlan.Candidates {
		leftFrame, err := left.SealCandidate(leftPlan.Candidates[index])
		if err != nil {
			t.Fatal(err)
		}
		rightOpened, err = right.Open(leftFrame)
		if err != nil {
			t.Fatal(err)
		}
		rightFrame, err := right.SealCandidate(rightPlan.Candidates[index])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := left.Open(rightFrame); err != nil {
			t.Fatal(err)
		}
	}
	proposal, err := right.RecordWinnerCandidate(rightOpened, rightPlan.Candidates[0].SocketSlot)
	if err != nil {
		t.Fatal(err)
	}
	statusFrame, status, err := right.SealWinnerSelection()
	if err != nil || !status.HasWinner || status.Winner != proposal {
		t.Fatalf("responder status = %+v/%v", status, err)
	}
	if _, err := left.Open(statusFrame); err != nil {
		t.Fatal(err)
	}
	decisionFrame, decision, err := left.SealWinnerSelection()
	if err != nil || decision != status {
		t.Fatalf("responder-only decision = %+v/%v", decision, err)
	}
	if _, err := right.Open(decisionFrame); err != nil {
		t.Fatal(err)
	}
	if _, _, leftSends := left.SelectedWinner(); leftSends {
		t.Fatal("initiator was allowed to send the responder-only winner")
	}
	selected, has, rightSends := right.SelectedWinner()
	if !has || !rightSends || selected != proposal {
		t.Fatalf("responder-only selected winner = %+v/%t/%t", selected, has, rightSends)
	}
	winnerFrame, err := right.SealWinner(selected)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := left.Open(winnerFrame)
	if err != nil || opened.Winner == nil || *opened.Winner != selected {
		t.Fatalf("responder-only winner = %+v/%v", opened.Winner, err)
	}
}

func TestHardCampaignExhaustionAckIsResponderOrdered(t *testing.T) {
	left, right, leftPlan, rightPlan := preparedHardProtocols(t)
	defer left.Close()
	defer right.Close()
	for index := range leftPlan.Candidates {
		leftFrame, err := left.SealCandidate(leftPlan.Candidates[index])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := right.Open(leftFrame); err != nil {
			t.Fatal(err)
		}
		rightFrame, err := right.SealCandidate(rightPlan.Candidates[index])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := left.Open(rightFrame); err != nil {
			t.Fatal(err)
		}
	}
	statusFrame, status, err := right.SealWinnerSelection()
	if err != nil || status.HasWinner {
		t.Fatalf("hard exhaustion status = %+v/%v", status, err)
	}
	if _, err := left.Open(statusFrame); err != nil {
		t.Fatal(err)
	}
	decisionFrame, decision, err := left.SealWinnerSelection()
	if err != nil || decision.HasWinner {
		t.Fatalf("hard exhaustion decision = %+v/%v", decision, err)
	}
	if _, err := right.Open(decisionFrame); err != nil {
		t.Fatal(err)
	}
	ack, err := right.SealExhausted()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := left.Open(ack)
	if err != nil || opened.Metadata.Type != FrameExhausted || opened.Metadata.Sequence != HardCampaignVerifySequence {
		t.Fatalf("hard exhaustion ack = %+v/%v", opened.Metadata, err)
	}
	if _, err := right.SealExhausted(); !errors.Is(err, ErrTerminal) {
		t.Fatalf("duplicate hard exhaustion ack = %v", err)
	}
}

func compactPredictive(t *testing.T, role hardnatplan.Role, attempt [32]byte, first uint16, label string) hardnatplan.LocalSourceCommitment {
	t.Helper()
	ports := make([]uint16, 32)
	for index := range ports {
		ports[index] = first + uint16(index)
	}
	commitment, err := hardnatplan.ReconstructLocalCommitment(hardnatplan.CompactSourceInput{
		Profile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive, Role: role,
		AttemptDigest: attempt, Generation: 1, PredictedPorts: ports, EvidenceDigest: sha256.Sum256([]byte(label + "-evidence")),
		ValidationDigest: sha256.Sum256([]byte(label + "-validation")), ModelCoverage: "samples=8;observers=2;alternate_port=true",
	})
	if err != nil {
		t.Fatal(err)
	}
	return commitment
}

func completeNoise(t *testing.T) (*noisecore.Session, *noisecore.Session) {
	t.Helper()
	psk := fixedPSK(sha256.Sum256([]byte("psk")))
	prologue := []byte("hardnat-control-test")
	left, err := noisecore.NewInitiator(noisecore.Config{Prologue: prologue, PSK: psk, Random: bytes.NewReader(bytes.Repeat([]byte{0x31}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	right, err := noisecore.NewResponder(noisecore.Config{Prologue: prologue, PSK: psk, Random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	first, err := left.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := right.ReadMessage(first); err != nil || len(payload) != 0 {
		t.Fatal(err)
	}
	second, err := right.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	if payload, err := left.ReadMessage(second); err != nil || len(payload) != 0 {
		t.Fatal(err)
	}
	return left, right
}

func sha256Bytes(value string) ([32]byte, error) { return sha256.Sum256([]byte(value)), nil }

func preparedProtocols(t *testing.T, mutualFire bool) (*Protocol, *Protocol, hardnatplan.Plan, hardnatplan.Plan, hardnatplan.JointPlanCommitment, [32]byte) {
	t.Helper()
	attempt := sha256.Sum256([]byte("prepared-attempt"))
	leftSource := compactPredictive(t, hardnatplan.RoleInitiator, attempt, 51000, "prepared-left")
	rightSource := compactPredictive(t, hardnatplan.RoleResponder, attempt, 61000, "prepared-right")
	leftSession, rightSession := completeNoise(t)
	leftPackets, leftPlanner, _ := leftSession.TakePacketCipherAndPlannerKeySource(MaxSequence)
	rightPackets, rightPlanner, _ := rightSession.TakePacketCipherAndPlannerKeySource(MaxSequence)
	t.Cleanup(leftPlanner.Close)
	t.Cleanup(rightPlanner.Close)
	bilateral, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{First: leftSource, Second: rightSource, KeySource: NoisePlannerKeySource{leftPlanner}})
	if err != nil {
		t.Fatal(err)
	}
	check, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{First: rightSource, Second: leftSource, KeySource: NoisePlannerKeySource{rightPlanner}})
	if err != nil || check.JointDigest != bilateral.JointDigest {
		t.Fatal("bilateral mismatch")
	}
	leftPlan, _ := bilateral.PlanForRole(hardnatplan.RoleInitiator)
	rightPlan, _ := bilateral.PlanForRole(hardnatplan.RoleResponder)
	joint := bilateral.Commitment()
	envelope, _ := hardnatbudget.For(hardnatplan.ProfilePredictiveEdm, hardnatplan.ResourcePredictive)
	envelopeDigest, _ := hardnatbudget.Digest(envelope)
	binding := Binding{AttemptID: "AAECAwQFBgcICQoLDA0ODw", ContextDigest: sha256.Sum256([]byte("context")), HandshakeHash: sha256.Sum256([]byte("handshake")), Generation: 1, Profile: hardnatplan.ProfilePredictiveEdm, ResourceClass: hardnatplan.ResourcePredictive, EnvelopeDigest: envelopeDigest}
	left, _ := NewProtocol(RoleInitiator, hardnatplan.RoleInitiator, binding, leftPackets)
	right, _ := NewProtocol(RoleResponder, hardnatplan.RoleResponder, binding, rightPackets)
	frame, _ := left.SealPrepare()
	_, _ = right.Open(frame)
	frame, _ = right.SealPrepare()
	_, _ = left.Open(frame)
	leftPayload, _ := NewSourcePayload(leftSource, hardnatplan.Address4([4]byte{192, 0, 2, 31}))
	rightPayload, _ := NewSourcePayload(rightSource, hardnatplan.Address4([4]byte{192, 0, 2, 32}))
	frame, _ = left.SealSource(leftPayload)
	_, _ = right.Open(frame)
	frame, _ = right.SealSource(rightPayload)
	_, _ = left.Open(frame)
	execution, _ := BuildExecutionDigest(joint, envelopeDigest, ExecutionSource{CarrierRole: RoleInitiator, PlannerRole: leftPlan.Role, SourceDigest: leftSource.SourceDigest, PublicAddress: leftPayload.PublicAddress}, ExecutionSource{CarrierRole: RoleResponder, PlannerRole: rightPlan.Role, SourceDigest: rightSource.SourceDigest, PublicAddress: rightPayload.PublicAddress})
	if err := left.BindExecution(leftPlan, rightPlan, joint, execution); err != nil {
		t.Fatal(err)
	}
	if err := right.BindExecution(rightPlan, leftPlan, joint, execution); err != nil {
		t.Fatal(err)
	}
	frame, _ = left.SealReady()
	_, _ = right.Open(frame)
	frame, _ = right.SealReady()
	_, _ = left.Open(frame)
	frame, _ = left.SealFire()
	_, _ = right.Open(frame)
	if mutualFire {
		frame, _ = right.SealFire()
		_, _ = left.Open(frame)
	}
	return left, right, leftPlan, rightPlan, joint, execution
}

func preparedHardProtocols(t *testing.T) (*Protocol, *Protocol, hardnatplan.Plan, hardnatplan.Plan) {
	t.Helper()
	attempt := sha256.Sum256([]byte("prepared-hard-attempt"))
	compact := func(role hardnatplan.Role, label string) hardnatplan.LocalSourceCommitment {
		commitment, err := hardnatplan.ReconstructLocalCommitment(hardnatplan.CompactSourceInput{
			Profile: hardnatplan.ProfileHardBirthday, ResourceClass: hardnatplan.ResourceHard16KLab, Role: role,
			AttemptDigest: attempt, Generation: 1, EvidenceDigest: sha256.Sum256([]byte(label + "-evidence")),
			ValidationDigest: sha256.Sum256([]byte(label + "-validation")),
			ModelCoverage:    "samples=8;observers=2;alternate_port=true;universe=49152-65535",
		})
		if err != nil {
			t.Fatal(err)
		}
		return commitment
	}
	leftSource := compact(hardnatplan.RoleInitiator, "hard-left")
	rightSource := compact(hardnatplan.RoleResponder, "hard-right")
	leftSession, rightSession := completeNoise(t)
	leftPackets, leftPlanner, err := leftSession.TakePacketCipherAndPlannerKeySource(HardCampaignMaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	rightPackets, rightPlanner, err := rightSession.TakePacketCipherAndPlannerKeySource(HardCampaignMaxSequence)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(leftPlanner.Close)
	t.Cleanup(rightPlanner.Close)
	bilateral, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{First: leftSource, Second: rightSource, KeySource: NoisePlannerKeySource{leftPlanner}})
	if err != nil {
		t.Fatal(err)
	}
	peerBilateral, err := hardnatplan.BuildBilateralPlan(hardnatplan.BilateralPlannerInput{First: rightSource, Second: leftSource, KeySource: NoisePlannerKeySource{rightPlanner}})
	if err != nil || peerBilateral.JointDigest != bilateral.JointDigest {
		t.Fatal("hard bilateral mismatch")
	}
	leftPlan, _ := bilateral.PlanForRole(hardnatplan.RoleInitiator)
	rightPlan, _ := bilateral.PlanForRole(hardnatplan.RoleResponder)
	envelope, _ := hardnatbudget.For(hardnatplan.ProfileHardBirthday, hardnatplan.ResourceHard16KLab)
	envelopeDigest, _ := hardnatbudget.Digest(envelope)
	binding := Binding{AttemptID: "AAECAwQFBgcICQoLDA0ODw", ContextDigest: sha256.Sum256([]byte("hard-context")),
		HandshakeHash: sha256.Sum256([]byte("hard-handshake")), Generation: 1,
		Profile: hardnatplan.ProfileHardBirthday, ResourceClass: hardnatplan.ResourceHard16KLab, EnvelopeDigest: envelopeDigest}
	left, err := NewProtocol(RoleInitiator, hardnatplan.RoleInitiator, binding, leftPackets)
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewProtocol(RoleResponder, hardnatplan.RoleResponder, binding, rightPackets)
	if err != nil {
		left.Close()
		t.Fatal(err)
	}
	exchange := func(sender, receiver *Protocol, frame []byte) OpenedFrame {
		t.Helper()
		opened, err := receiver.Open(frame)
		if err != nil {
			t.Fatal(err)
		}
		return opened
	}
	frame, _ := left.SealPrepare()
	exchange(left, right, frame)
	frame, _ = right.SealPrepare()
	exchange(right, left, frame)
	leftPayload, _ := NewSourcePayload(leftSource, hardnatplan.Address4([4]byte{192, 0, 2, 41}))
	rightPayload, _ := NewSourcePayload(rightSource, hardnatplan.Address4([4]byte{192, 0, 2, 42}))
	frame, _ = left.SealSource(leftPayload)
	exchange(left, right, frame)
	frame, _ = right.SealSource(rightPayload)
	exchange(right, left, frame)
	joint := bilateral.Commitment()
	execution, err := BuildExecutionDigest(joint, envelopeDigest,
		ExecutionSource{CarrierRole: RoleInitiator, PlannerRole: leftPlan.Role, SourceDigest: leftSource.SourceDigest, PublicAddress: leftPayload.PublicAddress},
		ExecutionSource{CarrierRole: RoleResponder, PlannerRole: rightPlan.Role, SourceDigest: rightSource.SourceDigest, PublicAddress: rightPayload.PublicAddress})
	if err != nil {
		t.Fatal(err)
	}
	if err := left.BindExecution(leftPlan, rightPlan, joint, execution); err != nil {
		t.Fatal(err)
	}
	if err := right.BindExecution(rightPlan, leftPlan, joint, execution); err != nil {
		t.Fatal(err)
	}
	frame, _ = left.SealReadyFire()
	exchange(left, right, frame)
	frame, _ = right.SealReadyFire()
	exchange(right, left, frame)
	return left, right, leftPlan, rightPlan
}
