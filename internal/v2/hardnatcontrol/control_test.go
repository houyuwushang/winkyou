package hardnatcontrol

import (
	"bytes"
	"crypto/sha256"
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
	left, right, leftPlan, _, _, _ := preparedProtocols(t)
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
	left2, right2, leftPlan2, _, _, _ := preparedProtocols(t)
	defer left2.Close()
	defer right2.Close()
	frame, _ = left2.SealCandidate(leftPlan2.Candidates[0])
	frame[5] = byte(DomainRendezvousControl)
	if _, err := right2.Open(frame); !errors.Is(err, ErrInvalidFrame) {
		t.Fatalf("cross-domain mutation = %v", err)
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

func preparedProtocols(t *testing.T) (*Protocol, *Protocol, hardnatplan.Plan, hardnatplan.Plan, hardnatplan.JointPlanCommitment, [32]byte) {
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
	return left, right, leftPlan, rightPlan, joint, execution
}
