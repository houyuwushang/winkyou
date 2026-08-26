package hardnatplan

import (
	"errors"
	"slices"
	"testing"
)

func TestEvidenceGraphDeterministicallyInfersAllocationModels(t *testing.T) {
	tests := []struct {
		name       string
		ports      []uint16
		allocation AllocationBehavior
		minimum    uint16
		maximum    uint16
		predicted  uint16
		window     int
		residual   uint32
	}{
		{name: "sequential uniform", ports: sequentialPorts(50000, 8, 1), allocation: AllocationSequentialUniform, minimum: 1, maximum: 1, predicted: 50008, window: 32, residual: 32},
		{name: "low dispersion monotonic", ports: []uint16{50000, 50002, 50005, 50007, 50010, 50012, 50015, 50017}, allocation: AllocationMonotonicNonuniform, minimum: 2, maximum: 3, predicted: 50019, window: 32, residual: 32},
		{name: "apparently random", ports: apparentlyRandomPorts(), allocation: AllocationApparentlyRandom, minimum: 1117, maximum: 63721, predicted: 5940, window: 0, residual: 65535},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := syntheticEvidence(MappingAPDM, FilteringAPDF, test.ports)
			model, err := InferStateModel(graph)
			if err != nil {
				t.Fatalf("infer model: %v", err)
			}
			if model.Mapping != MappingAPDM || model.Filtering != FilteringAPDF || model.Allocation != test.allocation ||
				model.MinimumDelta != test.minimum || model.MaximumDelta != test.maximum || model.PredictedNextPort != test.predicted ||
				len(model.CandidateWindow) != test.window || !model.PublicAddressStable || model.SuccessfulSamples != len(test.ports) ||
				model.ObserverAddressCount != 2 || !model.HasAlternatePort || model.FailedSamples != 0 || model.ResidualUniverse != test.residual ||
				model.AllocationLimitation == "" {
				t.Fatalf("model = %+v", model)
			}
			for _, port := range model.CandidateWindow {
				if port == 0 {
					t.Fatal("predictive window contains port zero")
				}
			}
		})
	}
}

func TestEvidenceBindsObserverSetSocketOwnerAndFailureTotals(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	failure := graph.Allocation[0]
	failure.Meta = evidenceMeta(graph, 220, SourceLocalTomography, OriginLocalTransaction, syntheticAddress(11).Address(), 3478)
	failure.Ordinal = 8
	failure.Success = false
	failure.MappedAddress = Address{}
	failure.MappedPort = 0
	graph.Allocation = append(graph.Allocation, failure)
	model, err := InferStateModel(graph)
	if err != nil || model.SuccessfulSamples != 8 || model.FailedSamples != 1 || model.ResidualUniverse != 32 {
		t.Fatalf("bound failure model/error = %+v/%v", model, err)
	}
	graph.Allocation = append(graph.Allocation, failure)
	deduplicated, err := InferStateModel(graph)
	if err != nil || deduplicated.FailedSamples != 1 {
		t.Fatalf("duplicate failure model/error = %+v/%v", deduplicated, err)
	}
	conflicting := failure
	conflicting.SocketSlot++
	graph.Allocation = append(graph.Allocation, conflicting)
	if _, err := InferStateModel(graph); !errors.Is(err, ErrEvidenceInsufficient) {
		t.Fatalf("conflicting transaction error = %v", err)
	}
	graph.Allocation = graph.Allocation[:len(graph.Allocation)-1]

	for name, mutate := range map[string]func(*EvidenceGraph){
		"observer set": func(value *EvidenceGraph) { value.ObservationSetDigest = [32]byte{} },
		"socket owner": func(value *EvidenceGraph) { value.SocketOwnerDigest = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := graph
			mutate(&mutated)
			failed, err := InferStateModel(mutated)
			if !errors.Is(err, ErrInvalidEvidence) || len(failed.CandidateWindow) != 0 {
				t.Fatalf("unbound graph model/error = %+v/%v", failed, err)
			}
		})
	}
}

func TestEvidenceBelowEightOrDriftedFailsWithNoWindow(t *testing.T) {
	t.Run("below threshold", func(t *testing.T) {
		model, err := InferStateModel(syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 7, 1)))
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.CandidateWindow) != 0 || model.Allocation != AllocationInsufficientData {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})

	t.Run("mapping drift", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		graph.Mapping = append(graph.Mapping, MappingEvidence{
			Meta: evidenceMeta(graph, 203, SourcePeerReflector, OriginLocalTransaction, syntheticAddress(11).Address(), 3478), Behavior: MappingEIM,
		})
		model, err := InferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.CandidateWindow) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})

	t.Run("public address drift", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		graph.Allocation[7].MappedAddress = syntheticAddress(201).Address()
		model, err := InferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.CandidateWindow) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
}

func TestRemoteReportsAreUntrustedAndCannotChangeActionableModel(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	baseline, err := InferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	remote := graph.Allocation[0]
	remote.Meta = evidenceMeta(graph, 210, SourcePeerReflector, OriginRemoteReport, syntheticAddress(99).Address(), 9999)
	remote.MappedPort = 1
	remote.MappedAddress = syntheticAddress(99).Address()
	graph.Allocation = append(graph.Allocation, remote)
	graph.Mapping = append(graph.Mapping, MappingEvidence{Meta: remote.Meta, Behavior: MappingEIM})
	withRemote, err := InferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.Mapping != withRemote.Mapping || baseline.Allocation != withRemote.Allocation ||
		!slices.Equal(baseline.CandidateWindow, withRemote.CandidateWindow) || baseline.EvidenceDigest != withRemote.EvidenceDigest {
		t.Fatalf("remote report changed actionable model\nbaseline=%+v\nremote=%+v", baseline, withRemote)
	}
	if baseline.RawEvidenceDigest == withRemote.RawEvidenceDigest {
		t.Fatal("raw evidence digest did not witness added remote report")
	}
}

func TestEvidenceSourceStrengthAndPoolingAreMergedIndependently(t *testing.T) {
	graph := syntheticEvidence(MappingADM, FilteringADF, sequentialPorts(50000, 8, 1))
	graph.Mapping = append(graph.Mapping,
		MappingEvidence{Meta: evidenceMeta(graph, 211, SourcePeerReflector, OriginLocalTransaction, syntheticAddress(11).Address(), 3478), Behavior: MappingADM},
		MappingEvidence{Meta: evidenceMeta(graph, 212, SourceAuthorizedGateway, OriginLocalTransaction, syntheticAddress(12).Address(), 3478), Behavior: MappingADM},
	)
	model, err := InferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	if model.Mapping != MappingADM || model.MappingSource != SourceAuthorizedGateway || model.Filtering != FilteringADF || model.FilteringSource != SourceRFC5780 {
		t.Fatalf("source-ranked model = %+v", model)
	}

	drifted := graph
	drifted.IPPooling = append([]IPPoolingEvidence(nil), graph.IPPooling...)
	drifted.IPPooling = append(drifted.IPPooling, IPPoolingEvidence{
		Meta:   evidenceMeta(drifted, 213, SourcePeerReflector, OriginLocalTransaction, syntheticAddress(11).Address(), 3478),
		Stable: false, PoolDigest: syntheticDigest("different-pool"),
	})
	driftedModel, err := InferStateModel(drifted)
	if !errors.Is(err, ErrEvidenceInsufficient) || len(driftedModel.CandidateWindow) != 0 {
		t.Fatalf("pooling drift model/error = %+v/%v", driftedModel, err)
	}
}

func TestEvidenceOrderAndCloneOwnershipAreDeterministic(t *testing.T) {
	graph := syntheticEvidence(MappingADM, FilteringADF, sequentialPorts(65530, 8, 1))
	first, err := InferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(graph.Mapping)
	slices.Reverse(graph.Filtering)
	slices.Reverse(graph.IPPooling)
	slices.Reverse(graph.Allocation)
	second, err := InferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	if first.EvidenceDigest != second.EvidenceDigest || first.RawEvidenceDigest != second.RawEvidenceDigest ||
		!slices.Equal(first.CandidateWindow, second.CandidateWindow) {
		t.Fatalf("reordered graph changed result\nfirst=%+v\nsecond=%+v", first, second)
	}
	clone := first.Clone()
	clone.CandidateWindow[0] = 1
	if first.CandidateWindow[0] == 1 {
		t.Fatal("StateModel.Clone shares candidate-window ownership")
	}
}

func TestReplayDuplicateAndQuorumOnlyReduceEvidence(t *testing.T) {
	t.Run("cross attempt replay", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		graph.Allocation[7].Meta.AttemptDigest = syntheticDigest("other-attempt")
		model, err := InferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || model.SuccessfulSamples != 7 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})

	t.Run("duplicate observer address lacks quorum", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		for index := range graph.Allocation {
			graph.Allocation[index].Meta.ObserverAddress = syntheticAddress(10).Address()
			graph.Allocation[index].Meta.ObserverPort = 3478
		}
		model, err := InferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || model.ObserverAddressCount != 1 || model.HasAlternatePort {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
}
