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
		schedule   int
		residual   uint32
	}{
		{name: "sequential uniform", ports: sequentialPorts(50000, 8, 1), allocation: AllocationSequentialUniform, minimum: 1, maximum: 1, predicted: 50008, schedule: 32, residual: 32},
		{name: "low dispersion monotonic", ports: []uint16{50000, 50002, 50005, 50007, 50010, 50012, 50015, 50017}, allocation: AllocationMonotonicNonuniform, minimum: 2, maximum: 3, predicted: 50019, schedule: 32, residual: 32},
		{name: "apparently random", ports: apparentlyRandomPorts(), allocation: AllocationApparentlyRandom, minimum: 1117, maximum: 63721, predicted: 5940, schedule: 0, residual: 65535},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			graph := syntheticEvidence(MappingAPDM, FilteringAPDF, test.ports)
			model, err := inferStateModel(graph)
			if err != nil {
				t.Fatalf("infer model: %v", err)
			}
			if model.Mapping != MappingAPDM || model.Filtering != FilteringAPDF || model.Allocation != test.allocation ||
				model.MinimumDelta != test.minimum || model.MaximumDelta != test.maximum || model.PredictedNextPort != test.predicted ||
				len(model.PredictedSourcePorts) != test.schedule || !model.PublicAddressStable || model.SuccessfulSamples != len(test.ports) ||
				model.ObserverAddressCount != 2 || !model.HasAlternatePort || model.FailedSamples != 0 || model.ResidualUniverse != test.residual ||
				model.AllocationLimitation == "" || allZero(model.ValidationDigest[:]) {
				t.Fatalf("model = %+v", model)
			}
			if test.schedule > 0 && model.PredictedSourcePorts[0] != test.predicted {
				t.Fatalf("first predicted source = %d, want %d", model.PredictedSourcePorts[0], test.predicted)
			}
			for _, port := range model.PredictedSourcePorts {
				if port == 0 {
					t.Fatal("predicted source schedule contains port zero")
				}
			}
		})
	}
}

func TestTrustedValidationBindsHeaderFreshnessAndIssuedManifest(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	trusted := trustedValidation(graph)
	baseline, err := InferStateModel(graph, trusted)
	if err != nil {
		t.Fatal(err)
	}
	later := trusted
	later.NowMilli++
	laterModel, err := InferStateModel(graph, later)
	if err != nil || laterModel.EvidenceDigest != baseline.EvidenceDigest || laterModel.ValidationDigest != baseline.ValidationDigest {
		t.Fatalf("evaluation clock changed actionable digest: %+v/%v", laterModel, err)
	}

	for name, mutate := range map[string]func(*EvidenceGraph){
		"machine scope": func(value *EvidenceGraph) { value.MachineScopeDigest = syntheticDigest("foreign-machine") },
		"socket owner":  func(value *EvidenceGraph) { value.SocketOwnerDigest = syntheticDigest("foreign-socket") },
		"peer":          func(value *EvidenceGraph) { value.PeerDigest = syntheticDigest("foreign-peer") },
		"attempt":       func(value *EvidenceGraph) { value.AttemptDigest = syntheticDigest("foreign-attempt") },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := graph
			mutate(&mutated)
			model, err := InferStateModel(mutated, trusted)
			if !errors.Is(err, ErrInvalidEvidence) || len(model.PredictedSourcePorts) != 0 {
				t.Fatalf("model/error = %+v/%v", model, err)
			}
		})
	}

	t.Run("stale evaluation", func(t *testing.T) {
		stale := trusted
		stale.NowMilli = graph.FinishedAtMilli + MaxEvidenceAgeMillis + 1
		model, err := InferStateModel(graph, stale)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
	t.Run("evaluation before acquisition finished", func(t *testing.T) {
		future := trusted
		future.NowMilli = graph.FinishedAtMilli - 1
		model, err := InferStateModel(graph, future)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
	t.Run("acquisition window exceeds bound", func(t *testing.T) {
		longWindow := graph
		longWindow.FinishedAtMilli = longWindow.StartedAtMilli + MaxEvidenceWindowMillis + 1
		longWindow.ExpiresAtMilli = longWindow.FinishedAtMilli + 1_000
		longTrusted := trustedValidation(longWindow)
		model, err := InferStateModel(longWindow, longTrusted)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
	t.Run("manifest missing issued transaction", func(t *testing.T) {
		missing := trusted
		missing.Issued = append([]IssuedTransaction(nil), trusted.Issued[:len(trusted.Issued)-1]...)
		model, err := InferStateModel(graph, missing)
		if !errors.Is(err, ErrInvalidEvidence) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
	t.Run("issued response missing from graph", func(t *testing.T) {
		missing := graph
		missing.Allocation = append([]AllocationSample(nil), graph.Allocation[:len(graph.Allocation)-1]...)
		model, err := InferStateModel(missing, trusted)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})

	for name, mutate := range map[string]func(*EvidenceGraph){
		"unissued transaction":  func(value *EvidenceGraph) { value.Allocation[7].Meta.TransactionID = TransactionID{0xff} },
		"wrong destination":     func(value *EvidenceGraph) { value.Allocation[7].Meta.ObserverPort++ },
		"wrong observed socket": func(value *EvidenceGraph) { value.Allocation[7].Meta.SocketSlot++ },
		"wrong sample socket":   func(value *EvidenceGraph) { value.Allocation[7].SocketSlot++ },
		"wrong ordinal":         func(value *EvidenceGraph) { value.Allocation[7].Ordinal++ },
	} {
		t.Run(name, func(t *testing.T) {
			mutated := graph
			mutated.Allocation = append([]AllocationSample(nil), graph.Allocation...)
			mutate(&mutated)
			model, err := InferStateModel(mutated, trusted)
			if !errors.Is(err, ErrInvalidEvidence) || len(model.PredictedSourcePorts) != 0 {
				t.Fatalf("model/error = %+v/%v", model, err)
			}
		})
	}
}

func TestAllocationRequiresContinuousSuccessfulSuffix(t *testing.T) {
	t.Run("sparse ordinals", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		for index := range graph.Allocation {
			graph.Allocation[index].Ordinal = uint32(index * 100)
		}
		model, err := inferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})

	t.Run("latest failure invalidates older successes", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		failure := graph.Allocation[0]
		failure.Meta = evidenceMeta(graph, 220, SourceLocalTomography, OriginLocalTransaction, syntheticAddress(11).Address(), 3478)
		failure.Ordinal = 8
		failure.SocketSlot = 8
		failure.Meta.SocketSlot = failure.SocketSlot
		failure.Success = false
		failure.MappedAddress = Address{}
		failure.MappedPort = 0
		graph.Allocation = append(graph.Allocation, failure)
		model, err := inferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})

	t.Run("failure before eight-success suffix is diagnostic only", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		for index := range graph.Allocation {
			graph.Allocation[index].Ordinal++
		}
		failure := graph.Allocation[0]
		failure.Meta = evidenceMeta(graph, 220, SourceLocalTomography, OriginLocalTransaction, syntheticAddress(11).Address(), 3478)
		failure.Ordinal = 0
		failure.SocketSlot = 0
		failure.Meta.SocketSlot = failure.SocketSlot
		failure.Success = false
		failure.MappedAddress = Address{}
		failure.MappedPort = 0
		graph.Allocation = append(graph.Allocation, failure)
		model, err := inferStateModel(graph)
		if err != nil || model.SuccessfulSamples != 8 || model.FailedSamples != 1 || len(model.PredictedSourcePorts) != 32 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
}

func TestRemoteReportsAndExactReplayDoNotChangeActionableInputs(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	baseline, err := inferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	baselineCommitment, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, graph))
	if err != nil {
		t.Fatal(err)
	}

	remote := graph.Allocation[0]
	remote.Meta = evidenceMeta(graph, 210, SourcePeerReflector, OriginRemoteReport, syntheticAddress(99).Address(), 9999)
	remote.MappedPort = 1
	remote.MappedAddress = syntheticAddress(99).Address()
	withDiagnostics := graph
	withDiagnostics.Allocation = append(append([]AllocationSample(nil), graph.Allocation...), remote)
	withDiagnostics.Mapping = append(append([]MappingEvidence(nil), graph.Mapping...), MappingEvidence{Meta: remote.Meta, Behavior: MappingEIM})
	withRemote, err := inferStateModel(withDiagnostics)
	if err != nil {
		t.Fatal(err)
	}
	remoteCommitment, err := BuildLocalCommitment(localCommitmentInput(ProfilePredictiveEdm, ResourcePredictive, RoleInitiator, withDiagnostics))
	if err != nil {
		t.Fatal(err)
	}
	if baseline.EvidenceDigest != withRemote.EvidenceDigest || baseline.ValidationDigest != withRemote.ValidationDigest ||
		!slices.Equal(baseline.PredictedSourcePorts, withRemote.PredictedSourcePorts) || baselineCommitment.SourceDigest != remoteCommitment.SourceDigest {
		t.Fatal("remote diagnostics changed actionable model or source commitment")
	}
	if baseline.RawEvidenceDigest == withRemote.RawEvidenceDigest {
		t.Fatal("raw evidence digest did not witness remote diagnostics")
	}

	replayedGraph := graph
	replayedGraph.RFC5780 = append(append([]RFC5780Transcript(nil), graph.RFC5780...), graph.RFC5780[0].Clone())
	replayed, err := inferStateModel(replayedGraph)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.EvidenceDigest != baseline.EvidenceDigest || replayed.RawEvidenceDigest == baseline.RawEvidenceDigest {
		t.Fatal("exact replay changed actionable digest or escaped raw witness")
	}
}

func TestConflictingReplayFailsClosedBeforeDigest(t *testing.T) {
	graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
	trusted := trustedValidation(graph)
	conflict := graph.Allocation[7]
	conflict.MappedPort++
	graph.Allocation = append(graph.Allocation, conflict)
	model, err := InferStateModel(graph, trusted)
	if !errors.Is(err, ErrEvidenceInsufficient) || !allZero(model.EvidenceDigest[:]) || len(model.PredictedSourcePorts) != 0 {
		t.Fatalf("model/error = %+v/%v", model, err)
	}
}

func TestEvidenceSourceStrengthPoolingOrderAndClone(t *testing.T) {
	graph := syntheticEvidence(MappingADM, FilteringADF, sequentialPorts(65530, 8, 1))
	graph.Mapping = append(graph.Mapping,
		MappingEvidence{Meta: evidenceMeta(graph, 211, SourcePeerReflector, OriginLocalTransaction, syntheticAddress(11).Address(), 3478), Behavior: MappingADM},
		MappingEvidence{Meta: evidenceMeta(graph, 212, SourceAuthorizedGateway, OriginLocalTransaction, syntheticAddress(12).Address(), 3478), Behavior: MappingADM},
	)
	first, err := inferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	if first.MappingSource != SourceAuthorizedGateway || first.FilteringSource != SourceRFC5780 {
		t.Fatalf("source-ranked model = %+v", first)
	}
	slices.Reverse(graph.Mapping)
	slices.Reverse(graph.Filtering)
	slices.Reverse(graph.IPPooling)
	slices.Reverse(graph.Allocation)
	slices.Reverse(graph.RFC5780)
	second, err := inferStateModel(graph)
	if err != nil {
		t.Fatal(err)
	}
	if first.EvidenceDigest != second.EvidenceDigest || first.RawEvidenceDigest != second.RawEvidenceDigest ||
		!slices.Equal(first.PredictedSourcePorts, second.PredictedSourcePorts) {
		t.Fatal("evidence order changed deterministic result")
	}
	clone := first.Clone()
	clone.PredictedSourcePorts[0] = 1
	if first.PredictedSourcePorts[0] == 1 {
		t.Fatal("StateModel.Clone shares predicted-source ownership")
	}
}

func TestEvidenceDriftAndCoverageFailClosed(t *testing.T) {
	t.Run("mapping drift", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		graph.Mapping = append(graph.Mapping, MappingEvidence{
			Meta: evidenceMeta(graph, 203, SourcePeerReflector, OriginLocalTransaction, syntheticAddress(11).Address(), 3478), Behavior: MappingEIM,
		})
		model, err := inferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
	t.Run("public address drift", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		graph.Allocation[7].MappedAddress = syntheticAddress(201).Address()
		model, err := inferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || len(model.PredictedSourcePorts) != 0 {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
	t.Run("observer quorum", func(t *testing.T) {
		graph := syntheticEvidence(MappingAPDM, FilteringAPDF, sequentialPorts(50000, 8, 1))
		for index := range graph.Allocation {
			graph.Allocation[index].Meta.ObserverAddress = syntheticAddress(10).Address()
			graph.Allocation[index].Meta.ObserverPort = 3478
		}
		model, err := inferStateModel(graph)
		if !errors.Is(err, ErrEvidenceInsufficient) || model.ObserverAddressCount != 1 || model.HasAlternatePort {
			t.Fatalf("model/error = %+v/%v", model, err)
		}
	})
}
