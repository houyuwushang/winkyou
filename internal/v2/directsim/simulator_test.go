package directsim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"winkyou/internal/natsim"
)

func TestN2StageOrderBlindPunchAndFrozenExactCounters100Times(t *testing.T) {
	config := successfulConfig(t, natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, natsim.FilterAddressPortDependent, natsim.FilterAddressPortDependent)
	for repetition := 0; repetition < 100; repetition++ {
		report, err := Run(context.Background(), config)
		if err != nil {
			t.Fatalf("repetition %d: %v", repetition+1, err)
		}
		assertSuccessfulReport(t, report)
	}
}

func TestNATMappingFilteringMatrix100TimesEach(t *testing.T) {
	mappings := []natsim.MappingBehavior{natsim.MappingEndpointIndependent, natsim.MappingEndpointDependent}
	filters := []natsim.FilteringBehavior{natsim.FilterAddressDependent, natsim.FilterAddressPortDependent}
	successes := 0
	boundedFailures := 0
	for _, initiatorMapping := range mappings {
		for _, responderMapping := range mappings {
			for _, initiatorFilter := range filters {
				for _, responderFilter := range filters {
					name := string(initiatorMapping) + "_" + string(responderMapping) + "_" + string(initiatorFilter) + "_" + string(responderFilter)
					t.Run(name, func(t *testing.T) {
						expectSuccess := initiatorMapping == natsim.MappingEndpointIndependent && responderMapping == natsim.MappingEndpointIndependent
						config := successfulConfig(t, initiatorMapping, responderMapping, initiatorFilter, responderFilter)
						for repetition := 0; repetition < 100; repetition++ {
							report, err := Run(context.Background(), config)
							if expectSuccess {
								if err != nil {
									t.Fatalf("repetition %d: %v", repetition+1, err)
								}
								assertSuccessfulReport(t, report)
								successes++
							} else {
								if !errors.Is(err, ErrAttemptFailed) || report.Success {
									t.Fatalf("repetition %d report=%+v err=%v", repetition+1, report, err)
								}
								assertFailedAfterBurnIsBounded(t, report)
								boundedFailures++
							}
						}
					})
				}
			}
		}
	}
	t.Logf("matrix stats: success=%d bounded_failure=%d total=%d", successes, boundedFailures, successes+boundedFailures)
}

func TestDeliveryFaultMatrixHasNoRetryOrBudgetEscape(t *testing.T) {
	tests := []struct {
		fault       Fault
		wantSuccess bool
	}{
		{FaultDropSYN, true},
		{FaultReorderDirect, true},
		{FaultDropSYNACK, false},
		{FaultDropACK, false},
		{FaultDuplicateSYN, false},
		{FaultDuplicateSYNACK, false},
		{FaultDuplicateACK, false},
	}
	for _, test := range tests {
		t.Run(string(test.fault), func(t *testing.T) {
			initiatorFilter := natsim.FilterAddressPortDependent
			responderFilter := natsim.FilterAddressPortDependent
			if test.fault == FaultReorderDirect || test.fault == FaultDuplicateSYN {
				initiatorFilter = natsim.FilterEndpointIndependent
				responderFilter = natsim.FilterEndpointIndependent
			}
			config := successfulConfig(t, natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, initiatorFilter, responderFilter)
			config.Fault = test.fault
			report, err := Run(context.Background(), config)
			if test.wantSuccess {
				if err != nil {
					t.Fatal(err)
				}
				assertSuccessfulReport(t, report)
			} else {
				if !errors.Is(err, ErrAttemptFailed) || report.Success {
					t.Fatalf("report=%+v err=%v", report, err)
				}
				assertFailedAfterBurnIsBounded(t, report)
			}
			if report.Emissions.DirectInitiator > 2 || report.Emissions.DirectResponder > 1 {
				t.Fatalf("fault injected a retry: %+v", report.Emissions)
			}
		})
	}
}

func TestNegativeMatrixTerminatesWithoutOutOfEnvelopeEmissionOrRefund(t *testing.T) {
	faults := []Fault{
		FaultDuplicateControl, FaultReplayControl, FaultWrongRole,
		FaultWrongGeneration, FaultWrongContext, FaultNonCanonicalReady,
		FaultCrossADDomain, FaultOversizeControl, FaultAuthentication,
		FaultCancelBeforeBurn, FaultCancelAfterHandshake, FaultCancelAfterFire,
	}
	for _, fault := range faults {
		t.Run(string(fault), func(t *testing.T) {
			config := successfulConfig(t, natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, natsim.FilterAddressPortDependent, natsim.FilterAddressPortDependent)
			config.Fault = fault
			report, err := Run(context.Background(), config)
			if !errors.Is(err, ErrAttemptFailed) || report.Success {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			if !report.WithinFrozenCost() || report.Refunds != 0 || !zeroResidual(report.NetworkResidual) {
				t.Fatalf("negative case escaped envelope: %+v", report)
			}
			if fault == FaultWrongGeneration || fault == FaultCancelBeforeBurn {
				if report.BurnedInitiator || report.BurnedResponder || report.Emissions != (Emissions{}) {
					t.Fatalf("pre-burn rejection emitted or burned: %+v", report)
				}
			} else if !report.BurnedInitiator || !report.BurnedResponder {
				t.Fatalf("post-burn failure refunded admission: %+v", report)
			}
		})
	}
}

func TestCancelAfterSuccessIsRejectedWithoutEmission(t *testing.T) {
	config := successfulConfig(t, natsim.MappingEndpointIndependent, natsim.MappingEndpointIndependent, natsim.FilterAddressPortDependent, natsim.FilterAddressPortDependent)
	config.Fault = FaultCancelAfterTerminal
	report, err := Run(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	assertSuccessfulReport(t, report)
	if !report.PostTerminalCancelRejected || report.Emissions.Cancel != 0 {
		t.Fatalf("post-terminal cancel = %+v", report)
	}
}

func TestFrozenWorstCaseIsExactAndOnlyLowerable(t *testing.T) {
	want := Cost{
		RendezvousConnections: 1, RendezvousTargets: 1, DNSResolutions: 1,
		UDPSocketsPerEndpoint: 1, UDPTargetsPerEndpoint: 2, STUNPacketsPerEndpoint: 3,
		DirectPacketsInitiator: 2, DirectPacketsResponder: 1,
		UDPOutboundInitiator: 5, UDPOutboundResponder: 4,
		ControlInitiator: 4, ControlResponder: 3, GlobalCancel: 1,
		HandshakePerDirection: 1, AttemptEnvelope: 15 * time.Second,
		PresenceEnvelope: 3 * time.Second, Retries: 0,
	}
	if got := FrozenWorstCase(); got != want {
		t.Fatalf("frozen cost = %+v, want %+v", got, want)
	}
	copy := FrozenWorstCase()
	copy.DirectPacketsInitiator = 999
	if FrozenWorstCase() != want {
		t.Fatal("caller mutated the compiled frozen cost")
	}
	stages := SuccessfulStages()
	stages[0] = StageTerminal
	if SuccessfulStages()[0] != StagePresence {
		t.Fatal("caller mutated the frozen successful stage order")
	}
}

func successfulConfig(t testing.TB, initiatorMapping, responderMapping natsim.MappingBehavior, initiatorFilter, responderFilter natsim.FilteringBehavior) Config {
	t.Helper()
	payload, err := os.ReadFile("../directattempt/testdata/direct_attempt.synthetic.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ArtifactJSON string `json:"artifact_json"`
	}
	if err := json.Unmarshal(bytes.ReplaceAll(payload, []byte("\r\n"), []byte("\n")), &fixture); err != nil {
		t.Fatal(err)
	}
	initiatorArtifact := []byte(fixture.ArtifactJSON)
	responderArtifact := []byte(strings.Replace(fixture.ArtifactJSON, `"local_role":"initiator"`, `"local_role":"responder"`, 1))
	if bytes.Equal(initiatorArtifact, responderArtifact) {
		t.Fatal("failed to derive responder artifact")
	}
	return Config{
		InitiatorArtifact: initiatorArtifact,
		ResponderArtifact: responderArtifact,
		Now:               time.Date(2026, 8, 24, 9, 10, 12, 0, time.UTC),
		InitiatorNAT:      testModel(initiatorMapping, initiatorFilter, 41000, 1),
		ResponderNAT:      testModel(responderMapping, responderFilter, 42000, 2),
	}
}

func testModel(mapping natsim.MappingBehavior, filtering natsim.FilteringBehavior, portMin int, seed uint64) natsim.Model {
	return natsim.Model{
		Mapping: mapping, Allocation: natsim.PortIncrement, Filtering: filtering,
		PortMin: portMin, PortMax: portMin + 99, RandomSeed: seed,
	}
}

func assertSuccessfulReport(t testing.TB, report Report) {
	t.Helper()
	if !report.Success || report.Cancelled || !report.BurnedInitiator || !report.BurnedResponder || report.Refunds != 0 ||
		!report.BlindSYNACKBeforeSYNReceive || !report.SameSocketSTUNAndPunch ||
		!reflect.DeepEqual(report.Stages, SuccessfulStages()) || !report.WithinFrozenCost() {
		t.Fatalf("successful report = %+v", report)
	}
	want := Emissions{
		HandshakeInitiator: 1, HandshakeResponder: 1,
		ControlInitiator: 4, ControlResponder: 3,
		STUNInitiator: 1, STUNResponder: 1,
		DirectInitiator: 2, DirectResponder: 1,
	}
	if report.Emissions != want || !zeroResidual(report.NetworkResidual) {
		t.Fatalf("successful resources = emissions=%+v residual=%+v", report.Emissions, report.NetworkResidual)
	}
	wantResources := Resources{SocketsInitiator: 1, SocketsResponder: 1, TargetsInitiator: 2, TargetsResponder: 2, FiveTuplesInitiator: 2, FiveTuplesResponder: 2}
	if report.Resources != wantResources {
		t.Fatalf("successful resources = %+v, want %+v", report.Resources, wantResources)
	}
}

func assertFailedAfterBurnIsBounded(t testing.TB, report Report) {
	t.Helper()
	if report.Success || !report.BurnedInitiator || !report.BurnedResponder || report.Refunds != 0 || !report.WithinFrozenCost() ||
		len(report.Stages) == 0 || report.Stages[len(report.Stages)-1] != StageTerminal || !zeroResidual(report.NetworkResidual) {
		t.Fatalf("failed report is not bounded: %+v", report)
	}
}

func zeroResidual(counters natsim.Counters) bool {
	return counters.ActivePacketConns == 0 && counters.ActiveMappings == 0 && counters.QueuedPackets == 0
}
