package natsim

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ResourceLimits is the scenario-declared peak envelope. Zero is a real zero,
// not an unspecified value.
type ResourceLimits struct {
	PacketConns   int
	Mappings      int
	QueuedPackets int
}

// Scenario defines one repeatable simulation. Execute must close every
// PacketConn it creates; the harness verifies teardown and then closes the
// Network defensively.
type Scenario struct {
	Name        string
	Repetitions int
	Network     Config
	Resources   ResourceLimits
	Execute     func(context.Context, *Network) error
}

// Report describes completed repetitions and the maximum peaks observed.
type Report struct {
	Name                 string
	CompletedRepetitions int
	PeakPacketConns      int
	PeakMappings         int
	PeakQueuedPackets    int
}

// ScenarioError identifies the first failed repetition. Repetitions are
// one-based for operator-facing diagnostics.
type ScenarioError struct {
	Name       string
	Repetition int
	Cause      error
}

func (scenarioError *ScenarioError) Error() string {
	if scenarioError == nil {
		return ErrScenarioFailed.Error()
	}
	return fmt.Sprintf("%s: %s repetition %d: %v", ErrScenarioFailed, scenarioError.Name, scenarioError.Repetition, scenarioError.Cause)
}

func (scenarioError *ScenarioError) Unwrap() []error {
	if scenarioError == nil || scenarioError.Cause == nil {
		return []error{ErrScenarioFailed}
	}
	return []error{ErrScenarioFailed, scenarioError.Cause}
}

// RunScenario repeats a scenario, stops at the first failure, and verifies both
// peak resource declarations and zero live resources before cleanup.
func RunScenario(ctx context.Context, scenario Scenario) (Report, error) {
	report := Report{Name: scenario.Name}
	if ctx == nil {
		return report, &ScenarioError{Name: scenario.Name, Cause: fmt.Errorf("%w: context is nil", ErrInvalidConfig)}
	}
	if strings.TrimSpace(scenario.Name) == "" || strings.TrimSpace(scenario.Name) != scenario.Name || scenario.Repetitions < 1 || scenario.Execute == nil {
		return report, &ScenarioError{Name: scenario.Name, Cause: ErrInvalidConfig}
	}
	if scenario.Resources.PacketConns < 0 || scenario.Resources.Mappings < 0 || scenario.Resources.QueuedPackets < 0 {
		return report, &ScenarioError{Name: scenario.Name, Cause: ErrInvalidConfig}
	}

	for repetition := 1; repetition <= scenario.Repetitions; repetition++ {
		if err := ctx.Err(); err != nil {
			return report, &ScenarioError{Name: scenario.Name, Repetition: repetition, Cause: err}
		}
		network, err := NewNetwork(scenario.Network)
		if err != nil {
			return report, &ScenarioError{Name: scenario.Name, Repetition: repetition, Cause: err}
		}
		executeErr := scenario.Execute(ctx, network)
		beforeCleanup := network.Snapshot()
		cleanupErr := network.Close()
		afterCleanup := network.Snapshot()

		cause := errors.Join(
			executeErr,
			cleanupErr,
			validateResourcePeaks(beforeCleanup, scenario.Resources),
			validateZeroResources(beforeCleanup, "before harness cleanup"),
			validateZeroResources(afterCleanup, "after harness cleanup"),
		)
		if cause != nil {
			return report, &ScenarioError{Name: scenario.Name, Repetition: repetition, Cause: cause}
		}
		report.CompletedRepetitions++
		report.PeakPacketConns = max(report.PeakPacketConns, beforeCleanup.PeakPacketConns)
		report.PeakMappings = max(report.PeakMappings, beforeCleanup.PeakMappings)
		report.PeakQueuedPackets = max(report.PeakQueuedPackets, beforeCleanup.PeakQueuedPackets)
	}
	return report, nil
}

func validateResourcePeaks(counters Counters, limits ResourceLimits) error {
	if counters.PeakPacketConns > limits.PacketConns {
		return fmt.Errorf("%w: packet conns peak=%d limit=%d", ErrResourceLimit, counters.PeakPacketConns, limits.PacketConns)
	}
	if counters.PeakMappings > limits.Mappings {
		return fmt.Errorf("%w: mappings peak=%d limit=%d", ErrResourceLimit, counters.PeakMappings, limits.Mappings)
	}
	if counters.PeakQueuedPackets > limits.QueuedPackets {
		return fmt.Errorf("%w: queued packets peak=%d limit=%d", ErrResourceLimit, counters.PeakQueuedPackets, limits.QueuedPackets)
	}
	return nil
}

func validateZeroResources(counters Counters, phase string) error {
	if counters.ActivePacketConns == 0 && counters.ActiveMappings == 0 && counters.QueuedPackets == 0 {
		return nil
	}
	return fmt.Errorf(
		"%w: %s packet_conns=%d mappings=%d queued_packets=%d",
		ErrResourceLeak,
		phase,
		counters.ActivePacketConns,
		counters.ActiveMappings,
		counters.QueuedPackets,
	)
}
