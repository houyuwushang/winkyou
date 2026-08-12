package governor

import (
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidLimits = errors.New("invalid governor limits")
	ErrLimitExceeded = errors.New("governor limit exceeded")
	ErrNotAllowed    = errors.New("operation is not allowed by governor profile")
)

// Profile is a compiled release policy. Configuration may lower its limits but
// cannot create a more capable profile.
type Profile string

const (
	ProfilePhase1Machine          Profile = "phase1_machine"
	ProfilePhase1UserAcknowledged Profile = "phase1_user_acknowledged"
)

func (p Profile) Scope() (Scope, error) {
	switch p {
	case ProfilePhase1Machine:
		return ScopeMachine, nil
	case ProfilePhase1UserAcknowledged:
		return ScopeUserAcknowledged, nil
	default:
		return "", fmt.Errorf("%w: unknown profile %q", ErrInvalidLimits, p)
	}
}

// Operation identifies why an attempt wants active-network capability.
// Phase 1 profiles deliberately allow only diagnose and one-shot connect tests.
type Operation string

const (
	OperationDiagnose    Operation = "diagnose"
	OperationConnectTest Operation = "connect_test"
	OperationNodeRuntime Operation = "node_runtime"
	OperationRecovery    Operation = "recovery"
	OperationPortMapping Operation = "port_mapping"
	OperationPrediction  Operation = "prediction"
	OperationBirthday    Operation = "birthday"
)

func (p Profile) Allows(operation Operation) bool {
	switch p {
	case ProfilePhase1Machine, ProfilePhase1UserAcknowledged:
		return operation == OperationDiagnose || operation == OperationConnectTest
	default:
		return false
	}
}

// Resources is a worst-case active-attempt reservation. Counts describe
// concurrently reserved capacity, not observed best-case use.
type Resources struct {
	Sockets          int
	Targets          int
	PacketsPerSecond int
	Packets          int
	FiveTuples       int
}

func (r Resources) add(other Resources) Resources {
	return Resources{
		Sockets:          r.Sockets + other.Sockets,
		Targets:          r.Targets + other.Targets,
		PacketsPerSecond: r.PacketsPerSecond + other.PacketsPerSecond,
		Packets:          r.Packets + other.Packets,
		FiveTuples:       r.FiveTuples + other.FiveTuples,
	}
}

func (r Resources) subtract(other Resources) Resources {
	return Resources{
		Sockets:          r.Sockets - other.Sockets,
		Targets:          r.Targets - other.Targets,
		PacketsPerSecond: r.PacketsPerSecond - other.PacketsPerSecond,
		Packets:          r.Packets - other.Packets,
		FiveTuples:       r.FiveTuples - other.FiveTuples,
	}
}

func (r Resources) validateNonNegative() error {
	switch {
	case r.Sockets < 0:
		return fmt.Errorf("%w: sockets must be non-negative", ErrInvalidLimits)
	case r.Targets < 0:
		return fmt.Errorf("%w: targets must be non-negative", ErrInvalidLimits)
	case r.PacketsPerSecond < 0:
		return fmt.Errorf("%w: packets per second must be non-negative", ErrInvalidLimits)
	case r.Packets < 0:
		return fmt.Errorf("%w: packets must be non-negative", ErrInvalidLimits)
	case r.FiveTuples < 0:
		return fmt.Errorf("%w: five-tuples must be non-negative", ErrInvalidLimits)
	default:
		return nil
	}
}

// Limits contains both aggregate reservations and per-attempt ceilings.
type Limits struct {
	MaxActivePeers           int
	MaxActiveAttempts        int
	MaxAttemptsPerPeer       int
	MaxHeavyweightAttempts   int
	MaxAttemptDuration       time.Duration
	CancellationDrainTimeout time.Duration
	Aggregate                Resources
	PerAttempt               Resources
}

// HardLimits returns the compiled Phase 1 ceiling for profile. These are
// intentionally conservative foundation values. Raising any value requires a
// code change and review; runtime configuration can only lower them.
func HardLimits(profile Profile) (Limits, error) {
	switch profile {
	case ProfilePhase1Machine:
		return Limits{
			MaxActivePeers:           20,
			MaxActiveAttempts:        8,
			MaxAttemptsPerPeer:       1,
			MaxHeavyweightAttempts:   1,
			MaxAttemptDuration:       60 * time.Second,
			CancellationDrainTimeout: 2 * time.Second,
			Aggregate: Resources{
				Sockets:          128,
				Targets:          512,
				PacketsPerSecond: 64,
				Packets:          4096,
				FiveTuples:       512,
			},
			PerAttempt: Resources{
				Sockets:          128,
				Targets:          512,
				PacketsPerSecond: 64,
				Packets:          512,
				FiveTuples:       512,
			},
		}, nil
	case ProfilePhase1UserAcknowledged:
		return Limits{
			MaxActivePeers:           1,
			MaxActiveAttempts:        1,
			MaxAttemptsPerPeer:       1,
			MaxHeavyweightAttempts:   0,
			MaxAttemptDuration:       15 * time.Second,
			CancellationDrainTimeout: time.Second,
			Aggregate: Resources{
				Sockets:          4,
				Targets:          8,
				PacketsPerSecond: 8,
				Packets:          64,
				FiveTuples:       8,
			},
			PerAttempt: Resources{
				Sockets:          4,
				Targets:          8,
				PacketsPerSecond: 8,
				Packets:          64,
				FiveTuples:       8,
			},
		}, nil
	default:
		return Limits{}, fmt.Errorf("%w: unknown profile %q", ErrInvalidLimits, profile)
	}
}

func validateLimits(limits Limits) error {
	if limits.MaxActivePeers <= 0 {
		return fmt.Errorf("%w: max active peers must be positive", ErrInvalidLimits)
	}
	if limits.MaxActiveAttempts <= 0 {
		return fmt.Errorf("%w: max active attempts must be positive", ErrInvalidLimits)
	}
	if limits.MaxAttemptsPerPeer <= 0 || limits.MaxAttemptsPerPeer > limits.MaxActiveAttempts {
		return fmt.Errorf("%w: max attempts per peer must be within active attempt capacity", ErrInvalidLimits)
	}
	if limits.MaxHeavyweightAttempts < 0 || limits.MaxHeavyweightAttempts > limits.MaxActiveAttempts {
		return fmt.Errorf("%w: invalid heavyweight attempt limit", ErrInvalidLimits)
	}
	if limits.MaxAttemptDuration <= 0 {
		return fmt.Errorf("%w: max attempt duration must be positive", ErrInvalidLimits)
	}
	if limits.CancellationDrainTimeout <= 0 {
		return fmt.Errorf("%w: cancellation drain timeout must be positive", ErrInvalidLimits)
	}
	if err := limits.Aggregate.validateNonNegative(); err != nil {
		return err
	}
	if err := limits.PerAttempt.validateNonNegative(); err != nil {
		return err
	}
	if field, current, maximum, exceeded := firstResourceExcess(limits.PerAttempt, limits.Aggregate); exceeded {
		return &LimitError{Field: "per_attempt_" + field, Requested: current, Maximum: maximum}
	}
	return nil
}

func validateNotRaised(requested, hard Limits) error {
	if err := validateLimits(requested); err != nil {
		return err
	}
	checks := []struct {
		field     string
		requested int64
		hard      int64
	}{
		{"max_active_peers", int64(requested.MaxActivePeers), int64(hard.MaxActivePeers)},
		{"max_active_attempts", int64(requested.MaxActiveAttempts), int64(hard.MaxActiveAttempts)},
		{"max_attempts_per_peer", int64(requested.MaxAttemptsPerPeer), int64(hard.MaxAttemptsPerPeer)},
		{"max_heavyweight_attempts", int64(requested.MaxHeavyweightAttempts), int64(hard.MaxHeavyweightAttempts)},
		{"max_attempt_duration_ns", int64(requested.MaxAttemptDuration), int64(hard.MaxAttemptDuration)},
		{"cancellation_drain_timeout_ns", int64(requested.CancellationDrainTimeout), int64(hard.CancellationDrainTimeout)},
	}
	for _, check := range checks {
		if check.requested > check.hard {
			return &LimitError{Field: check.field, Requested: check.requested, Maximum: check.hard}
		}
	}
	if field, current, maximum, exceeded := firstResourceExcess(requested.Aggregate, hard.Aggregate); exceeded {
		return &LimitError{Field: "aggregate_" + field, Requested: current, Maximum: maximum}
	}
	if field, current, maximum, exceeded := firstResourceExcess(requested.PerAttempt, hard.PerAttempt); exceeded {
		return &LimitError{Field: "per_attempt_" + field, Requested: current, Maximum: maximum}
	}
	return nil
}

func firstResourceExcess(current, maximum Resources) (string, int64, int64, bool) {
	checks := []struct {
		field   string
		current int
		maximum int
	}{
		{"sockets", current.Sockets, maximum.Sockets},
		{"targets", current.Targets, maximum.Targets},
		{"packets_per_second", current.PacketsPerSecond, maximum.PacketsPerSecond},
		{"packets", current.Packets, maximum.Packets},
		{"five_tuples", current.FiveTuples, maximum.FiveTuples},
	}
	for _, check := range checks {
		if check.current > check.maximum {
			return check.field, int64(check.current), int64(check.maximum), true
		}
	}
	return "", 0, 0, false
}

// LimitError identifies the first hard boundary rejected by an acquisition.
type LimitError struct {
	Field     string
	Requested int64
	Maximum   int64
}

func (e *LimitError) Error() string {
	if e == nil {
		return ErrLimitExceeded.Error()
	}
	return fmt.Sprintf(
		"%s: %s requested=%d maximum=%d",
		ErrLimitExceeded,
		e.Field,
		e.Requested,
		e.Maximum,
	)
}

func (e *LimitError) Unwrap() error {
	return ErrLimitExceeded
}
