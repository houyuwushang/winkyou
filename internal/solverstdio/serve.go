package solverstdio

import (
	"context"
	"errors"
	"fmt"
	"io"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/internal/v2/loopbackcarrier"
	"winkyou/pkg/version"
)

type Options struct {
	ConfigPath string
}

type authority interface {
	Info() governor.OwnerInfo
	SafetyTripStatus() governor.SafetyTripStatus
	Close() error
}

type connectTestAuthority interface {
	ConnectTest(context.Context, []byte, string, loopbackcarrier.ProgressReporter) (loopbackcarrier.Result, error)
	PairingLedgerStatus() governor.PairingLedgerStatus
}

type machineAuthority struct {
	owner   *governor.Owner
	machine *governor.Governor
}

func acquireMachineAuthority(buildVersion string) (*machineAuthority, error) {
	owner, err := governor.AcquireMachineNamespace(buildVersion)
	if err != nil {
		return nil, err
	}
	machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
	if err != nil {
		_ = owner.Close()
		return nil, err
	}
	return &machineAuthority{owner: owner, machine: machine}, nil
}

func (authority *machineAuthority) Info() governor.OwnerInfo {
	if authority == nil || authority.owner == nil {
		return governor.OwnerInfo{}
	}
	return authority.owner.Info()
}

func (authority *machineAuthority) SafetyTripStatus() governor.SafetyTripStatus {
	if authority == nil || authority.owner == nil {
		return governor.SafetyTripStatus{State: governor.SafetyTripIndeterminate, BlocksActiveWork: true, Detail: "machine authority is unavailable"}
	}
	return authority.owner.SafetyTripStatus()
}

func (authority *machineAuthority) PairingLedgerStatus() governor.PairingLedgerStatus {
	if authority == nil || authority.owner == nil {
		return unavailablePairingLedgerStatus("machine authority is unavailable")
	}
	ledger, err := authority.owner.PairingLedger()
	if err == nil {
		return ledger.Status()
	}
	var ledgerErr *governor.PairingLedgerError
	if errors.As(err, &ledgerErr) {
		return ledgerErr.Status
	}
	return unavailablePairingLedgerStatus("pairing ledger status is unavailable")
}

func (authority *machineAuthority) ConnectTest(ctx context.Context, payload []byte, buildVersion string, progress loopbackcarrier.ProgressReporter) (loopbackcarrier.Result, error) {
	if authority == nil || authority.machine == nil {
		return loopbackcarrier.Result{}, loopbackcarrier.ErrCarrierUnavailable
	}
	return loopbackcarrier.Connect(ctx, authority.machine, payload, buildVersion, progress)
}

func (authority *machineAuthority) Close() error {
	if authority == nil || authority.machine == nil {
		return nil
	}
	return authority.machine.Close()
}

func unavailablePairingLedgerStatus(detail string) governor.PairingLedgerStatus {
	return governor.PairingLedgerStatus{
		State:            governor.PairingLedgerIndeterminate,
		BlocksActiveWork: true,
		Limits:           governor.PairingAdmissionHardLimits(),
		Detail:           detail,
	}
}

type diagnoseRunner interface {
	Run(context.Context, passivediagnose.Options) passivediagnose.Report
}

type dependencies struct {
	Acquire     func(string) (authority, error)
	Diagnose    diagnoseRunner
	WriteReport func(string, passivediagnose.Report) (int64, error)
	Build       BuildInfo
	Limits      stdiojsonrpc.Limits
}

func Serve(ctx context.Context, input io.Reader, output io.Writer, options Options) error {
	current := version.Current()
	build := BuildInfo{
		Version:   current.Version,
		Commit:    current.Commit,
		BuildTime: current.BuildTime,
		GoVersion: current.GoVersion,
	}
	return serveWithDependencies(ctx, input, output, options, dependencies{
		Acquire: func(buildVersion string) (authority, error) {
			return acquireMachineAuthority(buildVersion)
		},
		Diagnose:    passivediagnose.SystemInspector(current.Version),
		WriteReport: passivediagnose.WriteRedactedReport,
		Build:       build,
		Limits:      stdiojsonrpc.DefaultLimits(),
	})
}

func serveWithDependencies(ctx context.Context, input io.Reader, output io.Writer, options Options, dependencies dependencies) (err error) {
	if dependencies.Acquire == nil || dependencies.Diagnose == nil || dependencies.WriteReport == nil {
		return errors.New("stdio API dependencies are incomplete")
	}
	if err := dependencies.Limits.Validate(); err != nil {
		return fmt.Errorf("stdio API limits: %w", err)
	}
	buildVersion := dependencies.Build.Version
	if buildVersion == "" {
		buildVersion = "unknown"
	}
	authority, err := dependencies.Acquire(buildVersion)
	if err != nil {
		return fmt.Errorf("%s: %w", ClassGovernorLockUnavailable, err)
	}
	defer func() {
		err = errors.Join(err, authority.Close())
	}()
	handler, err := newHandler(authority, dependencies.Diagnose, dependencies.WriteReport, options, dependencies.Build, dependencies.Limits)
	if err != nil {
		return err
	}
	server, err := stdiojsonrpc.NewServer(input, output, handler, dependencies.Limits, handler.deadline)
	if err != nil {
		return fmt.Errorf("create stdio JSON-RPC server: %w", err)
	}
	// The handshake gates every other method, so it must complete before any
	// later pipelined request is dispatched.
	server.MarkSynchronousMethod(MethodHandshake)
	return server.Run(ctx)
}
