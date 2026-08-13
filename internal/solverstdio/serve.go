package solverstdio

import (
	"context"
	"errors"
	"fmt"
	"io"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
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
			return governor.AcquireMachineNamespace(buildVersion)
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
	return server.Run(ctx)
}
