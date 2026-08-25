//go:build linux && natlab

package solverstdio

import (
	"context"
	"errors"
	"io"
	"strings"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/pkg/version"
)

// ServeN3BNatlab runs the exact stdio transport and handler with a disposable
// prepared machine namespace. It exists only in linux+natlab binaries so two
// endpoint subprocesses can represent two machines on one CI host without
// weakening the canonical machine namespace used by product builds.
func ServeN3BNatlab(ctx context.Context, input io.Reader, output io.Writer, namespace string) error {
	if strings.TrimSpace(namespace) == "" {
		return errors.New("solverstdio: natlab namespace is required")
	}
	current := version.Current()
	build := BuildInfo{
		Version: current.Version, Commit: current.Commit, BuildTime: current.BuildTime, GoVersion: current.GoVersion,
	}
	return serveWithDependencies(ctx, input, output, Options{}, dependencies{
		Acquire: func(buildVersion string) (authority, error) {
			owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, buildVersion)
			if err != nil {
				return nil, err
			}
			machine, err := governor.New(owner, governor.ProfilePhase1Machine, nil)
			if err != nil {
				_ = owner.Close()
				return nil, err
			}
			return &machineAuthority{owner: owner, machine: machine}, nil
		},
		Diagnose:    passivediagnose.SystemInspector(current.Version),
		WriteReport: passivediagnose.WriteRedactedReport,
		Build:       build,
		Limits:      stdiojsonrpc.DefaultLimits(),
	})
}
