//go:build linux && natlab

package solverstdio

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"

	passivediagnose "winkyou/internal/diagnose"
	"winkyou/internal/governor"
	"winkyou/internal/probeio"
	"winkyou/internal/stdiojsonrpc"
	"winkyou/internal/v2/directconnect"
	"winkyou/pkg/version"
)

// ServeN3BNatlab runs the exact stdio transport and handler with a disposable
// prepared machine namespace. It exists only in linux+natlab binaries so two
// endpoint subprocesses can represent two machines on one CI host without
// weakening the canonical machine namespace used by product builds.
func ServeN3BNatlab(ctx context.Context, input io.Reader, output io.Writer, namespace string, observers ...func(N3BNatlabFailureWitness)) error {
	if strings.TrimSpace(namespace) == "" || len(observers) > 1 {
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
			base := &machineAuthority{owner: owner, machine: machine}
			if len(observers) == 1 && observers[0] != nil {
				return &n3bObservedAuthority{machineAuthority: base, observe: observers[0]}, nil
			}
			return base, nil
		},
		Diagnose:    passivediagnose.SystemInspector(current.Version),
		WriteReport: passivediagnose.WriteRedactedReport,
		Build:       build,
		Limits:      stdiojsonrpc.DefaultLimits(),
	})
}

// This value-only witness exists only in linux+natlab builds. It cannot change
// the connector, its inputs/results or the public JSON-RPC failure schema.
// No error text, endpoint, ID, payload or secret crosses the observer boundary.
type N3BNatlabFailureWitness struct {
	Seen           bool
	Cause, Context string
	Operation      string
	NetworkTimeout bool
}

type n3bObservedAuthority struct {
	*machineAuthority
	observe func(N3BNatlabFailureWitness)
}

func (authority *n3bObservedAuthority) ConnectDirect(ctx context.Context, config directconnect.Config) (directconnect.Result, error) {
	result, err := authority.machineAuthority.ConnectDirect(ctx, config)
	if err != nil {
		authority.observe(n3bFailureWitness(err, ctx.Err()))
	}
	return result, err
}

func n3bFailureWitness(err, ctxErr error) N3BNatlabFailureWitness {
	witness := N3BNatlabFailureWitness{Seen: err != nil, Cause: "none", Context: "active", Operation: "none"}
	if ctxErr != nil {
		witness.Context = "other"
		if errors.Is(ctxErr, context.Canceled) {
			witness.Context = "canceled"
		} else if errors.Is(ctxErr, context.DeadlineExceeded) {
			witness.Context = "deadline"
		}
	}
	if err == nil {
		return witness
	}
	// Cleanup may join a later cancellation onto the original failed attempt.
	// Preserve that first typed failure instead of attributing its cause to drain.
	var failure *directconnect.Failure
	if errors.As(err, &failure) && failure.Cause != nil {
		err = failure.Cause
	}
	witness.Cause = "other"
	for _, item := range []struct {
		err   error
		class string
	}{
		{context.Canceled, "context_canceled"}, {context.DeadlineExceeded, "context_deadline"},
		{io.EOF, "eof"}, {net.ErrClosed, "closed"},
		{syscall.ECONNREFUSED, "connection_refused"}, {syscall.ECONNRESET, "connection_reset"},
		{syscall.ENETUNREACH, "network_unreachable"}, {syscall.EHOSTUNREACH, "host_unreachable"},
		{probeio.ErrUnregisteredTarget, "unregistered_target"}, {probeio.ErrInvalidTarget, "invalid_target"},
		{probeio.ErrReplyRejected, "reply_rejected"}, {probeio.ErrDatagramContract, "datagram_contract"},
		{probeio.ErrLeaseClosed, "lease_closed"}, {probeio.ErrSocketClosed, "socket_closed"},
	} {
		if errors.Is(err, item.err) {
			witness.Cause = item.class
			break
		}
	}
	var operation *net.OpError
	if errors.As(err, &operation) {
		witness.Operation = "other"
		switch operation.Op {
		case "read", "write", "dial", "listen":
			witness.Operation = operation.Op
		}
	}
	var networkErr net.Error
	witness.NetworkTimeout = errors.As(err, &networkErr) && networkErr.Timeout()
	return witness
}
