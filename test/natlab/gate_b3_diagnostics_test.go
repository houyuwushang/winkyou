package natlab

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Fixed-capacity, test-only observations. No raw errors, endpoints, command
// arguments or wall-clock timestamps can enter the exported log shape.
type gateB3DiagnosticPhase uint8

const (
	gateB3PreferredEnter gateB3DiagnosticPhase = iota
	gateB3PreferredDeadline
	gateB3PeerReady
	gateB3FirstSent
	gateB3DenialWait
	gateB3DenialDeadline
	gateB3FirstDenied
	gateB3PreferredReturn
	gateB3MappingBindBegin
	gateB3MappingBindEnd
	gateB3WriteBegin
	gateB3WriteEnd
	gateB3ObserverDone
	gateB3RouterTerminal
	gateB3RouterClose
	gateB3SocketOption
	gateB3OutboundFailure
	gateB3InboundFailure
	gateB3TUNFailure
	gateB3NamespaceFailure
	gateB3DiagnosticPhaseCount
)

func (phase gateB3DiagnosticPhase) String() string {
	names := [...]string{"preferred_enter", "preferred_deadline", "peer_ready", "first_sent",
		"denial_wait", "denial_deadline", "first_denied", "preferred_return", "mapping_bind_begin",
		"mapping_bind_end", "write_begin", "write_end", "observer_done", "router_terminal", "router_close",
		"socket_option", "outbound_forward", "inbound_inject", "tun_read", "namespace_runner"}
	if phase >= gateB3DiagnosticPhaseCount {
		return "unknown"
	}
	return names[phase]
}

type gateB3DiagnosticError struct {
	Class, Operation, Syscall, Context string
	ExitKnown                          bool
	ExitCode                           int
}

func gateB3SafeError(err, ctxErr error) gateB3DiagnosticError {
	result := gateB3DiagnosticError{Class: "none", Context: "active"}
	switch {
	case errors.Is(ctxErr, context.DeadlineExceeded):
		result.Context = "deadline"
	case errors.Is(ctxErr, context.Canceled):
		result.Context = "canceled"
	case ctxErr != nil:
		result.Context = "other"
	}
	if err == nil {
		return result
	}
	result.Class = "other"
	for _, item := range []struct {
		err   error
		class string
	}{
		{context.DeadlineExceeded, "context_deadline"}, {context.Canceled, "context_canceled"},
		{os.ErrDeadlineExceeded, "io_deadline"}, {net.ErrClosed, "closed"}, {os.ErrClosed, "closed"},
		{exec.ErrWaitDelay, "command_wait_delay"},
		{syscall.EADDRINUSE, "address_in_use"}, {syscall.EADDRNOTAVAIL, "address_unavailable"},
		{syscall.ENOBUFS, "no_buffers"}, {syscall.EMFILE, "process_fd_limit"}, {syscall.ENFILE, "system_fd_limit"},
		{syscall.EACCES, "permission"}, {syscall.EPERM, "permission"},
		{syscall.ECONNREFUSED, "connection_refused"}, {syscall.ENETUNREACH, "network_unreachable"},
		{syscall.EHOSTUNREACH, "host_unreachable"}, {syscall.EPIPE, "broken_pipe"},
		{syscall.EBADF, "bad_fd"}, {syscall.EINVAL, "invalid_argument"}, {syscall.ETIMEDOUT, "os_timeout"},
	} {
		if errors.Is(err, item.err) {
			result.Class = item.class
			break
		}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.Class = "command_exit"
		if exitErr.ProcessState != nil {
			result.ExitKnown, result.ExitCode = true, exitErr.ExitCode()
		}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		switch opErr.Op {
		case "dial", "read", "write", "listen", "set":
			result.Operation = opErr.Op
		default:
			result.Operation = "other"
		}
	}
	var callErr *os.SyscallError
	if errors.As(err, &callErr) {
		switch callErr.Syscall {
		case "socket", "bind", "connect", "setsockopt", "read", "write", "sendto", "recvfrom":
			result.Syscall = callErr.Syscall
		default:
			result.Syscall = "other"
		}
	}
	return result
}

type gateB3DiagnosticPoint struct {
	Seen  bool
	AtNS  int64
	Error gateB3DiagnosticError
}

type gateB3DiagnosticFailure struct {
	Phase gateB3DiagnosticPhase
	gateB3DiagnosticPoint
}

type gateB3DenialQueryWitness struct {
	Started, Completed                   uint64
	FirstStartNS, LastStartNS, LastEndNS int64
	Positive, Zero, Missing, Invalid     uint64
	Error                                gateB3DiagnosticError
}

type gateB3DiagnosticSnapshot struct {
	Points       [gateB3DiagnosticPhaseCount]gateB3DiagnosticPoint
	FirstFailure gateB3DiagnosticFailure
	Query        gateB3DenialQueryWitness
}

type gateB3NATDiagnostic struct {
	origin time.Time
	mu     sync.Mutex
	state  gateB3DiagnosticSnapshot
}

func (diag *gateB3NATDiagnostic) mark(phase gateB3DiagnosticPhase, at time.Time, err, ctxErr error) {
	if diag == nil || phase >= gateB3DiagnosticPhaseCount {
		return
	}
	diag.mu.Lock()
	defer diag.mu.Unlock()
	if !diag.state.Points[phase].Seen {
		diag.state.Points[phase] = gateB3DiagnosticPoint{Seen: true, AtNS: at.Sub(diag.origin).Nanoseconds(), Error: gateB3SafeError(err, ctxErr)}
	}
}

func (diag *gateB3NATDiagnostic) fail(phase gateB3DiagnosticPhase, err, ctxErr error) {
	if diag == nil || err == nil {
		return
	}
	diag.mu.Lock()
	defer diag.mu.Unlock()
	if !diag.state.FirstFailure.Seen {
		diag.state.FirstFailure = gateB3DiagnosticFailure{Phase: phase,
			gateB3DiagnosticPoint: gateB3DiagnosticPoint{Seen: true, AtNS: time.Since(diag.origin).Nanoseconds(), Error: gateB3SafeError(err, ctxErr)}}
	}
}

func (diag *gateB3NATDiagnostic) queryStart() {
	if diag == nil {
		return
	}
	diag.mu.Lock()
	defer diag.mu.Unlock()
	query := &diag.state.Query
	query.LastStartNS = time.Since(diag.origin).Nanoseconds()
	if query.Started == 0 {
		query.FirstStartNS = query.LastStartNS
	}
	query.Started++
}

func (diag *gateB3NATDiagnostic) queryEnd(outcome string, err, ctxErr error) {
	if diag == nil {
		return
	}
	diag.mu.Lock()
	defer diag.mu.Unlock()
	query := &diag.state.Query
	query.Completed++
	query.LastEndNS, query.Error = time.Since(diag.origin).Nanoseconds(), gateB3SafeError(err, ctxErr)
	switch outcome {
	case "positive":
		query.Positive++
	case "zero":
		query.Zero++
	case "missing":
		query.Missing++
	case "invalid":
		query.Invalid++
	}
}

func (diag *gateB3NATDiagnostic) snapshot() gateB3DiagnosticSnapshot {
	if diag == nil {
		return gateB3DiagnosticSnapshot{}
	}
	diag.mu.Lock()
	defer diag.mu.Unlock()
	return diag.state
}

// Same release predicate as the original inline parser: any positive,
// parseable DROP row. A missing/malformed row is diagnostic, not a new error.
func gateB3DenialOutcome(output []byte) string {
	outcome := "missing"
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == "DROP" {
			count, err := strconv.ParseUint(fields[0], 10, 64)
			if err == nil && count > 0 {
				return "positive"
			}
			if err != nil {
				outcome = "invalid"
			} else if outcome != "invalid" {
				outcome = "zero"
			}
		}
	}
	return outcome
}

// Ordered, fixed-cardinality checks. A failure must not bypass the next
// cleanup/observation or turn an unavailable counter into a claimed zero.
const gateB3FailureCleanupStageCount = 7

func gateB3RunFailureCleanup(checks [gateB3FailureCleanupStageCount]func() bool) (result [gateB3FailureCleanupStageCount]bool) {
	for stage, check := range checks {
		if check != nil {
			result[stage] = check()
		}
	}
	return result
}
