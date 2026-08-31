package sshassembly

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"winkyou/internal/governor"
	"winkyou/internal/v2/hardnatbudget"
	"winkyou/internal/v2/hardnatplan"
)

const assemblyClaimName = "gate-c-ssh-assembly"

type Config struct {
	Lease          *governor.AttemptLease
	Client         ClientConfig
	PlannerProfile hardnatplan.Profile
	ResourceClass  hardnatplan.ResourceClass
	ActiveDeadline time.Time

	testLease assemblyLease
}

type assemblyLease interface {
	Request() governor.AttemptRequest
	ClaimExclusive(string) error
	RegisterDrain(string) (governor.DrainHandle, error)
	Stopping() <-chan struct{}
}

var _ assemblyLease = (*governor.AttemptLease)(nil)

type processSpec struct {
	executable  string
	arguments   []string
	environment []string
}

type ownedProcess interface {
	Stdin() io.WriteCloser
	Stdout() io.ReadCloser
	Stderr() io.ReadCloser
	Wait() error
	Kill() error
}

type processRunner interface {
	Start(processSpec) (ownedProcess, error)
}

type dependencies struct {
	now                func() time.Time
	platform           Platform
	runner             processRunner
	validateExecutable func(string) error
}

type Witness struct {
	Spawned     bool
	Exited      bool
	Killed      bool
	StdinBytes  int
	StdoutBytes int
	StderrBytes int
	Deadline    bool
	Drained     bool
}

// Stream is the only child capability returned by this package. It satisfies
// Gate A's BoundedStream contract without exposing a process, pipe, fd,
// endpoint, command, username, path, host key, or underlying OS error.
type Stream struct {
	mu      sync.Mutex
	readMu  sync.Mutex
	writeMu sync.Mutex
	ops     sync.WaitGroup

	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	child  ownedProcess
	drain  governor.DrainHandle

	absoluteDeadline time.Time
	deadline         time.Time
	deadlineChanged  chan struct{}
	processDone      chan struct{}
	stderrDone       chan struct{}
	closed           chan struct{}
	closeOnce        sync.Once

	closing       bool
	processErr    bool
	terminalError error
	witness       Witness
}

// OpenClient validates the exact profile reservation, consumes one exclusive
// assembly claim, registers drain ownership, and starts one fixed OpenSSH
// child. It has no retry or queue path.
func OpenClient(ctx context.Context, config Config) (*Stream, error) {
	platform, err := currentPlatform()
	if err != nil {
		return nil, err
	}
	return openClient(ctx, config, dependencies{
		now: time.Now, platform: platform, runner: execProcessRunner{}, validateExecutable: validateSystemExecutable,
	})
}

func openClient(ctx context.Context, config Config, deps dependencies) (*Stream, error) {
	if ctx == nil || deps.now == nil || deps.runner == nil || deps.validateExecutable == nil || ctx.Err() != nil {
		return nil, ErrProfileInvalid
	}
	lease := assemblyLease(config.Lease)
	if config.Lease == nil {
		lease = config.testLease
	}
	if lease == nil || config.Client.authority == nil || config.Client.authority.validate() != nil ||
		config.Client.endpoint != config.Client.authority.Endpoint() || ExactAssemblyCost != (SSHAssemblyCost{1, 1, 0, 0, 0}) {
		return nil, ErrProfileInvalid
	}
	active, err := activeDuration(config.PlannerProfile, config.ResourceClass)
	if err != nil || !hardnatbudget.Exact(config.PlannerProfile, config.ResourceClass,
		lease.Request().Operation, lease.Request().Cost) {
		return nil, ErrProfileInvalid
	}
	now := deps.now()
	if config.ActiveDeadline.IsZero() || !config.ActiveDeadline.After(now) || config.ActiveDeadline.After(now.Add(active)) {
		return nil, ErrProfileInvalid
	}
	if err := validatePrivateClientFiles(config.Client.identityFile, config.Client.knownHostsFile); err != nil {
		return nil, err
	}
	executable, err := executableFor(deps.platform)
	if err != nil {
		return nil, err
	}
	arguments, err := buildArguments(config.Client)
	if err != nil || validateNoForbiddenArgument(arguments) != nil {
		return nil, ErrProfileInvalid
	}
	environment, err := fixedEnvironment(deps.platform)
	if err != nil {
		return nil, err
	}
	if err := lease.ClaimExclusive(assemblyClaimName); err != nil {
		return nil, errors.Join(ErrProfileInvalid, err)
	}
	drain, err := lease.RegisterDrain("gate-c-ssh-child")
	if err != nil {
		return nil, errors.Join(ErrProfileInvalid, err)
	}
	failBeforeSpawn := func(err error) (*Stream, error) {
		_ = drain.Complete()
		return nil, err
	}
	// Revalidate every local input and the sealed endpoint immediately before
	// the sole process creation boundary.
	if config.Client.authority.validate() != nil || config.Client.authority.Endpoint() != config.Client.endpoint ||
		validatePrivateClientFiles(config.Client.identityFile, config.Client.knownHostsFile) != nil ||
		deps.validateExecutable(executable) != nil {
		return failBeforeSpawn(ErrProfileInvalid)
	}
	child, err := deps.runner.Start(processSpec{executable: executable, arguments: arguments, environment: environment})
	if err != nil || child == nil || child.Stdin() == nil || child.Stdout() == nil || child.Stderr() == nil {
		if child != nil {
			_ = child.Kill()
		}
		return failBeforeSpawn(ErrTransport)
	}
	stream := &Stream{
		stdin: child.Stdin(), stdout: child.Stdout(), stderr: child.Stderr(), child: child, drain: drain,
		absoluteDeadline: config.ActiveDeadline, deadline: config.ActiveDeadline,
		deadlineChanged: make(chan struct{}, 1), processDone: make(chan struct{}), stderrDone: make(chan struct{}),
		closed: make(chan struct{}), witness: Witness{Spawned: true},
	}
	go stream.waitProcess()
	go stream.readStderr()
	go stream.watchDeadline()
	go stream.watchCancellation(ctx, lease.Stopping())
	return stream, nil
}

func (stream *Stream) Read(target []byte) (int, error) {
	if stream == nil {
		return 0, io.EOF
	}
	stream.readMu.Lock()
	defer stream.readMu.Unlock()
	if !stream.beginOperation() {
		return 0, io.EOF
	}
	defer stream.ops.Done()
	n, err := stream.stdout.Read(target)
	stream.mu.Lock()
	stream.witness.StdoutBytes += n
	closing := stream.closing
	stream.mu.Unlock()
	if err != nil && !errors.Is(err, io.EOF) && closing {
		return n, io.EOF
	}
	return n, err
}

func (stream *Stream) Write(payload []byte) (int, error) {
	if stream == nil {
		return 0, ErrAssemblyClosed
	}
	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()
	if !stream.beginOperation() {
		return 0, ErrAssemblyClosed
	}
	defer stream.ops.Done()
	n, err := stream.stdin.Write(payload)
	stream.mu.Lock()
	stream.witness.StdinBytes += n
	closing := stream.closing
	stream.mu.Unlock()
	if err != nil && closing {
		return n, ErrAssemblyClosed
	}
	if err != nil {
		return n, ErrChildTerminated
	}
	return n, nil
}

func (stream *Stream) SetDeadline(deadline time.Time) error {
	if stream == nil || deadline.IsZero() {
		return ErrDeadline
	}
	stream.mu.Lock()
	if stream.closing || deadline.After(stream.absoluteDeadline) {
		stream.mu.Unlock()
		return ErrDeadline
	}
	stream.deadline = deadline
	stream.mu.Unlock()
	select {
	case stream.deadlineChanged <- struct{}{}:
	default:
	}
	return nil
}

func (stream *Stream) Close() error {
	if stream == nil {
		return nil
	}
	stream.closeOnce.Do(stream.shutdown)
	<-stream.closed
	return nil
}

func (stream *Stream) Witness() Witness {
	if stream == nil {
		return Witness{Drained: true}
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	return stream.witness
}

func (stream *Stream) TerminalError() error {
	if stream == nil {
		return ErrAssemblyClosed
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.terminalError != nil {
		return stream.terminalError
	}
	if stream.processErr {
		return ErrChildTerminated
	}
	return nil
}

func (stream *Stream) beginOperation() bool {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.closing {
		return false
	}
	stream.ops.Add(1)
	return true
}

func (stream *Stream) waitProcess() {
	err := stream.child.Wait()
	stream.mu.Lock()
	stream.witness.Exited = true
	stream.processErr = err != nil
	stream.mu.Unlock()
	close(stream.processDone)
	_ = stream.Close()
}

func (stream *Stream) readStderr() {
	buffer := make([]byte, 1024)
	captured := make([]byte, 0, MaxStderrBytes)
	total := 0
	overflow := false
	for {
		n, err := stream.stderr.Read(buffer)
		if n > 0 {
			total += n
			remaining := MaxStderrBytes - len(captured)
			if remaining > 0 {
				copyCount := n
				if copyCount > remaining {
					copyCount = remaining
				}
				captured = append(captured, buffer[:copyCount]...)
			}
			if total > MaxStderrBytes {
				overflow = true
				break
			}
		}
		if err != nil {
			break
		}
	}
	classification := classifyStderr(captured)
	clear(buffer)
	clear(captured)
	stream.mu.Lock()
	stream.witness.StderrBytes = total
	if overflow {
		stream.terminalError = ErrBudgetExceeded
	} else if classification != nil {
		stream.terminalError = classification
	}
	stream.mu.Unlock()
	close(stream.stderrDone)
	if overflow {
		go func() { _ = stream.Close() }()
	}
}

func classifyStderr(payload []byte) error {
	if containsAny(payload, "Host key verification failed", "REMOTE HOST IDENTIFICATION HAS CHANGED") {
		return ErrHostIdentity
	}
	if containsAny(payload, "Permission denied", "Connection refused", "Connection timed out", "No route to host") {
		return ErrTransport
	}
	return nil
}

func containsAny(value []byte, candidates ...string) bool {
	for _, candidate := range candidates {
		if candidate != "" && bytes.Contains(value, []byte(candidate)) {
			return true
		}
	}
	return false
}

func (stream *Stream) watchCancellation(ctx context.Context, stopping <-chan struct{}) {
	select {
	case <-ctx.Done():
	case <-stopping:
	case <-stream.closed:
		return
	}
	_ = stream.Close()
}

func (stream *Stream) watchDeadline() {
	for {
		stream.mu.Lock()
		deadline := stream.deadline
		stream.mu.Unlock()
		duration := time.Until(deadline)
		if duration <= 0 {
			stream.mu.Lock()
			stream.witness.Deadline = true
			stream.terminalError = ErrDeadline
			stream.mu.Unlock()
			_ = stream.Close()
			return
		}
		timer := time.NewTimer(duration)
		select {
		case <-timer.C:
			stream.mu.Lock()
			stream.witness.Deadline = true
			stream.terminalError = ErrDeadline
			stream.mu.Unlock()
			_ = stream.Close()
			return
		case <-stream.deadlineChanged:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-stream.closed:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}

func (stream *Stream) shutdown() {
	stream.mu.Lock()
	stream.closing = true
	stream.mu.Unlock()
	_ = stream.stdin.Close()
	_ = stream.stdout.Close()
	_ = stream.stderr.Close()
	stream.ops.Wait()
	timer := time.NewTimer(DrainTimeout)
	select {
	case <-stream.processDone:
		if !timer.Stop() {
			<-timer.C
		}
	case <-timer.C:
		if stream.child.Kill() == nil {
			stream.mu.Lock()
			stream.witness.Killed = true
			stream.mu.Unlock()
		}
		<-stream.processDone
	}
	<-stream.stderrDone
	_ = stream.drain.Complete()
	stream.mu.Lock()
	stream.witness.Drained = true
	stream.mu.Unlock()
	close(stream.closed)
}

var _ io.ReadWriteCloser = (*Stream)(nil)
