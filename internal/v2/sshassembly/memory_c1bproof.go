//go:build c1bproof

package sshassembly

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"
)

// OpenMemoryProofClient uses the real reservation, validation, framing byte
// accounting and drain path with a fake process runner. This tagged proof
// adapter cannot launch an executable or acquire a network capability.
func OpenMemoryProofClient(ctx context.Context, cfg Config, stream io.ReadWriteCloser) (*Stream, error) {
	if stream == nil {
		return nil, ErrProfileInvalid
	}
	platform, err := currentPlatform()
	if err != nil {
		return nil, err
	}
	return openClient(ctx, cfg, dependencies{now: time.Now, platform: platform,
		runner: &memoryProofRunner{stream: stream}, validateExecutable: func(string) error { return nil }})
}

type memoryProofRunner struct {
	stream  io.ReadWriteCloser
	started bool
}

func (runner *memoryProofRunner) Start(processSpec) (ownedProcess, error) {
	if runner.started {
		return nil, ErrProfileInvalid
	}
	runner.started = true
	return &memoryProofProcess{ReadWriteCloser: runner.stream, done: make(chan struct{})}, nil
}

type memoryProofProcess struct {
	io.ReadWriteCloser
	done chan struct{}
	once sync.Once
}

func (process *memoryProofProcess) Stdin() io.WriteCloser { return process }
func (process *memoryProofProcess) Stdout() io.ReadCloser { return process }
func (process *memoryProofProcess) Stderr() io.ReadCloser { return io.NopCloser(bytes.NewReader(nil)) }
func (process *memoryProofProcess) Wait() error           { <-process.done; return nil }
func (process *memoryProofProcess) Kill() error           { return process.Close() }
func (process *memoryProofProcess) Close() error {
	var err error
	process.once.Do(func() { err = process.ReadWriteCloser.Close(); close(process.done) })
	return err
}
