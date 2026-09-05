package gatecorchestrator

import (
	"errors"
	"sync"
	"time"
)

type progressSequence struct {
	mu       sync.Mutex
	reporter ProgressReporter
	deadline time.Time
	index    int
	terminal bool
	last     string
}

func newProgressSequence(reporter ProgressReporter, deadline time.Time) *progressSequence {
	return &progressSequence{reporter: reporter, deadline: deadline}
}

func (sequence *progressSequence) emit(stage string, cancellable bool) error {
	if sequence == nil || sequence.reporter == nil {
		return ErrRequestInvalid
	}
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.terminal || sequence.index >= len(ProductProgressSequence) || ProductProgressSequence[sequence.index] != stage {
		return errors.New("gatecorchestrator: invalid progress transition")
	}
	remaining := time.Until(sequence.deadline)
	if remaining < 0 {
		remaining = 0
	}
	if err := sequence.reporter(Progress{Stage: stage, RemainingBudget: remaining, Cancellable: cancellable}); err != nil {
		return err
	}
	sequence.index++
	sequence.last = stage
	if stage == StageTerminal {
		sequence.terminal = true
	}
	return nil
}

func (sequence *progressSequence) lastStage() string {
	if sequence == nil {
		return StagePreflight
	}
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.last == "" {
		return StagePreflight
	}
	return sequence.last
}

func (sequence *progressSequence) emitTerminal() error {
	if sequence == nil {
		return nil
	}
	sequence.mu.Lock()
	if sequence.terminal {
		sequence.mu.Unlock()
		return nil
	}
	sequence.mu.Unlock()
	return sequence.emitAtTerminal()
}

func (sequence *progressSequence) emitAtTerminal() error {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	if sequence.terminal {
		return nil
	}
	remaining := time.Until(sequence.deadline)
	if remaining < 0 {
		remaining = 0
	}
	if err := sequence.reporter(Progress{Stage: StageTerminal, RemainingBudget: remaining, Cancellable: false}); err != nil {
		return err
	}
	sequence.terminal = true
	return nil
}
