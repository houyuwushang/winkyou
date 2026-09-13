//go:build unix

package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// Peer/SSH disconnect signals must follow caller cancellation so the existing
// cleanup can durably FINISH before releasing the attempt. SIGKILL is not
// catchable; the durable burn and restart rejection still cover that case.
func solverSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
}
