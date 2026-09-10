//go:build !unix

package cmd

import (
	"context"
	"os"
	"os/signal"
)

// Windows and other non-Unix targets retain the original interrupt-only
// contract. Do not introduce console/group signals or change child ownership.
func solverSignalContext(parent context.Context) (context.Context, context.CancelFunc) {
	return signal.NotifyContext(parent, os.Interrupt)
}
