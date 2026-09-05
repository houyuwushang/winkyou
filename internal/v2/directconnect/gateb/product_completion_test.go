package gateb

import (
	"context"
	"testing"

	"winkyou/internal/v2/oobcarrier"
)

func TestProductCarrierRequiresDurableFinishNotLocalTrace(t *testing.T) {
	for _, test := range []struct {
		name          string
		finished, eof bool
		cause         error
		cancel        bool
	}{
		{"pre-finish-eof", false, true, oobcarrier.ErrCarrierTransport, true},
		{"pre-finish-close", false, false, oobcarrier.ErrCarrierTerminal, true},
		{"post-finish-eof", true, true, oobcarrier.ErrCarrierTransport, false},
		{"post-finish-close", true, false, oobcarrier.ErrCarrierTerminal, false},
		{"post-finish-protocol", true, false, oobcarrier.ErrInvalidFrame, true},
		{"post-finish-transport-error", true, false, oobcarrier.ErrCarrierTransport, true},
		{"post-finish-deadline", true, false, context.DeadlineExceeded, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(context.Canceled)
			r := &runtime{activeCancel: cancel, activeContext: ctx}
			r.challengeComplete.Store(true) // must NOT authorize pre-FINISH EOF
			r.productFinishRecorded.Store(test.finished)
			r.productCarrierTerminal(test.cause, test.eof)
			if (ctx.Err() != nil) != test.cancel {
				t.Fatal("carrier used the wrong durable/terminal boundary")
			}
		})
	}
}
