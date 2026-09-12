//go:build linux && natlab

package solverstdio

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"syscall"
	"testing"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/directconnect"
)

func TestN3BNatlabFailureWitnessKeepsTypedCausePrivate(t *testing.T) {
	for _, test := range []struct {
		cause error
		want  string
	}{
		{syscall.ECONNREFUSED, "connection_refused"},
		{probeio.ErrUnregisteredTarget, "unregistered_target"},
		{probeio.ErrReplyRejected, "reply_rejected"},
		{probeio.ErrLeaseClosed, "lease_closed"},
		{context.DeadlineExceeded, "context_deadline"},
		{n3bWitnessPoison{}, "other"},
	} {
		t.Run(test.want, func(t *testing.T) {
			cause := errors.Join(test.cause, &net.OpError{Op: "SYNTHETIC_PRIVATE", Net: "SYNTHETIC_PRIVATE",
				Source: n3bWitnessPoisonAddress{}, Addr: n3bWitnessPoisonAddress{}, Err: n3bWitnessPoison{}})
			wrapped := &directconnect.Failure{Class: directconnect.ClassPunchTimeout, Stage: directconnect.StagePunch, Cause: cause}
			got := n3bFailureWitness(wrapped, nil)
			if !got.Seen || got.Cause != test.want || got.Operation != "other" || got.Context != "active" {
				t.Fatalf("typed cause classification = %+v", got)
			}
			payload, err := json.Marshal(got)
			if err != nil || strings.Contains(string(payload), "SYNTHETIC_PRIVATE") {
				t.Fatal("value-only witness leaked private material")
			}
		})
	}
	if got := n3bFailureWitness(nil, nil); got.Seen || got.Cause != "none" {
		t.Fatal("success fabricated a failure witness")
	}
	first := &directconnect.Failure{Class: directconnect.ClassPunchTimeout, Stage: directconnect.StagePunch, Cause: syscall.ECONNREFUSED}
	if got := n3bFailureWitness(errors.Join(first, context.Canceled), nil); got.Cause != "connection_refused" {
		t.Fatal("later cleanup cancellation overwrote the original I/O cause")
	}
}

func TestN3BNatlabObserverDelegatesWithoutChangingOutcome(t *testing.T) {
	base := &machineAuthority{}
	observed := 0
	authority := &n3bObservedAuthority{machineAuthority: base, observe: func(witness N3BNatlabFailureWitness) {
		observed++
		if !witness.Seen || witness.Context != "active" {
			t.Fatal("missing connector failure witness")
		}
		witness.Cause = "local-copy-only"
	}}
	result, err := authority.ConnectDirect(context.Background(), directconnect.Config{})
	var failure *directconnect.Failure
	if observed != 1 || result.Terminal != "" || !errors.As(err, &failure) ||
		failure.Class != directconnect.ClassDirectAttemptFailed || failure.Stage != directconnect.StagePreflight ||
		failure.Cause != nil || failure.CredentialBurned {
		t.Fatal("read-only observer changed the exact connector outcome")
	}
}

type n3bWitnessPoison struct{}

func (n3bWitnessPoison) Error() string { panic("raw error text must not be read") }

type n3bWitnessPoisonAddress struct{}

func (n3bWitnessPoisonAddress) Network() string { panic("network metadata must not be read") }
func (n3bWitnessPoisonAddress) String() string  { panic("endpoint metadata must not be read") }
