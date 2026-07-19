package main

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestRunRejoinPreservesConnectivityWhileReplacingBootstrapEdge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	got, err := runRejoin(ctx, []byte("rejoin-test"))
	if err != nil {
		t.Fatalf("runRejoin() error = %v", err)
	}
	if got.CoordinatorStarted {
		t.Fatal("runRejoin() started an infrastructure coordinator")
	}
	if got.RejoinedNode != "B" {
		t.Fatalf("RejoinedNode = %q, want B", got.RejoinedNode)
	}
	if !slices.Equal(got.BootstrapRoute, []string{"A", "C", "B"}) {
		t.Fatalf("BootstrapRoute = %v, want [A C B]", got.BootstrapRoute)
	}
	if got.FirstCoordinator != "C" || !slices.Equal(got.FirstDirectRoute, []string{"A", "B"}) {
		t.Fatalf("first shortcut = coordinator %q route %v, want C [A B]", got.FirstCoordinator, got.FirstDirectRoute)
	}
	if !slices.Equal(got.ReplacementRoute, []string{"B", "A", "C"}) {
		t.Fatalf("ReplacementRoute = %v, want [B A C]", got.ReplacementRoute)
	}
	if got.SecondCoordinator != "A" || !slices.Equal(got.SecondDirectRoute, []string{"B", "C"}) {
		t.Fatalf("second shortcut = coordinator %q route %v, want A [B C]", got.SecondCoordinator, got.SecondDirectRoute)
	}
	if !got.TemporaryDetached || !got.AllEdgesDirect || !got.DataBypassVerified {
		t.Fatalf(
			"acceptance = detached:%t all_direct:%t bypass:%t, want all true",
			got.TemporaryDetached,
			got.AllEdgesDirect,
			got.DataBypassVerified,
		)
	}
}
