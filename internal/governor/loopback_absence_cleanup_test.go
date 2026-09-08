package governor_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"winkyou/internal/governor"
)

func closeAbsentPeerGovernor(t *testing.T, machine *governor.Governor, namespace string) {
	t.Helper()
	if err := machine.Close(); err != nil {
		t.Error("absent_peer_cleanup governor_close_failed")
	}
	// Acquire only the OS owner; do not rewrite or repair the journal/trip file.
	owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "absence-cleanup-witness")
	if err != nil {
		t.Error("absent_peer_cleanup owner_lock_remains")
		return
	}
	if err := owner.Close(); err != nil {
		t.Error("absent_peer_cleanup witness_close_failed")
		return
	}
	t.Log("absent_peer_cleanup owner_lock_reacquired=true owner_lock_remaining=0")
}

// A deterministic cleanup RED/GREEN, separate from the still-investigated
// 15-second flake. The mutant models the old Close-after-Fatal ordering. No
// sleep, network or production timing injection is involved.
func TestAbsentPeerFatalCleanupWitness(t *testing.T) {
	if os.Getenv("WINKYOU_ABSENCE_FATAL_CHILD") == "1" {
		namespace := t.TempDir()
		if err := governor.PrepareLoopbackCarrierTestNamespace(namespace, time.Now()); err != nil {
			t.Fatal("cleanup_child namespace_setup_failed")
		}
		machine, err := governor.AcquireLoopbackCarrierTestGovernor(namespace, "absence-fatal-child")
		if err != nil {
			t.Fatal("cleanup_child owner_acquire_failed")
		}
		defer machine.Close()
		mutant := os.Getenv("WINKYOU_ABSENCE_FATAL_MUTANT") == "1"
		t.Run("intentional_fatal", func(t *testing.T) {
			if !mutant {
				t.Cleanup(func() { closeAbsentPeerGovernor(t, machine, namespace) })
			}
			t.Fatal("synthetic_failure_before_normal_close")
		})
		owner, err := governor.AcquirePreparedNamespace(namespace, governor.ScopeMachine, "absence-after-fatal")
		if err != nil {
			t.Log("fatal_cleanup lock_reacquired=false")
			return
		}
		if err := owner.Close(); err != nil {
			t.Fatal("cleanup_child witness_close_failed")
		}
		t.Log("fatal_cleanup lock_reacquired=true")
		return
	}
	for _, mutant := range []string{"1", "0"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAbsentPeerFatalCleanupWitness$", "-test.v", "-test.count=1")
		command.Env = append(os.Environ(), "WINKYOU_ABSENCE_FATAL_CHILD=1", "WINKYOU_ABSENCE_FATAL_MUTANT="+mutant)
		output, err := command.CombinedOutput()
		cancel()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 || !bytes.Contains(output, []byte("synthetic_failure_before_normal_close")) {
			t.Fatal("cleanup witness child did not complete the intentional Fatal")
		}
		want := "fatal_cleanup lock_reacquired=true"
		if mutant == "1" {
			want = "fatal_cleanup lock_reacquired=false"
		}
		if !bytes.Contains(output, []byte(want)) {
			t.Fatal("Fatal cleanup mutation witness mismatch")
		}
		t.Logf("cleanup_mutation old_order=%t witness_matched=true child_remaining=0", mutant == "1")
	}
}
