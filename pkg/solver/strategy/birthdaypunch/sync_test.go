package birthdaypunch

import (
	"net"
	"testing"
	"time"

	"winkyou/pkg/nat"
)

func TestPlanPunchSequentialTargetsPrediction(t *testing.T) {
	plan := planPunch(peerEndpoint{
		IP:           net.IPv4(210, 30, 106, 93),
		ObservedPort: 55161,
		Pattern:      nat.PortAllocationSequential,
		Delta:        1,
	})
	if plan.Method != "predictive" {
		t.Fatalf("method = %q, want predictive", plan.Method)
	}
	if plan.SocketCount != defaultPredictSockets {
		t.Fatalf("socketCount = %d, want %d", plan.SocketCount, defaultPredictSockets)
	}
	// The observed port and the next few must be covered.
	want := map[int]bool{55161: false, 55162: false, 55163: false}
	for _, p := range plan.Targets {
		if _, ok := want[p]; ok {
			want[p] = true
		}
	}
	for p, covered := range want {
		if !covered {
			t.Fatalf("predicted targets %v missing forward port %d", plan.Targets, p)
		}
	}
}

func TestPlanPunchPreserving(t *testing.T) {
	plan := planPunch(peerEndpoint{
		IP:           net.IPv4(198, 51, 100, 9),
		ObservedPort: 53381,
		Pattern:      nat.PortAllocationPreserving,
	})
	if plan.Method != "predictive" {
		t.Fatalf("method = %q, want predictive", plan.Method)
	}
	if len(plan.Targets) != 1 || plan.Targets[0] != 53381 {
		t.Fatalf("targets = %v, want [53381]", plan.Targets)
	}
}

func TestPlanPunchRandomSprays(t *testing.T) {
	plan := planPunch(peerEndpoint{
		IP:           net.IPv4(36, 33, 24, 21),
		ObservedPort: 41020,
		Pattern:      nat.PortAllocationRandom,
	})
	if plan.Method != "birthday" {
		t.Fatalf("method = %q, want birthday", plan.Method)
	}
	if plan.SocketCount != defaultBirthdaySockets {
		t.Fatalf("socketCount = %d, want %d", plan.SocketCount, defaultBirthdaySockets)
	}
	if plan.BirthdayN != defaultBirthdayPerRound {
		t.Fatalf("birthdayN = %d, want %d", plan.BirthdayN, defaultBirthdayPerRound)
	}
	if plan.RoundDelay != defaultBirthdayRoundDelay {
		t.Fatalf("roundDelay = %s, want %s", plan.RoundDelay, defaultBirthdayRoundDelay)
	}
	if len(plan.Targets) != 0 {
		t.Fatalf("fixed targets = %v, want fresh per-round birthday targets", plan.Targets)
	}
	if !plan.usable() {
		t.Fatal("birthday spray plan must be executable without fixed targets")
	}
}

func TestPatternFromStringRoundTrip(t *testing.T) {
	cases := []nat.PortAllocationPattern{
		nat.PortAllocationPreserving,
		nat.PortAllocationSequential,
		nat.PortAllocationRandom,
		nat.PortAllocationUnknown,
	}
	for _, want := range cases {
		if got := patternFromString(want.String()); got != want {
			t.Fatalf("patternFromString(%q) = %v, want %v", want.String(), got, want)
		}
	}
}

func TestSyncStartAtAndDelay(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	start := syncStartAt(now, 500*time.Millisecond)
	if d := delayUntil(now, start); d != 500*time.Millisecond {
		t.Fatalf("delayUntil = %v, want 500ms", d)
	}
	// Past start time yields zero delay, not negative.
	if d := delayUntil(start.Add(time.Second), start); d != 0 {
		t.Fatalf("delayUntil(past) = %v, want 0", d)
	}
}
