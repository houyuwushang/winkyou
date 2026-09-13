package natlab

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"winkyou/internal/v2/hardnatbudget"
)

const (
	gateB3ProcessLimit = 52 * time.Second
	// #135: 48.275s historical whole-case time minus the frozen 47s envelope
	// leaves 1.275s of aggregate overhead, rounded up to 2s. This is NOT an
	// isolated fsync measurement. Add 8s for process start/scheduling/publication.
	gateB3ResultObservedOverhead  = 2 * time.Second
	gateB3ResultRunnerMargin      = 8 * time.Second
	gateB3ResultPublicationBudget = gateB3ResultObservedOverhead + gateB3ResultRunnerMargin
	gateB3FullEnvelopeResultLimit = hardnatbudget.Hard16ActiveEnvelope + hardnatbudget.Hard16DrainTimeout + gateB3ResultPublicationBudget
)

func gateB3ResultWaitLimit(layer string) time.Duration {
	return gateB3ProcessLimit
}

// The original case defer decides whether a failure occurred. Cleanup must
// still run if a diagnostic itself exits the test goroutine; no retry follows.
func gateB3ReportFailedCase(diagnostic, cleanup func()) {
	defer cleanup()
	diagnostic()
}

func TestGateB3LifetimeResultWaitContract(t *testing.T) {
	if hardnatbudget.Hard16ActiveEnvelope != 45*time.Second || hardnatbudget.Hard16DrainTimeout != 2*time.Second ||
		gateB3ResultObservedOverhead != 2*time.Second || gateB3ResultRunnerMargin != 8*time.Second ||
		gateB3ResultPublicationBudget != 10*time.Second || gateB3FullEnvelopeResultLimit != 57*time.Second || gateB3ProcessLimit != 52*time.Second {
		t.Fatal("result observation wait lost its three-source derivation")
	}
	for _, layer := range []string{"", "M-S", "M-E", "M-X", "unknown"} {
		want := gateB3ProcessLimit
		if layer == "M-E" || layer == "M-X" {
			want = gateB3FullEnvelopeResultLimit
		}
		if got := gateB3ResultWaitLimit(layer); got != want {
			t.Errorf("result wait layer=%q got=%s want=%s", layer, got, want)
		}
	}
	for _, diagnosticExit := range []bool{false, true} {
		var events []string
		joined := make(chan struct{})
		go func() {
			defer close(joined)
			defer gateB3ReportFailedCase(func() {
				events = append(events, "both-endpoint-diagnostics")
				if diagnosticExit {
					runtime.Goexit()
				}
			}, func() { events = append(events, "original-residue-gate") })
			events = append(events, "wait-fatal")
			runtime.Goexit()
		}()
		<-joined
		if strings.Join(events, ",") != "wait-fatal,both-endpoint-diagnostics,original-residue-gate" {
			t.Fatal("Fatal bypassed or retried failure evidence")
		}
	}
}

func TestGateB3LifetimeResultWaitWiring(t *testing.T) {
	data, err := os.ReadFile("gate_b3_netns_linux_test.go")
	if err != nil {
		t.Fatal("result wait source unavailable")
	}
	valid := func(source string) bool {
		for _, required := range []string{
			"resultLimit := gateB3ResultWaitLimit(layer)",
			"waitGateB3ResultWithin(t, initiator, resultLimit)", "waitGateB3ResultWithin(t, responder, resultLimit)",
			"gateB3ReportFailedCase(", "logGateB3EndpointPair(t, initiator, responder)",
			"gateB3FailedCaseCleanup(t, topology, observer", "if t.Failed() && !residueComplete",
			"deadline := time.Now().Add(limit)",
		} {
			if !strings.Contains(source, required) {
				return false
			}
		}
		return true
	}
	if !valid(string(data)) {
		t.Fatal("full-envelope wait or bilateral diagnostics are not wired into the real fixture")
	}
	for _, needle := range []string{"resultLimit := gateB3ResultWaitLimit(layer)", "logGateB3EndpointPair(t, initiator, responder)", "gateB3FailedCaseCleanup(t, topology, observer"} {
		if valid(strings.Replace(string(data), needle, "removed", 1)) {
			t.Fatal("result wait wiring mutation escaped")
		}
	}
}
