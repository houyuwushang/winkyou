package governor_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"winkyou/internal/v2/hardnatobserve"
	"winkyou/internal/v2/hardnatplan"
)

type evidenceDiagnosticPhase uint8

const (
	evidenceSendBegin evidenceDiagnosticPhase = iota
	evidenceSendEnd
	evidenceResponderRead
	evidenceReplyBegin
	evidenceReplyEnd
	evidenceAdapterRead
	evidencePhaseCount
)

type evidenceDiagnosticPoint struct {
	Seen  bool
	AtNS  int64
	Error string
}

// Fixed 2 x 13 x 6 storage. The clock is a shared in-process monotonic origin,
// not the injected evidence clock. No transaction IDs or addresses are logged.
type gateB2EvidenceDiagnostic struct {
	origin time.Time
	mu     sync.Mutex
	ids    [2][hardnatobserve.ObservationPacketCount]hardnatplan.TransactionID
	points [2][hardnatobserve.ObservationPacketCount][evidencePhaseCount]evidenceDiagnosticPoint
}

func newGateB2EvidenceDiagnostic() *gateB2EvidenceDiagnostic {
	diag := &gateB2EvidenceDiagnostic{origin: time.Now()}
	for side := range 2 {
		input := gateB2ObservationRandom(byte(70 + side))
		for index := range diag.ids[side] {
			_, _ = io.ReadFull(input, diag.ids[side][index][:])
		}
	}
	return diag
}

func (diag *gateB2EvidenceDiagnostic) mark(packet []byte, phase evidenceDiagnosticPhase, err error) {
	if diag == nil || phase >= evidencePhaseCount || len(packet) < 20 ||
		binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 {
		return
	}
	// This is a diagnostic lookup of our issued transaction IDs, not a parser
	// or acceptance path. The real RFC decoder and all budgets are unchanged.
	var id hardnatplan.TransactionID
	copy(id[:], packet[8:20])
	for side := range diag.ids {
		for ordinal, expected := range diag.ids[side] {
			if id != expected {
				continue
			}
			point := evidenceDiagnosticPoint{Seen: true, AtNS: time.Since(diag.origin).Nanoseconds(), Error: "none"}
			if err != nil {
				point.Error = "other"
				if errors.Is(err, context.Canceled) {
					point.Error = "canceled"
				} else if errors.Is(err, context.DeadlineExceeded) {
					point.Error = "deadline"
				}
			}
			diag.mu.Lock()
			if !diag.points[side][ordinal][phase].Seen {
				diag.points[side][ordinal][phase] = point
			}
			diag.mu.Unlock()
			return
		}
	}
}

func (diag *gateB2EvidenceDiagnostic) log(t testing.TB) {
	t.Helper()
	if diag == nil {
		return
	}
	diag.mu.Lock()
	points := diag.points
	diag.mu.Unlock()
	for side, observations := range points {
		for ordinal, phases := range observations {
			if !phases[evidenceSendBegin].Seen {
				continue
			}
			for phase, point := range phases {
				t.Logf("EVIDENCE_TIMING side=%d ordinal=%d phase=%d seen=%t at_ns=%d error=%s",
					side, ordinal+1, phase, point.Seen, point.AtNS, point.Error)
			}
		}
	}
}

func TestEvidenceDiagnosticBoundedFirstWitness(t *testing.T) {
	diag := newGateB2EvidenceDiagnostic()
	request, err := hardnatplan.BuildBehaviorBindingRequest(diag.ids[1][12], hardnatplan.ChangeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	diag.mark(request, evidenceSendBegin, nil)
	first := diag.points[1][12][evidenceSendBegin]
	diag.mark(request, evidenceSendBegin, errors.New("SYNTHETIC_PRIVATE"))
	if diag.points[1][12][evidenceSendBegin] != first || !first.Seen || first.Error != "none" {
		t.Fatal("first observation replaced")
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Add(1)
		go func() { defer workers.Done(); diag.mark(request, evidenceReplyEnd, context.DeadlineExceeded) }()
	}
	workers.Wait()
	if got := diag.points[1][12][evidenceReplyEnd]; !got.Seen || got.Error != "deadline" {
		t.Fatalf("missing safe failure witness: %+v", got)
	}
	before := diag.points
	request[8] = 99
	diag.mark(request, evidenceSendEnd, nil)
	if diag.points != before {
		t.Fatal("unissued transaction changed observations")
	}
}
