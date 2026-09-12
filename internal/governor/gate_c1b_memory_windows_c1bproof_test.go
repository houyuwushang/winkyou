//go:build c1bproof

package governor_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winkyou/internal/v2/directconnect/gateb"
	"winkyou/internal/v2/gatecorchestrator"
	"winkyou/internal/v2/hardnatplan"
)

type memoryFixtureWindow struct {
	candidateTime time.Duration
	activeTime    time.Duration
}

// One timing policy for every C1b/liveness memory entry on BOTH platforms.
// Only the existing test harness consumes it; frozen production constants and
// the OS/natlab paths are untouched. Unknown profiles never inherit a default.
func memoryFixtureWindows(profile hardnatplan.Profile) memoryFixtureWindow {
	switch profile {
	case hardnatplan.ProfilePredictiveEdm:
		return memoryFixtureWindow{candidateTime: time.Second, activeTime: 10 * time.Second}
	case hardnatplan.ProfileAsymmetricBirthday:
		return memoryFixtureWindow{candidateTime: 1500 * time.Millisecond, activeTime: 10 * time.Second}
	case hardnatplan.ProfileHardBirthday:
		return memoryFixtureWindow{candidateTime: 4 * time.Second, activeTime: 12 * time.Second}
	default:
		panic("unsupported memory fixture profile")
	}
}

// Every C1b/liveness entry uses this one clock policy. Independent Gate B
// codec/exhaustion fixtures keep their original more compressed clocks and
// 100/200/250ms windows. Neither clock changes any product timer or wire value.
type gateC1bMemoryClock struct{ *gateB2ManualClock }

func memoryFixtureClock(now time.Time) *gateC1bMemoryClock {
	return &gateC1bMemoryClock{newGateB2ManualClock(now)}
}

func (clock *gateC1bMemoryClock) Wait(ctx context.Context, duration time.Duration) error {
	if duration >= time.Second {
		return clock.gateB2ManualClock.Wait(ctx, duration)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Unlike a PPS bookkeeping interval, a subsecond role lead orders two
	// actual senders. Keep the pause requested by the product, not a 2ms yield.
	clock.Advance(duration)
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func TestGateC1bMemoryClockPreservesSubsecondRoleLead(t *testing.T) {
	now := time.Date(2026, 8, 29, 16, 0, 0, 0, time.UTC)
	clock := memoryFixtureClock(now)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	const roleLead = 250 * time.Millisecond // Existing product pause, not new headroom.
	if err := clock.Wait(ctx, roleLead); err != nil {
		t.Fatal("role lead failed within its unchanged context")
	}
	if elapsed := time.Since(started); elapsed < roleLead {
		t.Fatalf("subsecond role ordering was compressed: elapsed_ns=%d required_ns=%d", elapsed.Nanoseconds(), roleLead.Nanoseconds())
	}
	if clock.Now().Sub(now) != roleLead {
		t.Fatal("role lead changed the governed logical time")
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if err := clock.Wait(cancelled, roleLead); !errors.Is(err, context.Canceled) || clock.Now().Sub(now) != roleLead {
		t.Fatal("canceled wait advanced the schedule")
	}
}

// The old profile timing fields no longer exist, so entry-specific assignments
// cannot compile. This gate also rejects a second hook or inline hook override.
func memoryFixtureWindowSourceValid(source []byte, ownsHook bool) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		return false
	}
	hooks, timingSelectors, sourceCalls, clockCalls, phaseCalls := 0, 0, 0, 0, 0
	valid := true
	ast.Inspect(file, func(node ast.Node) bool {
		if selector, ok := node.(*ast.SelectorExpr); ok && (selector.Sel.Name == "candidateTime" || selector.Sel.Name == "activeTime") {
			timingSelectors++
		}
		literal, ok := node.(*ast.CompositeLit)
		if !ok {
			return true
		}
		kind, ok := literal.Type.(*ast.SelectorExpr)
		if !ok || kind.Sel.Name != "HarnessHooks" {
			return true
		}
		hooks++
		fields := 0
		for _, element := range literal.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok {
				valid = false
				continue
			}
			key, ok := pair.Key.(*ast.Ident)
			if !ok || (key.Name != "CandidateWindow" && key.Name != "ActiveEnvelope") {
				continue
			}
			fields++
			want := map[string]string{"CandidateWindow": "candidateTime", "ActiveEnvelope": "activeTime"}[key.Name]
			value, ok := pair.Value.(*ast.SelectorExpr)
			if !ok {
				valid = false
				continue
			}
			owner, ok := value.X.(*ast.Ident)
			valid = valid && ok && owner.Name == "windows" && value.Sel.Name == want
		}
		valid = valid && fields == 2
		return true
	})
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "runGateC1bMemoryProductProfile" {
			continue
		}
		// The phase witness is unconditional at the common entry, not nested
		// under liveness/slow-FINISH/profile branches that would hide a RED.
		for _, statement := range function.Body.List {
			assignment, ok := statement.(*ast.AssignStmt)
			if !ok || len(assignment.Rhs) != 1 {
				continue
			}
			call, ok := assignment.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			name, ok := call.Fun.(*ast.Ident)
			if ok && name.Name == "newGateC1bMemoryPhaseWitness" {
				phaseCalls++
			}
		}
		ast.Inspect(function, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if ok && name.Name == "memoryFixtureWindows" {
				sourceCalls++
			}
			if ok && name.Name == "memoryFixtureClock" {
				clockCalls++
			}
			return true
		})
	}
	if ownsHook {
		return valid && hooks == 1 && timingSelectors == 2 && sourceCalls == 1 && clockCalls == 2 && phaseCalls == 1
	}
	return valid && hooks == 0 && timingSelectors == 0 && sourceCalls == 0
}

func testGateC1bMemoryFixtureWindowSource(t *testing.T) {
	t.Run("role-ordering-clock", TestGateC1bMemoryClockPreservesSubsecondRoleLead)
	t.Run("phase-witness", TestGateC1bMemoryPhaseWitnessIsBoundedFirstObservation)
	floors := []memoryFixtureWindow{{time.Second, 10 * time.Second}, {1500 * time.Millisecond, 10 * time.Second}, {4 * time.Second, 12 * time.Second}}
	for index, profile := range gateC1bMemoryProfiles {
		window := memoryFixtureWindows(profile.profile)
		if window.candidateTime < floors[index].candidateTime || window.activeTime < floors[index].activeTime ||
			window.candidateTime >= 5*time.Second && profile.profile != hardnatplan.ProfileHardBirthday ||
			window.candidateTime >= 38*time.Second ||
			window.activeTime >= 20*time.Second {
			t.Fatal("memory fixture window lost its measured floor or test-only compression")
		}
	}
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture source unavailable")
	}
	payload, err := os.ReadFile(filepath.Join(filepath.Dir(current), "gate_c1b_product_pipeline_c1bproof_test.go"))
	if err != nil || !memoryFixtureWindowSourceValid(payload, true) {
		t.Fatal("memory entry windows must have exactly one authority and one hook consumer")
	}
	for _, mutation := range [][2]string{
		{"phases := newGateC1bMemoryPhaseWitness()", "var phases *gateC1bMemoryPhaseWitness; if test.liveness != nil { phases = newGateC1bMemoryPhaseWitness() }"},
		{"memoryFixtureClock(now)", "newGateB2ManualClock(now)"},
		{"CandidateWindow: windows.candidateTime", "CandidateWindow: 250*time.Millisecond"},
		{"ActiveEnvelope: windows.activeTime", "ActiveEnvelope: 0"},
		{"windows := memoryFixtureWindows(test.profile)", "windows := memoryFixtureWindow{}"},
		{"windows := memoryFixtureWindows(test.profile)", "windows := memoryFixtureWindows(test.profile); windows.candidateTime = time.Millisecond"},
	} {
		changed := strings.Replace(string(payload), mutation[0], mutation[1], 1)
		if changed == string(payload) || memoryFixtureWindowSourceValid([]byte(changed), true) {
			t.Fatal("entry-local fixture timing mutation was accepted")
		}
	}
	liveness, err := os.ReadFile(filepath.Join(filepath.Dir(current), "session_liveness_c1bproof_test.go"))
	if err != nil || !memoryFixtureWindowSourceValid(liveness, false) {
		t.Fatal("liveness entries must consume the common runner, not override attempt windows")
	}
	for _, mutation := range []string{
		"func bad() { _ = gateb.HarnessHooks{CandidateWindow: time.Millisecond} }",
		"func bad() { profile.candidateTime = time.Millisecond }",
	} {
		changed := append(append([]byte(nil), liveness...), []byte("\n"+mutation)...)
		if memoryFixtureWindowSourceValid(changed, false) {
			t.Fatal("liveness-local fixture timing mutation was accepted")
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("unknown profile inherited a fixture window")
		}
	}()
	_ = memoryFixtureWindows(hardnatplan.Profile("unknown"))
}

// Read-only observations of the real memory composition, not a clock override.
// The result is printed even on the first RED; no sample is retried or discarded.
type gateC1bMemoryTimingWitness struct {
	mu        sync.Mutex
	start     [2]time.Time
	candidate [2]time.Time
	winner    [2]time.Time
	ready     [2]time.Time
	packets   [2]int
	success   [2]bool
}

// Observe only the existing progress callback. Fixed slots, monotonic process
// offsets and known stage names; no stream/packet/identity/path is recorded.
type gateC1bMemoryPhaseWitness struct {
	mu    sync.Mutex
	start time.Time
	seen  [2][32]bool
	at    [2][32]time.Duration
	io    [2][2]gateC1bMemoryIOWitness // side, read/write; never retains buffers.
}

type gateC1bMemoryIOWitness struct {
	started, finished int
	bytes             int
	begin, end        time.Duration
	err               string
}

// Observe the caller-provided memory stream only. The original connection,
// bytes, errors, deadlines and close behavior pass through unchanged; no I/O
// capability or retry is added. Pending operations remain visible at failure.
type gateC1bObservedMemoryConn struct {
	net.Conn
	witness *gateC1bMemoryPhaseWitness
	side    int
}

func (w *gateC1bMemoryPhaseWitness) observeStream(connection net.Conn, side int) net.Conn {
	return &gateC1bObservedMemoryConn{Conn: connection, witness: w, side: side}
}

func (connection *gateC1bObservedMemoryConn) Read(buffer []byte) (int, error) {
	connection.witness.beginIO(connection.side, 0)
	n, err := connection.Conn.Read(buffer)
	connection.witness.endIO(connection.side, 0, n, err)
	return n, err
}

func (connection *gateC1bObservedMemoryConn) Write(buffer []byte) (int, error) {
	connection.witness.beginIO(connection.side, 1)
	n, err := connection.Conn.Write(buffer)
	connection.witness.endIO(connection.side, 1, n, err)
	return n, err
}

func (w *gateC1bMemoryPhaseWitness) beginIO(side, direction int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry := &w.io[side][direction]
	entry.started++
	entry.begin = time.Since(w.start)
}

func (w *gateC1bMemoryPhaseWitness) endIO(side, direction, n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	entry := &w.io[side][direction]
	entry.finished++
	entry.bytes += n
	entry.end = time.Since(w.start)
	entry.err = "none"
	switch {
	case errors.Is(err, io.EOF):
		entry.err = "eof"
	case errors.Is(err, net.ErrClosed), errors.Is(err, io.ErrClosedPipe):
		entry.err = "closed"
	case errors.Is(err, os.ErrDeadlineExceeded):
		entry.err = "deadline"
	case err != nil:
		entry.err = "other"
	}
}

func newGateC1bMemoryPhaseWitness() *gateC1bMemoryPhaseWitness {
	return &gateC1bMemoryPhaseWitness{start: time.Now()}
}

func (w *gateC1bMemoryPhaseWitness) mark(side int, stage string) {
	if w == nil || side < 0 || side >= len(w.seen) {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for slot, known := range gatecorchestrator.ProductProgressSequence {
		if slot >= len(w.seen[side]) {
			return
		}
		if stage == known {
			if !w.seen[side][slot] {
				w.seen[side][slot], w.at[side][slot] = true, time.Since(w.start)
			}
			return
		}
	}
}

func (w *gateC1bMemoryPhaseWitness) report(t *testing.T) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	for side := range 2 {
		for slot, stage := range gatecorchestrator.ProductProgressSequence {
			if slot >= len(w.seen[side]) {
				t.Error("phase witness capacity exceeded")
				return
			}
			t.Logf("MEMORY_PHASE side=%d stage=%s seen=%t at_ns=%d", side, stage, w.seen[side][slot], w.at[side][slot].Nanoseconds())
		}
		for direction, entry := range w.io[side] {
			t.Logf("MEMORY_IO side=%d direction=%s started=%d finished=%d bytes=%d last_begin_ns=%d last_end_ns=%d error=%s",
				side, []string{"read", "write"}[direction], entry.started, entry.finished, entry.bytes,
				entry.begin.Nanoseconds(), entry.end.Nanoseconds(), entry.err)
		}
	}
}

func TestGateC1bMemoryPhaseWitnessIsBoundedFirstObservation(t *testing.T) {
	if len(gatecorchestrator.ProductProgressSequence) > 32 {
		t.Fatal("progress schema outgrew the bounded witness")
	}
	w := newGateC1bMemoryPhaseWitness()
	w.mark(0, gatecorchestrator.ProductProgressSequence[0])
	first := w.at[0][0]
	w.mark(0, gatecorchestrator.ProductProgressSequence[0])
	w.mark(-1, "private")
	w.mark(2, "private")
	w.mark(1, "private")
	if !w.seen[0][0] || w.at[0][0] != first || w.seen[1] != ([32]bool{}) {
		t.Fatal("repeated/unknown stage changed the first fixed-slot witness")
	}
	var workers sync.WaitGroup
	for side := range 2 {
		workers.Add(1)
		go func(side int) {
			defer workers.Done()
			for _, stage := range gatecorchestrator.ProductProgressSequence {
				w.mark(side, stage)
			}
		}(side)
	}
	workers.Wait()
	for side := range 2 {
		for slot := range gatecorchestrator.ProductProgressSequence {
			if !w.seen[side][slot] || w.at[side][slot] < 0 {
				t.Fatal("lost a concurrent phase observation")
			}
		}
	}
	t.Run("transparent_memory_stream", testGateC1bMemoryStreamWitness)
}

func testGateC1bMemoryStreamWitness(t *testing.T) {
	w := newGateC1bMemoryPhaseWitness()
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	writer, reader := w.observeStream(left, 0), w.observeStream(right, 1)
	if err := writer.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("original memory deadline failed")
	}
	if err := reader.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal("original memory read deadline failed")
	}
	joined := make(chan error, 1)
	go func() { _, err := writer.Write([]byte("SYNTHETIC_PRIVATE")); joined <- err }()
	buffer := make([]byte, len("SYNTHETIC_PRIVATE"))
	if _, err := io.ReadFull(reader, buffer); err != nil || string(buffer) != "SYNTHETIC_PRIVATE" {
		t.Fatal("stream witness changed bytes or errors")
	}
	select {
	case err := <-joined:
		if err != nil {
			t.Fatal("memory writer failed")
		}
	case <-time.After(time.Second):
		t.Fatal("memory writer did not join")
	}
	if err := writer.Close(); err != nil {
		t.Fatal("memory close failed")
	}
	if _, err := reader.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatal("close/EOF changed")
	}
	if w.io[0][1].started != 1 || w.io[0][1].finished != 1 || w.io[0][1].bytes != len(buffer) ||
		w.io[1][0].started != 2 || w.io[1][0].finished != 2 || w.io[1][0].err != "eof" {
		t.Fatal("memory stream counts lost actual completions")
	}
	w.beginIO(0, 0)
	w.endIO(0, 0, 0, errors.New("SYNTHETIC_PRIVATE"))
	if w.io[0][0].err != "other" {
		t.Fatal("stream error text was retained")
	}
}

func (w *gateC1bMemoryTimingWitness) stage(side int, stage string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	switch stage {
	case gateb.StagePreflight:
		w.start[side] = now
	case gateb.StageCandidates:
		w.candidate[side] = now
	case gateb.StageWinner:
		w.winner[side] = now
	case gatecorchestrator.StageDataPlaneReady:
		w.ready[side] = now
	}
}

func (w *gateC1bMemoryTimingWitness) finish(side int, result gatecorchestrator.Result) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.packets[side] = result.Witness.GateB.Emissions.CandidatePackets
	w.success[side] = result.DataPlaneReady
}

func (w *gateC1bMemoryTimingWitness) report(t *testing.T, profile gateC1bMemoryProfile, started time.Time) {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	var candidateMS, preflightMS [2]int64
	for side := range 2 {
		// Missing phase boundaries are explicit, never zero-time subtraction.
		candidateMS[side], preflightMS[side] = -1, -1
		if !w.candidate[side].IsZero() && !w.winner[side].IsZero() {
			candidateMS[side] = w.winner[side].Sub(w.candidate[side]).Milliseconds()
		}
		if !w.start[side].IsZero() && !w.ready[side].IsZero() {
			preflightMS[side] = w.ready[side].Sub(w.start[side]).Milliseconds()
		}
	}
	windows := memoryFixtureWindows(profile.profile)
	t.Logf("memory_fixture profile=%s gomaxprocs=%d busy_workers=2 candidate_budget_ms=%d active_budget_ms=%d candidate_to_winner_ms=%v preflight_to_ready_ms=%v candidates=%v ready=%v wall_ms=%d",
		profile.name, runtime.GOMAXPROCS(0), windows.candidateTime.Milliseconds(), windows.activeTime.Milliseconds(), candidateMS, preflightMS, w.packets, w.success, time.Since(started).Milliseconds())
}

func startGateC1bMemoryFixturePressure(t *testing.T) {
	t.Helper()
	stop, done := make(chan struct{}), make(chan struct{}, 2)
	var spins [2]atomic.Uint64
	for side := range 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			var value uint64 = 1
			for {
				select {
				case <-stop:
					return
				default:
				}
				for range 1024 {
					value = value*6364136223846793005 + 1
				}
				spins[side].Add(value | 1)
			}
		}()
	}
	t.Cleanup(func() {
		close(stop)
		deadline := time.NewTimer(2 * time.Second)
		defer deadline.Stop()
		for range 2 {
			select {
			case <-done:
			case <-deadline.C:
				t.Fatal("fixture pressure workers did not drain")
			}
		}
		if spins[0].Load() == 0 || spins[1].Load() == 0 {
			t.Fatal("both fixture pressure workers must actually run")
		}
		t.Log("memory_fixture pressure_workers=2 drained=2")
	})
}

func TestGateC1bMemoryFixtureStressSchedules(t *testing.T) {
	if os.Getenv("WINKYOU_FLAKE_119_STRESS") != "1" {
		t.Skip("fixture calibration requires explicit two-worker CPU pressure")
	}
	if runtime.GOMAXPROCS(0) != 2 {
		t.Fatal("fixture calibration requires GOMAXPROCS=2")
	}
	startGateC1bMemoryFixturePressure(t)
	for _, profile := range gateC1bMemoryProfiles {
		profile.cli, profile.timing = true, &gateC1bMemoryTimingWitness{}
		if !t.Run(profile.name, func(t *testing.T) {
			started := time.Now()
			defer profile.timing.report(t, profile, started)
			runGateC1bMemoryProductProfile(t, "fixture-stress-"+profile.name, profile)
		}) {
			t.FailNow()
		}
	}
}
