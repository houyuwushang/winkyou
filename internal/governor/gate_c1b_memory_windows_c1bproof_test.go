//go:build c1bproof

package governor_test

import (
	"go/ast"
	"go/parser"
	"go/token"
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

// The old profile timing fields no longer exist, so entry-specific assignments
// cannot compile. This gate also rejects a second hook or inline hook override.
func memoryFixtureWindowSourceValid(source []byte, ownsHook bool) bool {
	file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", source, 0)
	if err != nil {
		return false
	}
	hooks, timingSelectors, sourceCalls := 0, 0, 0
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
		ast.Inspect(function, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if ok && name.Name == "memoryFixtureWindows" {
				sourceCalls++
			}
			return true
		})
	}
	if ownsHook {
		return valid && hooks == 1 && timingSelectors == 2 && sourceCalls == 1
	}
	return valid && hooks == 0 && timingSelectors == 0 && sourceCalls == 0
}

func testGateC1bMemoryFixtureWindowSource(t *testing.T) {
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
