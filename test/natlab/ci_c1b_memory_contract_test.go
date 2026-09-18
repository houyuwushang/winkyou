package natlab

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type c1bMemoryCIWorkflow struct{ Jobs map[string]c1bMemoryCIJob }
type c1bMemoryCIJob struct {
	Name            string
	RunsOn          string `yaml:"runs-on"`
	TimeoutMinutes  string `yaml:"timeout-minutes"`
	If, Needs       any
	ContinueOnError any `yaml:"continue-on-error"`
	Env             map[string]string
	Strategy        struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   struct {
			OS      []string
			Include []c1bMemoryCILeg
			Exclude []any
		}
	}
	Steps []c1bMemoryCIStep
}
type c1bMemoryCILeg struct {
	OS             string
	TimeoutMinutes int `yaml:"timeout_minutes"`
}
type c1bMemoryCIStep struct {
	Name, Uses, Run, Shell string
	If                     any
	ContinueOnError        any    `yaml:"continue-on-error"`
	TimeoutMinutes         string `yaml:"timeout-minutes"`
	WorkingDirectory       string `yaml:"working-directory"`
	With, Env              map[string]string
}

// Decoded run values are byte-for-byte the nine original commands, not regex
// substrings: trailing overrides, skips and wrappers must not pass this gate.
var c1bMemoryCICommands = []c1bMemoryCIStep{
	{Name: "Vet the tagged CLI and isolated process seams", Run: "go vet -tags=c1bproof ./cmd/wink/cmd ./internal/governor ./internal/probeio ./internal/v2/gatecorchestrator ./internal/v2/gatecstage ./internal/v2/sshassembly ./internal/v2/hardnatcontrol"},
	{Name: "Prove the untagged capability boundary and mutations", Run: "go test ./internal/architecture -run 'GateC1b' -count=1"},
	{Name: "Repeat the governed handoff and actual CLI pipelines with race detection", Run: "go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1b(MemoryProductPipelineReachesPostOOBEcho|MemoryCLIAndClaimedChildPipeline|GateBProductHandoffRetainsOwnershipUntilFinish)$' -count=20 -timeout=12m"},
	{Name: "Repeat consumer readiness, shared cap, cancellation and session tests", Run: "go test -race ./internal/probeio ./internal/v2/hardnatcontrol ./internal/v2/gatecorchestrator -run 'WireGuard|ConsumerReady|ConsumerFinished|Foreground|CanceledInner|PostOOB|Conflict' -skip '^Test(ConsumerFinished.*(Completion|ConfirmationAfterChallengeDeadline|DetachAfterChallengeDeadline)|WireGuardCompletion)' -count=20 -timeout=3m"},
	{Name: "Repeat completion-phase wall-clock and cancellation regressions", Run: "go test -race ./internal/probeio ./internal/v2/hardnatcontrol ./internal/v2/gatecorchestrator -run '^Test(ConsumerFinished.*(Completion|ConfirmationAfterChallengeDeadline|DetachAfterChallengeDeadline)|WireGuardCompletion)' -count=20 -timeout=12m"},
	{Name: "Repeat slow durable FINISH with bounded test-session headroom", Run: "go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemory(SlowDurableFinishReachesPostOOBEcho|FixtureSessionWindows)$' -count=20 -timeout=10m"},
	{Name: "Repeat cancellation after successful durable FINISH", Run: "go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryCancellationAfterDurableFinish$' -count=20 -timeout=3m"},
	{Name: "Repeat real-entry memory evidence drift and candidate exhaustion", Run: "go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryCLIEvidenceDriftAndExhaustionAreOneShot$' -count=20 -timeout=3m"},
	{Name: "Prove 100 fresh CLI and durable-slot lifecycles", Run: "go test -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryProductPipelineFresh100$' -v -count=1 -timeout=9m", Env: map[string]string{"WINKYOU_GATE_C1B_REPEAT_REQUIRED": "1"}},
}
var c1bMemoryCIGroups = []struct {
	key, label     string
	begin, end     int
	linux, windows int
}{
	{"pipelines", "Pipelines", 0, 3, 8, 12},
	{"phases", "Phases", 3, 8, 16, 21},
	{"fresh100", "Fresh100", 8, 9, 5, 6},
}

func c1bMemoryCISetup() []c1bMemoryCIStep {
	return []c1bMemoryCIStep{
		{Name: "Check out repository", Uses: "actions/checkout@v4"},
		{Name: "Set up Go", Uses: "actions/setup-go@v5", With: map[string]string{"go-version-file": "go.mod"}},
	}
}

// Numeric capture is the only new step: all original proof commands above and
// their test-runner timeouts stay unchanged, including failure behavior.
func c1bMemoryCICapture(group string) c1bMemoryCIStep {
	return c1bMemoryCIStep{
		Name: "Preserve numeric fixture timing", Uses: "./.github/actions/fixture-timing", If: "always()",
		With: map[string]string{"artifact-name": "fixture-timing-" + group + "-${{ matrix.os }}"},
	}
}

func c1bMemoryCIContractViolations(payload []byte) []string {
	var workflow c1bMemoryCIWorkflow
	if err := yaml.Unmarshal(payload, &workflow); err != nil {
		return []string{"invalid workflow"}
	}
	var violations []string
	if _, exists := workflow.Jobs["gate-c1b-memory-pipeline"]; exists {
		violations = append(violations, "legacy combined memory job")
	}
	for _, group := range c1bMemoryCIGroups {
		job, ok := workflow.Jobs["gate-c1b-memory-"+group.key]
		if !ok {
			violations = append(violations, group.key+" missing independent job")
			continue
		}
		if job.Name != "Gate C1b Memory "+group.label+" (${{ matrix.os }}, required)" ||
			job.RunsOn != "${{ matrix.os }}" || job.TimeoutMinutes != "${{ matrix.timeout_minutes }}" ||
			len(job.Strategy.Matrix.OS) != 0 || len(job.Strategy.Matrix.Exclude) != 0 ||
			!reflect.DeepEqual(job.Strategy.Matrix.Include, []c1bMemoryCILeg{{"ubuntu-latest", group.linux}, {"windows-latest", group.windows}}) {
			violations = append(violations, group.key+" exact OS, required name and measured ceilings")
		}
		if job.If != nil || job.ContinueOnError != nil || job.Needs != nil ||
			job.Strategy.FailFast == nil || *job.Strategy.FailFast {
			violations = append(violations, group.key+" independent non-advisory fail-fast-false")
		}
		if !reflect.DeepEqual(job.Env, map[string]string{
			"GORACE": "halt_on_error=1", "WINKYOU_FIXTURE_TIMING_DIR": "${{ github.workspace }}/../fixture-timing",
		}) {
			violations = append(violations, group.key+" original race environment")
		}
		wantSteps := append(c1bMemoryCISetup(), c1bMemoryCICommands[group.begin:group.end]...)
		wantSteps = append(wantSteps, c1bMemoryCICapture(group.key))
		if !reflect.DeepEqual(job.Steps, wantSteps) {
			violations = append(violations, group.key+" exact commands, order, setup and step environment")
		}
	}
	return violations
}
func c1bMemoryCIRead(t *testing.T) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal("C1b memory workflow unavailable")
	}
	return payload
}
func TestGateC1bMemoryCIContract(t *testing.T) {
	if violations := c1bMemoryCIContractViolations(c1bMemoryCIRead(t)); len(violations) != 0 {
		t.Fatalf("C1b memory partition lost its contract: %v", violations)
	}
}
func TestGateC1bMemoryCIContractMutations(t *testing.T) {
	payload := c1bMemoryCIRead(t)
	if violations := c1bMemoryCIContractViolations(payload); len(violations) != 0 {
		t.Fatalf("mutation baseline invalid: %v", violations)
	}
	for _, group := range c1bMemoryCIGroups {
		key := "gate-c1b-memory-" + group.key
		for _, mutation := range []struct {
			name, cause string
			change      func(*c1bMemoryCIJob)
		}{
			{"drop-command", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) {
				i := len(j.Steps) - 2 // Last original proof, not numeric capture.
				j.Steps = append(j.Steps[:i], j.Steps[i+1:]...)
			}},
			{"shorten-test-timeout", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) {
				i := len(j.Steps) - 2
				switch group.key {
				case "pipelines":
					j.Steps[i].Run = strings.Replace(j.Steps[i].Run, "-timeout=12m", "-timeout=11m", 1)
				case "phases":
					j.Steps[i].Run = strings.Replace(j.Steps[i].Run, "-timeout=3m", "-timeout=2m", 1)
				case "fresh100":
					j.Steps[i].Run = strings.Replace(j.Steps[i].Run, "-timeout=9m", "-timeout=8m", 1)
				}
			}},
			{"lower-count", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) {
				i := len(j.Steps) - 2
				if group.key == "fresh100" {
					j.Steps[i].Run = strings.Replace(j.Steps[i].Run, "-count=1", "-count=0", 1)
				} else {
					j.Steps[i].Run = strings.Replace(j.Steps[i].Run, "-count=20", "-count=19", 1)
				}
			}},
			{"low-linux-cap", "exact OS, required name and measured ceilings", func(j *c1bMemoryCIJob) { j.Strategy.Matrix.Include[0].TimeoutMinutes-- }},
			{"low-windows-cap", "exact OS, required name and measured ceilings", func(j *c1bMemoryCIJob) { j.Strategy.Matrix.Include[1].TimeoutMinutes-- }},
			{"drop-os", "exact OS, required name and measured ceilings", func(j *c1bMemoryCIJob) { j.Strategy.Matrix.Include = j.Strategy.Matrix.Include[:1] }},
			{"missing-required", "exact OS, required name and measured ceilings", func(j *c1bMemoryCIJob) { j.Name = strings.Replace(j.Name, ", required)", ")", 1) }},
			{"fail-fast", "independent non-advisory fail-fast-false", func(j *c1bMemoryCIJob) { v := true; j.Strategy.FailFast = &v }},
			{"missing-fail-fast", "independent non-advisory fail-fast-false", func(j *c1bMemoryCIJob) { j.Strategy.FailFast = nil }},
			{"conditional", "independent non-advisory fail-fast-false", func(j *c1bMemoryCIJob) { j.If = false }},
			{"advisory", "independent non-advisory fail-fast-false", func(j *c1bMemoryCIJob) { j.ContinueOnError = true }},
			{"dependent", "independent non-advisory fail-fast-false", func(j *c1bMemoryCIJob) { j.Needs = "another-job" }},
			{"race-env", "original race environment", func(j *c1bMemoryCIJob) { j.Env["GORACE"] = "halt_on_error=0" }},
			{"missing-capture-env", "original race environment", func(j *c1bMemoryCIJob) { delete(j.Env, "WINKYOU_FIXTURE_TIMING_DIR") }},
			{"changed-capture-env", "original race environment", func(j *c1bMemoryCIJob) { j.Env["WINKYOU_FIXTURE_TIMING_DIR"] += "/other" }},
			{"unavailable-runner-context", "original race environment", func(j *c1bMemoryCIJob) { j.Env["WINKYOU_FIXTURE_TIMING_DIR"] = "${{ runner.temp }}/fixture-timing" }},
			{"conditional-step", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[2].If = false }},
			{"advisory-step", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[2].ContinueOnError = true }},
			{"flag-override", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[len(j.Steps)-2].Run += " -count=1" }},
			{"missing-capture", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps = j.Steps[:len(j.Steps)-1] }},
			{"capture-success-only", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[len(j.Steps)-1].If = "success()" }},
			{"capture-bypasses-validation", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[len(j.Steps)-1].Uses = "actions/upload-artifact@v4" }},
			{"capture-advisory", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[len(j.Steps)-1].ContinueOnError = true }},
			{"capture-wrong-artifact", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) { j.Steps[len(j.Steps)-1].With["artifact-name"] = "other" }},
			{"capture-before-proof", "exact commands, order, setup and step environment", func(j *c1bMemoryCIJob) {
				i := len(j.Steps) - 1
				j.Steps[i], j.Steps[i-1] = j.Steps[i-1], j.Steps[i]
			}},
		} {
			t.Run(group.key+"/"+mutation.name, func(t *testing.T) {
				var workflow c1bMemoryCIWorkflow
				if err := yaml.Unmarshal(payload, &workflow); err != nil {
					t.Fatal(err)
				}
				job := workflow.Jobs[key]
				before, err := yaml.Marshal(job)
				if err != nil {
					t.Fatal(err)
				}
				mutation.change(&job)
				after, err := yaml.Marshal(job)
				if err != nil || string(before) == string(after) {
					t.Fatal("mutation did not change its real target")
				}
				workflow.Jobs[key] = job
				c1bMemoryCIReject(t, workflow, group.key+" "+mutation.cause)
			})
		}
	}
	t.Run("fresh100-required-flag", func(t *testing.T) {
		var workflow c1bMemoryCIWorkflow
		if err := yaml.Unmarshal(payload, &workflow); err != nil {
			t.Fatal(err)
		}
		job := workflow.Jobs["gate-c1b-memory-fresh100"]
		delete(job.Steps[2].Env, "WINKYOU_GATE_C1B_REPEAT_REQUIRED")
		workflow.Jobs["gate-c1b-memory-fresh100"] = job
		c1bMemoryCIReject(t, workflow, "fresh100 exact commands, order, setup and step environment")
	})
	t.Run("recombine-all-nine-commands", func(t *testing.T) {
		var workflow c1bMemoryCIWorkflow
		if err := yaml.Unmarshal(payload, &workflow); err != nil {
			t.Fatal(err)
		}
		combined := workflow.Jobs["gate-c1b-memory-pipelines"]
		combined.Steps = c1bMemoryCISetup()
		for _, group := range c1bMemoryCIGroups {
			key := "gate-c1b-memory-" + group.key
			steps := workflow.Jobs[key].Steps
			if !reflect.DeepEqual(steps[len(steps)-1], c1bMemoryCICapture(group.key)) {
				t.Fatal("numeric capture baseline changed")
			}
			combined.Steps = append(combined.Steps, steps[2:len(steps)-1]...)
			delete(workflow.Jobs, key)
		}
		if !reflect.DeepEqual(combined.Steps[2:], c1bMemoryCICommands) {
			t.Fatal("combined mutation lost original commands")
		}
		workflow.Jobs["gate-c1b-memory-pipeline"] = combined
		c1bMemoryCIReject(t, workflow, "legacy combined memory job")
	})
}
func c1bMemoryCIReject(t *testing.T, workflow c1bMemoryCIWorkflow, cause string) {
	t.Helper()
	changed, err := yaml.Marshal(workflow)
	if err != nil {
		t.Fatal(err)
	}
	violations := c1bMemoryCIContractViolations(changed)
	for _, violation := range violations {
		if violation == cause {
			return
		}
	}
	t.Fatalf("mutation missed its specific invariant %q: %v", cause, violations)
}

// Run 35308117620 measured a 12-second collector maximum. Every capturing
// leg reserves that same maximum; model/non-capturing jobs reserve zero.
const fixtureTimingCollectorMaxSeconds = 12

func TestGateC1bMemoryCIContractBudget(t *testing.T) {
	// Union of evidence §8 and PR #150's first push/PR attempts. Checkout +
	// setup-go maxima are 83s/18s, counted once per job. See timing evidence §5.
	for _, budget := range []struct {
		key, os     string
		setup       int
		steps       []int
		extra, want int
	}{
		{"pipelines", "windows-latest", 83, []int{40, 10, 429}, 0, 12},
		{"pipelines", "ubuntu-latest", 18, []int{12, 4, 311}, 0, 8},
		{"phases", "windows-latest", 83, []int{118, 203, 389, 89, 91}, 0, 21},
		{"phases", "ubuntu-latest", 18, []int{46, 191, 341, 68, 49}, 0, 16},
		{"fresh100", "windows-latest", 83, []int{189}, 0, 6},
		{"fresh100", "ubuntu-latest", 18, []int{117}, 1, 5},
	} {
		t.Run(budget.key+"/"+budget.os, func(t *testing.T) {
			seconds := budget.setup + fixtureTimingCollectorMaxSeconds
			for _, step := range budget.steps {
				seconds += step
			}
			// Exact ceil(1.25 * seconds / 60). Only Linux Fresh100 has the
			// expressly authorized extra setup minute (now 4m -> 5m).
			minutes := (5*seconds+239)/240 + budget.extra
			if minutes != budget.want {
				t.Fatal("measured ceiling arithmetic changed")
			}
			var workflow c1bMemoryCIWorkflow
			if err := yaml.Unmarshal(c1bMemoryCIRead(t), &workflow); err != nil {
				t.Fatal(err)
			}
			found := false
			for _, leg := range workflow.Jobs["gate-c1b-memory-"+budget.key].Strategy.Matrix.Include {
				if leg.OS == budget.os {
					found = true
					if leg.TimeoutMinutes != minutes {
						t.Fatal("workflow ceiling differs from measured formula")
					}
				}
			}
			if !found {
				t.Fatal("measured budget has no matching job/platform")
			}
			job := workflow.Jobs["gate-c1b-memory-"+budget.key]
			for i := range job.Strategy.Matrix.Include {
				if job.Strategy.Matrix.Include[i].OS == budget.os {
					job.Strategy.Matrix.Include[i].TimeoutMinutes = minutes - 1
				}
			}
			workflow.Jobs["gate-c1b-memory-"+budget.key] = job
			c1bMemoryCIReject(t, workflow, budget.key+" exact OS, required name and measured ceilings")
			t.Logf("C1B_MEMORY_CI_BUDGET leg=%s os=%s measured_seconds=%d timeout_minutes=%d first_run_limit_seconds=%d", budget.key, budget.os, seconds, minutes, 48*minutes)
		})
	}
}
