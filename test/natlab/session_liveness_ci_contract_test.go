package natlab

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type livenessCIWorkflow struct {
	Jobs map[string]livenessCIJob
}

type livenessCIJob struct {
	Name            string
	RunsOn          string `yaml:"runs-on"`
	TimeoutMinutes  string `yaml:"timeout-minutes"`
	ContinueOnError string `yaml:"continue-on-error"`
	Needs           []string
	If              string
	Env             map[string]string
	Strategy        struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   struct {
			OS      []string `yaml:"os"`
			Include []struct {
				OS             string `yaml:"os"`
				Case           string
				Test           string
				TestTimeout    string `yaml:"test_timeout"`
				TimeoutMinutes int    `yaml:"timeout_minutes"`
			}
		}
	}
	Steps []livenessCIStep
}

type livenessCIStep struct {
	Name, Uses, Run, If, Shell string
	ContinueOnError            string `yaml:"continue-on-error"`
	Env, With                  map[string]string
}

const (
	livenessCIVet        = "go vet ./..."
	livenessCIAffected   = "go test -race -count=20 -timeout=15m ./internal/probeio ./internal/v2/gatecorchestrator ./pkg/config ./pkg/tunnel"
	livenessCIArch       = "go test -race ./internal/architecture -run 'SessionLiveness|GateC1b' -count=20"
	livenessCIOwner      = "go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessOwnerTripCasesAreDistinct$' -count=20 -timeout=8m"
	livenessCIBusiness   = "go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessBusinessCoexistsWithTap$' -count=20 -timeout=8m"
	livenessCIRestart    = "go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessRestartRejectsSpentArtifactBeforeIO$' -count=1 -timeout=2m"
	livenessCIByteVector = "python internal/v2/gatecorchestrator/testdata/liveness_reference.py"
)

// Source: docs/GATE-C-LIVENESS-EVIDENCE.md section 11.2. These are completed
// CI step wall clocks, never product windows or test-runner timeouts.
var livenessCISplitBudgets = []struct {
	job, os        string
	setupSeconds   int
	stepSeconds    []int
	timeoutMinutes int
}{
	{"model", "ubuntu-latest", 17, []int{11, 257, 156, 1}, 10},
	{"model", "windows-latest", 93, []int{38, 300, 190, 5}, 14},
	{"owner", "ubuntu-latest", 17, []int{286, 240, 15}, 12},
	{"owner", "windows-latest", 93, []int{363, 266, 22}, 16},
}

func livenessCISplitViolations(workflow livenessCIWorkflow) []string {
	var violations []string
	if _, combined := workflow.Jobs["model-and-owner"]; combined {
		violations = append(violations, "legacy combined model/owner job")
	}
	commands := map[string][]string{
		"model": {livenessCIVet, livenessCIAffected, livenessCIArch, livenessCIByteVector},
		"owner": {livenessCIOwner, livenessCIBusiness, livenessCIRestart},
	}
	for _, name := range []string{"model", "owner"} {
		job, exists := workflow.Jobs[name]
		if !exists || job.Name != "Liveness "+name+" (${{ matrix.os }})" || job.RunsOn != "${{ matrix.os }}" || job.TimeoutMinutes != "${{ matrix.timeout_minutes }}" ||
			job.Strategy.FailFast == nil || *job.Strategy.FailFast || job.If != "" || job.ContinueOnError != "" || len(job.Needs) != 0 {
			violations = append(violations, name+" independent fail-fast-false matrix")
		}
		want := map[string]int{}
		for _, budget := range livenessCISplitBudgets {
			if budget.job == name {
				want[budget.os] = budget.timeoutMinutes
			}
		}
		actual := map[string]int{}
		for _, leg := range job.Strategy.Matrix.Include {
			actual[leg.OS] = leg.TimeoutMinutes
			if leg.Case != "" || leg.Test != "" || leg.TestTimeout != "" {
				violations = append(violations, name+" unexpected matrix dimension")
			}
		}
		if len(job.Strategy.Matrix.OS) != 0 || len(job.Strategy.Matrix.Include) != 2 || !reflect.DeepEqual(actual, want) {
			violations = append(violations, name+" exact two OS and measured ceilings")
		}
		wantEnv := map[string]string{"GORACE": "halt_on_error=1"}
		if name == "owner" {
			wantEnv["WINKYOU_FIXTURE_TIMING_DIR"] = "${{ runner.temp }}/fixture-timing"
		}
		if !reflect.DeepEqual(job.Env, wantEnv) {
			violations = append(violations, name+" original race environment")
		}
		actualCommands := []string{}
		captureCount := 0
		for index, step := range job.Steps {
			if name == "owner" && step.Uses == "./.github/actions/fixture-timing" {
				want := livenessCIStep{Name: "Preserve numeric fixture timing", Uses: "./.github/actions/fixture-timing", If: "always()",
					With: map[string]string{"artifact-name": "fixture-timing-owner-${{ matrix.os }}"}}
				if !reflect.DeepEqual(step, want) || index != len(job.Steps)-1 {
					violations = append(violations, "owner bounded numeric capture changed")
				}
				captureCount++
				continue
			}
			if step.Run != "" {
				actualCommands = append(actualCommands, step.Run)
			}
			if step.If != "" || step.ContinueOnError != "" || step.Shell != "" || len(step.Env) != 0 {
				violations = append(violations, name+" step cannot skip or override proof")
			}
		}
		wantSetup := []livenessCIStep{
			{Uses: "actions/checkout@v4"},
			{Uses: "actions/setup-go@v5", With: map[string]string{"go-version-file": "go.mod"}},
		}
		wantCapture := 0
		if name == "owner" {
			wantCapture = 1
		}
		if captureCount != wantCapture || !reflect.DeepEqual(actualCommands, commands[name]) || len(job.Steps) != len(commands[name])+2+wantCapture ||
			len(job.Steps) < 2 || !reflect.DeepEqual(job.Steps[:2], wantSetup) {
			violations = append(violations, name+" exact original commands and setup")
		}
	}
	return violations
}

func livenessCIContractViolations(payload []byte) []string {
	var workflow livenessCIWorkflow
	if err := yaml.Unmarshal(payload, &workflow); err != nil {
		return []string{"workflow decode"}
	}
	violations := livenessCISplitViolations(workflow)
	windows := workflow.Jobs["real-wireguard-windows"]
	if windows.RunsOn != "windows-latest" || windows.TimeoutMinutes != "${{ matrix.timeout_minutes }}" || windows.Strategy.FailFast == nil || *windows.Strategy.FailFast {
		violations = append(violations, "Windows independent jobs")
	}
	want := map[string]string{
		"idle":       "TestSessionLivenessMemoryIdle180Required/6m/7",
		"blackholes": "TestSessionLivenessMemoryBlackholesRequired/4m/6",
		"nonproof":   "TestSessionLivenessOneWayTrafficCannotReplaceProofRequired/6m/8",
	}
	actual := map[string]string{}
	for _, leg := range windows.Strategy.Matrix.Include {
		actual[leg.Case] = fmt.Sprintf("%s/%s/%d", leg.Test, leg.TestTimeout, leg.TimeoutMinutes)
	}
	if len(windows.Strategy.Matrix.Include) != 3 || !reflect.DeepEqual(actual, want) {
		violations = append(violations, "Windows exact three proofs and measured ceilings")
	}
	const prefix = "go test -race -tags=c1bproof ./internal/governor -run '^"
	const suffix = "$' -count=1 -v -timeout="
	windowsCommands := []string{}
	for _, step := range windows.Steps {
		if step.Run != "" {
			windowsCommands = append(windowsCommands, step.Run)
		}
	}
	if !reflect.DeepEqual(windowsCommands, []string{prefix + "${{ matrix.test }}" + suffix + "${{ matrix.test_timeout }}"}) ||
		windows.Env["WINKYOU_LIVENESS_IDLE_REQUIRED"] != "1" || windows.Env["WINKYOU_LIVENESS_BLACKHOLE_REQUIRED"] != "1" {
		violations = append(violations, "Windows original command and required flags")
	}
	linux := workflow.Jobs["real-wireguard"]
	linuxCommands := []string{}
	for _, step := range linux.Steps {
		if step.Run != "" {
			linuxCommands = append(linuxCommands, step.Run)
		}
	}
	if linux.RunsOn != "ubuntu-latest" || linux.TimeoutMinutes != "14" || !reflect.DeepEqual(linuxCommands, []string{
		prefix + "TestSessionLivenessMemoryIdle180Required" + suffix + "6m",
		prefix + "TestSessionLivenessMemoryBlackholesRequired" + suffix + "4m",
		prefix + "TestSessionLivenessOneWayTrafficCannotReplaceProofRequired" + suffix + "6m",
	}) {
		violations = append(violations, "Linux original three commands")
	}
	required := workflow.Jobs["required"]
	wantRequiredEnv := map[string]string{
		"MODEL": "${{ needs.model.result }}", "OWNER": "${{ needs.owner.result }}",
		"WIREGUARD": "${{ needs.real-wireguard.result }}", "WINDOWS_WIREGUARD": "${{ needs.real-wireguard-windows.result }}",
		"FRESH": "${{ needs.fresh100.result }}", "NETNS": "${{ needs.netns.result }}",
	}
	const requiredCommand = `test "$MODEL" = success && test "$OWNER" = success && test "$WIREGUARD" = success && test "$WINDOWS_WIREGUARD" = success && test "$FRESH" = success && test "$NETNS" = success`
	if required.If != "always()" || required.ContinueOnError != "" || required.RunsOn != "ubuntu-latest" ||
		!reflect.DeepEqual(required.Needs, []string{"model", "owner", "real-wireguard", "real-wireguard-windows", "fresh100", "netns"}) ||
		len(required.Steps) != 1 || !reflect.DeepEqual(required.Steps[0].Env, wantRequiredEnv) || required.Steps[0].Run != requiredCommand ||
		required.Steps[0].If != "" || required.Steps[0].ContinueOnError != "" {
		violations = append(violations, "required complete fail-closed aggregation")
	}
	return violations
}

func TestSessionLivenessCIContract(t *testing.T) {
	payload, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "session-liveness.yml"))
	if err != nil {
		t.Fatal("liveness workflow unavailable")
	}
	if violations := livenessCIContractViolations(payload); len(violations) != 0 {
		t.Fatalf("liveness proof partition changed: %v", violations)
	}
	for _, mutation := range []struct{ name, before, after string }{
		{"drop-proof", "- case: nonproof", "- case: idle"},
		{"skip-required", "WINKYOU_LIVENESS_IDLE_REQUIRED: '1'", "WINKYOU_LIVENESS_IDLE_REQUIRED: '0'"},
		{"lower-count", "-count=1 -v", "-count=0 -v"},
		{"shorten-test-runner", "test_timeout: 6m", "test_timeout: 3m"},
		{"lose-aggregation", "real-wireguard, real-wireguard-windows, fresh100", "real-wireguard, fresh100"},
		{"ignore-failure", `test "$WINDOWS_WIREGUARD" = success`, `test "$WINDOWS_WIREGUARD" != unknown`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(string(payload), mutation.before, mutation.after, -1)
			if changed == string(payload) || len(livenessCIContractViolations([]byte(changed))) == 0 {
				t.Fatal("CI partition mutation escaped")
			}
		})
	}
	for _, mutation := range []struct{ name, before, after, cause string }{
		{"model-drop-command", livenessCIVet, "true", "model exact original commands and setup"},
		{"owner-drop-command", livenessCIBusiness, "true", "owner exact original commands and setup"},
		{"model-shorten-timeout", livenessCIAffected, strings.Replace(livenessCIAffected, "-timeout=15m", "-timeout=14m", 1), "model exact original commands and setup"},
		{"owner-shorten-timeout", livenessCIOwner, strings.Replace(livenessCIOwner, "-timeout=8m", "-timeout=7m", 1), "owner exact original commands and setup"},
		{"model-lower-count", livenessCIAffected, strings.Replace(livenessCIAffected, "-count=20", "-count=19", 1), "model exact original commands and setup"},
		{"owner-lower-count", livenessCIBusiness, strings.Replace(livenessCIBusiness, "-count=20", "-count=19", 1), "owner exact original commands and setup"},
		{"restart-shorten-timeout", livenessCIRestart, strings.Replace(livenessCIRestart, "-timeout=2m", "-timeout=1m", 1), "owner exact original commands and setup"},
		{"model-low-windows-ceiling", "timeout_minutes: 14", "timeout_minutes: 13", "model exact two OS and measured ceilings"},
		{"model-low-linux-ceiling", "timeout_minutes: 10", "timeout_minutes: 9", "model exact two OS and measured ceilings"},
		{"owner-low-windows-ceiling", "timeout_minutes: 16", "timeout_minutes: 15", "owner exact two OS and measured ceilings"},
		{"owner-low-linux-ceiling", "timeout_minutes: 12", "timeout_minutes: 11", "owner exact two OS and measured ceilings"},
		{"drop-model-dependency", "needs: [model, owner,", "needs: [owner,", "required complete fail-closed aggregation"},
		{"drop-owner-dependency", "needs: [model, owner,", "needs: [model,", "required complete fail-closed aggregation"},
		{"ignore-model-result", `test "$MODEL" = success && `, "", "required complete fail-closed aggregation"},
		{"ignore-owner-result", `test "$OWNER" = success && `, "", "required complete fail-closed aggregation"},
		{"wrong-owner-result-binding", "OWNER: ${{ needs.owner.result }}", "OWNER: ${{ needs.model.result }}", "required complete fail-closed aggregation"},
		{"required-skips-failure", "if: always()", "if: success()", "required complete fail-closed aggregation"},
		{"fail-fast-enabled", "fail-fast: false", "fail-fast: true", "model independent fail-fast-false matrix"},
		{"fail-fast-omitted", "      fail-fast: false\n", "", "owner independent fail-fast-false matrix"},
		{"owner-continue-on-error", "  owner:\n", "  owner:\n    continue-on-error: true\n", "owner independent fail-fast-false matrix"},
		{"model-skip-command", "      - name: Vet\n", "      - name: Vet\n        if: false\n", "model step cannot skip or override proof"},
		{"race-environment-change", "GORACE: halt_on_error=1", "GORACE: halt_on_error=0", "owner original race environment"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			original := strings.ReplaceAll(string(payload), "\r\n", "\n")
			changed := strings.ReplaceAll(original, mutation.before, mutation.after)
			if original == changed {
				t.Fatal("CI mutation fixture did not change the workflow")
			}
			violations := livenessCIContractViolations([]byte(changed))
			if !livenessCIHasViolation(violations, mutation.cause) {
				t.Fatalf("CI mutation missed its specific invariant: %v", violations)
			}
		})
	}
	t.Run("combine-model-and-owner", func(t *testing.T) {
		var combined livenessCIWorkflow
		if err := yaml.Unmarshal(payload, &combined); err != nil {
			t.Fatal("combined-job mutation fixture decode failed")
		}
		model, owner := combined.Jobs["model"], combined.Jobs["owner"]
		vector := model.Steps[len(model.Steps)-1]
		model.Steps = append(model.Steps[:len(model.Steps)-1], owner.Steps[2:]...)
		model.Steps = append(model.Steps, vector)
		combined.Jobs["model-and-owner"] = model
		delete(combined.Jobs, "model")
		delete(combined.Jobs, "owner")
		// This mutation keeps all seven commands in one actual job; merely
		// renaming or deleting a proof would not prove the split invariant.
		var commands []string
		for _, step := range model.Steps {
			if step.Run != "" {
				commands = append(commands, step.Run)
			}
		}
		if !reflect.DeepEqual(commands, []string{livenessCIVet, livenessCIAffected, livenessCIArch, livenessCIOwner, livenessCIBusiness, livenessCIRestart, livenessCIByteVector}) {
			t.Fatal("combined-job mutation did not preserve the original seven commands")
		}
		changed, err := yaml.Marshal(combined)
		if err != nil || !livenessCIHasViolation(livenessCIContractViolations(changed), "legacy combined model/owner job") {
			t.Fatal("combined-job mutation escaped")
		}
	})
}

func livenessCIHasViolation(violations []string, want string) bool {
	for _, violation := range violations {
		if violation == want {
			return true
		}
	}
	return false
}

func TestSessionLivenessCIContractBudget(t *testing.T) {
	for _, budget := range livenessCISplitBudgets {
		t.Run(budget.job+"-"+budget.os, func(t *testing.T) {
			seconds := budget.setupSeconds
			for _, step := range budget.stepSeconds {
				seconds += step
			}
			// ceil(1.25 * seconds / 60), exactly, without a floating-point
			// approximation and with the measured setup included only once.
			minutes := (5*seconds + 239) / 240
			if budget.timeoutMinutes != minutes {
				t.Fatalf("measured ceiling mismatch: got %d want %d", budget.timeoutMinutes, minutes)
			}
			t.Logf("LIVENESS_CI_BUDGET job=%s os=%s measured_seconds=%d timeout_minutes=%d first_run_limit_seconds=%d",
				budget.job, budget.os, seconds, minutes, 48*minutes)
		})
	}
}
