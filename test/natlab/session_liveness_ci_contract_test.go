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
	Jobs map[string]struct {
		Name           string
		RunsOn         string `yaml:"runs-on"`
		TimeoutMinutes string `yaml:"timeout-minutes"`
		Needs          []string
		If             string
		Env            map[string]string
		Strategy       struct {
			FailFast bool `yaml:"fail-fast"`
			Matrix   struct {
				Include []struct {
					Case           string
					Test           string
					TestTimeout    string `yaml:"test_timeout"`
					TimeoutMinutes int    `yaml:"timeout_minutes"`
				}
			}
		}
		Steps []struct {
			Run string
			Env map[string]string
		}
	}
}

func livenessCIContractViolations(payload []byte) []string {
	var workflow livenessCIWorkflow
	if err := yaml.Unmarshal(payload, &workflow); err != nil {
		return []string{"workflow decode"}
	}
	var violations []string
	windows := workflow.Jobs["real-wireguard-windows"]
	if windows.RunsOn != "windows-latest" || windows.TimeoutMinutes != "${{ matrix.timeout_minutes }}" || windows.Strategy.FailFast {
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
	if required.If != "always()" || !reflect.DeepEqual(required.Needs, []string{"model-and-owner", "real-wireguard", "real-wireguard-windows", "fresh100", "netns"}) ||
		len(required.Steps) != 1 || required.Steps[0].Env["WINDOWS_WIREGUARD"] != "${{ needs.real-wireguard-windows.result }}" ||
		!strings.Contains(required.Steps[0].Run, `test "$WINDOWS_WIREGUARD" = success`) {
		violations = append(violations, "required Windows aggregation")
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
}
