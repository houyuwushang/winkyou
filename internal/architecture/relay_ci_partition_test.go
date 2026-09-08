package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type relayCIJob struct {
	Name            string `yaml:"name"`
	RunsOn          string `yaml:"runs-on"`
	If              string `yaml:"if"`
	ContinueOnError bool   `yaml:"continue-on-error"`
	Steps           []struct {
		Run             string `yaml:"run"`
		If              string `yaml:"if"`
		ContinueOnError bool   `yaml:"continue-on-error"`
	} `yaml:"steps"`
}

func TestRelayCIPartitionPreservesEveryPlatformAndRepetition(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !relayCIPartitionValid(data) {
		t.Fatal("relay CI partition omitted, duplicated or weakened a required execution")
	}
}

func TestRelayCIPartitionDetectsOmissionAndCountMutations(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for name, rewrite := range map[string]func(string) string{
		"missing_windows": func(s string) string {
			return strings.Replace(s, "  relay-isolated-windows:", "  removed-relay-windows:", 1)
		},
		"reduced_smoke": func(s string) string { return strings.Replace(s, "-count=3\n", "-count=2\n", 1) },
		"missing_race": func(s string) string {
			return strings.Replace(s, "go test -race ./pkg/client -run", "go test ./pkg/client -run", 1)
		},
		"unbounded_skip": func(s string) string {
			return strings.ReplaceAll(s, "-skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'", "-skip '^TestRelay'")
		},
		"duplicate_in_bulk": func(s string) string {
			return strings.Replace(s, " -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'", "", 1)
		},
		"optional_windows": func(s string) string {
			return strings.Replace(s, "  relay-isolated-windows:\n", "  relay-isolated-windows:\n    continue-on-error: true\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
			changed := rewrite(normalized)
			if changed == normalized || relayCIPartitionValid([]byte(changed)) {
				t.Fatal("relay partition mutation escaped")
			}
		})
	}
}

func relayCIPartitionValid(data []byte) bool {
	var workflow struct {
		Jobs map[string]relayCIJob `yaml:"jobs"`
	}
	if yaml.Unmarshal(data, &workflow) != nil {
		return false
	}
	const test = "'^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'"
	bulk := "go test ./... -count=1 -skip " + test
	coreRace := "go test -race ./pkg/session ./pkg/client ./pkg/solver/... -count=1 -skip " + test
	ordinary := "go test ./pkg/client -run " + test + " -count=1"
	race := "go test -race ./pkg/client -run " + test + " -count=1"
	smoke := "go test ./pkg/client -run " + test + " -count=3"
	expected := map[string]struct {
		platform string
		commands []string
	}{
		"test-linux":             {"ubuntu-latest", []string{bulk, coreRace}},
		"test-windows":           {"windows-latest", []string{bulk}},
		"relay-smoke-linux":      {"ubuntu-latest", []string{smoke, ordinary, race}},
		"relay-isolated-windows": {"windows-latest", []string{ordinary}},
	}
	for id, want := range expected {
		job, ok := workflow.Jobs[id]
		if !ok || job.RunsOn != want.platform || job.If != "" || job.ContinueOnError || strings.Contains(strings.ToLower(job.Name), "advisory") {
			return false
		}
		var selected []string
		for _, step := range job.Steps {
			command := strings.Join(strings.Fields(step.Run), " ")
			if strings.Contains(command, "go test ./...") || strings.Contains(command, "go test -race ./pkg/session ./pkg/client") || strings.Contains(command, "TestRelayWGGoTwoEnginesExchangeIPv4Packets") {
				if step.If != "" || step.ContinueOnError {
					return false
				}
				selected = append(selected, command)
			}
		}
		if len(selected) != len(want.commands) {
			return false
		}
		for index := range selected {
			if selected[index] != want.commands[index] {
				return false
			}
		}
	}
	return true
}
