package architecture

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const gateC1bOriginalConsumerSelection = "WireGuard|ConsumerReady|ConsumerFinished|Foreground|CanceledInner|PostOOB|Conflict"

var gateC1bConsumerPackages = []string{
	"internal/probeio", "internal/v2/hardnatcontrol", "internal/v2/gatecorchestrator",
}

func TestGateC1bConsumerCIPartitionPreservesEveryRegression(t *testing.T) {
	workflow, tests := gateC1bConsumerCIInputs(t)
	if violations := gateC1bConsumerCIPartition(workflow, tests); len(violations) != 0 {
		t.Fatalf("consumer CI partition lost its contract: %v", violations)
	}
}

func TestGateC1bConsumerCIPartitionRejectsOmissionAndBudgetMutations(t *testing.T) {
	workflow, tests := gateC1bConsumerCIInputs(t)
	text := string(workflow)
	for _, mutation := range []struct{ name, before, after string }{
		{"missing_group", "Repeat completion-phase wall-clock and cancellation regressions", "Removed completion group"},
		{"missing_confirmation", "ConfirmationAfterChallengeDeadline", "NotARealConfirmationTest"},
		{"duplicate_tests", "-skip '^Test(ConsumerFinished", "-skip '^NoTest(ConsumerFinished"},
		{"reduced_repetitions", "-count=20 -timeout=3m", "-count=19 -timeout=3m"},
		{"changed_ordinary_timeout", "-count=20 -timeout=3m", "-count=20 -timeout=6m"},
		{"advisory_group", "- name: Repeat completion-phase wall-clock and cancellation regressions", "- name: Repeat completion-phase wall-clock and cancellation regressions\n        continue-on-error: true"},
		{"conditional_group", "- name: Repeat completion-phase wall-clock and cancellation regressions", "- name: Repeat completion-phase wall-clock and cancellation regressions\n        if: false"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			changed := strings.Replace(text, mutation.before, mutation.after, 1)
			if changed == text {
				t.Fatal("mutation did not reach its CI target")
			}
			if violations := gateC1bConsumerCIPartition([]byte(changed), tests); len(violations) == 0 {
				t.Fatal("invalid test partition was accepted")
			}
		})
	}
}

// Inventory top-level tests in the same three packages, including both OS test
// files. The anchored CI partition never filters child subtests. This protects
// coverage, not just a hand-maintained list of the currently slow tests.
func gateC1bConsumerCIInputs(t *testing.T) ([]byte, []string) {
	t.Helper()
	root := repositoryRoot(t)
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var tests []string
	for _, pkg := range gateC1bConsumerPackages {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(pkg)))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(pkg), entry.Name()), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, declaration := range file.Decls {
				fn, ok := declaration.(*ast.FuncDecl)
				if ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
					tests = append(tests, fn.Name.Name)
				}
			}
		}
	}
	return workflow, tests
}

type gateC1bCIStep struct {
	Name            string `yaml:"name"`
	Run             string `yaml:"run"`
	If              any    `yaml:"if"`
	ContinueOnError any    `yaml:"continue-on-error"`
}

func gateC1bConsumerCIPartition(data []byte, tests []string) []string {
	var workflow struct {
		Jobs map[string]struct {
			TimeoutMinutes int             `yaml:"timeout-minutes"`
			Steps          []gateC1bCIStep `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		return []string{"invalid workflow"}
	}
	job, ok := workflow.Jobs["gate-c1b-memory-pipeline"]
	if !ok || job.TimeoutMinutes != 25 {
		return []string{"original required job or its 25m bound changed"}
	}
	var selected [2]*regexp.Regexp
	var excluded *regexp.Regexp
	for index, expected := range []struct{ name, timeout string }{
		{"Repeat consumer readiness, shared cap, cancellation and session tests", "3m"},
		{"Repeat completion-phase wall-clock and cancellation regressions", "12m"},
	} {
		var matches []gateC1bCIStep
		for _, step := range job.Steps {
			if step.Name == expected.name {
				matches = append(matches, step)
			}
		}
		if len(matches) != 1 {
			return []string{"missing or duplicate required consumer group"}
		}
		step := matches[0]
		if step.If != nil || step.ContinueOnError != nil || !strings.Contains(step.Run, "go test -race ") ||
			!strings.Contains(step.Run, "-count=20 -timeout="+expected.timeout) {
			return []string{"consumer group became conditional, advisory or changed repetitions/time bound"}
		}
		for _, pkg := range gateC1bConsumerPackages {
			if !strings.Contains(step.Run, "./"+pkg) {
				return []string{"consumer package lost from group"}
			}
		}
		run := regexp.MustCompile(`-run '([^']+)'`).FindStringSubmatch(step.Run)
		if len(run) != 2 {
			return []string{"consumer group lacks its explicit selector"}
		}
		var err error
		selected[index], err = regexp.Compile(run[1])
		if err != nil {
			return []string{"invalid consumer selector"}
		}
		skip := regexp.MustCompile(`-skip '([^']+)'`).FindStringSubmatch(step.Run)
		if index == 0 {
			if run[1] != gateC1bOriginalConsumerSelection || len(skip) != 2 || !strings.HasPrefix(skip[1], "^Test") {
				return []string{"ordinary group changed its original scope or filters child subtests"}
			}
			excluded, err = regexp.Compile(skip[1])
			if err != nil {
				return []string{"invalid ordinary exclusion"}
			}
		} else if len(skip) != 0 || !strings.HasPrefix(run[1], "^Test") || run[1] != excluded.String() {
			return []string{"completion group is not the exact anchored complement"}
		}
	}
	var violations []string
	original := regexp.MustCompile(gateC1bOriginalConsumerSelection)
	for _, test := range tests {
		count := 0
		if selected[0].MatchString(test) && !excluded.MatchString(test) {
			count++
		}
		if selected[1].MatchString(test) {
			count++
		}
		want := 0
		if original.MatchString(test) {
			want = 1
		}
		if count != want {
			violations = append(violations, fmt.Sprintf("%s selected %d times, want %d", test, count, want))
		}
	}
	return violations
}
