package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const gateC1bResponderSlowJob = "gate-c1b-responder-slow"

type gateC1bSlowCIJob struct {
	Name            string            `yaml:"name"`
	RunsOn          string            `yaml:"runs-on"`
	TimeoutMinutes  string            `yaml:"timeout-minutes"`
	If              any               `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
	Needs           any               `yaml:"needs"`
	Env             map[string]string `yaml:"env"`
	Strategy        struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   struct {
			OS      []string `yaml:"os"`
			Include []struct {
				OS             string `yaml:"os"`
				TimeoutMinutes int    `yaml:"timeout_minutes"`
			} `yaml:"include"`
			Exclude []any `yaml:"exclude"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []gateC1bCIStep `yaml:"steps"`
}

type gateC1bSlowCIWorkflow struct {
	Jobs map[string]gateC1bSlowCIJob `yaml:"jobs"`
}

func readGateC1bSlowCI(t *testing.T) gateC1bSlowCIWorkflow {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow gateC1bSlowCIWorkflow
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow
}

func TestGateC1bSlowCIPartitionPreservesBothRolesAndPlatforms(t *testing.T) {
	if failure := validateGateC1bSlowCI(readGateC1bSlowCI(t)); failure != "" {
		t.Fatal(failure)
	}
}

func TestGateC1bSlowCIPartitionRejectsOmissionAndConcurrencyMutations(t *testing.T) {
	for _, mutation := range []struct {
		name   string
		change func(*gateC1bSlowCIJob)
	}{
		{"missing_platform", func(j *gateC1bSlowCIJob) { j.Strategy.Matrix.OS = []string{"ubuntu-latest"} }},
		{"extra_platform_filter", func(j *gateC1bSlowCIJob) { j.Strategy.Matrix.Exclude = []any{"windows-latest"} }},
		{"fail_fast", func(j *gateC1bSlowCIJob) { v := true; j.Strategy.FailFast = &v }},
		{"advisory_job", func(j *gateC1bSlowCIJob) { j.ContinueOnError = true }},
		{"conditional_job", func(j *gateC1bSlowCIJob) { j.If = false }},
		{"dependent_job", func(j *gateC1bSlowCIJob) { j.Needs = "gate-c1b-memory-phases" }},
		{"changed_job_bound", func(j *gateC1bSlowCIJob) { j.TimeoutMinutes = "30" }},
		{"parallel_profiles", func(j *gateC1bSlowCIJob) { mutateGateC1bSlowCommand(j, "-parallel=1", "-parallel=3") }},
		{"reduced_repetitions", func(j *gateC1bSlowCIJob) { mutateGateC1bSlowCommand(j, "-count=20", "-count=19") }},
		{"filtered_profile", func(j *gateC1bSlowCIJob) { mutateGateC1bSlowCommand(j, "-parallel=1", "-skip hard-16k -parallel=1") }},
		{"wrong_role", func(j *gateC1bSlowCIJob) { mutateGateC1bSlowCommand(j, "SlowResponder", "Slow") }},
		{"flag_override", func(j *gateC1bSlowCIJob) { mutateGateC1bSlowCommand(j, "-v", "-v -count=1") }},
		{"advisory_step", func(j *gateC1bSlowCIJob) { j.Steps[len(j.Steps)-1].ContinueOnError = true }},
		{"conditional_step", func(j *gateC1bSlowCIJob) { j.Steps[len(j.Steps)-1].If = false }},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			workflow := readGateC1bSlowCI(t)
			job, ok := workflow.Jobs[gateC1bResponderSlowJob]
			if !ok {
				t.Fatal("mutation requires the real isolated job")
			}
			mutation.change(&job)
			workflow.Jobs[gateC1bResponderSlowJob] = job
			if validateGateC1bSlowCI(workflow) == "" {
				t.Fatal("invalid slow FINISH partition accepted")
			}
		})
	}
	t.Run("missing_job", func(t *testing.T) {
		workflow := readGateC1bSlowCI(t)
		delete(workflow.Jobs, gateC1bResponderSlowJob)
		if validateGateC1bSlowCI(workflow) == "" {
			t.Fatal("missing responder proof accepted")
		}
	})
	t.Run("duplicate_responder", func(t *testing.T) {
		workflow := readGateC1bSlowCI(t)
		job := workflow.Jobs["gate-c1b-memory-phases"]
		if !mutateGateC1bSlowCommand(&job, "SlowDurable", "Slow(Responder)?Durable") {
			t.Fatal("duplicate responder mutation missed the migrated initiator group")
		}
		workflow.Jobs["gate-c1b-memory-phases"] = job
		if validateGateC1bSlowCI(workflow) == "" {
			t.Fatal("duplicate responder proof accepted")
		}
	})
}

func mutateGateC1bSlowCommand(job *gateC1bSlowCIJob, before, after string) bool {
	changed := false
	for i := range job.Steps {
		changed = changed || strings.Contains(job.Steps[i].Run, before)
		job.Steps[i].Run = strings.ReplaceAll(job.Steps[i].Run, before, after)
	}
	return changed
}

func validateGateC1bSlowCI(workflow gateC1bSlowCIWorkflow) string {
	for _, expected := range []struct {
		job, step, command string
		timeout            string
	}{
		{
			job: "gate-c1b-memory-phases", timeout: "${{ matrix.timeout_minutes }}",
			step: "Repeat slow durable FINISH with bounded test-session headroom",
			command: "go test -race -tags=c1bproof ./internal/governor " +
				"-run '^TestGateC1bMemory(SlowDurableFinishReachesPostOOBEcho|FixtureSessionWindows)$' " +
				"-count=20 -timeout=10m",
		},
		{
			job: gateC1bResponderSlowJob, timeout: "15",
			step: "Repeat isolated responder slow FINISH without cross-profile concurrency",
			command: "go test -race -tags=c1bproof ./internal/governor " +
				"-run '^TestGateC1bMemorySlowResponderDurableFinishReachesPostOOBEcho$' " +
				"-parallel=1 -count=20 -timeout=10m -v",
		},
	} {
		job, ok := workflow.Jobs[expected.job]
		if !ok || job.TimeoutMinutes != expected.timeout || job.If != nil || job.ContinueOnError != nil || job.Needs != nil {
			return "slow FINISH requires independent bounded non-advisory jobs"
		}
		if job.RunsOn != "${{ matrix.os }}" || !strings.Contains(job.Name, "required") || job.Env["GORACE"] != "halt_on_error=1" ||
			job.Strategy.FailFast == nil || *job.Strategy.FailFast || len(job.Strategy.Matrix.Exclude) != 0 {
			return "slow FINISH platform or race policy changed"
		}
		platforms := job.Strategy.Matrix.OS
		if expected.job == "gate-c1b-memory-phases" {
			if !gateC1bPhaseCIBounds(job) {
				return "both original platforms require measured phases bounds"
			}
		} else if len(job.Strategy.Matrix.Include) != 0 || len(platforms) != 2 || platforms[0] != "ubuntu-latest" || platforms[1] != "windows-latest" {
			return "both original platforms must run the isolated responder role"
		}
		found := 0
		for _, step := range job.Steps {
			if step.Name != expected.step {
				continue
			}
			found++
			// Exact normalized commands reject trailing flag overrides and
			// subtest filters, not just a matching substring of the flags.
			if step.If != nil || step.ContinueOnError != nil || strings.Join(strings.Fields(step.Run), " ") != expected.command {
				return "slow FINISH selection, count, concurrency or time bound changed"
			}
		}
		if found != 1 {
			return "slow FINISH step missing or duplicated"
		}
	}
	return ""
}

// #146 relocates the initiator and consumer groups, without changing their
// commands, concurrency, selection or test-runner timeouts.
func gateC1bPhaseCIBounds(job gateC1bSlowCIJob) bool {
	legs := job.Strategy.Matrix.Include
	return job.TimeoutMinutes == "${{ matrix.timeout_minutes }}" &&
		job.RunsOn == "${{ matrix.os }}" &&
		job.Name == "Gate C1b Memory Phases (${{ matrix.os }}, required)" &&
		job.If == nil && job.ContinueOnError == nil && job.Needs == nil &&
		job.Strategy.FailFast != nil && !*job.Strategy.FailFast &&
		len(job.Strategy.Matrix.OS) == 0 && len(job.Strategy.Matrix.Exclude) == 0 &&
		len(legs) == 2 && legs[0].OS == "ubuntu-latest" && legs[0].TimeoutMinutes == 15 &&
		legs[1].OS == "windows-latest" && legs[1].TimeoutMinutes == 19
}
