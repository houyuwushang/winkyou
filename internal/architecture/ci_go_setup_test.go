package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const ciGoSetupAction = "actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16" // v6.5.0

type ciGoSetupStep struct {
	Uses            string            `yaml:"uses"`
	TimeoutMinutes  int               `yaml:"timeout-minutes"`
	With            map[string]string `yaml:"with"`
	If              any               `yaml:"if"`
	ContinueOnError any               `yaml:"continue-on-error"`
}

func validCIGoSetup(step ciGoSetupStep) bool {
	token, hasToken := step.With["token"]
	return step.Uses == ciGoSetupAction && step.TimeoutMinutes == 2 &&
		step.If == nil && step.ContinueOnError == nil && len(step.With) == 3 &&
		step.With["go-version-file"] == "go.mod" &&
		step.With["go-download-base-url"] == "https://go.dev/dl" && hasToken && token == ""
}

func TestCIGoSetupUsesBoundedOfficialDownload(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repositoryRoot(t), ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatal("workflow files unavailable")
	}
	found := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var workflow struct {
			Jobs map[string]struct{ Steps []ciGoSetupStep }
		}
		if err := yaml.Unmarshal(data, &workflow); err != nil {
			t.Fatal(err)
		}
		for name, job := range workflow.Jobs {
			for _, step := range job.Steps {
				if strings.HasPrefix(step.Uses, "actions/setup-go@") {
					found++
					if !validCIGoSetup(step) {
						t.Errorf("%s/%s: Go setup must use the pinned action, official source, empty token and two-minute step bound", filepath.Base(file), name)
					}
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("Go setup missing")
	}
}

func TestCIGoSetupRejectsDownloadAndBypassMutations(t *testing.T) {
	for name, mutate := range map[string]func(*ciGoSetupStep){
		"old_installer":      func(s *ciGoSetupStep) { s.Uses = "actions/setup-go@v5" },
		"unbounded_install":  func(s *ciGoSetupStep) { s.TimeoutMinutes = 0 },
		"wrong_source":       func(s *ciGoSetupStep) { s.With["go-download-base-url"] = "https://example.invalid" },
		"implicit_token":     func(s *ciGoSetupStep) { delete(s.With, "token") },
		"forwarded_token":    func(s *ciGoSetupStep) { s.With["token"] = "${{ github.token }}" },
		"different_version":  func(s *ciGoSetupStep) { s.With["go-version"] = "stable" },
		"advisory_installer": func(s *ciGoSetupStep) { s.ContinueOnError = true },
		"skipped_installer":  func(s *ciGoSetupStep) { s.If = false },
	} {
		t.Run(name, func(t *testing.T) {
			step := ciGoSetupStep{Uses: ciGoSetupAction, TimeoutMinutes: 2, With: map[string]string{
				"go-version-file": "go.mod", "go-download-base-url": "https://go.dev/dl", "token": "",
			}}
			if !validCIGoSetup(step) {
				t.Fatal("valid setup rejected")
			}
			mutate(&step)
			if validCIGoSetup(step) {
				t.Fatal("invalid setup accepted")
			}
		})
	}
}

func TestCIGoSetupPublicPinPrivacyExceptionIsExact(t *testing.T) {
	if len(sourcePrivacyLine(ciGoSetupAction)) != 0 || len(docPrivacyLine("uses: "+ciGoSetupAction)) != 0 {
		t.Fatal("public action pin rejected")
	}
	for _, changed := range []string{
		strings.Replace(ciGoSetupAction, "924", "925", 1),
		ciGoSetupAction + ".example",
		strings.Replace(ciGoSetupAction, "actions/", "private/", 1),
	} {
		if len(sourcePrivacyLine(changed)) == 0 || len(docPrivacyLine("uses: "+changed)) == 0 {
			t.Fatal("privacy exception accepted a different identity")
		}
	}
}
