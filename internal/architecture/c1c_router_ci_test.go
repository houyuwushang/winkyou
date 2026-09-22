package architecture

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestC1cRouterRequiredCIBudget(t *testing.T) {
	const preparation = 63 * time.Second
	const symbols = 56 * time.Second
	const twoBuilds = 46 * time.Second
	const focusedRace = 35 * time.Second
	const matrix = 7 * time.Minute
	const guardian = time.Minute
	budget := (preparation + symbols + twoBuilds + focusedRace + matrix + guardian) * 5 / 4
	if (budget+time.Minute-1)/time.Minute != 15 {
		t.Fatal("router budget derivation changed")
	}
	b, e := os.ReadFile(filepath.Join(repositoryRoot(t), ".github/workflows/c1c-router.yml"))
	if e != nil {
		t.Fatal(e)
	}
	s := string(b)
	for _, want := range []string{"timeout-minutes: 15", "WINKYOU_C1C_ROUTER_REQUIRED=1", "-test.timeout=7m", "-test.count=1", "go-version-file: go.mod", "-race -buildvcs=true -tags=fieldc1c", "./cmd/c1crouter", "run_gate_b3_required_linux.sh", "nftables", "WINKYOU_GATE_B3_DISPOSABLE_RUNNER=github-hosted", "-count=20 -failfast", "TestLinuxC1cRouterGuardianCrash", "-test.timeout=1m", `winkyou/internal/v2/fieldc1c\.loadRouter`} {
		if !strings.Contains(s, want) {
			t.Fatalf("router CI missing %s", want)
		}
	}
	for _, forbidden := range []string{"continue-on-error", "systemctl ", "service ssh", "apt-get install openssh-server"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("router CI escaped privacy or isolation")
		}
	}
	if !c1cRouterFailureUploadValid(s) {
		t.Fatal("router failure upload escaped its checked summary-only boundary")
	}
	b, e = os.ReadFile(filepath.Join(repositoryRoot(t), "test/natlab/c1c_router_netns_linux_test.go"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "sample <= 3") || !strings.Contains(string(b), "t.FailNow()") {
		t.Fatal("router three-fresh fail-fast proof weakened")
	}
}

// Only this exact failure-only tail is authorized. The original required
// proof commands, budgets and isolation exclusions above remain unchanged.
const c1cRouterFailureUpload = `      - name: Validate redacted router failure evidence
        id: router-failure-privacy
        if: failure()
        run: go test ./internal/architecture -run '^TestC1cRouterFailureEvidencePrivacy$' -count=1
      - name: Upload redacted router failure evidence
        if: failure() && steps.router-failure-privacy.outcome == 'success'
        uses: actions/upload-artifact@v4
        with:
          name: router-failure-summary
          path: /tmp/winkyou-c1c-router-failure/*.json
          if-no-files-found: ignore
          retention-days: 7
`

func c1cRouterFailureUploadValid(workflow string) bool {
	s := strings.ReplaceAll(workflow, "\r\n", "\n")
	return strings.HasSuffix(s, c1cRouterFailureUpload) && strings.Count(s, "upload-artifact") == 1
}

func TestC1cRouterFailureUploadMutation(t *testing.T) {
	if !c1cRouterFailureUploadValid(c1cRouterFailureUpload) {
		t.Fatal("valid failure tail rejected")
	}
	for _, change := range [][2]string{
		{"if: failure()", "if: always()"},
		{" && steps.router-failure-privacy.outcome == 'success'", ""},
		{"/tmp/winkyou-c1c-router-failure/*.json", "/tmp/**"},
		{"^TestC1cRouterFailureEvidencePrivacy$", "^TestC1cRouter$"},
	} {
		if c1cRouterFailureUploadValid(strings.ReplaceAll(c1cRouterFailureUpload, change[0], change[1])) {
			t.Fatal("unsafe failure upload mutation accepted")
		}
	}
	if c1cRouterFailureUploadValid("uses: actions/upload-artifact@v4\n" + c1cRouterFailureUpload) {
		t.Fatal("second upload accepted")
	}
}

// Exact projection contract: no raw summary/inspection/journal, identity,
// arbitrary strings or nested extension fields can enter the public artifact.
type c1cRouterPublicFailure struct {
	Source    string  `json:"source"`
	Stage     string  `json:"stage"`
	Class     string  `json:"class"`
	Socket    *uint64 `json:"socket_residue"`
	Process   *uint64 `json:"process_residue"`
	Conntrack *uint64 `json:"conntrack_residue"`
	Namespace *uint64 `json:"namespace_residue"`
	Veth      *uint64 `json:"veth_residue"`
	NFT       *uint64 `json:"nft_residue"`
}

func c1cRouterFailurePrivate(data []byte) bool {
	if len(data) > 4096 || len(docPrivacyLine(string(data))) != 0 || len(sourcePrivacyLine(string(data))) != 0 {
		return true
	}
	var row c1cRouterPublicFailure
	if json.Unmarshal(data, &row) != nil {
		return true
	}
	canonical, err := json.Marshal(row)
	// Also reject duplicate keys, unknown fields and alternate escaped spellings.
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return true
	}
	allowed := func(value string, choices ...string) bool {
		for _, choice := range choices {
			if value == choice {
				return true
			}
		}
		return false
	}
	return !allowed(row.Source, "summary", "teardown", "inspection", "after") ||
		!allowed(row.Stage, "unknown", "before", "after", "preflight", "router_ready", "drain", "terminal") ||
		!allowed(row.Class, "unavailable", "invalid", "available", "success", "cancelled", "expired", "gate_c_request_invalid", "c1c_router_resource_limit", "c1c_router_ownership_invalid", "c1c_router_drain_failed", "c1c_router_command_unavailable", "c1c_router_query_failed", "c1c_router_io_failed")
}

func TestC1cRouterFailureEvidencePrivacy(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "winkyou-c1c-router-failure")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal("failure evidence enumeration failed")
	}
	for _, path := range files {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			t.Fatal("unsafe failure evidence file")
		}
		b, err := os.ReadFile(path)
		if err != nil || c1cRouterFailurePrivate(b) {
			t.Fatal("failure evidence privacy rejected")
		}
	}
	t.Logf("ROUTER_ARTIFACT checked=%d privacy=clear", len(files))
}

func TestC1cRouterFailureEvidencePrivacyMutation(t *testing.T) {
	row := c1cRouterPublicFailure{Source: "summary", Stage: "terminal", Class: "c1c_router_drain_failed"}
	b, _ := json.Marshal(row)
	if c1cRouterFailurePrivate(b) {
		t.Fatal("redacted failure rejected")
	}
	for _, bad := range [][]byte{
		bytes.Replace(b, []byte(`"terminal"`), []byte(`"synthetic-private-marker"`), 1),
		bytes.Replace(b, []byte(`"socket_residue":null`), []byte(`"socket_residue":-1`), 1),
		bytes.Replace(b, []byte(`"source":"summary"`), []byte(`"source":"summary","source":"summary"`), 1),
		bytes.Replace(b, []byte(`"source":"summary"`), []byte(`"source":"summary","instance_id":"synthetic-private-marker"`), 1),
		bytes.Replace(b, []byte(`"source":"summary"`), []byte(`"source":"summary","endpoint":"192.0.2.1"`), 1),
	} {
		if !c1cRouterFailurePrivate(bad) {
			t.Fatal("private failure artifact accepted")
		}
	}
}
