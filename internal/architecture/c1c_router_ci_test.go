package architecture

import (
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
	for _, want := range []string{"timeout-minutes: 15", "WINKYOU_C1C_ROUTER_REQUIRED=1", "-test.timeout=7m", "-test.count=1", "go-version-file: go.mod", "-race -buildvcs=true -tags=fieldc1c", "./cmd/c1crouter", "run_gate_b3_required_linux.sh", "nftables", "WINKYOU_GATE_B3_DISPOSABLE_RUNNER=github-hosted", "-count=20 -failfast", "TestLinuxC1cRouterGuardianCrash", "-test.timeout=1m"} {
		if !strings.Contains(s, want) {
			t.Fatalf("router CI missing %s", want)
		}
	}
	for _, forbidden := range []string{"continue-on-error", "upload-artifact", "systemctl ", "service ssh", "apt-get install openssh-server"} {
		if strings.Contains(s, forbidden) {
			t.Fatal("router CI escaped privacy or isolation")
		}
	}
	b, e = os.ReadFile(filepath.Join(repositoryRoot(t), "test/natlab/c1c_router_netns_linux_test.go"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(b), "sample <= 3") || !strings.Contains(string(b), "t.FailNow()") {
		t.Fatal("router three-fresh fail-fast proof weakened")
	}
}
