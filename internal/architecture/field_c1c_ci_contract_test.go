package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFieldC1cRequiredCIBudgetAndAuthority(t *testing.T) {
	// The baseline preparation/build measurement is CI run 35594822353;
	// symbols and focused race are the first local measurements, not field I/O.
	const baselinePreparation = 63 * time.Second
	const symbolProof = 56 * time.Second
	const secondBuild = 23 * time.Second
	const focusedRace = 21 * time.Second
	const isolatedMatrix = 4 * time.Minute
	budget := (baselinePreparation + symbolProof + secondBuild + focusedRace + isolatedMatrix) * 5 / 4
	minutes := int((budget + time.Minute - 1) / time.Minute)
	if minutes != 9 {
		t.Fatal("field proof CI derivation changed")
	}
	data, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "field-c1c.yml"))
	if err != nil {
		t.Fatal("field proof workflow missing")
	}
	source := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, required := range []string{"timeout-minutes: 9", "WINKYOU_FIELD_C1C_REQUIRED=1", "-test.timeout=4m", "-test.count=1",
		"go build -race -buildvcs=true -tags=fieldc1c", "-X winkyou/internal/v2/fieldc1c.BuildSHA=", "-tags=natlab,c1bproof,fieldc1c",
		"run_gate_b3_required_linux.sh", "WINKYOU_GATE_B3_DISPOSABLE_RUNNER=github-hosted", "go-version-file: go.mod"} {
		if !strings.Contains(source, required) {
			t.Fatalf("missing field CI contract %s", required)
		}
	}
	for _, forbidden := range []string{"continue-on-error", "upload-artifact", "systemctl ", "service ssh", "apt-get install openssh-server"} {
		if strings.Contains(source, forbidden) {
			t.Fatal("field proof bypassed isolation or privacy")
		}
	}
}

func TestFieldC1cExitWaitOwnsBothRaceProcesses(t *testing.T) {
	const closeWindow = time.Second
	const drain = 2 * time.Second
	const twoRaceExits = 2 * time.Second
	limit := ((closeWindow+drain+twoRaceExits)*5/4 + time.Second - 1) / time.Second * time.Second
	if limit != 7*time.Second {
		t.Fatal("field exit wait derivation changed")
	}
	read := func(relative string) string {
		data, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal("field exit contract source unavailable")
		}
		return strings.Join(strings.Fields(string(data)), " ")
	}
	if !strings.Contains(read("internal/v2/gatecorchestrator/liveness_clock.go"), "livenessWriteWindow = time.Second") ||
		!strings.Contains(read("internal/v2/gatecorchestrator/types.go"), "SessionDrainTimeout = 2 * time.Second") {
		t.Fatal("frozen field exit budget source changed")
	}
	harness := read("test/natlab/field_c1c_netns_linux_test.go")
	for _, required := range []string{
		"fieldC1cCloseAllowance = time.Second", "fieldC1cRaceExitAllowance = 2 * time.Second",
		"fieldC1cStopBase = fieldC1cCloseAllowance + gatecorchestrator.SessionDrainTimeout + fieldC1cRaceExitAllowance",
		"fieldC1cStopResultLimit = (fieldC1cStopBase*5/4 + time.Second - 1) / time.Second * time.Second",
		"case <-time.After(fieldC1cStopResultLimit):", "waitFieldC1cEndpoint(t, client, configs)",
	} {
		if !strings.Contains(harness, required) {
			t.Fatalf("missing field exit contract %s", required)
		}
	}
	if strings.Contains(harness, "client.wait(t)") {
		t.Fatal("field reused single-process C1b wait")
	}
}
