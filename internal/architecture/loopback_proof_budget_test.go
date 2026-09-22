package architecture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only the aggregate governor timeout may change. Hash the normalized original
// script after undoing that exact delta, preserving selection, counts, other
// steps, failure propagation and execution order. See issue #165's first runs.
const loopbackProofOriginalSHA256 = "57a545d5b9322c7276e408e299ad79d392b6ca02bc308f95a01d63d226b1b755"

const loopbackProofBudgetBlock = `# Harness-only budget: per-group maxima from the two first runs in issue #165.
# ceil(92990ms * 1.25 / 10000ms) * 10s = 120s; no product deadline changes.
# See docs/FLAKE-165-LOOPBACK-PROOF-BUDGET.md for samples and limitations.
$loopbackPreFinishMeasuredMs = 26700
$loopbackSlowFinishMeasuredMs = 42200
$loopbackTwoProcessesMeasuredMs = 8860
$loopbackCrashAfterNoiseMeasuredMs = 890
$loopbackCrashBeforePromoteMeasuredMs = 1300
$loopbackAbsenceMeasuredMs = 13040
$loopbackObservedTotalMs = $loopbackPreFinishMeasuredMs + $loopbackSlowFinishMeasuredMs + $loopbackTwoProcessesMeasuredMs + $loopbackCrashAfterNoiseMeasuredMs + $loopbackCrashBeforePromoteMeasuredMs + $loopbackAbsenceMeasuredMs
$loopbackProofTimeoutSeconds = [int]([Math]::Ceiling($loopbackObservedTotalMs * 1.25 / 10000) * 10)

`

func loopbackProofBudgetViolations(source string) []string {
	source = strings.ReplaceAll(source, "\r\n", "\n")
	if strings.Count(source, loopbackProofBudgetBlock) != 1 {
		return []string{"aggregate budget must derive 120s from all six recorded groups, 25% margin and upward 10s rounding"}
	}
	const argument = `"-timeout=${loopbackProofTimeoutSeconds}s"`
	if strings.Count(source, argument) != 1 {
		return []string{"governor proof must consume the derived timeout exactly once"}
	}
	original := strings.Replace(source, loopbackProofBudgetBlock, "", 1)
	original = strings.Replace(original, argument, `"-timeout=90s"`, 1)
	if fmt.Sprintf("%x", sha256.Sum256([]byte(original))) != loopbackProofOriginalSHA256 {
		return []string{"proof changed outside the measured aggregate timeout delta"}
	}
	return nil
}

func TestLoopbackProofAggregateBudget(t *testing.T) {
	// Integer rational arithmetic avoids a downward floating-point admission.
	observedMs := int64(26700 + 42200 + 8860 + 890 + 1300 + 13040)
	wantSeconds := ((observedMs*5 + 40000 - 1) / 40000) * 10
	if observedMs != 92990 || wantSeconds != 120 || 90*1000 >= observedMs {
		t.Fatal("recorded evidence no longer derives the 120s outer proof budget")
	}
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "verify-loopback-connect.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	if violations := loopbackProofBudgetViolations(string(source)); len(violations) != 0 {
		t.Fatal(violations)
	}
}
