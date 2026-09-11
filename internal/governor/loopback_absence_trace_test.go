package governor_test

import (
	"context"
	"os"
	"runtime/trace"
)

// These optional fixed-name regions annotate only the test goroutine. Capture
// with go test -trace outside the repository, and keep the raw trace private:
// runtime stacks contain local source paths. No product hook or clock changes.
func absenceTraceRegion(name string) func() {
	if os.Getenv("WINKYOU_FLAKE_111_CPU_STRESS") != "1" || !trace.IsEnabled() {
		return func() {}
	}
	region := trace.StartRegion(context.Background(), name)
	return region.End
}
