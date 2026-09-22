//go:build !fieldc1c

package cmd

import (
	"io"
	"strings"
	"testing"
)

func TestOrdinaryBuildHasNoFieldCommand(t *testing.T) {
	command := newRootCmd()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{"gate-c1c", "run", "--instance", "synthetic"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatal("ordinary command acquired field path")
	}
}
