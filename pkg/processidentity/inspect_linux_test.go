//go:build linux

package processidentity

import (
	"strings"
	"testing"
)

func TestParseLinuxStat(t *testing.T) {
	numericFields := make([]string, 19)
	for i := range numericFields {
		numericFields[i] = "0"
	}
	numericFields[len(numericFields)-1] = "424242"
	stat := "123 (worker ) with spaces) S " + strings.Join(numericFields, " ")

	got, err := parseLinuxStat([]byte(stat))
	if err != nil {
		t.Fatalf("parseLinuxStat() error = %v", err)
	}
	if got != "424242" {
		t.Fatalf("parseLinuxStat() = %q, want %q", got, "424242")
	}
	got, state, err := parseLinuxStatDetails([]byte(strings.Replace(stat, ") S ", ") Z ", 1)))
	if err != nil {
		t.Fatalf("parseLinuxStatDetails() error = %v", err)
	}
	if got != "424242" || state != "Z" {
		t.Fatalf("parseLinuxStatDetails() = %q/%q, want 424242/Z", got, state)
	}
}

func TestParseLinuxStatRejectsMalformedInput(t *testing.T) {
	tests := []string{
		"",
		"123 no-command-field",
		"not-a-pid (worker) S 0 0 0",
		"123 (worker) S 0 0 0",
	}
	for _, stat := range tests {
		if _, err := parseLinuxStat([]byte(stat)); err == nil {
			t.Errorf("parseLinuxStat(%q) error = nil, want error", stat)
		}
	}
}
