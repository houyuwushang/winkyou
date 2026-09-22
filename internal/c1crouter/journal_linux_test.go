//go:build linux && fieldc1c

package c1crouter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestJournalInterruptedWriteDoesNotBlockOwnedCleanup(t *testing.T) {
	dir := t.TempDir()
	j := &journal{dir: dir, value: ownership{Schema: "winkyou-router-ownership/1", Digest: "synthetic", PID: 2, Start: "1"}}
	if err := j.save(); err != nil {
		t.Fatal("initial durable journal unavailable")
	}
	// The interrupted file is deliberately invalid and cannot become authority.
	interrupted := filepath.Join(dir, "ownership.pending-interrupted")
	const partial = `{"clean":true`
	if err := os.WriteFile(interrupted, []byte(partial), 0o600); err != nil {
		t.Fatal("interrupted-write fixture unavailable")
	}
	j.value.Clean = true // the actual cleanup/readback has now completed
	if err := j.save(); err != nil {
		t.Fatal("interrupted write blocked the next durable cleanup record")
	}
	b, err := os.ReadFile(filepath.Join(dir, "ownership.json"))
	var value ownership
	if err != nil || json.Unmarshal(b, &value) != nil || !value.Clean || value.Digest != j.value.Digest {
		t.Fatal("cleanup journal did not replace only the committed authority")
	}
	if b, err := os.ReadFile(interrupted); err != nil || string(b) != partial {
		t.Fatal("interrupted evidence was lost or repaired")
	}
	if info, err := os.Stat(filepath.Join(dir, "ownership.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("journal lost its owner-only permissions")
	}
}
