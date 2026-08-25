package rendezvousadmission

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseAcceptsOnlyExactCanonicalWindow(t *testing.T) {
	now := time.Date(2026, 8, 25, 1, 2, 3, 0, time.UTC)
	association := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	valid := `{"profile":"winkyou-test-direct-presence/1","association_id":"` + association + `","issued_at":"2026-08-25T01:02:03Z","expires_at":"2026-08-25T01:12:03Z"}`
	parsed, err := Parse([]byte(valid), now)
	if err != nil || parsed.AssociationID != association || parsed.IssuedAt != now || parsed.ExpiresAt != now.Add(10*time.Minute) {
		t.Fatalf("valid admission = %+v, %v", parsed, err)
	}
	for _, payload := range []string{
		`{}`,
		strings.Replace(valid, `"profile":`, `"unknown":true,"profile":`, 1),
		strings.Replace(valid, `"profile":`, `"profile":"winkyou-test-direct-presence/1","profile":`, 1),
		strings.Replace(valid, "01:02:03Z", "01:02:03+00:00", 1),
		strings.Replace(valid, "01:12:03Z", "01:12:04Z", 1),
		strings.Replace(valid, association, "not-canonical", 1),
	} {
		if _, err := Parse([]byte(payload), now); !errors.Is(err, ErrInvalid) {
			t.Fatalf("payload %s error = %v", payload, err)
		}
	}
}

func TestLoadRejectsSymlinkAndOversize(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "admission.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "admission-link.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := Load(link, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
			t.Fatalf("symlink load = %v", err)
		}
	}
	oversize := filepath.Join(root, "oversize.json")
	if err := os.WriteFile(oversize, make([]byte, MaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(oversize, time.Now().UTC()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversize load = %v", err)
	}
}
