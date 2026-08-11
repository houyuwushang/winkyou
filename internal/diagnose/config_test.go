package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestExplicitMissingConfigurationIsReportedWithoutPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.yaml")
	status := inspectConfiguration(path)
	if status.State != ConfigMissing || !status.ExplicitPath || status.FilePresent {
		t.Fatalf("config status = %+v", status)
	}
	if strings.Contains(status.Detail, path) {
		t.Fatalf("detail leaked config path: %q", status.Detail)
	}
}

func TestConfigurationDirectoryIsInvalid(t *testing.T) {
	status := inspectConfiguration(t.TempDir())
	if status.State != ConfigInvalid || !status.FilePresent {
		t.Fatalf("config status = %+v", status)
	}
}

func TestConfigurationErrorSanitizerBoundsAndRemovesControlText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret-location.yaml")
	detail := path + "\n" + strings.Repeat("界", 300)
	got := sanitizeConfigError(detail, path)
	if strings.Contains(got, path) || strings.ContainsAny(got, "\r\n\t") {
		t.Fatalf("sanitized detail = %q", got)
	}
	if len(got) > 512 || !utf8.ValidString(got) {
		t.Fatalf("sanitized detail length/encoding = %d/%t", len(got), utf8.ValidString(got))
	}
}

func TestExplicitInvalidConfigurationDoesNotExposeContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("wireguard:\n  listen_port: not-a-number\n"), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
	status := inspectConfiguration(path)
	if status.State != ConfigInvalid || !status.FilePresent {
		t.Fatalf("config status = %+v", status)
	}
	if strings.Contains(status.Detail, path) || strings.Contains(status.Detail, "not-a-number") {
		t.Fatalf("detail leaked config path or value: %q", status.Detail)
	}
}
