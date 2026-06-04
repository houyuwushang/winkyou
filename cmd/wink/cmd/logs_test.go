package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLogsReadsConfiguredLogFile(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "wink.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	configPath := writeDebugConfig(t, `
node:
  name: alpha
log:
  output: file
  file: `+quoteYAMLString(logPath)+`
`)

	opts := &Options{ConfigPath: configPath}
	cmd := newLogsCmd(opts)
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("logs execute error: %v", err)
	}

	output := buf.String()
	assertContains(t, output, "Log File: "+logPath)
	assertContains(t, output, "one")
	assertContains(t, output, "three")
}

func TestLogsTailFromExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "wink.log")
	if err := os.WriteFile(logPath, []byte("one\ntwo\nthree\n"), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}

	cmd := newLogsCmd(&Options{ConfigPath: filepath.Join(tmpDir, "config.yaml")})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"--path", logPath, "--tail", "2"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("logs --path execute error: %v", err)
	}

	output := buf.String()
	if strings.Contains(output, "one") {
		t.Fatalf("tail output should omit first line, got:\n%s", output)
	}
	assertContains(t, output, "two")
	assertContains(t, output, "three")
}

func TestLogsReportsDisabledFileLogging(t *testing.T) {
	configPath := writeDebugConfig(t, `
node:
  name: alpha
log:
  output: stderr
`)

	cmd := newLogsCmd(&Options{ConfigPath: configPath})
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	if err := cmd.Execute(); err != nil {
		t.Fatalf("logs execute error: %v", err)
	}
	assertContains(t, buf.String(), "File logging is disabled")
}

func TestLogsRejectsNegativeTail(t *testing.T) {
	cmd := newLogsCmd(&Options{})
	cmd.SetArgs([]string{"--tail", "-1"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("logs --tail -1 error = nil, want error")
	}
}

func quoteYAMLString(value string) string {
	return `"` + strings.ReplaceAll(value, `\`, `\\`) + `"`
}
