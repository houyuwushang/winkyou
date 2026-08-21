package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"winkyou/internal/signalserver"
)

func TestParseOptionsRequiresLiteralNonzeroListen(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing listen", want: "--listen is required"},
		{name: "DNS", args: []string{"--listen", "signal.invalid:8080"}, want: "hostnames are not accepted"},
		{name: "zero port", args: []string{"--listen", "127.0.0.1:0"}, want: "non-zero port"},
		{name: "multicast", args: []string{"--listen", "224.0.0.1:8080"}, want: "unicast, loopback, or unspecified"},
		{name: "positional", args: []string{"--listen", "127.0.0.1:8080", "extra"}, want: "unexpected positional"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOptions(test.args, &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseOptions() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseOptionsAcceptsExplicitLiteralListeners(t *testing.T) {
	for _, value := range []string{"127.0.0.1:8080", "0.0.0.0:8080", "192.0.2.10:8080", "[::]:8080", "[::1]:8080"} {
		config, err := parseOptions([]string{"--listen", value}, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("parseOptions(%q): %v", value, err)
		}
		if config.listen.Port() != 8080 {
			t.Fatalf("options for %q = %+v", value, config)
		}
	}
}

func TestVersionDoesNotRequireListener(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --version code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "wink-signal version ") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestStructuredLogsDeclareTestOnlyLimitsAndContainNoExchangeData(t *testing.T) {
	var output bytes.Buffer
	record := logRecord{
		Event:          "started",
		Listen:         "0.0.0.0:8080",
		WildcardListen: true,
		Exposure:       "all_interfaces",
		TestOnly:       true,
		Warning:        "plaintext_observation_exchange_no_secrets",
		TTLSeconds:     int64(signalserver.MailboxTTL.Seconds()),
		MaxActiveCodes: signalserver.MaxActiveCodes,
		MaxBodyBytes:   signalserver.MaxBodyBytes,
	}
	if err := writeLog(&output, record); err != nil {
		t.Fatalf("writeLog: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	if decoded["test_only"] != true || decoded["warning"] != "plaintext_observation_exchange_no_secrets" {
		t.Fatalf("test-only disclosure = %#v", decoded)
	}
	for _, forbidden := range []string{"code", "role", "payload", "client_ip", "source_ip"} {
		if _, found := decoded[forbidden]; found {
			t.Fatalf("structured log contains forbidden field %q: %s", forbidden, output.String())
		}
	}
}
