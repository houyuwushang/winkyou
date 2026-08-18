package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"winkyou/internal/stunserver"
)

func TestParseOptionsRequiresLiteralListenAndLowerOnlyPPS(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "missing listen", want: "--listen is required"},
		{name: "DNS", args: []string{"--listen", "stun.invalid:3478"}, want: "hostnames are not accepted"},
		{name: "zero port", args: []string{"--listen", "127.0.0.1:0"}, want: "non-zero port"},
		{name: "multicast", args: []string{"--listen", "224.0.0.1:3478"}, want: "unicast, loopback, or unspecified"},
		{name: "raise ceiling", args: []string{"--listen", "127.0.0.1:3478", "--max-pps", "201"}, want: "compiled ceiling cannot be raised"},
		{name: "zero rate", args: []string{"--listen", "127.0.0.1:3478", "--max-pps", "0"}, want: "use 1..200"},
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
	for _, value := range []string{"127.0.0.1:3478", "0.0.0.0:3478", "192.0.2.10:3478", "[::]:3478", "[::1]:3478"} {
		config, err := parseOptions([]string{"--listen", value, "--max-pps", "17", "--log-prefixes"}, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("parseOptions(%q): %v", value, err)
		}
		if config.listen.Port() != 3478 || config.maxPPS != 17 || !config.logPrefixes {
			t.Fatalf("options for %q = %+v", value, config)
		}
	}
}

func TestVersionDoesNotRequireListener(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --version code = %d, stderr=%s", code, stderr.String())
	}
	if !strings.HasPrefix(stdout.String(), "wink-stund version ") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestStructuredLogsExposeWildcardStateAndNoClientFields(t *testing.T) {
	var output bytes.Buffer
	record := logRecord{
		Event:          "started",
		Listen:         "0.0.0.0:3478",
		WildcardListen: true,
		Exposure:       "all_interfaces",
		MaxPPS:         stunserver.HardMaxPPS,
		PerSourcePPS:   stunserver.PerSourceMaxPPS,
	}
	if err := writeLog(&output, record); err != nil {
		t.Fatalf("writeLog: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("decode log: %v", err)
	}
	if decoded["wildcard_listen"] != true || decoded["exposure"] != "all_interfaces" {
		t.Fatalf("wildcard disclosure = %#v", decoded)
	}
	for _, forbidden := range []string{"client_ip", "source_ip", "transaction_id", "packet"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("structured log contains forbidden client field %q: %s", forbidden, output.String())
		}
	}
}
