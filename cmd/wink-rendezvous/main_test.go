package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"winkyou/internal/v2/rendezvousserver"
)

func TestRunAcceptsExactlyFourServeFlagsAndWritesOneTerminalRecord(t *testing.T) {
	privateMarker := "operator-private-marker"
	args := []string{
		"serve", "--listen", "127.0.0.1:12345", "--tls-cert", privateMarker + "-cert",
		"--tls-key=" + privateMarker + "-key", "--association-file=" + privateMarker + "-association",
	}
	var got rendezvousserver.Config
	serve := func(_ context.Context, config rendezvousserver.Config) rendezvousserver.TerminalRecord {
		got = config
		return rendezvousserver.TerminalRecord{
			Event: "terminal", Class: rendezvousserver.ClassCompleted,
			AcceptedConnections: 2, FramesRead: 13, FramesWritten: 13, BytesRead: 100, BytesWritten: 100,
		}
	}
	var stdout, stderr bytes.Buffer
	if code := runWithServer(context.Background(), args, &stdout, &stderr, serve); code != 0 {
		t.Fatalf("exit code = %d stderr=%s", code, stderr.String())
	}
	want := rendezvousserver.Config{
		ListenAddress: "127.0.0.1:12345", TLSCertFile: privateMarker + "-cert",
		TLSKeyFile: privateMarker + "-key", AssociationFile: privateMarker + "-association",
	}
	if !reflect.DeepEqual(got, want) || stdout.Len() != 0 || strings.Count(stderr.String(), "\n") != 1 || strings.Contains(stderr.String(), privateMarker) {
		t.Fatalf("config=%+v stdout=%q stderr=%q", got, stdout.String(), stderr.String())
	}
	var record rendezvousserver.TerminalRecord
	if err := json.Unmarshal(bytes.TrimSpace(stderr.Bytes()), &record); err != nil || record.Class != rendezvousserver.ClassCompleted {
		t.Fatalf("terminal=%+v error=%v", record, err)
	}
}

func TestRunRejectsMissingDuplicateUnknownAndSingleDashFlagsWithoutServing(t *testing.T) {
	valid := []string{
		"serve", "--listen", "127.0.0.1:12345", "--tls-cert", "cert",
		"--tls-key", "key", "--association-file", "admission",
	}
	tests := [][]string{
		{"serve"},
		append(append([]string(nil), valid...), "--listen", "127.0.0.1:12346"),
		append(append([]string(nil), valid...), "--extra", "value"),
		{"serve", "-listen", "127.0.0.1:12345", "--tls-cert", "cert", "--tls-key", "key", "--association-file", "admission"},
		{"other", "--listen", "127.0.0.1:12345", "--tls-cert", "cert", "--tls-key", "key", "--association-file", "admission"},
	}
	for _, args := range tests {
		called := false
		var stdout, stderr bytes.Buffer
		code := runWithServer(context.Background(), args, &stdout, &stderr, func(context.Context, rendezvousserver.Config) rendezvousserver.TerminalRecord {
			called = true
			return rendezvousserver.TerminalRecord{Event: "terminal", Class: rendezvousserver.ClassCompleted}
		})
		if code != 1 || called || stdout.Len() != 0 || strings.Count(stderr.String(), "\n") != 1 ||
			!strings.Contains(stderr.String(), `"class":"internal_error"`) {
			t.Fatalf("args=%v code=%d called=%t stdout=%q stderr=%q", args, code, called, stdout.String(), stderr.String())
		}
	}
}
