//go:build linux && natlab

package natlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"winkyou/internal/probeio"
	"winkyou/internal/v2/directattempt"
)

// Pure test-side projection: no sockets, error text, addresses, payloads or
// identity fields. The Linux child captures the original cause BEFORE FINISH;
// cleanup cannot replace it with a later cancellation. It changes no outcome.
type n2dCauseWitness struct {
	Seen      bool   `json:"seen"`
	Cause     string `json:"cause"`
	Operation string `json:"operation"`
	Timeout   bool   `json:"timeout"`
}

func n2dObserveCause(err error) n2dCauseWitness {
	w := n2dCauseWitness{Seen: err != nil, Cause: "none", Operation: "none"}
	if err == nil {
		return w
	}
	w.Cause = "other"
	for _, item := range []struct {
		err   error
		class string
	}{
		{context.Canceled, "context_canceled"}, {context.DeadlineExceeded, "context_deadline"},
		{io.EOF, "eof"}, {net.ErrClosed, "closed"},
		{syscall.ECONNREFUSED, "connection_refused"}, {syscall.ECONNRESET, "connection_reset"},
		{syscall.ENETUNREACH, "network_unreachable"}, {syscall.EHOSTUNREACH, "host_unreachable"},
		{probeio.ErrUnregisteredTarget, "unregistered_target"}, {probeio.ErrInvalidTarget, "invalid_target"},
		{probeio.ErrReplyRejected, "reply_rejected"}, {probeio.ErrDatagramContract, "datagram_contract"},
		{probeio.ErrLeaseClosed, "lease_closed"}, {probeio.ErrSocketClosed, "socket_closed"},
		{directattempt.ErrInvalidFrame, "invalid_frame"}, {directattempt.ErrInvalidTransition, "invalid_transition"},
	} {
		if errors.Is(err, item.err) {
			w.Cause = item.class
			break
		}
	}
	var operation *net.OpError
	if errors.As(err, &operation) {
		w.Operation = n2dSafeOperation(operation.Op)
	}
	var networkErr net.Error
	w.Timeout = errors.As(err, &networkErr) && networkErr.Timeout()
	return w
}

func n2dSafeCause(class string) string {
	switch class {
	case "none", "other", "context_canceled", "context_deadline", "eof", "closed",
		"connection_refused", "connection_reset", "network_unreachable", "host_unreachable",
		"unregistered_target", "invalid_target", "reply_rejected", "datagram_contract",
		"lease_closed", "socket_closed", "invalid_frame", "invalid_transition":
		return class
	}
	return "other"
}

func n2dSafeOperation(operation string) string {
	switch operation {
	case "none", "read", "write", "dial", "listen":
		return operation
	}
	return "other"
}

func n2dSourceRelation(source, peer netip.AddrPort) string {
	if !source.IsValid() || !peer.IsValid() {
		return "unobserved"
	}
	if source == peer {
		return "matches_peer"
	}
	if source.Addr() == peer.Addr() {
		return "peer_address_different_port"
	}
	return "different_address"
}

func n2dSafeSourceRelation(relation string) string {
	switch relation {
	case "unobserved", "matches_peer", "peer_address_different_port", "different_address":
		return relation
	case "":
		return "unobserved"
	}
	return "other"
}

func TestN2DCauseWitnessTypedErrorsAndPrivacy(t *testing.T) {
	t.Run("actual_harness_wiring", testN2DCauseWitnessWiring)
	const poison = "SYNTHETIC_PRIVATE"
	for _, test := range []struct {
		err   error
		class string
	}{
		{nil, "none"}, {context.Canceled, "context_canceled"}, {context.DeadlineExceeded, "context_deadline"},
		{io.EOF, "eof"}, {net.ErrClosed, "closed"},
		{syscall.ECONNREFUSED, "connection_refused"}, {syscall.ECONNRESET, "connection_reset"},
		{syscall.ENETUNREACH, "network_unreachable"}, {syscall.EHOSTUNREACH, "host_unreachable"},
		{probeio.ErrUnregisteredTarget, "unregistered_target"}, {probeio.ErrReplyRejected, "reply_rejected"},
		{probeio.ErrInvalidTarget, "invalid_target"}, {probeio.ErrDatagramContract, "datagram_contract"},
		{probeio.ErrLeaseClosed, "lease_closed"}, {probeio.ErrSocketClosed, "socket_closed"},
		{directattempt.ErrInvalidFrame, "invalid_frame"}, {directattempt.ErrInvalidTransition, "invalid_transition"},
		{errors.New(poison), "other"},
	} {
		w := n2dObserveCause(test.err)
		if w.Seen != (test.err != nil) || w.Cause != test.class || n2dSafeCause(w.Cause) != w.Cause {
			t.Fatalf("typed cause lost: got=%s want=%s", w.Cause, test.class)
		}
		if test.err == nil {
			continue
		}
		wrapped := &net.OpError{Op: poison, Net: poison,
			Source: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 12345},
			Addr:   &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 23456},
			Err:    &os.PathError{Op: poison, Path: poison, Err: test.err}}
		w = n2dObserveCause(wrapped)
		encoded, err := json.Marshal(w)
		if err != nil || w.Cause != test.class || w.Operation != "other" ||
			bytes.Contains(encoded, []byte(poison)) || bytes.Contains(encoded, []byte("192.0.2")) ||
			bytes.Contains(encoded, []byte("198.51.100")) {
			t.Fatal("error projection lost its typed cause or leaked raw details")
		}
	}
	if n2dSafeCause(poison) != "other" || n2dSafeOperation(poison) != "other" ||
		n2dSafeSourceRelation(poison) != "other" {
		t.Fatal("decoded private witness bypassed the logging whitelist")
	}
	peer := netip.MustParseAddrPort("192.0.2.10:12345")
	for _, test := range []struct {
		source netip.AddrPort
		want   string
	}{
		{netip.AddrPort{}, "unobserved"}, {peer, "matches_peer"},
		{netip.MustParseAddrPort("192.0.2.10:12346"), "peer_address_different_port"},
		{netip.MustParseAddrPort("192.0.2.20:12345"), "different_address"},
	} {
		if got := n2dSourceRelation(test.source, peer); got != test.want || n2dSafeSourceRelation(got) != got {
			t.Fatal("source relation did not remain address-free")
		}
	}
}

func testN2DCauseWitnessWiring(t *testing.T) {
	for _, file := range []struct {
		name     string
		required map[string]int
	}{
		{"n2d_endpoint_linux_test.go", map[string]int{
			"runtime.result.FailureCause = n2dObserveCause(cause)":                2,
			"runtime.result.PunchReceiveSource = n2dSourceRelation(source, peer)": 2,
		}},
		{"n2d_e2e_linux_test.go", map[string]int{
			"N2D_CAUSE_FAILURE":                                1,
			"n2dSafeCause(witness.Cause)":                      1,
			"n2dSafeOperation(witness.Operation)":              1,
			"n2dSafeSourceRelation(result.PunchReceiveSource)": 1,
		}},
	} {
		payload, err := os.ReadFile(file.name)
		if os.IsNotExist(err) {
			payload, err = os.ReadFile(filepath.Join("test", "natlab", file.name))
		}
		if err != nil {
			t.Fatal("harness source unavailable")
		}
		check := func(source string) bool {
			for required, count := range file.required {
				if strings.Count(source, required) != count {
					return false
				}
			}
			return true
		}
		if !check(string(payload)) {
			t.Fatal("original failure cause/source projection is disconnected")
		}
		for required := range file.required {
			if check(strings.Replace(string(payload), required, "REMOVED_DIAGNOSTIC", 1)) {
				t.Fatal("one disconnected cause/source/log site was accepted")
			}
		}
	}
}
