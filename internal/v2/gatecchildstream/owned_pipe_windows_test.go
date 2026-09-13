//go:build windows

package gatecchildstream

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestWindowsPipeKeepsCloseBasedCancellationWithoutNativeDeadlines(t *testing.T) {
	for _, expired := range []bool{false, true} {
		name := "close"
		if expired {
			name = "expired-deadline"
		}
		t.Run(name, func(t *testing.T) {
			input, peer, err := os.Pipe()
			if err != nil {
				t.Fatal("owned pipe unavailable")
			}
			defer peer.Close()
			defer input.Close()
			absolute := time.Now().Add(5 * time.Second)
			if err := input.SetReadDeadline(absolute); !errors.Is(err, os.ErrNoDeadline) {
				t.Fatal("synchronous Windows pipe deadline precondition changed")
			}
			stream, err := New(input, &memoryWriteCloser{}, absolute)
			if err != nil {
				t.Fatal("existing Windows pipe rejected")
			}
			defer stream.Close()
			done := make(chan error, 1)
			go func() { _, err := stream.Read(make([]byte, 1)); done <- err }()
			observed := false
			buffer := make([]byte, 64<<10)
			defer clear(buffer)
			deadline := time.Now().Add(time.Second)
			for time.Now().Before(deadline) {
				n := runtime.Stack(buffer, true)
				for _, stack := range strings.Split(string(buffer[:n]), "\n\n") {
					if strings.Contains(stack, "[syscall]") && strings.Contains(stack, "syscall.SyscallN(") &&
						strings.Contains(stack, "winkyou/internal/v2/gatecchildstream.(*Stream).Read(") {
						observed = true
					}
				}
				if observed {
					break
				}
				time.Sleep(time.Millisecond)
			}
			if !observed {
				t.Fatal("real Windows pipe read was not observed")
			}
			started := time.Now()
			if expired {
				if err := stream.SetDeadline(time.Now()); err != nil {
					t.Fatal(err)
				}
			} else if err := stream.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil || expired && !errors.Is(err, ErrDeadline) {
					t.Fatalf("cancelled read=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Windows pipe read required peer EOF")
			}
			if err := stream.Close(); err != nil || !stream.Witness().Drained {
				t.Fatal("Windows pipe did not drain")
			}
			t.Logf("windows pipe: expired=%t close_ms=%d read_joined=true peer_eof=false sockets=0", expired, time.Since(started).Milliseconds())
		})
	}
}
