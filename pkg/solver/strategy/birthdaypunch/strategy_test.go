package birthdaypunch

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/nat/puncher"
	"winkyou/pkg/solver"
)

type mockSessionIO struct {
	mu   sync.Mutex
	sent []solver.Message
}

func (m *mockSessionIO) Send(ctx context.Context, msg solver.Message) error {
	m.mu.Lock()
	m.sent = append(m.sent, msg)
	m.mu.Unlock()
	return nil
}

func (m *mockSessionIO) ReportObservation(ctx context.Context, obs solver.Observation) error {
	return nil
}

func (m *mockSessionIO) types(msgType string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, msg := range m.sent {
		if msg.Type == msgType {
			count++
		}
	}
	return count
}

// TestExecuteInitiatorProtectedDirect drives the full Execute orchestration for
// the initiator with injected local-probe and punch seams: it must exchange
// endpoints, self-schedule the start, punch the peer's predicted ports, and
// return a protected_direct path.
func TestExecuteInitiatorProtectedDirect(t *testing.T) {
	var (
		gotCfgMu sync.Mutex
		gotCfg   puncher.Config
	)
	s := New(Config{
		StartLead:       10 * time.Millisecond,
		EndpointTimeout: 3 * time.Second,
		localEndpointFunc: func(ctx context.Context) (localEndpoint, error) {
			return localEndpoint{
				IP:           net.IPv4(1, 2, 3, 4),
				ObservedPort: 5000,
				Pattern:      nat.PortAllocationPreserving,
			}, nil
		},
		punchFunc: func(ctx context.Context, cfg puncher.Config) (*puncher.Result, error) {
			gotCfgMu.Lock()
			gotCfg = cfg
			gotCfgMu.Unlock()
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				return nil, err
			}
			return &puncher.Result{
				Conn:       conn,
				LocalAddr:  conn.LocalAddr().(*net.UDPAddr),
				RemoteAddr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
				Method:     cfg.Method,
			}, nil
		},
	})

	in := solver.SolveInput{SessionID: "s/a/b", LocalNodeID: "a", RemoteNodeID: "b", Initiator: true}
	if _, err := s.Plan(context.Background(), in); err != nil {
		t.Fatal(err)
	}

	sess := &mockSessionIO{}
	resCh := make(chan solver.Result, 1)
	errCh := make(chan error, 1)
	go func() {
		res, err := s.Execute(context.Background(), sess, solver.Plan{ID: PlanID, Strategy: StrategyName})
		if err != nil {
			errCh <- err
			return
		}
		resCh <- res
	}()

	// Feed the peer's endpoint: predictable sequential NAT at port 6000.
	ep, err := marshalEndpoint(endpointPayload{
		SessionID:    "s/a/b",
		PublicIP:     "9.8.7.6",
		ObservedPort: 6000,
		Pattern:      "sequential",
		Delta:        1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.HandleMessage(context.Background(), sess, NewMessage(MessageTypeEndpoint, ep, time.Now())); err != nil {
		t.Fatal(err)
	}

	select {
	case res := <-resCh:
		if !solver.IsProtectedDirectPath(res.Summary) {
			t.Fatalf("summary is not protected_direct: %+v", res.Summary)
		}
		wantDetails := map[string]string{
			"local_public_ip":      "1.2.3.4",
			"local_observed_port":  "5000",
			"local_nat_pattern":    "preserving",
			"remote_public_ip":     "9.8.7.6",
			"remote_observed_port": "6000",
			"remote_nat_pattern":   "sequential",
			"remote_nat_delta":     "1",
		}
		for key, want := range wantDetails {
			if got := res.Summary.Details[key]; got != want {
				t.Fatalf("summary detail %q = %q, want %q", key, got, want)
			}
		}
		if res.Summary.Details["local_addr"] == "" || res.Summary.Details["remote_addr"] == "" {
			t.Fatalf("summary is missing installed socket addresses: %+v", res.Summary.Details)
		}
		if res.Transport == nil {
			t.Fatal("nil transport")
		}
		_ = res.Transport.Close()
	case err := <-errCh:
		t.Fatalf("Execute error: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Execute timed out")
	}

	// The initiator must have advertised its own endpoint and a start signal.
	if sess.types(MessageTypeEndpoint) < 1 {
		t.Fatal("no endpoint message sent")
	}
	if sess.types(MessageTypeStart) < 1 {
		t.Fatal("no start message sent")
	}

	// Punch must target the peer's IP and its predicted ports around 6000.
	gotCfgMu.Lock()
	defer gotCfgMu.Unlock()
	if gotCfg.RemoteIP.String() != "9.8.7.6" {
		t.Fatalf("punch RemoteIP = %v, want 9.8.7.6", gotCfg.RemoteIP)
	}
	found := false
	for _, p := range gotCfg.TargetPorts {
		if p == 6000 {
			found = true
		}
	}
	if !found {
		t.Fatalf("punch targets %v missing predicted peer port 6000", gotCfg.TargetPorts)
	}
	if gotCfg.Method != "predictive" {
		t.Fatalf("punch method = %q, want predictive", gotCfg.Method)
	}
	if gotCfg.LocalPort != 5000 {
		t.Fatalf("punch local port = %d, want advertised preserving port 5000", gotCfg.LocalPort)
	}
}

func TestExecuteRejectsClosed(t *testing.T) {
	s := New(Config{
		localEndpointFunc: func(ctx context.Context) (localEndpoint, error) {
			return localEndpoint{IP: net.IPv4(1, 2, 3, 4)}, nil
		},
	})
	_, _ = s.Plan(context.Background(), solver.SolveInput{SessionID: "s"})
	_ = s.Close()
	if _, err := s.Execute(context.Background(), &mockSessionIO{}, solver.Plan{ID: PlanID}); err == nil {
		t.Fatal("expected error executing a closed strategy")
	}
}

func TestHandleMessageRejectsForeignSession(t *testing.T) {
	s := New(Config{})
	_, _ = s.Plan(context.Background(), solver.SolveInput{SessionID: "s/a/b"})
	ep, _ := marshalEndpoint(endpointPayload{SessionID: "other", PublicIP: "9.8.7.6", ObservedPort: 6000, Pattern: "sequential"})
	if err := s.HandleMessage(context.Background(), &mockSessionIO{}, NewMessage(MessageTypeEndpoint, ep, time.Now())); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	remote := s.remote
	s.mu.Unlock()
	if remote != nil {
		t.Fatal("accepted endpoint from foreign session")
	}
}

func TestLocalEndpointTreatsNoNATAsPortPreserving(t *testing.T) {
	report := nat.PortAllocationReport{
		Pattern:        nat.PortAllocationUnknown,
		MappedIP:       net.IPv4(211, 86, 158, 136),
		MappingNATType: nat.NATTypeNone,
		Samples: []nat.PortAllocationSample{{
			MappedIP: net.IPv4(211, 86, 158, 136), MappedPort: 53934, LocalPort: 53934,
		}},
	}
	got := localEndpointFromReport(report)
	if got.Pattern != nat.PortAllocationPreserving || got.ObservedPort != 53934 {
		t.Fatalf("local endpoint = %+v, want preserving port 53934", got)
	}
}
