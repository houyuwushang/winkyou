package nat

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestRelayOnlyICEAgent verifies that ForceRelay config forces relay-only candidate gathering
func TestRelayOnlyICEAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping relay integration test in short mode")
	}

	// This test requires a TURN server to be available
	// Set WINKYOU_TEST_TURN_URL to run this test
	// Example: WINKYOU_TEST_TURN_URL=turn:localhost:3478 go test -v -run TestRelayOnly

	turnURL := getTestTURNURL(t)
	if turnURL == "" {
		t.Skip("WINKYOU_TEST_TURN_URL not set, skipping relay test")
	}

	turnUser := getTestTURNUser(t)
	turnPass := getTestTURNPass(t)

	cfg := ICEConfig{
		GatherTimeout:  5 * time.Second,
		CheckTimeout:   10 * time.Second,
		ConnectTimeout: 30 * time.Second,
		TURNServers: []TURNServer{
			{
				URL:      turnURL,
				Username: turnUser,
				Password: turnPass,
			},
		},
		ForceRelay: true,
		Controlling: true,
	}

	agent, err := newICEPionAgent(cfg)
	if err != nil {
		t.Fatalf("newICEPionAgent() error = %v", err)
	}
	defer agent.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	candidates, err := agent.GatherCandidates(ctx)
	if err != nil {
		t.Fatalf("GatherCandidates() error = %v", err)
	}

	if len(candidates) == 0 {
		t.Fatal("GatherCandidates() returned no candidates")
	}

	// Verify all candidates are relay type
	for i, c := range candidates {
		if c.Type != CandidateTypeRelay {
			t.Errorf("candidate[%d].Type = %v, want %v", i, c.Type, CandidateTypeRelay)
		}
	}

	t.Logf("gathered %d relay candidates", len(candidates))
}

// TestRelayTransportAttach verifies that relay transport can be attached to ICE agent
func TestRelayTransportAttach(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping relay integration test in short mode")
	}

	turnURL := getTestTURNURL(t)
	if turnURL == "" {
		t.Skip("WINKYOU_TEST_TURN_URL not set, skipping relay test")
	}

	turnUser := getTestTURNUser(t)
	turnPass := getTestTURNPass(t)

	// Create two agents with relay-only mode
	cfg1 := ICEConfig{
		GatherTimeout:  5 * time.Second,
		CheckTimeout:   10 * time.Second,
		ConnectTimeout: 30 * time.Second,
		TURNServers: []TURNServer{
			{
				URL:      turnURL,
				Username: turnUser,
				Password: turnPass,
			},
		},
		ForceRelay:  true,
		Controlling: true,
	}

	cfg2 := cfg1
	cfg2.Controlling = false

	agent1, err := newICEPionAgent(cfg1)
	if err != nil {
		t.Fatalf("newICEPionAgent(1) error = %v", err)
	}
	defer agent1.Close()

	agent2, err := newICEPionAgent(cfg2)
	if err != nil {
		t.Fatalf("newICEPionAgent(2) error = %v", err)
	}
	defer agent2.Close()

	// Gather candidates
	ctx := context.Background()

	cands1, err := agent1.GatherCandidates(ctx)
	if err != nil {
		t.Fatalf("agent1.GatherCandidates() error = %v", err)
	}

	cands2, err := agent2.GatherCandidates(ctx)
	if err != nil {
		t.Fatalf("agent2.GatherCandidates() error = %v", err)
	}

	// Exchange credentials
	ufrag1, pwd1, err := agent1.GetLocalCredentials()
	if err != nil {
		t.Fatalf("agent1.GetLocalCredentials() error = %v", err)
	}

	ufrag2, pwd2, err := agent2.GetLocalCredentials()
	if err != nil {
		t.Fatalf("agent2.GetLocalCredentials() error = %v", err)
	}

	if err := agent1.SetRemoteCredentials(ufrag2, pwd2); err != nil {
		t.Fatalf("agent1.SetRemoteCredentials() error = %v", err)
	}

	if err := agent2.SetRemoteCredentials(ufrag1, pwd1); err != nil {
		t.Fatalf("agent2.SetRemoteCredentials() error = %v", err)
	}

	// Exchange candidates
	if err := agent1.SetRemoteCandidates(cands2); err != nil {
		t.Fatalf("agent1.SetRemoteCandidates() error = %v", err)
	}

	if err := agent2.SetRemoteCandidates(cands1); err != nil {
		t.Fatalf("agent2.SetRemoteCandidates() error = %v", err)
	}

	// Connect
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	done := make(chan error, 2)

	go func() {
		transport, pair, err := agent1.Connect(connectCtx)
		if err != nil {
			done <- err
			return
		}
		defer transport.Close()

		if pair == nil {
			done <- err
			return
		}

		// Verify relay candidate
		hasRelay := pair.Local.Type == CandidateTypeRelay || pair.Remote.Type == CandidateTypeRelay
		if !hasRelay {
			t.Errorf("agent1 selected pair has no relay candidate: local=%v remote=%v",
				pair.Local.Type, pair.Remote.Type)
		}

		t.Logf("agent1 connected via relay: local=%v remote=%v",
			pair.Local.Type, pair.Remote.Type)

		done <- nil
	}()

	go func() {
		transport, pair, err := agent2.Connect(connectCtx)
		if err != nil {
			done <- err
			return
		}
		defer transport.Close()

		if pair == nil {
			done <- err
			return
		}

		hasRelay := pair.Local.Type == CandidateTypeRelay || pair.Remote.Type == CandidateTypeRelay
		if !hasRelay {
			t.Errorf("agent2 selected pair has no relay candidate: local=%v remote=%v",
				pair.Local.Type, pair.Remote.Type)
		}

		t.Logf("agent2 connected via relay: local=%v remote=%v",
			pair.Local.Type, pair.Remote.Type)

		done <- nil
	}()

	// Wait for both to connect
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Connect() error = %v", err)
			}
		case <-connectCtx.Done():
			t.Fatal("Connect() timeout")
		}
	}
}

func getTestTURNURL(t *testing.T) string {
	// Check env var or use default
	if url := getEnv("WINKYOU_TEST_TURN_URL", ""); url != "" {
		return url
	}
	return ""
}

func getTestTURNUser(t *testing.T) string {
	return getEnv("WINKYOU_TEST_TURN_USER", "winkdemo")
}

func getTestTURNPass(t *testing.T) string {
	return getEnv("WINKYOU_TEST_TURN_PASS", "winkdemo-pass")
}

func getEnv(key, defaultValue string) string {
	if v := getEnvHelper(key); v != "" {
		return v
	}
	return defaultValue
}

func getEnvHelper(key string) string {
	return os.Getenv(key)
}
