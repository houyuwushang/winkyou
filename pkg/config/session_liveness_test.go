package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
	"winkyou/pkg/config"
)

func TestSessionLivenessFileOnlyStrictPolicy(t *testing.T) {
	base := validGateCConfig()
	base.GateC.Peers[0].SessionLiveness = &config.SessionLivenessConfig{Mode: "challenge_v1", MissedRounds: 3}
	data, err := yaml.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, from, to string
		ok             bool
		rounds         int
	}{
		{"valid", "missed_rounds: 3", "missed_rounds: 3", true, 3},
		{"lower", "missed_rounds: 3", "missed_rounds: 2", true, 2},
		{"default", "missed_rounds: 3", "", true, 3},
		{"zero", "missed_rounds: 3", "missed_rounds: 0", false, 0},
		{"higher", "missed_rounds: 3", "missed_rounds: 4", false, 0},
		{"float", "missed_rounds: 3", "missed_rounds: 2.0", false, 0},
		{"fraction", "missed_rounds: 3", "missed_rounds: 2.5", false, 0},
		{"string", "missed_rounds: 3", "missed_rounds: '3'", false, 0},
		{"null", "missed_rounds: 3", "missed_rounds: null", false, 0},
		{"unknown", "missed_rounds: 3", "interval: 3", false, 0},
		{"mode", "mode: challenge_v1", "mode: unknown", false, 0},
		{"missing mode", "mode: challenge_v1", "", false, 0},
		{"case", "missed_rounds: 3", "MISSED_ROUNDS: 3", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.yaml")
			if err := os.WriteFile(path, []byte(strings.Replace(string(data), tc.from, tc.to, 1)), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("WINK_GATE_C_PEERS_0_SESSION_LIVENESS_MISSED_ROUNDS", "2")
			got, err := config.Load(path)
			if (err == nil) != tc.ok {
				t.Fatalf("accepted=%v want=%v", err == nil, tc.ok)
			}
			if tc.ok && got.GateC.Peers[0].SessionLiveness.MissedRounds != tc.rounds {
				t.Fatal("policy changed outside the file")
			}
		})
	}
}

func TestSessionLivenessAbsentPreservesLegacyConfig(t *testing.T) {
	cfg := validGateCConfig()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "session_liveness") {
		t.Fatal("absent policy changed serialized config")
	}
	path := filepath.Join(t.TempDir(), "legacy.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WINK_GATE_C_PEERS_0_SESSION_LIVENESS_MODE", "challenge_v1")
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.GateC.Peers[0].SessionLiveness != nil {
		t.Fatal("environment activated liveness")
	}
	for _, rounds := range []int{-1, 0, 1, 4} {
		cfg.GateC.Peers[0].SessionLiveness = &config.SessionLivenessConfig{Mode: "challenge_v1", MissedRounds: rounds}
		if cfg.Validate() == nil {
			t.Fatal("out-of-range typed policy accepted")
		}
	}
}
