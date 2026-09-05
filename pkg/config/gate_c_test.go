package config_test

import (
	"encoding/base64"
	"testing"
	"time"

	"winkyou/pkg/config"
)

func TestGateCTrustedPeerConfigIsStrictAndInertByDefault(t *testing.T) {
	defaultConfig := config.Default()
	if len(defaultConfig.GateC.Peers) != 0 {
		t.Fatalf("default Gate C peers = %d, want zero", len(defaultConfig.GateC.Peers))
	}
	if err := defaultConfig.Validate(); err != nil {
		t.Fatalf("default config = %v", err)
	}

	valid := validGateCConfig()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Gate C config = %v", err)
	}
	mutations := []struct {
		name string
		edit func(*config.Config)
	}{
		{"missing private key", func(candidate *config.Config) { candidate.WireGuard.PrivateKey = "" }},
		{"duplicate ref", func(candidate *config.Config) {
			peer := candidate.GateC.Peers[0]
			peer.PublicKey = gateCTestKey(3)
			peer.MemoryInterfaceName = "wink-c1b-b"
			candidate.GateC.Peers = append(candidate.GateC.Peers, peer)
		}},
		{"duplicate interface", func(candidate *config.Config) {
			peer := candidate.GateC.Peers[0]
			peer.Ref = "peer-b"
			peer.PublicKey = gateCTestKey(3)
			candidate.GateC.Peers = append(candidate.GateC.Peers, peer)
		}},
		{"non canonical virtual IP", func(candidate *config.Config) { candidate.GateC.Peers[0].PeerVirtualIP = "10.0.0.01" }},
		{"local route overlap", func(candidate *config.Config) { candidate.GateC.Peers[0].AllowedIPs = []string{"10.0.0.0/24"} }},
		{"remote not covered", func(candidate *config.Config) { candidate.GateC.Peers[0].AllowedIPs = []string{"10.0.2.0/24"} }},
		{"unsafe interface", func(candidate *config.Config) { candidate.GateC.Peers[0].MemoryInterfaceName = "../wink" }},
		{"unbounded session", func(candidate *config.Config) { candidate.GateC.Peers[0].SessionCeiling = 0 }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			candidate := validGateCConfig()
			mutation.edit(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid Gate C config was accepted")
			}
		})
	}
}

func validGateCConfig() config.Config {
	candidate := config.Default()
	candidate.WireGuard.PrivateKey = gateCTestKey(1)
	candidate.GateC.Peers = []config.GateCPeerConfig{{
		Ref: "peer-a", PublicKey: gateCTestKey(2), AllowedIPs: []string{"10.0.1.2/32"},
		LocalVirtualIP: "10.0.1.1", PeerVirtualIP: "10.0.1.2",
		MemoryInterfaceName: "wink-c1b-a", MemoryMTU: 1280, SessionCeiling: time.Minute,
	}}
	return candidate
}

func gateCTestKey(seed byte) string {
	key := make([]byte, 32)
	for index := range key {
		key[index] = seed + byte(index)
	}
	return base64.StdEncoding.EncodeToString(key)
}
