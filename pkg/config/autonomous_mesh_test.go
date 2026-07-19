package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"winkyou/pkg/config"
)

func TestDefaultAutonomousMeshIsDisabled(t *testing.T) {
	cfg := config.Default()
	if cfg.AutonomousMesh.Enabled {
		t.Fatal("default autonomous_mesh.enabled = true, want false")
	}
	if cfg.AutonomousMesh.Listen != "off" {
		t.Fatalf("default autonomous_mesh.listen = %q, want off", cfg.AutonomousMesh.Listen)
	}
	if cfg.AutonomousMesh.ControlListen != "127.0.0.1:32110" {
		t.Fatalf("default autonomous_mesh.control_listen = %q, want 127.0.0.1:32110", cfg.AutonomousMesh.ControlListen)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default Validate() error = %v", err)
	}
}

func TestLoadLegacyConfigLeavesAutonomousMeshDisabled(t *testing.T) {
	cfg, err := config.Load(filepath.Join("testdata", "valid.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.AutonomousMesh.Enabled {
		t.Fatal("legacy config unexpectedly enabled autonomous mesh")
	}
	if cfg.AutonomousMesh.Listen != "off" || cfg.AutonomousMesh.ControlListen != "127.0.0.1:32110" {
		t.Fatalf("legacy autonomous mesh defaults = %#v", cfg.AutonomousMesh)
	}
}

func TestLoadTypedAutonomousMeshConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
autonomous_mesh:
  enabled: true
  node_id: A
  virtual_ip: fd7a:115c:a1e0::a
  listen: off
  control_listen: 127.0.0.1:32110
  bootstrap_peers:
    - node_id: B
      address: 203.0.113.2:32100
  maintain_peers: [B, C]
  recovery_card: A-recovery.json
  self_bootstrap_secret_file: mesh.secret
  tcp_target: 127.0.0.1:22
  tcp_forwards:
    - listen: 127.0.0.1:22024
      remote_id: B
  virtual_tcp_forwards:
    - listen: "[fd7a:115c:a1e0::b]:22"
      remote_id: B
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	mesh := cfg.AutonomousMesh
	if !mesh.Enabled || mesh.NodeID != "A" || mesh.VirtualIP != "fd7a:115c:a1e0::a" {
		t.Fatalf("autonomous mesh identity = %#v", mesh)
	}
	if len(mesh.BootstrapPeers) != 1 || mesh.BootstrapPeers[0].NodeID != "B" || mesh.BootstrapPeers[0].Address != "203.0.113.2:32100" {
		t.Fatalf("bootstrap peers = %#v", mesh.BootstrapPeers)
	}
	if len(mesh.MaintainPeers) != 2 || mesh.MaintainPeers[0] != "B" || mesh.MaintainPeers[1] != "C" {
		t.Fatalf("maintain peers = %#v", mesh.MaintainPeers)
	}
	if len(mesh.TCPForwards) != 1 || mesh.TCPForwards[0].Listen != "127.0.0.1:22024" || mesh.TCPForwards[0].RemoteID != "B" {
		t.Fatalf("TCP forwards = %#v", mesh.TCPForwards)
	}
	if len(mesh.VirtualTCPForwards) != 1 || mesh.VirtualTCPForwards[0].Listen != "[fd7a:115c:a1e0::b]:22" || mesh.VirtualTCPForwards[0].RemoteID != "B" {
		t.Fatalf("virtual TCP forwards = %#v", mesh.VirtualTCPForwards)
	}
}

func TestLoadAutonomousMeshEnabledEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := []byte(`
autonomous_mesh:
  enabled: false
  node_id: A
  virtual_ip: fd7a:115c:a1e0::a
`)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("WINK_AUTONOMOUS_MESH_ENABLED", "true")

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.AutonomousMesh.Enabled {
		t.Fatal("autonomous_mesh.enabled env override = false, want true")
	}
}

func TestValidateAutonomousMeshValid(t *testing.T) {
	cfg := validAutonomousConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAutonomousMeshAllowsEphemeralLoopbackControlPort(t *testing.T) {
	cfg := validAutonomousConfig()
	cfg.AutonomousMesh.ControlListen = "127.0.0.1:0"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() ephemeral control port error = %v", err)
	}
}

func TestValidateAutonomousMeshDisabledBlockIsInert(t *testing.T) {
	cfg := config.Default()
	cfg.AutonomousMesh.NodeID = "A"
	cfg.AutonomousMesh.VirtualIP = "not-an-ip"
	cfg.AutonomousMesh.BootstrapPeers = []config.AutonomousMeshBootstrapPeer{{NodeID: "A", Address: "broken"}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled autonomous mesh changed legacy validation: %v", err)
	}
}

func TestValidateAutonomousMeshRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.Config)
		wantErr string
	}{
		{
			name: "missing node id",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.NodeID = ""
			},
			wantErr: "autonomous_mesh.node_id is required",
		},
		{
			name: "non ULA virtual IP",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.VirtualIP = "2001:db8::a"
			},
			wantErr: "invalid autonomous_mesh.virtual_ip",
		},
		{
			name: "invalid bootstrap listen",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.Listen = "127.0.0.1"
			},
			wantErr: "invalid autonomous_mesh.listen",
		},
		{
			name: "invalid control listen",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.ControlListen = "32110"
			},
			wantErr: "invalid autonomous_mesh.control_listen",
		},
		{
			name: "disabled control listen",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.ControlListen = "off"
			},
			wantErr: "control_listen is required",
		},
		{
			name: "non loopback control listen",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.ControlListen = "0.0.0.0:32110"
			},
			wantErr: "host must be loopback",
		},
		{
			name: "bootstrap self",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.BootstrapPeers[0].NodeID = "A"
			},
			wantErr: "bootstrap_peers[0].node_id must not equal",
		},
		{
			name: "duplicate bootstrap peer",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.BootstrapPeers = append(cfg.AutonomousMesh.BootstrapPeers,
					config.AutonomousMeshBootstrapPeer{NodeID: "B", Address: "203.0.113.3:32100"})
			},
			wantErr: "duplicate autonomous_mesh.bootstrap_peers[1].node_id",
		},
		{
			name: "invalid bootstrap address",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.BootstrapPeers[0].Address = "203.0.113.2"
			},
			wantErr: "invalid autonomous_mesh.bootstrap_peers[0].address",
		},
		{
			name: "maintain self",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.MaintainPeers[0] = "A"
			},
			wantErr: "maintain_peers[0] must not equal",
		},
		{
			name: "duplicate maintained peer",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.MaintainPeers = []string{"B", "B"}
			},
			wantErr: "duplicate autonomous_mesh.maintain_peers[1]",
		},
		{
			name: "recovery card without maintained peers",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.MaintainPeers = nil
			},
			wantErr: "recovery_card requires at least one",
		},
		{
			name: "secret without recovery card",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.RecoveryCard = ""
			},
			wantErr: "self_bootstrap_secret_file requires autonomous_mesh.recovery_card",
		},
		{
			name: "non-loopback target",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.TCPTarget = "10.0.0.1:22"
			},
			wantErr: "tcp_target",
		},
		{
			name: "non-loopback TCP listener",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.TCPForwards[0].Listen = "10.0.0.1:22024"
			},
			wantErr: "tcp_forwards[0].listen",
		},
		{
			name: "TCP forward to self",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.TCPForwards[0].RemoteID = "A"
			},
			wantErr: "tcp_forwards[0].remote_id must not equal",
		},
		{
			name: "duplicate TCP listener",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.TCPForwards = append(cfg.AutonomousMesh.TCPForwards,
					config.AutonomousMeshTCPForward{Listen: "127.0.0.1:22024", RemoteID: "C"})
			},
			wantErr: "duplicate autonomous mesh TCP listener",
		},
		{
			name: "global virtual TCP listener",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.VirtualTCPForwards[0].Listen = "[2001:db8::b]:22"
			},
			wantErr: "virtual_tcp_forwards[0].listen",
		},
		{
			name: "virtual TCP listener uses local IP",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.VirtualTCPForwards[0].Listen = "[fd7a:115c:a1e0::a]:22"
			},
			wantErr: "uses this node's virtual IP",
		},
		{
			name: "virtual TCP forward to self",
			mutate: func(cfg *config.Config) {
				cfg.AutonomousMesh.VirtualTCPForwards[0].RemoteID = "A"
			},
			wantErr: "virtual_tcp_forwards[0].remote_id must not equal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validAutonomousConfig()
			tt.mutate(&cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() error = nil, want %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func validAutonomousConfig() config.Config {
	cfg := config.Default()
	cfg.AutonomousMesh = config.AutonomousMeshConfig{
		Enabled:       true,
		NodeID:        "A",
		VirtualIP:     "fd7a:115c:a1e0::a",
		Listen:        "off",
		ControlListen: "127.0.0.1:32110",
		BootstrapPeers: []config.AutonomousMeshBootstrapPeer{
			{NodeID: "B", Address: "203.0.113.2:32100"},
		},
		MaintainPeers:           []string{"B", "C"},
		RecoveryCard:            "A-recovery.json",
		SelfBootstrapSecretFile: "mesh.secret",
		TCPTarget:               "127.0.0.1:22",
		TCPForwards: []config.AutonomousMeshTCPForward{
			{Listen: "127.0.0.1:22024", RemoteID: "B"},
		},
		VirtualTCPForwards: []config.AutonomousMeshVirtualTCPForward{
			{Listen: "[fd7a:115c:a1e0::b]:22", RemoteID: "B"},
		},
	}
	return cfg
}
