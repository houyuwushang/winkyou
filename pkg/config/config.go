package config

import "time"

type Config struct {
	Node           NodeConfig           `mapstructure:"node" yaml:"node"`
	Log            LogConfig            `mapstructure:"log" yaml:"log"`
	Coordinator    CoordinatorConfig    `mapstructure:"coordinator" yaml:"coordinator"`
	NetIf          NetIfConfig          `mapstructure:"netif" yaml:"netif"`
	WireGuard      WireGuardConfig      `mapstructure:"wireguard" yaml:"wireguard"`
	NAT            NATConfig            `mapstructure:"nat" yaml:"nat"`
	Connectivity   ConnectivityConfig   `mapstructure:"connectivity" yaml:"connectivity"`
	TCPFramed      TCPFramedConfig      `mapstructure:"tcp_framed" yaml:"tcp_framed"`
	AutonomousMesh AutonomousMeshConfig `mapstructure:"autonomous_mesh" yaml:"autonomous_mesh"`
}

type NodeConfig struct {
	Name            string   `mapstructure:"name" yaml:"name"`
	AdvertiseRoutes []string `mapstructure:"advertise_routes" yaml:"advertise_routes"`
}

type LogConfig struct {
	Level  string `mapstructure:"level" yaml:"level"`
	Format string `mapstructure:"format" yaml:"format"`
	Output string `mapstructure:"output" yaml:"output"`
	File   string `mapstructure:"file" yaml:"file"`
}

type CoordinatorConfig struct {
	URL     string        `mapstructure:"url" yaml:"url"`
	Timeout time.Duration `mapstructure:"timeout" yaml:"timeout"`
	AuthKey string        `mapstructure:"auth_key" yaml:"auth_key"`
	TLS     TLSConfig     `mapstructure:"tls" yaml:"tls"`
}

type TLSConfig struct {
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify"`
	CAFile             string `mapstructure:"ca_file" yaml:"ca_file"`
}

type NetIfConfig struct {
	Backend string `mapstructure:"backend" yaml:"backend"`
	MTU     int    `mapstructure:"mtu" yaml:"mtu"`
}

type WireGuardConfig struct {
	PrivateKey string `mapstructure:"private_key" yaml:"private_key"`
	ListenPort int    `mapstructure:"listen_port" yaml:"listen_port"`
}

type NATConfig struct {
	GatherTimeout                time.Duration      `mapstructure:"gather_timeout" yaml:"gather_timeout"`
	ConnectTimeout               time.Duration      `mapstructure:"connect_timeout" yaml:"connect_timeout"`
	CheckTimeout                 time.Duration      `mapstructure:"check_timeout" yaml:"check_timeout"`
	RetryInterval                time.Duration      `mapstructure:"retry_interval" yaml:"retry_interval"`
	RetryMaxInterval             time.Duration      `mapstructure:"retry_max_interval" yaml:"retry_max_interval"`
	CandidatePortMin             int                `mapstructure:"candidate_port_min" yaml:"candidate_port_min"`
	CandidatePortMax             int                `mapstructure:"candidate_port_max" yaml:"candidate_port_max"`
	STUNServers                  []string           `mapstructure:"stun_servers" yaml:"stun_servers"`
	TURNServers                  []TURNServerConfig `mapstructure:"turn_servers" yaml:"turn_servers"`
	ForceRelay                   bool               `mapstructure:"force_relay" yaml:"force_relay"`
	CandidateInterfaceInclude    []string           `mapstructure:"candidate_interface_include" yaml:"candidate_interface_include"`
	CandidateInterfaceExclude    []string           `mapstructure:"candidate_interface_exclude" yaml:"candidate_interface_exclude"`
	CandidateCIDRInclude         []string           `mapstructure:"candidate_cidr_include" yaml:"candidate_cidr_include"`
	CandidateCIDRExclude         []string           `mapstructure:"candidate_cidr_exclude" yaml:"candidate_cidr_exclude"`
	NAT1To1IPs                   []string           `mapstructure:"nat1to1_ips" yaml:"nat1to1_ips"`
	NAT1To1CandidateType         string             `mapstructure:"nat1to1_candidate_type" yaml:"nat1to1_candidate_type"`
	PublicEndpointHints          []string           `mapstructure:"public_endpoint_hints" yaml:"public_endpoint_hints"`
	AutoPublicEndpointHints      bool               `mapstructure:"auto_public_endpoint_hints" yaml:"auto_public_endpoint_hints"`
	PublicEndpointHintPortWindow int                `mapstructure:"public_endpoint_hint_port_window" yaml:"public_endpoint_hint_port_window"`
	DirectTrustedCIDRs           []string           `mapstructure:"direct_trusted_cidrs" yaml:"direct_trusted_cidrs"`
	PublicDirectTrustedCIDRs     []string           `mapstructure:"public_direct_trusted_cidrs" yaml:"public_direct_trusted_cidrs"`
}

type ConnectivityConfig struct {
	Mode          string          `mapstructure:"mode" yaml:"mode"`
	StrategyOrder []string        `mapstructure:"strategy_order" yaml:"strategy_order"`
	Multipath     MultipathConfig `mapstructure:"multipath" yaml:"multipath"`
}

type MultipathConfig struct {
	Enabled                  bool          `mapstructure:"enabled" yaml:"enabled"`
	ProtectDirect            bool          `mapstructure:"protect_direct" yaml:"protect_direct"`
	MaxPaths                 int           `mapstructure:"max_paths" yaml:"max_paths"`
	ShadowWrite              bool          `mapstructure:"shadow_write" yaml:"shadow_write"`
	DependencyPenalty        int           `mapstructure:"dependency_penalty" yaml:"dependency_penalty"`
	DirectProtectionBonus    int           `mapstructure:"direct_protection_bonus" yaml:"direct_protection_bonus"`
	ActivePathSilenceTimeout time.Duration `mapstructure:"active_path_silence_timeout" yaml:"active_path_silence_timeout"`
}

type TCPFramedConfig struct {
	Enabled       bool          `mapstructure:"enabled" yaml:"enabled"`
	ListenAddr    string        `mapstructure:"listen_addr" yaml:"listen_addr"`
	AdvertiseAddr string        `mapstructure:"advertise_addr" yaml:"advertise_addr"`
	DialAddr      string        `mapstructure:"dial_addr" yaml:"dial_addr"`
	Role          string        `mapstructure:"role" yaml:"role"`
	DialTimeout   time.Duration `mapstructure:"dial_timeout" yaml:"dial_timeout"`
}

// AutonomousMeshConfig describes the coordinator-independent graph runtime.
// It is deliberately disabled by default so existing client configurations
// retain their coordinator/WireGuard lifecycle until the runtime integration
// explicitly opts in.
type AutonomousMeshConfig struct {
	Enabled                 bool                              `mapstructure:"enabled" yaml:"enabled"`
	NodeID                  string                            `mapstructure:"node_id" yaml:"node_id"`
	VirtualIP               string                            `mapstructure:"virtual_ip" yaml:"virtual_ip"`
	Listen                  string                            `mapstructure:"listen" yaml:"listen"`
	ControlListen           string                            `mapstructure:"control_listen" yaml:"control_listen"`
	BootstrapPeers          []AutonomousMeshBootstrapPeer     `mapstructure:"bootstrap_peers" yaml:"bootstrap_peers"`
	MaintainPeers           []string                          `mapstructure:"maintain_peers" yaml:"maintain_peers"`
	RecoveryCard            string                            `mapstructure:"recovery_card" yaml:"recovery_card"`
	RecoveryDebounce        time.Duration                     `mapstructure:"recovery_debounce" yaml:"recovery_debounce"`
	SelfBootstrapSecretFile string                            `mapstructure:"self_bootstrap_secret_file" yaml:"self_bootstrap_secret_file"`
	TCPTarget               string                            `mapstructure:"tcp_target" yaml:"tcp_target"`
	TCPForwards             []AutonomousMeshTCPForward        `mapstructure:"tcp_forwards" yaml:"tcp_forwards"`
	VirtualTCPForwards      []AutonomousMeshVirtualTCPForward `mapstructure:"virtual_tcp_forwards" yaml:"virtual_tcp_forwards"`
}

// AutonomousMeshBootstrapPeer is a typed bootstrap seed. Node identity and
// transport address remain separate instead of exposing meshnode's CLI-only
// NODE_ID=HOST:PORT encoding in the public configuration model.
type AutonomousMeshBootstrapPeer struct {
	NodeID  string `mapstructure:"node_id" yaml:"node_id"`
	Address string `mapstructure:"address" yaml:"address"`
}

// AutonomousMeshTCPForward exposes a loopback TCP listener that routes to one
// remote mesh node.
type AutonomousMeshTCPForward struct {
	Listen   string `mapstructure:"listen" yaml:"listen"`
	RemoteID string `mapstructure:"remote_id" yaml:"remote_id"`
}

// AutonomousMeshVirtualTCPForward exposes a selected remote node through a
// managed IPv6 ULA listener. It remains distinct from the loopback form so a
// later runtime cannot accidentally weaken the address-lifecycle checks.
type AutonomousMeshVirtualTCPForward struct {
	Listen   string `mapstructure:"listen" yaml:"listen"`
	RemoteID string `mapstructure:"remote_id" yaml:"remote_id"`
}

type TURNServerConfig struct {
	URL      string `mapstructure:"url" yaml:"url"`
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}
