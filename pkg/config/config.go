package config

import "time"

type Config struct {
	Node         NodeConfig         `mapstructure:"node" yaml:"node"`
	Log          LogConfig          `mapstructure:"log" yaml:"log"`
	Coordinator  CoordinatorConfig  `mapstructure:"coordinator" yaml:"coordinator"`
	NetIf        NetIfConfig        `mapstructure:"netif" yaml:"netif"`
	WireGuard    WireGuardConfig    `mapstructure:"wireguard" yaml:"wireguard"`
	NAT          NATConfig          `mapstructure:"nat" yaml:"nat"`
	Connectivity ConnectivityConfig `mapstructure:"connectivity" yaml:"connectivity"`
	TCPFramed    TCPFramedConfig    `mapstructure:"tcp_framed" yaml:"tcp_framed"`
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
	GatherTimeout             time.Duration      `mapstructure:"gather_timeout" yaml:"gather_timeout"`
	ConnectTimeout            time.Duration      `mapstructure:"connect_timeout" yaml:"connect_timeout"`
	CheckTimeout              time.Duration      `mapstructure:"check_timeout" yaml:"check_timeout"`
	RetryInterval             time.Duration      `mapstructure:"retry_interval" yaml:"retry_interval"`
	RetryMaxInterval          time.Duration      `mapstructure:"retry_max_interval" yaml:"retry_max_interval"`
	CandidatePortMin          int                `mapstructure:"candidate_port_min" yaml:"candidate_port_min"`
	CandidatePortMax          int                `mapstructure:"candidate_port_max" yaml:"candidate_port_max"`
	STUNServers               []string           `mapstructure:"stun_servers" yaml:"stun_servers"`
	TURNServers               []TURNServerConfig `mapstructure:"turn_servers" yaml:"turn_servers"`
	ForceRelay                bool               `mapstructure:"force_relay" yaml:"force_relay"`
	CandidateInterfaceInclude []string           `mapstructure:"candidate_interface_include" yaml:"candidate_interface_include"`
	CandidateInterfaceExclude []string           `mapstructure:"candidate_interface_exclude" yaml:"candidate_interface_exclude"`
	CandidateCIDRInclude      []string           `mapstructure:"candidate_cidr_include" yaml:"candidate_cidr_include"`
	CandidateCIDRExclude      []string           `mapstructure:"candidate_cidr_exclude" yaml:"candidate_cidr_exclude"`
	NAT1To1IPs                []string           `mapstructure:"nat1to1_ips" yaml:"nat1to1_ips"`
	NAT1To1CandidateType      string             `mapstructure:"nat1to1_candidate_type" yaml:"nat1to1_candidate_type"`
	PublicEndpointHints       []string           `mapstructure:"public_endpoint_hints" yaml:"public_endpoint_hints"`
	AutoPublicEndpointHints   bool               `mapstructure:"auto_public_endpoint_hints" yaml:"auto_public_endpoint_hints"`
	DirectTrustedCIDRs        []string           `mapstructure:"direct_trusted_cidrs" yaml:"direct_trusted_cidrs"`
	PublicDirectTrustedCIDRs  []string           `mapstructure:"public_direct_trusted_cidrs" yaml:"public_direct_trusted_cidrs"`
}

type ConnectivityConfig struct {
	Mode          string          `mapstructure:"mode" yaml:"mode"`
	StrategyOrder []string        `mapstructure:"strategy_order" yaml:"strategy_order"`
	Multipath     MultipathConfig `mapstructure:"multipath" yaml:"multipath"`
}

type MultipathConfig struct {
	Enabled               bool `mapstructure:"enabled" yaml:"enabled"`
	ProtectDirect         bool `mapstructure:"protect_direct" yaml:"protect_direct"`
	MaxPaths              int  `mapstructure:"max_paths" yaml:"max_paths"`
	ShadowWrite           bool `mapstructure:"shadow_write" yaml:"shadow_write"`
	DependencyPenalty     int  `mapstructure:"dependency_penalty" yaml:"dependency_penalty"`
	DirectProtectionBonus int  `mapstructure:"direct_protection_bonus" yaml:"direct_protection_bonus"`
}

type TCPFramedConfig struct {
	Enabled       bool          `mapstructure:"enabled" yaml:"enabled"`
	ListenAddr    string        `mapstructure:"listen_addr" yaml:"listen_addr"`
	AdvertiseAddr string        `mapstructure:"advertise_addr" yaml:"advertise_addr"`
	DialTimeout   time.Duration `mapstructure:"dial_timeout" yaml:"dial_timeout"`
}

type TURNServerConfig struct {
	URL      string `mapstructure:"url" yaml:"url"`
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}
