package config

import "time"

type Config struct {
	Node        NodeConfig        `mapstructure:"node" yaml:"node"`
	Log         LogConfig         `mapstructure:"log" yaml:"log"`
	Coordinator CoordinatorConfig `mapstructure:"coordinator" yaml:"coordinator"`
	NetIf       NetIfConfig       `mapstructure:"netif" yaml:"netif"`
	WireGuard   WireGuardConfig   `mapstructure:"wireguard" yaml:"wireguard"`
	NAT         NATConfig         `mapstructure:"nat" yaml:"nat"`
}

type NodeConfig struct {
	Name string `mapstructure:"name" yaml:"name"`
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
	STUNServers []string           `mapstructure:"stun_servers" yaml:"stun_servers"`
	TURNServers []TURNServerConfig `mapstructure:"turn_servers" yaml:"turn_servers"`
}

type TURNServerConfig struct {
	URL      string `mapstructure:"url" yaml:"url"`
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

