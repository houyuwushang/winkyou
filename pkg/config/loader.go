package config

import (
	"errors"
	"os"
	"strings"

	"github.com/spf13/viper"
)

func Load(path string) (*Config, error) {
	cfg := Default()
	explicitPath := path != ""

	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("WINK")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDefaults(v, cfg)

	if path == "" {
		path = DefaultPath()
	}

	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		var notFound viper.ConfigFileNotFoundError
		if explicitPath || (!errors.As(err, &notFound) && !errors.Is(err, os.ErrNotExist)) {
			return nil, err
		}
	}

	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	if cfg.Node.Name == "" {
		cfg.Node.Name = hostnameOr("wink-node")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func setDefaults(v *viper.Viper, cfg Config) {
	v.SetDefault("node.name", cfg.Node.Name)
	v.SetDefault("node.advertise_routes", cfg.Node.AdvertiseRoutes)
	v.SetDefault("log.level", cfg.Log.Level)
	v.SetDefault("log.format", cfg.Log.Format)
	v.SetDefault("log.output", cfg.Log.Output)
	v.SetDefault("log.file", cfg.Log.File)

	v.SetDefault("coordinator.url", cfg.Coordinator.URL)
	v.SetDefault("coordinator.timeout", cfg.Coordinator.Timeout)
	v.SetDefault("coordinator.auth_key", cfg.Coordinator.AuthKey)
	v.SetDefault("coordinator.tls.insecure_skip_verify", cfg.Coordinator.TLS.InsecureSkipVerify)
	v.SetDefault("coordinator.tls.ca_file", cfg.Coordinator.TLS.CAFile)

	v.SetDefault("netif.backend", cfg.NetIf.Backend)
	v.SetDefault("netif.mtu", cfg.NetIf.MTU)

	v.SetDefault("wireguard.private_key", cfg.WireGuard.PrivateKey)
	v.SetDefault("wireguard.listen_port", cfg.WireGuard.ListenPort)

	v.SetDefault("nat.gather_timeout", cfg.NAT.GatherTimeout)
	v.SetDefault("nat.connect_timeout", cfg.NAT.ConnectTimeout)
	v.SetDefault("nat.check_timeout", cfg.NAT.CheckTimeout)
	v.SetDefault("nat.retry_interval", cfg.NAT.RetryInterval)
	v.SetDefault("nat.retry_max_interval", cfg.NAT.RetryMaxInterval)
	v.SetDefault("nat.candidate_port_min", cfg.NAT.CandidatePortMin)
	v.SetDefault("nat.candidate_port_max", cfg.NAT.CandidatePortMax)
	v.SetDefault("nat.stun_servers", cfg.NAT.STUNServers)
	v.SetDefault("nat.turn_servers", cfg.NAT.TURNServers)
	v.SetDefault("nat.nat1to1_ips", cfg.NAT.NAT1To1IPs)
	v.SetDefault("nat.nat1to1_candidate_type", cfg.NAT.NAT1To1CandidateType)
	v.SetDefault("nat.public_endpoint_hints", cfg.NAT.PublicEndpointHints)
	v.SetDefault("nat.direct_trusted_cidrs", cfg.NAT.DirectTrustedCIDRs)
	v.SetDefault("nat.public_direct_trusted_cidrs", cfg.NAT.PublicDirectTrustedCIDRs)

	v.SetDefault("connectivity.mode", cfg.Connectivity.Mode)
	v.SetDefault("connectivity.strategy_order", cfg.Connectivity.StrategyOrder)
	v.SetDefault("connectivity.multipath.enabled", cfg.Connectivity.Multipath.Enabled)
	v.SetDefault("connectivity.multipath.protect_direct", cfg.Connectivity.Multipath.ProtectDirect)
	v.SetDefault("connectivity.multipath.max_paths", cfg.Connectivity.Multipath.MaxPaths)
	v.SetDefault("connectivity.multipath.shadow_write", cfg.Connectivity.Multipath.ShadowWrite)
	v.SetDefault("connectivity.multipath.dependency_penalty", cfg.Connectivity.Multipath.DependencyPenalty)
	v.SetDefault("connectivity.multipath.direct_protection_bonus", cfg.Connectivity.Multipath.DirectProtectionBonus)

	v.SetDefault("tcp_framed.enabled", cfg.TCPFramed.Enabled)
	v.SetDefault("tcp_framed.listen_addr", cfg.TCPFramed.ListenAddr)
	v.SetDefault("tcp_framed.advertise_addr", cfg.TCPFramed.AdvertiseAddr)
	v.SetDefault("tcp_framed.dial_timeout", cfg.TCPFramed.DialTimeout)
}
