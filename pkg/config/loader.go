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

	v.SetDefault("nat.stun_servers", cfg.NAT.STUNServers)
	v.SetDefault("nat.turn_servers", cfg.NAT.TURNServers)
}
