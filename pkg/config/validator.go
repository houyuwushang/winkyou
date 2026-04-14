package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

var (
	validLogLevels  = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	validLogFormats = map[string]struct{}{"text": {}, "json": {}}
	validLogOutputs = map[string]struct{}{"stderr": {}, "stdout": {}, "file": {}}
	validBackends   = map[string]struct{}{"auto": {}, "tun": {}, "userspace": {}, "proxy": {}}
)

func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}

	if err := requireOneOf("log.level", c.Log.Level, validLogLevels); err != nil {
		return err
	}
	if err := requireOneOf("log.format", c.Log.Format, validLogFormats); err != nil {
		return err
	}
	if err := requireOneOf("log.output", c.Log.Output, validLogOutputs); err != nil {
		return err
	}
	if c.Log.Output == "file" && strings.TrimSpace(c.Log.File) == "" {
		return errors.New("log.file is required when log.output=file")
	}

	if strings.TrimSpace(c.Coordinator.URL) != "" {
		if _, err := url.ParseRequestURI(c.Coordinator.URL); err != nil {
			return fmt.Errorf("invalid coordinator.url: %w", err)
		}
	}
	if c.Coordinator.Timeout <= 0 {
		return errors.New("coordinator.timeout must be greater than zero")
	}

	if err := requireOneOf("netif.backend", c.NetIf.Backend, validBackends); err != nil {
		return err
	}
	if c.NetIf.MTU <= 0 {
		return errors.New("netif.mtu must be greater than zero")
	}

	if c.WireGuard.ListenPort < 0 || c.WireGuard.ListenPort > 65535 {
		return errors.New("wireguard.listen_port must be between 0 and 65535")
	}

	for i, server := range c.NAT.STUNServers {
		if strings.TrimSpace(server) == "" {
			return fmt.Errorf("nat.stun_servers[%d] must not be empty", i)
		}
	}
	if c.NAT.GatherTimeout <= 0 {
		return errors.New("nat.gather_timeout must be greater than zero")
	}
	if c.NAT.ConnectTimeout <= 0 {
		return errors.New("nat.connect_timeout must be greater than zero")
	}
	if c.NAT.CheckTimeout <= 0 {
		return errors.New("nat.check_timeout must be greater than zero")
	}
	if c.NAT.RetryInterval <= 0 {
		return errors.New("nat.retry_interval must be greater than zero")
	}
	if c.NAT.RetryMaxInterval <= 0 {
		return errors.New("nat.retry_max_interval must be greater than zero")
	}
	if c.NAT.RetryMaxInterval < c.NAT.RetryInterval {
		return errors.New("nat.retry_max_interval must be greater than or equal to nat.retry_interval")
	}
	for i, server := range c.NAT.TURNServers {
		if strings.TrimSpace(server.URL) == "" {
			return fmt.Errorf("nat.turn_servers[%d].url must not be empty", i)
		}
	}

	return nil
}

func requireOneOf(field, value string, allowed map[string]struct{}) error {
	if _, ok := allowed[strings.ToLower(strings.TrimSpace(value))]; !ok {
		return fmt.Errorf("invalid %s: %q", field, value)
	}
	return nil
}
