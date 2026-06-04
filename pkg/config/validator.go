package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

var (
	validLogLevels              = map[string]struct{}{"debug": {}, "info": {}, "warn": {}, "error": {}}
	validLogFormats             = map[string]struct{}{"text": {}, "json": {}}
	validLogOutputs             = map[string]struct{}{"stderr": {}, "stdout": {}, "file": {}}
	validBackends               = map[string]struct{}{"auto": {}, "tun": {}, "userspace": {}, "proxy": {}}
	validConnectivityModes      = map[string]struct{}{"auto": {}, "relay_only": {}}
	validConnectivityStrategies = map[string]struct{}{"legacy_ice_udp": {}, "relay_only": {}, "tcp_framed": {}}
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
	if err := validateStringList("nat.candidate_interface_include", c.NAT.CandidateInterfaceInclude); err != nil {
		return err
	}
	if err := validateStringList("nat.candidate_interface_exclude", c.NAT.CandidateInterfaceExclude); err != nil {
		return err
	}
	if err := validateCIDRList("nat.candidate_cidr_include", c.NAT.CandidateCIDRInclude); err != nil {
		return err
	}
	if err := validateCIDRList("nat.candidate_cidr_exclude", c.NAT.CandidateCIDRExclude); err != nil {
		return err
	}

	mode := strings.ToLower(strings.TrimSpace(c.Connectivity.Mode))
	if mode == "" {
		mode = "auto"
	}
	if err := requireOneOf("connectivity.mode", mode, validConnectivityModes); err != nil {
		return err
	}
	seenStrategies := make(map[string]struct{}, len(c.Connectivity.StrategyOrder))
	for i, strategy := range c.Connectivity.StrategyOrder {
		name := strings.TrimSpace(strategy)
		if name == "" {
			return fmt.Errorf("connectivity.strategy_order[%d] must not be empty", i)
		}
		if _, ok := validConnectivityStrategies[name]; !ok {
			return fmt.Errorf("invalid connectivity.strategy_order[%d]: %q", i, strategy)
		}
		if _, exists := seenStrategies[name]; exists {
			return fmt.Errorf("duplicate connectivity.strategy_order[%d]: %q", i, strategy)
		}
		seenStrategies[name] = struct{}{}
	}
	if c.TCPFramed.Enabled {
		if strings.TrimSpace(c.TCPFramed.ListenAddr) == "" {
			return errors.New("tcp_framed.listen_addr must not be empty when tcp_framed.enabled=true")
		}
		if c.TCPFramed.DialTimeout <= 0 {
			return errors.New("tcp_framed.dial_timeout must be greater than zero when tcp_framed.enabled=true")
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

func validateStringList(field string, values []string) error {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
	}
	return nil
}

func validateCIDRList(field string, values []string) error {
	for i, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s[%d] must not be empty", field, i)
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("invalid %s[%d]: %q", field, i, value)
		}
	}
	return nil
}
