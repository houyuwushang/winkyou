package config

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	defaultLogLevel         = "info"
	defaultLogFormat        = "text"
	defaultLogOutput        = "stderr"
	defaultCoordinatorURL   = ""
	defaultCoordinatorAuth  = ""
	defaultNetIfBackend     = "auto"
	defaultNetIfMTU         = 1280
	defaultWireGuardPort    = 51820
	defaultCoordinatorDelay = 10 * time.Second
)

func Default() Config {
	return Config{
		Node: NodeConfig{
			Name: hostnameOr(""),
		},
		Log: LogConfig{
			Level:  defaultLogLevel,
			Format: defaultLogFormat,
			Output: defaultLogOutput,
		},
		Coordinator: CoordinatorConfig{
			URL:     defaultCoordinatorURL,
			Timeout: defaultCoordinatorDelay,
			AuthKey: defaultCoordinatorAuth,
		},
		NetIf: NetIfConfig{
			Backend: defaultNetIfBackend,
			MTU:     defaultNetIfMTU,
		},
		WireGuard: WireGuardConfig{
			ListenPort: defaultWireGuardPort,
		},
		NAT: NATConfig{
			STUNServers: []string{
				"stun:stun.l.google.com:19302",
				"stun:stun.cloudflare.com:3478",
			},
		},
	}
}

func DefaultPath() string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return filepath.Join(appData, "wink", "config.yaml")
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}

	return filepath.Join(home, ".wink", "config.yaml")
}

func hostnameOr(fallback string) string {
	name, err := os.Hostname()
	if err != nil || name == "" {
		return fallback
	}
	return name
}

