package tcpframed

import (
	"fmt"
	"strings"
	"time"
)

const (
	RoleAuto   = "auto"
	RoleListen = "listen"
	RoleDial   = "dial"
)

type Config struct {
	ListenAddr    string
	AdvertiseAddr string
	DialAddr      string
	Role          string
	DialTimeout   time.Duration
}

func (c Config) withDefaults() Config {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:0"
	}
	if strings.TrimSpace(c.Role) == "" {
		c.Role = RoleAuto
	} else {
		c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	return c
}

func (c Config) roleForInitiator(initiator bool) (string, error) {
	role := strings.ToLower(strings.TrimSpace(c.Role))
	if role == "" {
		role = RoleAuto
	}
	switch role {
	case RoleAuto:
		if initiator {
			return RoleListen, nil
		}
		return RoleDial, nil
	case RoleListen, RoleDial:
		return role, nil
	default:
		return "", fmt.Errorf("tcpframed: invalid role %q", c.Role)
	}
}
