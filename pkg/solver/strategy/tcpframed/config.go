package tcpframed

import "time"

type Config struct {
	ListenAddr    string
	AdvertiseAddr string
	DialTimeout   time.Duration
}

func (c Config) withDefaults() Config {
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:0"
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	return c
}
