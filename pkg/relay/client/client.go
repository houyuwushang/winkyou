package client

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pion/logging"
	turn "github.com/pion/turn/v2"
)

type Config struct {
	ServerURL string
	Username  string
	Password  string
	Realm     string
	Timeout   time.Duration
}

type Client struct {
	cfg Config
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ServerURL) == "" {
		return nil, fmt.Errorf("relay client: server url is required")
	}
	if strings.TrimSpace(cfg.Username) == "" || strings.TrimSpace(cfg.Password) == "" {
		return nil, fmt.Errorf("relay client: username/password are required")
	}
	if strings.TrimSpace(cfg.Realm) == "" {
		cfg.Realm = "winkyou"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &Client{cfg: cfg}, nil
}

func (c *Client) Allocate(ctx context.Context) (*net.UDPAddr, error) {
	// This helper only probes TURN allocation reachability and returns the
	// relayed address observed during that short-lived probe. The allocation is
	// closed before Allocate returns, so callers must not treat the returned
	// address as a reusable data-plane transport. The runtime data plane uses
	// TURN indirectly through pion/ice, not through this helper.
	host, port, ok := parseTURNHostPort(c.cfg.ServerURL)
	if !ok {
		return nil, fmt.Errorf("relay client: invalid turn url %q", c.cfg.ServerURL)
	}
	serverAddr := net.JoinHostPort(host, port)
	pc, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer pc.Close()

	tc, err := turn.NewClient(&turn.ClientConfig{
		TURNServerAddr: serverAddr,
		STUNServerAddr: serverAddr,
		Username:       c.cfg.Username,
		Password:       c.cfg.Password,
		Realm:          c.cfg.Realm,
		Conn:           pc,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	if err := tc.Listen(); err != nil {
		return nil, err
	}

	type allocResult struct {
		conn net.PacketConn
		err  error
	}
	resultCh := make(chan allocResult, 1)
	go func() {
		allocConn, allocErr := tc.Allocate()
		resultCh <- allocResult{conn: allocConn, err: allocErr}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			return nil, res.err
		}
		defer res.conn.Close()
		addr, _ := res.conn.LocalAddr().(*net.UDPAddr)
		if addr == nil {
			return nil, fmt.Errorf("relay client: unexpected relayed addr type %T", res.conn.LocalAddr())
		}
		return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port}, nil
	case <-time.After(c.cfg.Timeout):
		return nil, context.DeadlineExceeded
	}
}

func parseTURNHostPort(raw string) (string, string, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "turn:")
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", false
	}
	if net.ParseIP(host) == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return "", "", false
		}
		host = ips[0].String()
	}
	return host, port, true
}
