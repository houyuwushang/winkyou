package server

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/pion/logging"
	turn "github.com/pion/turn/v2"
)

type Config struct {
	ListenAddress string
	Realm         string
	Users         map[string]string
	RelayAddress  string
}

type Server struct {
	cfg    Config
	pc     net.PacketConn
	turn   *turn.Server
	close  sync.Once
	closed chan struct{}
}

func New(cfg Config) (*Server, error) {
	if strings.TrimSpace(cfg.ListenAddress) == "" {
		cfg.ListenAddress = ":3478"
	}
	if strings.TrimSpace(cfg.Realm) == "" {
		cfg.Realm = "winkyou"
	}
	if len(cfg.Users) == 0 {
		return nil, fmt.Errorf("relay server: at least one static user is required")
	}
	return &Server{cfg: cfg, closed: make(chan struct{})}, nil
}

func (s *Server) Start() error {
	if s.turn != nil {
		return nil
	}
	pc, err := net.ListenPacket("udp4", s.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("relay server: listen udp: %w", err)
	}

	relayIP := net.ParseIP(strings.TrimSpace(s.cfg.RelayAddress))
	if relayIP == nil {
		host, _, _ := net.SplitHostPort(pc.LocalAddr().String())
		relayIP = net.ParseIP(host)
		if relayIP == nil {
			relayIP = net.ParseIP("127.0.0.1")
		}
	}

	ts, err := turn.NewServer(turn.ServerConfig{
		Realm:         s.cfg.Realm,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		AuthHandler: func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
			pass, ok := s.cfg.Users[username]
			if !ok {
				return nil, false
			}
			return turn.GenerateAuthKey(username, realm, pass), true
		},
		PacketConnConfigs: []turn.PacketConnConfig{{
			PacketConn: pc,
			RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
				RelayAddress: relayIP,
				Address:      "0.0.0.0",
			},
		}},
	})
	if err != nil {
		_ = pc.Close()
		return fmt.Errorf("relay server: new turn server: %w", err)
	}
	s.pc = pc
	s.turn = ts
	return nil
}

func (s *Server) Close() error {
	var err error
	s.close.Do(func() {
		if s.turn != nil {
			err = s.turn.Close()
		}
		if s.pc != nil {
			_ = s.pc.Close()
		}
		close(s.closed)
	})
	return err
}

func (s *Server) Addr() net.Addr {
	if s.pc == nil {
		return nil
	}
	return s.pc.LocalAddr()
}
