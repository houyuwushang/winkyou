package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"winkyou/pkg/dataplane/portforward"
	"winkyou/pkg/nat"
	"winkyou/pkg/nat/puncher"
)

func runBridge(args []string) {
	fs := flag.NewFlagSet("bridge", flag.ExitOnError)
	remoteIP := fs.String("remote-ip", "", "peer public IPv4")
	remotePort := fs.Int("remote-port", 0, "peer's most recent observed mapped port")
	remotePattern := fs.String("remote-pattern", "sequential", "peer NAT port pattern: sequential|preserving|random")
	remoteDelta := fs.Int("remote-delta", 1, "peer sequential delta")
	role := fs.String("role", "initiator", "initiator (local listener) | responder (remote target)")
	session := fs.String("session", "punchtest-bridge", "shared punch session id")
	secretFile := fs.String("secret-file", "", "file containing at least 32 random bytes or 64 hex characters")
	listenAddr := fs.String("listen", "127.0.0.1:22022", "initiator local TCP listener")
	targetAddr := fs.String("target", "127.0.0.1:22", "responder fixed TCP target")
	sockets := fs.Int("sockets", 256, "source socket count")
	span := fs.Int("span", 24, "predicted ports ahead for sequential peers")
	birthday := fs.Int("birthday", 256, "fresh random target ports per socket and round")
	burst := fs.Int("burst", 2, "probe packets per target per round")
	localPort := fs.Int("local-port", 0, "bind a single fixed local source port; ignores --sockets")
	roundDelay := fs.Duration("round-delay", 250*time.Millisecond, "pause between punch rounds")
	punchDuration := fs.Duration("duration", 60*time.Second, "punch attempt window")
	fs.Parse(args)

	selectionRole, err := punchRoleForCLI(*role)
	if err != nil {
		fatalUsage("bridge: " + err.Error())
	}
	ip := net.ParseIP(strings.TrimSpace(*remoteIP))
	if ip == nil || ip.To4() == nil {
		fatalUsage("bridge: --remote-ip must be IPv4")
	}
	secret, err := loadBridgeSecret(*secretFile)
	if err != nil {
		fatalUsage(err.Error())
	}

	cfg := puncher.Config{
		RemoteIP:    ip.To4(),
		Session:     sessionKey(*session),
		Role:        selectionRole,
		SocketCount: *sockets,
		Burst:       *burst,
		LocalPort:   *localPort,
		RoundDelay:  *roundDelay,
		Method:      "punchtest-bridge",
	}
	pattern := patternFromString(*remotePattern)
	if pattern == nat.PortAllocationSequential || pattern == nat.PortAllocationPreserving {
		report := nat.PortAllocationReport{Pattern: pattern, Delta: *remoteDelta}
		cfg.TargetPorts = report.PredictMappedPorts(*remotePort, *span)
		if len(cfg.TargetPorts) == 0 && *remotePort > 0 {
			cfg.TargetPorts = []int{*remotePort}
		}
		if len(cfg.TargetPorts) == 0 {
			fatalUsage("bridge: --remote-port is required for a predictable peer")
		}
		fmt.Printf("[punch] role=%s remote=%s predict=%d sockets=%d burst=%d\n",
			*role, ip, len(cfg.TargetPorts), *sockets, *burst)
	} else {
		cfg.BirthdayN = *birthday
		cfg.BirthdayLo = 1024
		cfg.BirthdayHi = 65535
		fmt.Printf("[punch] role=%s remote=%s birthday=%d/socket/round sockets=%d delay=%s\n",
			*role, ip, *birthday, *sockets, *roundDelay)
	}

	runCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	punchCtx, cancelPunch := context.WithTimeout(runCtx, *punchDuration)
	start := time.Now()
	result, err := puncher.Punch(punchCtx, cfg)
	cancelPunch()
	if err != nil {
		fmt.Printf("[punch] FAILED after %s: %v\n", time.Since(start).Round(time.Millisecond), err)
		os.Exit(1)
	}
	fmt.Printf("[punch] HIT in %s: local=%s peer=%s\n",
		time.Since(start).Round(time.Millisecond), result.LocalAddr, result.RemoteAddr)

	logf := func(format string, values ...any) {
		fmt.Printf("[bridge] "+format+"\n", values...)
	}
	if *role == "responder" {
		err = portforward.RunServer(runCtx, portforward.ServerConfig{
			PacketConn: result.Conn,
			PeerAddr:   result.RemoteAddr,
			Secret:     secret,
			Target:     *targetAddr,
			OnReady: func(local, remote net.Addr) {
				fmt.Printf("[bridge] READY authenticated=%s local_udp=%s target=%s\n", remote, local, *targetAddr)
			},
			Logf: logf,
		})
	} else {
		err = portforward.RunClient(runCtx, portforward.ClientConfig{
			PacketConn: result.Conn,
			PeerAddr:   result.RemoteAddr,
			Secret:     secret,
			Listen:     *listenAddr,
			OnReady: func(listener, local, remote net.Addr) {
				fmt.Printf("[bridge] READY listen=%s authenticated=%s local_udp=%s\n", listener, remote, local)
			},
			Logf: logf,
		})
	}
	if err != nil && runCtx.Err() == nil {
		fmt.Fprintf(os.Stderr, "[bridge] stopped: %v\n", err)
		os.Exit(1)
	}
}

func loadBridgeSecret(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("bridge: --secret-file is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("bridge: read secret file: %w", err)
	}
	encoded := bytes.TrimSpace(raw)
	if decoded, decodeErr := hex.DecodeString(string(encoded)); decodeErr == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if len(raw) < 32 {
		return nil, fmt.Errorf("bridge: secret file must contain at least 32 random bytes or 64 hex characters")
	}
	return append([]byte(nil), raw...), nil
}

func fatalUsage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
