// Command punchtest is a self-contained, controllable tool to validate the
// birthday-paradox hole punch on the real network path between two machines,
// independent of WireGuard/Wintun. It probes the local NAT's public endpoint and
// port-allocation pattern, punches the peer's predicted/sprayed ports with the
// multi-socket puncher, and on success either verifies the punched UDP path with
// ping/echo or carries an authenticated TCP forward over its own QUIC data plane.
//
// Usage:
//
//	punchtest probe [--stun stun:host:port] [--samples 12]
//	punchtest punch --remote-ip IP --remote-port N --remote-pattern P [--remote-delta D]
//	         [--role initiator|responder] [--session S] [--sockets 256]
//	         [--span 24] [--birthday 256] [--burst 2] [--duration 25s]
//	punchtest bridge <same punch flags> --secret-file FILE
//	         [--listen 127.0.0.1:22022] [--target 127.0.0.1:22]
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"winkyou/pkg/nat"
	"winkyou/pkg/nat/puncher"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: punchtest <probe|mapping|punch|bridge> [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "probe":
		runProbe(os.Args[2:])
	case "punch":
		runPunch(os.Args[2:])
	case "bridge":
		runBridge(os.Args[2:])
	case "mapping":
		runMapping(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", os.Args[1])
		os.Exit(2)
	}
}

// runMapping probes several STUN servers from one socket to reveal the NAT's
// mapping behavior: an endpoint-independent (cone/preserving) NAT reports the
// same mapped port to every server; an endpoint-dependent (symmetric) NAT
// reports different ports, meaning a fixed local port does NOT fix the public
// source port toward an arbitrary peer.
func runMapping(args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	servers := []string{
		"stun:stun.cloudflare.com:3478",
		"stun:stun.l.google.com:19302",
		"stun:stun.miwifi.com:3478",
	}
	report, err := nat.ProbeSTUNMapping(ctx, servers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mapping probe error: %v\n", err)
	}
	for _, p := range report.Probes {
		if p.MappedAddr != nil {
			fmt.Printf("%-34s -> %s (local %s)\n", p.Server, p.MappedAddr, p.LocalAddr)
		} else {
			fmt.Printf("%-34s -> ERROR: %s\n", p.Server, p.Error)
		}
	}
	fmt.Printf("NAT mapping behavior: %s (symmetric = fixed local port will NOT help)\n", report.NATType)
}

func runProbe(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	stun := fs.String("stun", "stun:stun.cloudflare.com:3478,stun:stun.l.google.com:19302,stun:stun.miwifi.com:3478", "comma-separated STUN servers")
	samples := fs.Int("samples", 12, "number of probe sockets")
	fs.Parse(args)
	servers := splitServerList(*stun)
	if len(servers) == 0 {
		fmt.Fprintln(os.Stderr, "probe failed: no STUN servers")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	report, err := nat.ProbePortAllocationWithMapping(ctx, servers, *samples)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe failed: %v\n", err)
		os.Exit(1)
	}
	observed := 0
	if n := len(report.Samples); n > 0 {
		observed = report.Samples[n-1].MappedPort
	}
	ip := ""
	if report.MappedIP != nil {
		ip = report.MappedIP.String()
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
		"public_ip":      ip,
		"observed_port":  observed,
		"mapping_type":   report.MappingNATType.String(),
		"mapping_error":  report.MappingError,
		"pattern":        report.Pattern.String(),
		"delta":          report.Delta,
		"stable_ip":      report.StableIP,
		"confidence":     report.Confidence,
		"sample_count":   len(report.Samples),
		"samples":        report.Samples,
		"stun_servers":   servers,
		"mapping_probes": report.MappingProbes,
	})
}

func splitServerList(raw string) []string {
	seen := make(map[string]struct{})
	servers := make([]string, 0)
	for _, server := range strings.Split(raw, ",") {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		if _, ok := seen[server]; ok {
			continue
		}
		seen[server] = struct{}{}
		servers = append(servers, server)
	}
	return servers
}

func runPunch(args []string) {
	fs := flag.NewFlagSet("punch", flag.ExitOnError)
	remoteIP := fs.String("remote-ip", "", "peer public IPv4")
	remotePort := fs.Int("remote-port", 0, "peer's most recent observed mapped port")
	remotePattern := fs.String("remote-pattern", "sequential", "peer NAT port pattern: sequential|preserving|random")
	remoteDelta := fs.Int("remote-delta", 1, "peer sequential delta")
	role := fs.String("role", "initiator", "initiator|responder")
	session := fs.String("session", "punchtest", "shared session id")
	sockets := fs.Int("sockets", 256, "source socket count")
	span := fs.Int("span", 24, "predicted ports ahead for sequential peers")
	birthday := fs.Int("birthday", 256, "random target ports for unpredictable peers")
	burst := fs.Int("burst", 2, "probe packets per target per round")
	localPort := fs.Int("local-port", 0, "bind a single fixed local source port (preserving NAT); ignores --sockets")
	roundDelay := fs.Duration("round-delay", 250*time.Millisecond, "pause between punch rounds (rate control)")
	duration := fs.Duration("duration", 25*time.Second, "punch attempt window")
	fs.Parse(args)

	ip := net.ParseIP(strings.TrimSpace(*remoteIP))
	if ip == nil || ip.To4() == nil {
		fmt.Fprintln(os.Stderr, "punch: --remote-ip must be IPv4")
		os.Exit(2)
	}

	cfg := puncher.Config{
		RemoteIP:    ip.To4(),
		Session:     sessionKey(*session),
		SocketCount: *sockets,
		Burst:       *burst,
		LocalPort:   *localPort,
		RoundDelay:  *roundDelay,
		Method:      "punchtest",
	}
	if pat := patternFromString(*remotePattern); pat == nat.PortAllocationSequential || pat == nat.PortAllocationPreserving {
		report := nat.PortAllocationReport{Pattern: pat, Delta: *remoteDelta}
		cfg.TargetPorts = report.PredictMappedPorts(*remotePort, *span)
		if len(cfg.TargetPorts) == 0 && *remotePort > 0 {
			cfg.TargetPorts = []int{*remotePort}
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

	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	start := time.Now()
	res, err := puncher.Punch(ctx, cfg)
	if err != nil {
		fmt.Printf("[punch] FAILED after %s: %v\n", time.Since(start).Round(time.Millisecond), err)
		os.Exit(1)
	}
	fmt.Printf("[punch] HIT in %s: local=%s peer=%s\n",
		time.Since(start).Round(time.Millisecond), res.LocalAddr, res.RemoteAddr)

	conn := res.Connected()
	defer conn.Close()
	if err := verifyDataPlane(conn, *role); err != nil {
		fmt.Printf("[data] verification error: %v\n", err)
		os.Exit(1)
	}
}

// computeTargets mirrors the strategy's planPunch: predict for sequential/
// preserving peers, spray for unpredictable ones.
func computeTargets(pattern string, observedPort, delta, span, birthdayN int) []int {
	report := nat.PortAllocationReport{Pattern: patternFromString(pattern), Delta: delta}
	switch report.Pattern {
	case nat.PortAllocationSequential, nat.PortAllocationPreserving:
		targets := report.PredictMappedPorts(observedPort, span)
		if len(targets) == 0 && observedPort > 0 {
			targets = []int{observedPort}
		}
		return targets
	default:
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		targets := puncher.BirthdayTargets(r, birthdayN, 1024, 65535)
		if observedPort >= 1024 && observedPort <= 65535 {
			targets = append(targets, observedPort)
		}
		return targets
	}
}

func patternFromString(s string) nat.PortAllocationPattern {
	switch s {
	case "preserving":
		return nat.PortAllocationPreserving
	case "sequential":
		return nat.PortAllocationSequential
	case "random":
		return nat.PortAllocationRandom
	default:
		return nat.PortAllocationUnknown
	}
}

// verifyDataPlane exchanges application ping/echo over the punched path to prove
// it carries real bidirectional traffic (our own minimal data plane).
func verifyDataPlane(conn net.Conn, role string) error {
	const rounds = 5
	deadline := time.Now().Add(15 * time.Second)
	buf := make([]byte, 1500)

	if role == "responder" {
		echoed := 0
		for time.Now().Before(deadline) && echoed < rounds {
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				continue
			}
			msg := string(buf[:n])
			if strings.HasPrefix(msg, "PING-") {
				pong := "PONG-" + strings.TrimPrefix(msg, "PING-")
				if _, err := conn.Write([]byte(pong)); err != nil {
					return err
				}
				echoed++
				fmt.Printf("[data] echoed %s\n", msg)
			}
		}
		fmt.Printf("[data] responder echoed %d/%d pings — data plane OK\n", echoed, rounds)
		if echoed == 0 {
			return fmt.Errorf("no application pings received")
		}
		return nil
	}

	// initiator: send pings, expect pongs, measure RTT.
	got := 0
	for i := 0; i < rounds; i++ {
		payload := fmt.Sprintf("PING-%d", i)
		sent := time.Now()
		if _, err := conn.Write([]byte(payload)); err != nil {
			return err
		}
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			if string(buf[:n]) == "PONG-"+strconv.Itoa(i) {
				got++
				fmt.Printf("[data] round %d RTT=%s\n", i, time.Since(sent).Round(time.Millisecond))
				break
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("[data] initiator got %d/%d pongs — data plane %s\n", got, rounds,
		map[bool]string{true: "OK", false: "PARTIAL/FAILED"}[got > 0])
	if got == 0 {
		return fmt.Errorf("no pongs received over punched path")
	}
	return nil
}

func sessionKey(s string) [8]byte {
	sum := sha256.Sum256([]byte(s))
	var k [8]byte
	copy(k[:], sum[:8])
	return k
}
