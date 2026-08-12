// Command meshnode runs one autonomous WinkYou mesh peer for multi-host field
// experiments. Existing SSH/natpierce reachability is used only to bootstrap a
// stream neighbor; shortcut attempts install independent public UDP edges.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"winkyou/pkg/meshruntime"
)

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, ",") }

func (f *repeatedFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("value must not be empty")
	}
	*f = append(*f, value)
	return nil
}

func main() {
	var peers repeatedFlag
	var maintainedPeers repeatedFlag
	var stunServers repeatedFlag
	var tcpForwards repeatedFlag
	var virtualTCPForwards repeatedFlag
	var shutdownToken string
	cfg := meshruntime.Config{}

	flag.StringVar(&cfg.NodeID, "id", "", "stable mesh node ID (required)")
	flag.StringVar(&cfg.VirtualIP, "virtual-ip", "", "virtual IP advertised in membership (virtual TCP facade requires an IPv6 ULA)")
	flag.StringVar(&cfg.MeshListen, "mesh-listen", "127.0.0.1:32100", "bootstrap stream listen address, or 'off'")
	flag.StringVar(&cfg.ControlListen, "control-listen", "127.0.0.1:32110", "local HTTP control listen address, or 'off'")
	flag.StringVar(&shutdownToken, "shutdown-token", "", "token enabling loopback-only POST /v1/shutdown (disabled when empty)")
	flag.Var(&peers, "peer", "desired bootstrap peer as NODE_ID=HOST:PORT (repeatable)")
	flag.Var(&maintainedPeers, "maintain-peer", "peer whose protected-direct edge should be maintained (autonomous birthday recovery is currently paused and rejected)")
	flag.Var(&stunServers, "stun", "STUN URL used by birthday punch (repeatable)")
	flag.StringVar(&cfg.PunchInterface, "punch-interface", "", "optional interface name that must carry every birthday/self-bootstrap UDP socket")
	flag.StringVar(&cfg.TCPTarget, "tcp-target", "", "fixed local TCP target exposed to mesh peers, e.g. 127.0.0.1:22")
	flag.Var(&tcpForwards, "tcp-forward", "loopback listener and remote node as LISTEN=NODE_ID (repeatable)")
	flag.Var(&virtualTCPForwards, "virtual-tcp-forward", "managed ULA listener and remote node as [VIRTUAL_IP]:PORT=NODE_ID (repeatable; Windows, administrator required)")
	flag.DurationVar(&cfg.Lease, "lease", 15*time.Second, "flooded membership/link-state lease")
	flag.DurationVar(&cfg.RefreshInterval, "refresh", 3*time.Second, "membership/link-state refresh interval")
	flag.DurationVar(&cfg.DialRetry, "dial-retry", time.Second, "bootstrap peer redial interval")
	flag.DurationVar(&cfg.HandshakeTimeout, "handshake-timeout", 5*time.Second, "bootstrap stream hello timeout")
	flag.IntVar(&cfg.ProbeSamples, "probe-samples", 8, "STUN port-allocation samples per shortcut")
	flag.DurationVar(&cfg.EndpointTimeout, "endpoint-timeout", 60*time.Second, "birthday endpoint exchange timeout")
	flag.DurationVar(&cfg.PunchTimeout, "punch-timeout", 90*time.Second, "birthday punch window")
	flag.DurationVar(&cfg.StartLead, "start-lead", time.Second, "lead time before synchronized punching")
	flag.DurationVar(&cfg.SolveTimeout, "solve-timeout", 150*time.Second, "whole shortcut solver timeout")
	flag.DurationVar(&cfg.AttemptTimeout, "attempt-timeout", 0, "whole shortcut protocol deadline (default: two solve windows plus probation/liveness margin)")
	flag.DurationVar(&cfg.Probation, "probation", 35*time.Second, "direct-edge probation before stable commit")
	flag.DurationVar(&cfg.KeepAliveInterval, "keepalive", time.Second, "packet-neighbor keepalive interval")
	flag.DurationVar(&cfg.PeerTimeout, "peer-timeout", 30*time.Second, "packet-neighbor total-receive-silence timeout")
	flag.DurationVar(&cfg.RecoveryDebounce, "recovery-debounce", 250*time.Millisecond, "topology convergence delay before direct-edge repair")
	flag.DurationVar(&cfg.RecoveryMinBackoff, "recovery-min-backoff", 2*time.Second, "minimum automatic repair retry backoff")
	flag.DurationVar(&cfg.RecoveryMaxBackoff, "recovery-max-backoff", time.Minute, "maximum automatic repair retry backoff")
	flag.DurationVar(&cfg.RecoveryStableReset, "recovery-stable-reset", 0, "healthy duration before clearing repair failures (default: probation)")
	flag.StringVar(&cfg.RecoveryCardPath, "recovery-card", "", "persistent peer recovery card (autonomous birthday recovery is currently paused and rejected)")
	flag.StringVar(&cfg.SelfBootstrapSecretFile, "self-bootstrap-secret-file", "", "optional pre-shared secret for self-bootstrap authentication (without it, node IDs are trusted)")
	flag.DurationVar(&cfg.SelfBootstrapWindow, "self-bootstrap-window", 45*time.Second, "active cached-endpoint punch window")
	flag.DurationVar(&cfg.SelfBootstrapCycle, "self-bootstrap-cycle", time.Minute, "deterministic interval between cached-endpoint punch windows")
	flag.DurationVar(&cfg.SelfBootstrapHelloTimeout, "self-bootstrap-hello-timeout", 8*time.Second, "peer identity handshake reserve inside each self-bootstrap window")
	flag.DurationVar(&cfg.TCPFrameTimeout, "tcp-frame-timeout", 0, "routed TCP frame ACK deadline (default: two peer timeouts plus 15s)")
	flag.Parse()

	cfg.InitialPeers = append([]string(nil), peers...)
	cfg.MaintainedPeers = append([]string(nil), maintainedPeers...)
	cfg.STUNServers = append([]string(nil), stunServers...)
	cfg.TCPForwards = append([]string(nil), tcpForwards...)
	cfg.VirtualTCPForwards = append([]string(nil), virtualTCPForwards...)
	if len(cfg.STUNServers) == 0 {
		cfg.STUNServers = []string{
			"stun:stun.cloudflare.com:3478",
			"stun:stun.l.google.com:19302",
			"stun:stun.miwifi.com:3478",
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	node, err := meshruntime.New(cfg, meshruntime.Options{EventWriter: os.Stderr, ShutdownToken: shutdownToken})
	if err != nil {
		fmt.Fprintf(os.Stderr, "meshnode configuration failed: %v\n", err)
		os.Exit(2)
	}
	if err := node.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "meshnode start failed: %v\n", err)
		_ = node.Close()
		os.Exit(1)
	}
	select {
	case <-ctx.Done():
	case <-node.Done():
	}
	if err := node.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "meshnode shutdown: %v\n", err)
		os.Exit(1)
	}
}
