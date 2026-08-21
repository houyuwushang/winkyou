package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"winkyou/internal/signalserver"
	"winkyou/pkg/version"
)

const statsInterval = time.Minute

type options struct {
	listen      netip.AddrPort
	showVersion bool
}

type logRecord struct {
	Time           string              `json:"time"`
	Event          string              `json:"event"`
	Listen         string              `json:"listen,omitempty"`
	WildcardListen bool                `json:"wildcard_listen,omitempty"`
	Exposure       string              `json:"exposure,omitempty"`
	TestOnly       bool                `json:"test_only,omitempty"`
	Warning        string              `json:"warning,omitempty"`
	TTLSeconds     int64               `json:"ttl_seconds,omitempty"`
	MaxActiveCodes int                 `json:"max_active_codes,omitempty"`
	MaxBodyBytes   int                 `json:"max_body_bytes,omitempty"`
	GlobalMaxRPS   int                 `json:"global_max_rps,omitempty"`
	PerSourceRPS   int                 `json:"per_source_max_rps,omitempty"`
	Stats          *signalserver.Stats `json:"stats,omitempty"`
	Error          string              `json:"error,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	config, err := parseOptions(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "wink-signal: %v\n", err)
		return 2
	}
	if config.showVersion {
		info := version.Current()
		fmt.Fprintf(stdout, "wink-signal version %s (commit: %s, built: %s, go: %s)\n", info.Version, info.Commit, info.BuildTime, info.GoVersion)
		return 0
	}
	server, err := signalserver.Open(signalserver.Config{ListenAddr: config.listen})
	if err != nil {
		fmt.Fprintf(stderr, "wink-signal: %v\n", err)
		return 1
	}
	defer func() { _ = server.Close() }()

	wildcard := server.ListenAddr().Addr().IsUnspecified()
	start := logRecord{
		Event:          "started",
		Listen:         server.ListenAddr().String(),
		WildcardListen: wildcard,
		TestOnly:       true,
		Warning:        "plaintext_observation_exchange_no_secrets",
		TTLSeconds:     int64(signalserver.MailboxTTL / time.Second),
		MaxActiveCodes: signalserver.MaxActiveCodes,
		MaxBodyBytes:   signalserver.MaxBodyBytes,
		GlobalMaxRPS:   signalserver.GlobalMaxRPS,
		PerSourceRPS:   signalserver.PerSourceMaxRPS,
	}
	if wildcard {
		start.Exposure = "all_interfaces"
	}
	if err := writeLog(stderr, start); err != nil {
		fmt.Fprintf(stderr, "wink-signal: write startup log: %v\n", err)
		return 1
	}
	if err := serveWithStats(ctx, server, stderr, statsInterval); err != nil {
		_ = writeLog(stderr, logRecord{Event: "stopped", Stats: statsPointer(server.Snapshot()), Error: "serve_failed"})
		fmt.Fprintf(stderr, "wink-signal: %v\n", err)
		return 1
	}
	if err := writeLog(stderr, logRecord{Event: "stopped", Stats: statsPointer(server.Snapshot())}); err != nil {
		return 1
	}
	return 0
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	var result options
	var listen string
	flags := flag.NewFlagSet("wink-signal", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&listen, "listen", "", "required literal TCP listen IP:port")
	flags.BoolVar(&result.showVersion, "version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments")
	}
	if result.showVersion {
		return result, nil
	}
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return options{}, fmt.Errorf("--listen is required")
	}
	endpoint, err := netip.ParseAddrPort(listen)
	if err != nil {
		return options{}, fmt.Errorf("invalid --listen %q: use a literal IPv4 or bracketed IPv6 IP:port; hostnames are not accepted", listen)
	}
	if endpoint.Port() == 0 || endpoint.Addr().Zone() != "" {
		return options{}, fmt.Errorf("invalid --listen %q: a non-zero port and no IPv6 zone are required", listen)
	}
	address := endpoint.Addr().Unmap()
	if !(address.IsUnspecified() || address.IsLoopback() || address.IsGlobalUnicast()) {
		return options{}, fmt.Errorf("invalid --listen %q: address must be unicast, loopback, or unspecified", listen)
	}
	result.listen = netip.AddrPortFrom(address, endpoint.Port())
	return result, nil
}

func serveWithStats(parent context.Context, server *signalserver.Server, output io.Writer, interval time.Duration) error {
	if parent == nil || server == nil || output == nil || interval <= 0 {
		return errors.New("invalid serve/log configuration")
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx) }()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-serveDone:
			return err
		case <-ticker.C:
			if err := writeLog(output, logRecord{Event: "counters", Stats: statsPointer(server.Snapshot())}); err != nil {
				cancel()
				<-serveDone
				return fmt.Errorf("write counter log: %w", err)
			}
		}
	}
}

func statsPointer(stats signalserver.Stats) *signalserver.Stats {
	return &stats
}

func writeLog(output io.Writer, record logRecord) error {
	record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	return json.NewEncoder(output).Encode(record)
}
