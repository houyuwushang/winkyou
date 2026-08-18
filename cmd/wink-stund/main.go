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

	"winkyou/internal/stunserver"
	"winkyou/pkg/version"
)

const statsInterval = time.Minute

type options struct {
	listen      netip.AddrPort
	maxPPS      int
	logPrefixes bool
	showVersion bool
}

type logRecord struct {
	Time           string            `json:"time"`
	Event          string            `json:"event"`
	Listen         string            `json:"listen,omitempty"`
	WildcardListen bool              `json:"wildcard_listen,omitempty"`
	Exposure       string            `json:"exposure,omitempty"`
	MaxPPS         int               `json:"max_pps,omitempty"`
	PerSourcePPS   int               `json:"per_source_pps,omitempty"`
	PrefixLogging  bool              `json:"prefix_logging,omitempty"`
	Stats          *stunserver.Stats `json:"stats,omitempty"`
	Error          string            `json:"error,omitempty"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	config, err := parseOptions(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "wink-stund: %v\n", err)
		return 2
	}
	if config.showVersion {
		info := version.Current()
		fmt.Fprintf(stdout, "wink-stund version %s (commit: %s, built: %s, go: %s)\n", info.Version, info.Commit, info.BuildTime, info.GoVersion)
		return 0
	}
	server, err := stunserver.Open(stunserver.Config{
		ListenAddr:  config.listen,
		MaxPPS:      config.maxPPS,
		LogPrefixes: config.logPrefixes,
	})
	if err != nil {
		fmt.Fprintf(stderr, "wink-stund: %v\n", err)
		return 1
	}
	defer func() { _ = server.Close() }()

	wildcard := server.ListenAddr().Addr().IsUnspecified()
	start := logRecord{
		Event:          "started",
		Listen:         server.ListenAddr().String(),
		WildcardListen: wildcard,
		MaxPPS:         server.MaxPPS(),
		PerSourcePPS:   server.PerSourcePPS(),
		PrefixLogging:  config.logPrefixes,
	}
	if wildcard {
		start.Exposure = "all_interfaces"
	}
	if err := writeLog(stderr, start); err != nil {
		fmt.Fprintf(stderr, "wink-stund: write startup log: %v\n", err)
		return 1
	}
	if err := serveWithStats(ctx, server, stderr, statsInterval); err != nil {
		_ = writeLog(stderr, logRecord{Event: "stopped", Stats: statsPointer(server.Snapshot()), Error: "serve_failed"})
		fmt.Fprintf(stderr, "wink-stund: %v\n", err)
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
	flags := flag.NewFlagSet("wink-stund", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&listen, "listen", "", "required literal UDP listen IP:port")
	flags.IntVar(&result.maxPPS, "max-pps", stunserver.DefaultMaxPPS, "global sustained response rate; may only lower the compiled maximum")
	flags.BoolVar(&result.logPrefixes, "log-prefixes", false, "include bounded /24 or /48 response counters")
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
	if result.maxPPS < 1 || result.maxPPS > stunserver.HardMaxPPS {
		return options{}, fmt.Errorf("invalid --max-pps %d: use 1..%d; the compiled ceiling cannot be raised", result.maxPPS, stunserver.HardMaxPPS)
	}
	result.listen = netip.AddrPortFrom(address, endpoint.Port())
	return result, nil
}

func serveWithStats(parent context.Context, server *stunserver.Server, output io.Writer, interval time.Duration) error {
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

func statsPointer(stats stunserver.Stats) *stunserver.Stats {
	return &stats
}

func writeLog(output io.Writer, record logRecord) error {
	record.Time = time.Now().UTC().Format(time.RFC3339Nano)
	return json.NewEncoder(output).Encode(record)
}
