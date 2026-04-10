package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"winkyou/pkg/config"
	"winkyou/pkg/coordinator/server"
	"winkyou/pkg/logger"
	"winkyou/pkg/version"
)

func main() {
	os.Exit(run())
}

func run() int {
	defaults := server.DefaultConfig()

	var (
		configPath  string
		listen      string
		networkCIDR string
		leaseTTL    = defaults.LeaseTTL
		authKey     string
		showVersion bool
	)

	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.StringVar(&listen, "listen", defaults.ListenAddress, "coordinator listen address")
	flag.StringVar(&networkCIDR, "network-cidr", defaults.NetworkCIDR, "overlay network CIDR")
	flag.DurationVar(&leaseTTL, "lease-ttl", defaults.LeaseTTL, "node lease TTL")
	flag.StringVar(&authKey, "auth-key", "", "optional shared registration auth key")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return 0
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	log, err := logger.New(&cfg.Log)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() {
		_ = log.Sync()
	}()

	srv, err := server.New(&server.Config{
		ListenAddress: listen,
		NetworkCIDR:   networkCIDR,
		LeaseTTL:      leaseTTL,
		AuthKey:       authKey,
	})
	if err != nil {
		log.Error("failed to create coordinator server", logger.Error(err))
		return 1
	}

	log.Info(
		"wink coordinator placeholder started",
		logger.String("listen", srv.ListenAddress()),
		logger.String("network_cidr", srv.NetworkCIDR()),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()

	log.Info("wink coordinator shutting down")
	return 0
}
