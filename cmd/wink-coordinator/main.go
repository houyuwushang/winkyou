package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	coordinatorv1 "winkyou/api/proto/coordinatorv1"
	"winkyou/pkg/config"
	"winkyou/pkg/coordinator/server"
	"winkyou/pkg/logger"
	"winkyou/pkg/version"

	"google.golang.org/grpc"
)

func main() {
	os.Exit(run())
}

func run() int {
	defaults := server.DefaultConfig()

	var (
		configPath   string
		listen       string
		networkCIDR  string
		leaseTTL     = defaults.LeaseTTL
		authKey      string
		storeBackend string
		sqlitePath   string
		showVersion  bool
	)

	flag.StringVar(&configPath, "config", "", "path to config file")
	flag.StringVar(&listen, "listen", defaults.ListenAddress, "coordinator listen address")
	flag.StringVar(&networkCIDR, "network-cidr", defaults.NetworkCIDR, "overlay network CIDR")
	flag.DurationVar(&leaseTTL, "lease-ttl", defaults.LeaseTTL, "node lease TTL")
	flag.StringVar(&authKey, "auth-key", "", "optional shared registration auth key")
	flag.StringVar(&storeBackend, "store-backend", defaults.StoreBackend, "coordinator store backend: memory|sqlite")
	flag.StringVar(&sqlitePath, "sqlite-path", "", "sqlite db path when store-backend=sqlite")
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
		StoreBackend:  storeBackend,
		SQLitePath:    sqlitePath,
	})
	if err != nil {
		log.Error("failed to create coordinator server", logger.Error(err))
		return 1
	}
	defer func() {
		_ = srv.Close()
	}()

	log.Info(
		"starting wink coordinator",
		logger.String("listen", srv.ListenAddress()),
		logger.String("network_cidr", srv.NetworkCIDR()),
	)

	listener, err := net.Listen("tcp", srv.ListenAddress())
	if err != nil {
		log.Error("failed to listen", logger.Error(err), logger.String("listen", srv.ListenAddress()))
		return 1
	}
	defer func() {
		_ = listener.Close()
	}()

	grpcServer := grpc.NewServer()
	coordinatorv1.RegisterCoordinatorServer(grpcServer, server.NewGRPCService(srv))

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- grpcServer.Serve(listener)
	}()

	log.Info(
		"wink coordinator started",
		logger.String("listen", listener.Addr().String()),
		logger.String("network_cidr", srv.NetworkCIDR()),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if err != nil {
			log.Error("coordinator serve loop exited", logger.Error(err))
			return 1
		}
		return 0
	}

	log.Info("wink coordinator shutting down")

	shutdownDone := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		grpcServer.Stop()
	}

	return 0
}
