package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
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
		authKeyFile  string
		tlsCertPath  string
		tlsKeyPath   string
		storeBackend string
		sqlitePath   string
		showVersion  bool
	)

	flag.StringVar(&configPath, "config", "", "optional config file for log settings only")
	flag.StringVar(&listen, "listen", defaults.ListenAddress, "coordinator listen address")
	flag.StringVar(&networkCIDR, "network-cidr", defaults.NetworkCIDR, "overlay network CIDR")
	flag.DurationVar(&leaseTTL, "lease-ttl", defaults.LeaseTTL, "node lease TTL")
	flag.StringVar(&authKey, "auth-key", "", "shared coordinator RPC auth key; prefer --auth-key-file because command arguments may be observable")
	flag.StringVar(&authKeyFile, "auth-key-file", "", "path to a one-line shared coordinator RPC auth key; required for non-loopback listeners unless --auth-key is set")
	flag.StringVar(&tlsCertPath, "tls-cert", "", "PEM TLS certificate path; required for non-loopback listeners")
	flag.StringVar(&tlsKeyPath, "tls-key", "", "PEM TLS private key path; required for non-loopback listeners")
	flag.StringVar(&storeBackend, "store-backend", defaults.StoreBackend, "coordinator store backend: memory|sqlite")
	flag.StringVar(&sqlitePath, "sqlite-path", "", "sqlite db path when store-backend=sqlite")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return 0
	}
	var err error
	authKey, err = resolveCoordinatorAuthKey(authKey, authKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wink-coordinator: %v\n", err)
		return 1
	}
	if err := validateCoordinatorSecurity(listen, authKey, tlsCertPath, tlsKeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "wink-coordinator: %v\n", err)
		return 1
	}

	logCfg := config.Default().Log
	if configPath != "" {
		cfg, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		logCfg = cfg.Log
		fmt.Fprintln(os.Stderr, "wink-coordinator: --config only applies log settings; server listen/network/store parameters still come from flags")
	}

	log, err := logger.New(&logCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() {
		_ = log.Sync()
	}()

	grpcOptions, err := server.GRPCServerOptions(authKey, tlsCertPath, tlsKeyPath)
	if err != nil {
		log.Error("failed to configure coordinator transport security", logger.Error(err))
		return 1
	}

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
		logger.Bool("tls_enabled", strings.TrimSpace(tlsCertPath) != ""),
		logger.Bool("shared_auth_enabled", strings.TrimSpace(authKey) != ""),
	)

	listener, err := net.Listen("tcp", srv.ListenAddress())
	if err != nil {
		log.Error("failed to listen", logger.Error(err), logger.String("listen", srv.ListenAddress()))
		return 1
	}
	defer func() {
		_ = listener.Close()
	}()

	grpcServer := grpc.NewServer(grpcOptions...)
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

const maxCoordinatorAuthKeyBytes = 4 * 1024

func resolveCoordinatorAuthKey(authKey, authKeyFile string) (string, error) {
	filePath := strings.TrimSpace(authKeyFile)
	if filePath == "" {
		return authKey, nil
	}
	if authKey != "" {
		return "", fmt.Errorf("--auth-key and --auth-key-file are mutually exclusive")
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("open --auth-key-file: %w", err)
	}
	defer func() { _ = file.Close() }()

	data, err := io.ReadAll(io.LimitReader(file, maxCoordinatorAuthKeyBytes+1))
	if err != nil {
		return "", fmt.Errorf("read --auth-key-file: %w", err)
	}
	if len(data) > maxCoordinatorAuthKeyBytes {
		return "", fmt.Errorf("--auth-key-file exceeds %d bytes", maxCoordinatorAuthKeyBytes)
	}

	key := string(data)
	if strings.HasSuffix(key, "\r\n") {
		key = strings.TrimSuffix(key, "\r\n")
	} else {
		key = strings.TrimSuffix(key, "\n")
	}
	if strings.ContainsAny(key, "\r\n") {
		return "", fmt.Errorf("--auth-key-file must contain exactly one line")
	}
	if strings.TrimSpace(key) == "" {
		return "", fmt.Errorf("--auth-key-file contains an empty auth key")
	}
	return key, nil
}

func validateCoordinatorSecurity(listen, authKey, tlsCertPath, tlsKeyPath string) error {
	loopback, err := isExplicitLoopbackListener(listen)
	if err != nil {
		return err
	}

	hasCert := strings.TrimSpace(tlsCertPath) != ""
	hasKey := strings.TrimSpace(tlsKeyPath) != ""
	if hasCert != hasKey {
		return fmt.Errorf("--tls-cert and --tls-key must be provided together")
	}
	if loopback {
		return nil
	}
	if !hasCert || strings.TrimSpace(authKey) == "" {
		return fmt.Errorf(
			"non-loopback listener %q requires --tls-cert, --tls-key, and a non-empty --auth-key-file (or --auth-key); plaintext or unauthenticated mode is loopback-only",
			listen,
		)
	}
	return nil
}

func isExplicitLoopbackListener(listen string) (bool, error) {
	listen = strings.TrimSpace(listen)
	host, port, err := net.SplitHostPort(listen)
	if err != nil || strings.TrimSpace(port) == "" {
		return false, fmt.Errorf("invalid coordinator listen address %q", listen)
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback(), nil
}
