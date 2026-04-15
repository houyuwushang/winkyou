package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	relayserver "winkyou/pkg/relay/server"
	"winkyou/pkg/version"
)

func main() { os.Exit(run()) }

func run() int {
	var (
		listen             string
		realm              string
		users              string
		relayIP            string
		externalIP         string
		minPort            int
		maxPort            int
		allowWildcardListen bool
		showVersion        bool
	)
	flag.StringVar(&listen, "listen", ":3478", "udp listen address")
	flag.StringVar(&realm, "realm", "winkyou", "turn realm")
	flag.StringVar(&users, "users", "", "static users: user1:pass1,user2:pass2")
	flag.StringVar(&relayIP, "relay-ip", "", "relay public ip (optional, deprecated: use --external-ip)")
	flag.StringVar(&externalIP, "external-ip", "", "external/public ip for relay candidates")
	flag.IntVar(&minPort, "min-port", 0, "minimum relay port (requires --max-port)")
	flag.IntVar(&maxPort, "max-port", 0, "maximum relay port (requires --min-port)")
	flag.BoolVar(&allowWildcardListen, "allow-wildcard-listen", false, "allow wildcard listen with explicit external-ip")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return 0
	}

	if externalIP == "" && relayIP != "" {
		externalIP = relayIP
	}

	userMap, err := parseUsers(users)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if minPort > 0 && maxPort > 0 && maxPort < minPort {
		fmt.Fprintf(os.Stderr, "invalid port range: min-port (%d) > max-port (%d)\n", minPort, maxPort)
		return 1
	}

	srv, err := relayserver.New(relayserver.Config{
		ListenAddress:       listen,
		Realm:               realm,
		Users:               userMap,
		RelayAddress:        externalIP,
		MinPort:             minPort,
		MaxPort:             maxPort,
		AllowWildcardListen: allowWildcardListen,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := srv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer srv.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return 0
}

func parseUsers(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid users format, expected user:pass[,user:pass]")
		}
		out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one static user is required via --users")
	}
	return out, nil
}
