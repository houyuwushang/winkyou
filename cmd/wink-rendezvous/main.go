package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/signal"
	"strings"

	"winkyou/internal/v2/rendezvousserver"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithServer(ctx, args, stdout, stderr, rendezvousserver.Serve)
}

func runWithServer(ctx context.Context, args []string, stdout, stderr io.Writer, serve func(context.Context, rendezvousserver.Config) rendezvousserver.TerminalRecord) int {
	_ = stdout
	config := rendezvousserver.Config{}
	valid := len(args) > 0 && args[0] == "serve" && validateServeArgs(args[1:]) && serve != nil
	if valid {
		flags := flag.NewFlagSet("wink-rendezvous serve", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		flags.StringVar(&config.ListenAddress, "listen", "", "")
		flags.StringVar(&config.TLSCertFile, "tls-cert", "", "")
		flags.StringVar(&config.TLSKeyFile, "tls-key", "", "")
		flags.StringVar(&config.AssociationFile, "association-file", "", "")
		valid = flags.Parse(args[1:]) == nil && flags.NArg() == 0
	}
	record := rendezvousserver.TerminalRecord{Event: "terminal", Class: rendezvousserver.ClassInternalError}
	if valid {
		record = serve(ctx, config)
	}
	payload := rendezvousserver.MarshalTerminal(record)
	_, _ = stderr.Write(append(payload, '\n'))
	clear(payload)
	if record.Class == rendezvousserver.ClassCompleted {
		return 0
	}
	return 1
}

func validateServeArgs(args []string) bool {
	allowed := map[string]struct{}{
		"listen": {}, "tls-cert": {}, "tls-key": {}, "association-file": {},
	}
	seen := make(map[string]struct{}, len(allowed))
	for index := 0; index < len(args); index++ {
		token := args[index]
		if !strings.HasPrefix(token, "--") || token == "--" {
			return false
		}
		nameValue := strings.TrimPrefix(token, "--")
		name, value, hasValue := strings.Cut(nameValue, "=")
		if _, ok := allowed[name]; !ok {
			return false
		}
		if _, duplicate := seen[name]; duplicate {
			return false
		}
		seen[name] = struct{}{}
		if hasValue {
			if value == "" {
				return false
			}
			continue
		}
		index++
		if index >= len(args) || args[index] == "" || strings.HasPrefix(args[index], "--") {
			return false
		}
	}
	return len(seen) == len(allowed)
}
