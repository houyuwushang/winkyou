//go:build linux && fieldc1c

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"winkyou/internal/c1crouter"
)

func main() {
	os.Exit(run())
}

func run() (exit int) {
	defer func() {
		if recover() != nil {
			_, _ = os.Stdout.Write([]byte(`{"profile":"","stage":"terminal","class":"c1c_router_io_failed","duration_ns":0,"counts":{},"evidence_sha256":""}` + "\n"))
			exit = 1
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer cancel()
	result := c1crouter.Execute(ctx, os.Args[1:])
	b, err := result.Encode()
	if err != nil {
		b = []byte(`{"profile":"","stage":"terminal","class":"gate_c_request_invalid","duration_ns":0,"counts":{},"evidence_sha256":""}`)
	}
	_, _ = os.Stdout.Write(append(b, '\n'))
	if !oneOfSuccess(result.Class) {
		return 1
	}
	return 0
}
func oneOfSuccess(class string) bool {
	return class == "success" || class == "cancelled" || class == "expired"
}
