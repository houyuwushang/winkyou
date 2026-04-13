//go:build !linux && !darwin && !windows

package netif

import "fmt"

func createTUNInterface(cfg Config) (NetworkInterface, error) {
	return nil, fmt.Errorf("netif: tun backend unsupported on %s: %w", currentGOOS(), errUnsupportedBackend)
}
