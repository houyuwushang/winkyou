//go:build windows

package netif

import "fmt"

func createTUNInterface(cfg Config) (NetworkInterface, error) {
	return nil, fmt.Errorf("netif: tun backend unsupported on windows in current build: %w", errUnsupportedBackend)
}
