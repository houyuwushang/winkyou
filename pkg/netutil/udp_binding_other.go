//go:build !windows && !linux

package netutil

import "fmt"

func bindUDP4SocketToInterface(_ uintptr, interfaceName string, _ int) error {
	return fmt.Errorf("explicit UDP interface binding %q is unsupported on this platform", interfaceName)
}
