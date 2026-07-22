//go:build linux

package netutil

import "golang.org/x/sys/unix"

func bindUDP4SocketToInterface(fd uintptr, interfaceName string, _ int) error {
	return unix.BindToDevice(int(fd), interfaceName)
}
