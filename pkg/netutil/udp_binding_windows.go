//go:build windows

package netutil

import (
	"math/bits"

	"golang.org/x/sys/windows"
)

const windowsIPUnicastIF = 31

func bindUDP4SocketToInterface(fd uintptr, _ string, interfaceIndex int) error {
	// IP_UNICAST_IF expects an interface index encoded in network byte order.
	value := int(bits.ReverseBytes32(uint32(interfaceIndex)))
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windowsIPUnicastIF, value)
}
