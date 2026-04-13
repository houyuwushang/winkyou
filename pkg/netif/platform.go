package netif

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
)

func cidrFromIPv4(ip net.IP, mask net.IPMask) (string, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", errIPv4Required
	}
	if mask == nil {
		return "", errMaskRequired
	}
	ones, bits := net.IPMask(mask).Size()
	if bits != 32 {
		return "", errMaskRequired
	}
	return fmt.Sprintf("%s/%d", ip4.String(), ones), nil
}

func isExitError(err error) bool {
	_, ok := err.(*exec.ExitError)
	return ok
}

func currentGOOS() string {
	return runtime.GOOS
}
