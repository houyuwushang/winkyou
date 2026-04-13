//go:build linux

package netif

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	linuxIFFTUN   = 0x0001
	linuxIFFNO_PI = 0x1000
)

type wgTunInterface struct {
	file  *os.File
	name  string
	mtu   int
	mu    sync.Mutex
	close bool
}

func createTUNInterface(cfg Config) (NetworkInterface, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("netif: open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq("wink0")
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netif: new ifreq: %w", err)
	}
	ifr.SetUint16(linuxIFFTUN | linuxIFFNO_PI)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(ifr))); errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netif: ioctl TUNSETIFF: %w", errno)
	}

	name := ifr.Name()
	return &wgTunInterface{file: os.NewFile(uintptr(fd), name), name: name, mtu: cfg.MTU}, nil
}

func (w *wgTunInterface) Name() string { return w.name }
func (w *wgTunInterface) Type() string { return "tun" }
func (w *wgTunInterface) MTU() int     { return w.mtu }

func (w *wgTunInterface) Read(buf []byte) (int, error) {
	return w.file.Read(buf)
}

func (w *wgTunInterface) Write(buf []byte) (int, error) {
	return w.file.Write(buf)
}

func (w *wgTunInterface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.close {
		return nil
	}
	w.close = true
	return w.file.Close()
}

func (w *wgTunInterface) SetIP(ip net.IP, mask net.IPMask) error {
	cidr, err := cidrFromIPv4(ip, mask)
	if err != nil {
		return err
	}
	if err := runCmd("ip", "link", "set", "dev", w.name, "mtu", fmt.Sprintf("%d", w.mtu)); err != nil {
		return err
	}
	if err := runCmd("ip", "addr", "replace", cidr, "dev", w.name); err != nil {
		return err
	}
	return runCmd("ip", "link", "set", "dev", w.name, "up")
}

func (w *wgTunInterface) AddRoute(dst *net.IPNet, gateway net.IP) error {
	if dst == nil {
		return errRouteRequired
	}
	args := []string{"route", "replace", dst.String(), "dev", w.name}
	if gw := gateway.To4(); gw != nil {
		args = append(args, "via", gw.String())
	}
	return runCmd("ip", args...)
}

func (w *wgTunInterface) RemoveRoute(dst *net.IPNet) error {
	if dst == nil {
		return errRouteRequired
	}
	if err := runCmd("ip", "route", "del", dst.String(), "dev", w.name); err != nil {
		if isExitError(err) {
			return nil
		}
		return err
	}
	return nil
}

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netif: command %s %v failed: %w (%s)", name, args, err, string(out))
	}
	return nil
}
