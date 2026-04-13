//go:build darwin

package netif

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	darwinUTUNControlName = "com.apple.net.utun_control"
	darwinUTUNOptIfName   = 2
	darwinSysprotoControl = 2
)

type wgTunInterface struct {
	file  *os.File
	name  string
	mtu   int
	mu    sync.Mutex
	close bool
}

func createTUNInterface(cfg Config) (NetworkInterface, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, darwinSysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("netif: create utun socket: %w", err)
	}

	info := &unix.CtlInfo{}
	copy(info.Name[:], darwinUTUNControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netif: lookup utun control id: %w", err)
	}

	addr := &unix.SockaddrCtl{ID: info.Id, Unit: 0}
	if err := unix.Connect(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netif: connect utun control: %w", err)
	}

	name, err := unix.GetsockoptString(fd, darwinSysprotoControl, darwinUTUNOptIfName)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netif: get utun interface name: %w", err)
	}

	return &wgTunInterface{file: os.NewFile(uintptr(fd), name), name: name, mtu: cfg.MTU}, nil
}

func (w *wgTunInterface) Name() string { return w.name }
func (w *wgTunInterface) Type() string { return "tun" }
func (w *wgTunInterface) MTU() int     { return w.mtu }

func (w *wgTunInterface) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	tmp := make([]byte, len(buf)+4)
	n, err := w.file.Read(tmp)
	if err != nil {
		return 0, err
	}
	if n <= 4 {
		return 0, nil
	}
	return copy(buf, tmp[4:n]), nil
}

func (w *wgTunInterface) Write(buf []byte) (int, error) {
	hdr := make([]byte, 4)
	if ip4 := net.IP(buf).To4(); ip4 != nil {
		binary.BigEndian.PutUint32(hdr, unix.AF_INET)
	} else {
		binary.BigEndian.PutUint32(hdr, unix.AF_INET6)
	}
	pkt := append(hdr, buf...)
	n, err := w.file.Write(pkt)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, nil
	}
	return n - 4, nil
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
	if err := runCmd("ifconfig", w.name, "inet", cidr, cidr, "up"); err != nil {
		return err
	}
	return runCmd("ifconfig", w.name, "mtu", fmt.Sprintf("%d", w.mtu))
}

func (w *wgTunInterface) AddRoute(dst *net.IPNet, gateway net.IP) error {
	if dst == nil {
		return errRouteRequired
	}
	if gw := gateway.To4(); gw != nil {
		return runCmd("route", "-n", "add", "-net", dst.String(), gw.String())
	}
	return runCmd("route", "-n", "add", "-net", dst.String(), "-interface", w.name)
}

func (w *wgTunInterface) RemoveRoute(dst *net.IPNet) error {
	if dst == nil {
		return errRouteRequired
	}
	if err := runCmd("route", "-n", "delete", "-net", dst.String()); err != nil {
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
