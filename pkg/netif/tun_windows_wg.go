//go:build windows

package netif

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
)

const defaultWindowsTUNName = "wink0"
const windowsTUNNameEnv = "WINKYOU_TUN_NAME"

type batchTunDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	Name() (string, error)
	MTU() (int, error)
	Close() error
	BatchSize() int
}

type wgTunInterface struct {
	device    batchTunDevice
	name      string
	mtu       int
	mu        sync.Mutex
	closed    bool
	runScript func(action, script string) error
}

func createTUNInterface(cfg Config) (NetworkInterface, error) {
	device, err := wgtun.CreateTUN(windowsTUNName(), cfg.MTU)
	if err != nil {
		return nil, explainWindowsTUNCreateError(err)
	}

	name, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("netif: determine Windows TUN interface name: %w", err)
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		if detected, mtuErr := device.MTU(); mtuErr == nil && detected > 0 {
			mtu = detected
		} else {
			mtu = 1280
		}
	}

	return &wgTunInterface{
		device:    device,
		name:      name,
		mtu:       mtu,
		runScript: runWindowsPowerShell,
	}, nil
}

func windowsTUNName() string {
	name := strings.TrimSpace(os.Getenv(windowsTUNNameEnv))
	if name == "" {
		return defaultWindowsTUNName
	}
	return name
}

func (w *wgTunInterface) Name() string { return w.name }
func (w *wgTunInterface) Type() string { return "tun" }
func (w *wgTunInterface) MTU() int     { return w.mtu }

func (w *wgTunInterface) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if err := w.ensureOpen(); err != nil {
		return 0, err
	}
	return readPacketFromBatchDevice(w.device, buf)
}

func (w *wgTunInterface) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	if err := w.ensureOpen(); err != nil {
		return 0, err
	}
	return writePacketToBatchDevice(w.device, buf)
}

func (w *wgTunInterface) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.device.Close()
}

func (w *wgTunInterface) SetIP(ip net.IP, mask net.IPMask) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}

	script, err := buildWindowsSetIPScript(w.name, ip, mask, w.mtu)
	if err != nil {
		return err
	}
	return w.runScript("configure Windows TUN address", script)
}

func (w *wgTunInterface) AddRoute(dst *net.IPNet, gateway net.IP) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	if dst == nil {
		return errRouteRequired
	}

	script := buildWindowsAddRouteScript(w.name, dst, gateway)
	return w.runScript("add Windows route", script)
}

func (w *wgTunInterface) RemoveRoute(dst *net.IPNet) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	if dst == nil {
		return errRouteRequired
	}

	script := buildWindowsRemoveRouteScript(w.name, dst)
	return w.runScript("remove Windows route", script)
}

func (w *wgTunInterface) ensureOpen() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return net.ErrClosed
	}
	return nil
}

func readPacketFromBatchDevice(device batchTunDevice, buf []byte) (int, error) {
	sizes := make([]int, 1)
	count, err := device.Read([][]byte{buf}, sizes, 0)
	if count == 0 {
		return 0, err
	}
	return sizes[0], err
}

func writePacketToBatchDevice(device batchTunDevice, buf []byte) (int, error) {
	count, err := device.Write([][]byte{buf}, 0)
	if err != nil {
		return 0, err
	}
	if count == 0 {
		return 0, nil
	}
	return len(buf), nil
}

func buildWindowsSetIPScript(iface string, ip net.IP, mask net.IPMask, mtu int) (string, error) {
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

	return windowsPSScript(
		fmt.Sprintf("$alias = '%s'", escapePowerShellSingleQuoted(iface)),
		fmt.Sprintf("$ip = '%s'", ip4.String()),
		fmt.Sprintf("$prefix = %d", ones),
		fmt.Sprintf("$mtu = %d", mtu),
		"$existing = @(Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue)",
		"foreach ($entry in $existing) {",
		"  if ($entry.IPAddress -ne $ip -or $entry.PrefixLength -ne $prefix) {",
		"    Remove-NetIPAddress -InputObject $entry -Confirm:$false -ErrorAction SilentlyContinue",
		"  }",
		"}",
		"$matched = @($existing | Where-Object { $_.IPAddress -eq $ip -and $_.PrefixLength -eq $prefix })",
		"if ($matched.Count -eq 0) {",
		"  New-NetIPAddress -InterfaceAlias $alias -IPAddress $ip -PrefixLength $prefix -AddressFamily IPv4 -Type Unicast -PolicyStore ActiveStore | Out-Null",
		"}",
		"Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -NlMtuBytes $mtu | Out-Null",
		"Enable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue | Out-Null",
	), nil
}

func buildWindowsAddRouteScript(iface string, dst *net.IPNet, gateway net.IP) string {
	nextHop := "0.0.0.0"
	if gw := gateway.To4(); gw != nil {
		nextHop = gw.String()
	}

	return windowsPSScript(
		fmt.Sprintf("$alias = '%s'", escapePowerShellSingleQuoted(iface)),
		fmt.Sprintf("$destination = '%s'", dst.String()),
		fmt.Sprintf("$nextHop = '%s'", nextHop),
		"$ipif = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1",
		"if ($null -eq $ipif) { throw \"interface not found or IPv4 not ready: $alias\" }",
		"$existing = @(Get-NetRoute -DestinationPrefix $destination -InterfaceIndex $ipif.InterfaceIndex -ErrorAction SilentlyContinue)",
		"foreach ($route in $existing) {",
		"  Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue",
		"}",
		"New-NetRoute -DestinationPrefix $destination -InterfaceIndex $ipif.InterfaceIndex -NextHop $nextHop -PolicyStore ActiveStore | Out-Null",
	)
}

func buildWindowsRemoveRouteScript(iface string, dst *net.IPNet) string {
	return windowsPSScript(
		fmt.Sprintf("$alias = '%s'", escapePowerShellSingleQuoted(iface)),
		fmt.Sprintf("$destination = '%s'", dst.String()),
		"$ipif = Get-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1",
		"if ($null -eq $ipif) { return }",
		"$existing = @(Get-NetRoute -DestinationPrefix $destination -InterfaceIndex $ipif.InterfaceIndex -ErrorAction SilentlyContinue)",
		"foreach ($route in $existing) {",
		"  Remove-NetRoute -InputObject $route -Confirm:$false -ErrorAction SilentlyContinue",
		"}",
	)
}

func windowsPSScript(lines ...string) string {
	body := append([]string{"$ErrorActionPreference = 'Stop'"}, lines...)
	return strings.Join(body, "\n")
}

func escapePowerShellSingleQuoted(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func runWindowsPowerShell(action, script string) error {
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err == nil {
		return nil
	}
	return explainWindowsCommandError(action, err, out)
}

func explainWindowsTUNCreateError(err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED) || strings.Contains(strings.ToLower(err.Error()), "access is denied"):
		return fmt.Errorf("netif: creating the Windows TUN adapter requires Administrator privileges. Re-run wink from an elevated shell: %w", err)
	case errors.Is(err, windows.ERROR_MOD_NOT_FOUND),
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND),
		strings.Contains(strings.ToLower(err.Error()), "wintun.dll"),
		strings.Contains(strings.ToLower(err.Error()), "unable to load library"):
		return fmt.Errorf("netif: Wintun is unavailable. Install WireGuard for Windows or place wintun.dll next to wink.exe: %w", err)
	default:
		return fmt.Errorf("netif: create Windows TUN adapter: %w", err)
	}
}

func explainWindowsCommandError(action string, err error, output []byte) error {
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		detail = err.Error()
	}

	lower := strings.ToLower(detail + " " + err.Error())
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return fmt.Errorf("netif: %s failed because powershell.exe is unavailable: %w", action, err)
	case strings.Contains(lower, "access is denied"), strings.Contains(lower, "requested operation requires elevation"), errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return fmt.Errorf("netif: %s requires Administrator privileges on Windows: %s", action, detail)
	case strings.Contains(lower, "cannot find path"), strings.Contains(lower, "no matching"), strings.Contains(lower, "interface not found"):
		return fmt.Errorf("netif: %s failed because the Wintun interface was not found or is not ready: %s", action, detail)
	default:
		return fmt.Errorf("netif: %s failed: %s", action, detail)
	}
}
