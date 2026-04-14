//go:build windows

package netif

import (
	"errors"
	"net"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

type fakeBatchTunDevice struct {
	readCount  int
	readErr    error
	readData   []byte
	writeCount int
	writeErr   error
	writes     [][]byte
}

func (f *fakeBatchTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(f.readData) > 0 && len(bufs) > 0 {
		n := copy(bufs[0][offset:], f.readData)
		sizes[0] = n
	}
	return f.readCount, f.readErr
}

func (f *fakeBatchTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		f.writes = append(f.writes, append([]byte(nil), buf[offset:]...))
	}
	return f.writeCount, f.writeErr
}

func (f *fakeBatchTunDevice) Name() (string, error) { return "wink0", nil }
func (f *fakeBatchTunDevice) MTU() (int, error)     { return 1280, nil }
func (f *fakeBatchTunDevice) Close() error          { return nil }
func (f *fakeBatchTunDevice) BatchSize() int        { return 1 }

func TestReadPacketFromBatchDevice(t *testing.T) {
	device := &fakeBatchTunDevice{
		readCount: 1,
		readData:  []byte{0x45, 0x00, 0x00, 0x14},
	}

	buf := make([]byte, 16)
	n, err := readPacketFromBatchDevice(device, buf)
	if err != nil {
		t.Fatalf("readPacketFromBatchDevice() error = %v", err)
	}
	if n != 4 {
		t.Fatalf("readPacketFromBatchDevice() = %d, want 4", n)
	}
	if got := buf[:n]; string(got) != string(device.readData) {
		t.Fatalf("payload = %v, want %v", got, device.readData)
	}
}

func TestWritePacketToBatchDevice(t *testing.T) {
	device := &fakeBatchTunDevice{writeCount: 1}
	packet := []byte{0x45, 0x00, 0x00, 0x14}

	n, err := writePacketToBatchDevice(device, packet)
	if err != nil {
		t.Fatalf("writePacketToBatchDevice() error = %v", err)
	}
	if n != len(packet) {
		t.Fatalf("writePacketToBatchDevice() = %d, want %d", n, len(packet))
	}
	if len(device.writes) != 1 || string(device.writes[0]) != string(packet) {
		t.Fatalf("writes = %v, want single packet %v", device.writes, packet)
	}
}

func TestBuildWindowsSetIPScript(t *testing.T) {
	script, err := buildWindowsSetIPScript("wink0", net.ParseIP("10.42.0.2"), net.CIDRMask(24, 32), 1280)
	if err != nil {
		t.Fatalf("buildWindowsSetIPScript() error = %v", err)
	}
	for _, want := range []string{
		"Get-NetIPAddress",
		"New-NetIPAddress",
		"Set-NetIPInterface",
		"$ip = '10.42.0.2'",
		"$prefix = 24",
		"$mtu = 1280",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}
}

func TestBuildWindowsRouteScripts(t *testing.T) {
	_, dst, _ := net.ParseCIDR("10.42.0.0/24")

	addScript := buildWindowsAddRouteScript("wink0", dst, net.ParseIP("10.42.0.1"))
	if !strings.Contains(addScript, "New-NetRoute") || !strings.Contains(addScript, "$nextHop = '10.42.0.1'") {
		t.Fatalf("unexpected add route script:\n%s", addScript)
	}

	removeScript := buildWindowsRemoveRouteScript("wink0", dst)
	if !strings.Contains(removeScript, "Remove-NetRoute") || !strings.Contains(removeScript, "$destination = '10.42.0.0/24'") {
		t.Fatalf("unexpected remove route script:\n%s", removeScript)
	}
}

func TestExplainWindowsTUNCreateError(t *testing.T) {
	err := explainWindowsTUNCreateError(windows.ERROR_ACCESS_DENIED)
	if err == nil || !strings.Contains(err.Error(), "Administrator") {
		t.Fatalf("access denied error = %v, want admin guidance", err)
	}

	err = explainWindowsTUNCreateError(errors.New("Error loading wintun DLL: Unable to load library: The specified module could not be found."))
	if err == nil || !strings.Contains(err.Error(), "Install WireGuard for Windows") {
		t.Fatalf("missing DLL error = %v, want Wintun guidance", err)
	}
}
