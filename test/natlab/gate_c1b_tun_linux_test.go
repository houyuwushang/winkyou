//go:build linux && natlab && c1bproof

package natlab

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"winkyou/pkg/netif"
)

const gateC1bInnerPort = 32112

type gateC1bTUNWitness struct {
	Used         bool   `json:"used"`
	Closed       bool   `json:"closed"`
	KernelReads  uint64 `json:"kernel_reads"`
	KernelWrites uint64 `json:"kernel_writes"`
	InnerSends   uint64 `json:"inner_sends"`
	InnerReads   uint64 `json:"inner_reads"`
}

// The only inner listener is a harness-owned, fixed TEST-NET UDP socket. Its
// outbound packet traverses the kernel route/TUN before WireGuard reads it;
// decrypted inbound IP is written into the TUN, then received from the kernel.
// There is no memory shortcut and no host interface/route mutation.
type gateC1bKernelInterface struct {
	name         string
	mtu          int
	local        netip.AddrPort
	remote       netip.AddrPort
	tun          *os.File
	inner        *net.UDPConn
	closeOnce    sync.Once
	closed       atomic.Bool
	kernelReads  atomic.Uint64
	kernelWrites atomic.Uint64
	innerSends   atomic.Uint64
	innerReads   atomic.Uint64
}

func newGateC1bKernelInterface(cfg gateC1bHostConfig, name string, mtu int) (*gateC1bKernelInterface, error) {
	if !gateC1bCurrentNamespace(cfg.Namespace) || !gateC1bIsolatedMount(cfg.ParentMount) ||
		name != "wink-c1b-proof" || mtu != 1280 || !filepath.IsAbs(cfg.IPBinary) {
		return nil, errors.New("isolated interface authority rejected")
	}
	local, remote := netip.MustParseAddr("192.0.2.100"), netip.MustParseAddr("192.0.2.101")
	if cfg.Server {
		local, remote = remote, local
	}
	tun, err := openGateB2TUN(name)
	if err != nil {
		return nil, errors.New("isolated TUN creation failed")
	}
	instance := &gateC1bKernelInterface{name: name, mtu: mtu, tun: tun,
		local: netip.AddrPortFrom(local, gateC1bInnerPort), remote: netip.AddrPortFrom(remote, gateC1bInnerPort)}
	for _, args := range [][]string{
		{"link", "set", "dev", name, "mtu", strconv.Itoa(mtu), "up"},
		{"address", "add", local.String() + "/32", "dev", name},
		{"route", "add", remote.String() + "/32", "dev", name, "src", local.String()},
	} {
		// The exact wrapper intentionally clears PATH. Use the private harness
		// tool path and ip -n directly, without another shell or inherited env.
		if _, err := runCommand(cfg.IPBinary, append([]string{"-n", cfg.Namespace}, args...)...); err != nil {
			_ = instance.Close()
			return nil, errors.New("isolated interface route setup failed")
		}
	}
	// Opening this inner test listener is not a probe socket and is never used
	// before handoff. It has a separate witness and closes with the TUN session.
	instance.inner, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(instance.local))
	if err != nil {
		_ = instance.Close()
		return nil, errors.New("isolated inner listener failed")
	}
	return instance, nil
}

func (instance *gateC1bKernelInterface) Name() string { return instance.name }
func (*gateC1bKernelInterface) Type() string          { return "tun" }
func (instance *gateC1bKernelInterface) MTU() int     { return instance.mtu }
func (*gateC1bKernelInterface) SetIP(net.IP, net.IPMask) error {
	return netif.ErrNotImplemented
}
func (*gateC1bKernelInterface) AddRoute(*net.IPNet, net.IP) error {
	return netif.ErrNotImplemented
}
func (*gateC1bKernelInterface) RemoveRoute(*net.IPNet) error { return netif.ErrNotImplemented }

func (instance *gateC1bKernelInterface) Read(buffer []byte) (int, error) {
	n, err := instance.tun.Read(buffer)
	if n > 0 {
		instance.kernelReads.Add(1)
	}
	return n, err
}

func (instance *gateC1bKernelInterface) Write(buffer []byte) (int, error) {
	n, err := instance.tun.Write(buffer)
	if n > 0 {
		instance.kernelWrites.Add(1)
	}
	return n, err
}

func (instance *gateC1bKernelInterface) InjectPacket(buffer []byte) (int, error) {
	packet, err := parseGateB2IPv4UDP(buffer)
	if err != nil || packet.source != instance.local || packet.destination != instance.remote || len(packet.payload) != 48 {
		return 0, errors.New("isolated inner injection rejected")
	}
	defer clear(packet.payload)
	if instance.innerSends.Add(1) > 2 {
		return 0, errors.New("isolated inner send ceiling reached")
	}
	n, err := instance.inner.WriteToUDPAddrPort(packet.payload, instance.remote)
	if err != nil || n != len(packet.payload) {
		return 0, io.ErrShortWrite
	}
	return len(buffer), nil
}

func (instance *gateC1bKernelInterface) ReceivePacket(buffer []byte) (int, error) {
	var payload [49]byte
	n, source, err := instance.inner.ReadFromUDPAddrPort(payload[:])
	if err != nil {
		return 0, err
	}
	if source != instance.remote || n != 48 || instance.innerReads.Add(1) > 2 {
		return 0, errors.New("isolated inner reply rejected")
	}
	packet, err := buildGateB2IPv4UDP(source, instance.local, payload[:n])
	clear(payload[:])
	if err != nil || len(buffer) < len(packet) {
		clear(packet)
		return 0, io.ErrShortBuffer
	}
	n = copy(buffer, packet)
	clear(packet)
	return n, nil
}

func (instance *gateC1bKernelInterface) Close() error {
	instance.closeOnce.Do(func() {
		if instance.inner != nil {
			_ = instance.inner.Close()
		}
		_ = instance.tun.Close() // Non-persistent TUN removal also removes its routes/address.
		instance.closed.Store(true)
	})
	return nil
}

func (instance *gateC1bKernelInterface) witness() gateC1bTUNWitness {
	return gateC1bTUNWitness{Used: true, Closed: instance.closed.Load(), KernelReads: instance.kernelReads.Load(),
		KernelWrites: instance.kernelWrites.Load(), InnerSends: instance.innerSends.Load(), InnerReads: instance.innerReads.Load()}
}

var _ netif.MemoryTestInterface = (*gateC1bKernelInterface)(nil)
