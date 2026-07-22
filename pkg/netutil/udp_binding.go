package netutil

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// UDPBinding is an operator-selected IPv4 underlay. ResolveUDPBinding creates
// it from an interface name once; callers can then reuse the exact interface
// index and source address for every socket in one probe or punch attempt.
type UDPBinding struct {
	InterfaceName  string
	InterfaceIndex int
	LocalIP        net.IP
}

// ResolveUDPBinding resolves an optional interface name to one active,
// globally-unicast IPv4 address. An empty name preserves the operating
// system's normal routing behavior and returns nil.
func ResolveUDPBinding(name string) (*UDPBinding, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("resolve UDP interface %q: %w", name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("resolve UDP interface %q: interface is down", iface.Name)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("resolve UDP interface %q addresses: %w", iface.Name, err)
	}
	var ipv4s []net.IP
	for _, address := range addresses {
		var ip net.IP
		switch value := address.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		default:
			parsed, _, parseErr := net.ParseCIDR(address.String())
			if parseErr == nil {
				ip = parsed
			}
		}
		ip = ip.To4()
		if ip == nil || !ip.IsGlobalUnicast() {
			continue
		}
		ipv4s = append(ipv4s, append(net.IP(nil), ip...))
	}
	if len(ipv4s) == 0 {
		return nil, fmt.Errorf("resolve UDP interface %q: interface has no usable unicast IPv4 address", iface.Name)
	}
	sort.Slice(ipv4s, func(i, j int) bool { return bytesLess(ipv4s[i], ipv4s[j]) })
	return &UDPBinding{
		InterfaceName:  iface.Name,
		InterfaceIndex: iface.Index,
		LocalIP:        append(net.IP(nil), ipv4s[0]...),
	}, nil
}

// ListenUDP4 creates an IPv4 UDP socket. With an explicit binding it enforces
// both the interface selector and the source IP before bind; it never silently
// falls back to the system-selected route.
func ListenUDP4(ctx context.Context, binding *UDPBinding, port int) (*net.UDPConn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("listen UDP4: port %d is outside 0..65535", port)
	}
	if binding == nil {
		return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	}
	if err := validateUDPBinding(binding); err != nil {
		return nil, err
	}
	listenConfig := net.ListenConfig{
		Control: func(network, address string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(fd uintptr) {
				controlErr = bindUDP4SocketToInterface(fd, binding.InterfaceName, binding.InterfaceIndex)
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	address := net.JoinHostPort(binding.LocalIP.String(), strconv.Itoa(port))
	packetConn, err := listenConfig.ListenPacket(ctx, "udp4", address)
	if err != nil {
		return nil, fmt.Errorf("listen UDP4 on interface %q (index %d, source %s): %w",
			binding.InterfaceName, binding.InterfaceIndex, binding.LocalIP, err)
	}
	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		_ = packetConn.Close()
		return nil, fmt.Errorf("listen UDP4 on interface %q: unexpected packet connection %T", binding.InterfaceName, packetConn)
	}
	local, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil || !local.IP.Equal(binding.LocalIP) {
		_ = udpConn.Close()
		return nil, fmt.Errorf("listen UDP4 on interface %q: bound source %v, want %s", binding.InterfaceName, local, binding.LocalIP)
	}
	return udpConn, nil
}

func validateUDPBinding(binding *UDPBinding) error {
	if binding == nil {
		return nil
	}
	if strings.TrimSpace(binding.InterfaceName) == "" || binding.InterfaceIndex <= 0 {
		return fmt.Errorf("listen UDP4: explicit interface binding is incomplete")
	}
	ipv4 := binding.LocalIP.To4()
	if ipv4 == nil || !ipv4.IsGlobalUnicast() {
		return fmt.Errorf("listen UDP4 on interface %q: source %q is not a usable unicast IPv4 address", binding.InterfaceName, binding.LocalIP)
	}
	return nil
}

func bytesLess(left, right net.IP) bool {
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return len(left) < len(right)
}
