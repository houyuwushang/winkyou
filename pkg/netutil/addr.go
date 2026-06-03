package netutil

import "net"

func UDPAddrFromAddr(addr net.Addr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return CloneUDPAddr(udpAddr)
	}
	host, portText, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil
	}
	port, err := net.LookupPort("udp", portText)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), ip...), Port: port}
}

func CloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
