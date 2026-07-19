package puncher

import (
	"fmt"
	"net"
)

// ConnectedConn must satisfy net.Conn so it can feed iceadapter.New / the data
// plane. This is a compile-time guarantee of that contract.
var _ net.Conn = (*ConnectedConn)(nil)

// ConnectedConn adapts a punched *net.UDPConn into a net.Conn fixed to the
// peer's learned address: reads accept only datagrams from that peer, writes go
// to it. This lets a punched path feed iceadapter.New (and the WireGuard data
// plane) through the same net.Conn boundary the other strategies use, without
// re-dialing the socket (which would change the NAT mapping).
type ConnectedConn struct {
	*net.UDPConn
	remote *net.UDPAddr
}

// Connected wraps the winning socket into a peer-fixed net.Conn. Use the
// returned value for I/O afterwards; do not read Result.Conn directly once
// wrapped.
func (r *Result) Connected() *ConnectedConn {
	if r == nil {
		return nil
	}
	return &ConnectedConn{UDPConn: r.Conn, remote: r.RemoteAddr}
}

// Read returns the next datagram from the punched peer, dropping packets from
// any other source (stale punch traffic, port scans).
func (c *ConnectedConn) Read(b []byte) (int, error) {
	if c == nil || c.UDPConn == nil || c.remote == nil || c.remote.IP == nil {
		return 0, fmt.Errorf("puncher: connected UDP path is incomplete")
	}
	for {
		n, src, err := c.UDPConn.ReadFromUDP(b)
		if err != nil {
			return n, err
		}
		if src != nil && src.IP.Equal(c.remote.IP) && src.Port == c.remote.Port {
			return n, nil
		}
	}
}

// Write sends to the punched peer's fixed address.
func (c *ConnectedConn) Write(b []byte) (int, error) {
	if c == nil || c.UDPConn == nil || c.remote == nil || c.remote.IP == nil {
		return 0, fmt.Errorf("puncher: connected UDP path is incomplete")
	}
	return c.UDPConn.WriteToUDP(b, c.remote)
}

// RemoteAddr reports the punched peer's address.
func (c *ConnectedConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	return c.remote
}
