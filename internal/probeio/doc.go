// Package probeio owns the active datagram capability used by v2 connectivity
// probes. Callers receive bounded handles, never a net.PacketConn, UDPConn, file
// descriptor, or underlying socket.
//
// This foundation deliberately contains no production socket opener. A later
// reviewed adapter may implement Factory, but v2 strategies must not open
// sockets directly or route Pion ICE/quic-go active I/O around this package.
package probeio
