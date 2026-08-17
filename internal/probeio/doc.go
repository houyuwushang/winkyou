// Package probeio owns the active datagram capability used by v2 connectivity
// probes. Callers receive bounded handles, never a net.PacketConn, UDPConn, file
// descriptor, or underlying socket.
//
// The reviewed production Factory is loopback-only by default. An explicit
// unicast target scope may use only an unspecified ephemeral bind; that
// capability does not itself authorize live-network use. Callers must not open
// sockets directly or route Pion ICE/quic-go active I/O around this package.
package probeio
