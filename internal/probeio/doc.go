// Package probeio owns the active datagram capability used by v2 connectivity
// probes. Callers receive bounded handles, never a net.PacketConn, UDPConn, file
// descriptor, or underlying socket.
//
// The reviewed production Factory is intentionally loopback-only in Phase 1a
// and is not wired to diagnose, a strategy, or a daemon. V2 strategies must not
// open sockets directly or route Pion ICE/quic-go active I/O around this
// package.
package probeio
