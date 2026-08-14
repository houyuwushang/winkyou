// Package natsim provides a deterministic, in-memory UDP/NAT simulation
// transport. It implements net.PacketConn semantics without opening an OS
// socket and is intended for bounded v2 strategy and connect-test tests.
package natsim
