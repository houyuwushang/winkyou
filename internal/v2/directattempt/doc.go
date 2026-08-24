// Package directattempt freezes the zero-I/O artifact, authenticated frame,
// READY payload, and role-specific transition rules for one non-loopback
// direct attempt.
//
// The package owns no socket, resolver, rendezvous transport, governor,
// goroutine, retry loop, clock source, or product entry point. Its only
// network-shaped value is netip.AddrPort, used as an inert canonical value.
package directattempt
