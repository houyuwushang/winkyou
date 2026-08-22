// Package loopbackcarrier is the only reviewed Phase 1a adapter allowed to
// combine pairing admission, probeio, Noise, and the direct-punch protocol.
//
// It is intentionally terminal-only: every accepted attempt is restricted to
// literal loopback endpoints, establishes one short-lived secure channel,
// proves bidirectional reachability, records FINISH, and closes. It exposes no
// raw socket, descriptor, packet transport, retry loop, reconnect path, or
// business-data channel.
package loopbackcarrier
