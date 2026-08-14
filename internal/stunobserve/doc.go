// Package stunobserve implements the deliberately small RFC 8489 Binding
// observation slice used by WinkYou v2.
//
// The package never owns a socket. A Client receives an already admitted
// probeio attempt and performs every open, target registration, send, and read
// through probeio. The Phase 1a implementation accepts loopback targets only
// and is not connected to diagnose, stdio, a strategy, or a daemon.
//
// One Client is single-use. WorstCaseCost reserves one socket, one target, one
// five-tuple, at most two packets per second, three outbound packets, and four
// seconds. The retransmission schedule starts at 500 ms and doubles for each
// of the three transmissions. A result is a time-windowed solver.Observation;
// it never assigns a permanent NAT type.
package stunobserve
