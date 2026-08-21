// Package stunobserve implements the deliberately small RFC 8489 Binding
// observation slice used by WinkYou v2.
//
// The package never owns a socket. A Client receives an already admitted
// probeio attempt and performs every open, target registration, send, and read
// through probeio. Targets are loopback-only by default. The explicit
// AllowNonLoopback option accepts unicast targets only and must remain behind
// a reviewed user-opt-in or isolated-lab boundary; it does not grant raw socket
// access.
//
// Client, MappingClient, and AllocationClient are single-use. WorstCaseCost reserves one socket,
// one target, one five-tuple, at most two packets per second, three outbound
// packets, and four seconds. MappingWorstCaseCost reserves one socket plus the
// aggregate target, five-tuple, packet, PPS, and duration bounds for two or
// three serial exchanges. AllocationWorstCaseCost reserves three to eight
// sockets against one target and keeps them all open through a serial round.
// The retransmission schedule starts at 500 ms and doubles for each of the
// three transmissions. Every result is time-windowed; mapping and allocation
// classifications are narrow evidence, never permanent NAT properties.
package stunobserve
