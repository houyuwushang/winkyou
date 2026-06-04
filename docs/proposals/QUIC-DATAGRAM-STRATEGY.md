# QUIC Datagram Strategy Proposal

Status: proposal for v0.2 or later.

This document proposes a future `quic_datagram` strategy. It is not part of v0.1, does not modify `go.mod`, and does not introduce a QUIC dependency.

## Strategy Name

```text
quic_datagram
```

The strategy should advertise and commit as `quic_datagram`, not as `legacy_ice_udp`, `relay_only`, or `tcp_framed`.

## Why Not v0.1

QUIC datagram is valuable, but it adds a larger dependency and runtime matrix than v0.1 needs.

v0.1 is focused on:

- self-host coordinator + TURN relay
- explicit `relay_only`
- diagnostics through `wink doctor`
- long-running client workflow
- release artifacts

Adding QUIC before those paths are validated would make failures harder to diagnose.

## Dependency Candidates

Potential implementation dependency:

- `quic-go`

Before selecting it, verify:

- supported Go versions
- Windows behavior
- datagram support status
- TLS configuration surface
- connection migration behavior
- operational maturity for long-running clients

No dependency should be added until implementation work starts.

## PacketTransport Adapter

The adapter should preserve the current boundary:

```go
transport.PacketTransport
```

Expected shape:

- one QUIC connection per selected path
- one datagram-capable transport adapter
- `ReadPacket` receives QUIC datagrams
- `WritePacket` sends QUIC datagrams
- `Close` closes the QUIC connection/session
- counters and last error feed existing peer runtime status

The tunnel must continue to see packet semantics only.

## MTU And Datagram Size

QUIC datagram paths must respect effective packet size limits.

Open decisions:

- default maximum payload size
- whether to probe datagram size during strategy execution
- how to report fragmentation or oversized packet failures
- whether to clamp WireGuard MTU when QUIC datagram is selected

Initial implementation should choose conservative defaults and expose the selected MTU in observation/path metadata.

## Handshake, TLS, And ALPN

QUIC requires TLS. The strategy needs a clear policy for:

- server certificate validation
- local development certificates
- ALPN value, for example `wink-quic-datagram/1`
- session identity binding to coordinator node identity
- replay and stale session handling

WireGuard remains the secure data plane, but QUIC TLS still protects metadata and transport establishment.

## Connection Migration

QUIC connection migration could eventually help mobile or changing-network clients, but it should not be part of the first alpha.

Initial scope:

- establish one QUIC path
- bind it as PacketTransport
- reconnect through normal strategy fallback if the path breaks

Later scope:

- evaluate migration behavior
- record migration events as observations
- decide whether migration should trigger re-solving

## Strategy Messages

Likely strategy-local message types:

- `quic_offer`
- `quic_answer`
- `quic_endpoint`
- `quic_ready`
- `quic_error`

Messages should use the existing generic solver/session envelope. Do not add QUIC details to solver core.

## Plans

Initial plan:

```text
quicdatagram/direct_explicit
```

Potential metadata:

```text
transport=quic_datagram
mode=direct_explicit
alpn=wink-quic-datagram/1
```

If a relay server is needed later, add a separate plan rather than overloading direct semantics.

## Fallback Behavior

`quic_datagram` should participate in existing ordered strategy fallback:

- if QUIC setup fails, session tries the next ordered strategy
- failures emit scoped observations
- successful QUIC paths emit path commit and candidate/path observations with `Strategy=quic_datagram`

The strategy must not bypass `OrderedStrategyResolver`.

## Configuration Sketch

Possible future config:

```yaml
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
    - tcp_framed
    - quic_datagram

quic_datagram:
  enabled: false
  listen_addr: "0.0.0.0:0"
  advertise_addr: ""
  dial_timeout: 5s
  max_datagram_size: 1200
  alpn: "wink-quic-datagram/1"
```

Unknown strategy validation should stay strict until the implementation exists.

## Testing Matrix

Unit tests:

- config validation
- plan output
- unsupported plan errors
- strategy message encode/decode
- PacketTransport adapter read/write/close behavior

Integration tests:

- loopback QUIC datagram between two sessions
- explicit LAN endpoint
- fallback from failed QUIC to `relay_only`
- fallback from failed UDP path to QUIC when configured first
- runtime stats and last error through `wink peers`

Failure tests:

- TLS validation failure
- ALPN mismatch
- dial timeout
- oversized datagram
- remote endpoint unavailable
- path closed during bind

Non-default tests:

- connection migration behavior
- lossy network behavior
- long-running idle timeout behavior

## Exit Criteria

Do not start implementation until:

- v0.1 freeze gate is satisfied
- `tcp_framed` alpha results are reviewed
- a QUIC dependency decision is documented
- default MTU/datagram sizing policy is selected
- local integration tests can run without public infrastructure
- `PacketTransport` remains sufficient without a V2 interface
