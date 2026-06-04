# HTTP CONNECT / WebSocket Transport Strategy Proposal

Status: proposal for v0.2 or later.

This document proposes proxy-friendly fallback strategies. It does not change the current v0.1 architecture, resolver behavior, or `transport.PacketTransport` interface.

## Why This Is Needed

Some networks block UDP and arbitrary outbound TCP ports, but still allow HTTPS proxy traffic or WebSocket traffic through enterprise gateways. WinkYou currently has:

- `legacy_ice_udp` for ICE/UDP direct or TURN paths
- `relay_only` for explicit TURN relay
- `tcp_framed` alpha for explicit reachable TCP endpoints

Those cover important cases, but they do not cover proxy-constrained networks where the only practical path is through HTTP CONNECT or WebSocket over TCP/TLS.

## Relationship To `tcp_framed`

`tcp_framed` proves that a stream can be adapted to packet semantics through `transport/framedstream`.

HTTP CONNECT and WebSocket should reuse the same packet framing idea:

- establish a stream through an HTTP proxy, HTTPS endpoint, or WebSocket server
- wrap the stream with a framed PacketTransport adapter
- return `transport.PacketTransport` to session/tunnel

They should not fork the tunnel data plane.

## Candidate Strategy Names

Suggested capability names:

- `http_connect_framed`
- `websocket_framed`

These names describe the transport setup and packet framing boundary without implying a new data plane.

## Relay Server Requirements

HTTP CONNECT can work in two variants:

- direct proxy mode: the client dials a reachable peer endpoint through an HTTP proxy
- relay mode: both peers connect to a known relay service that bridges framed packet streams

WebSocket will usually require a reachable server endpoint:

- one peer exposes a reachable WebSocket endpoint in controlled environments
- or both peers connect to a relay service that pairs sessions

For v0.2, a relay-backed design is likely more realistic than assuming peers can accept inbound HTTPS/WebSocket traffic.

## Security Boundary

WireGuard remains the secure data plane.

HTTP CONNECT and WebSocket only carry encrypted WireGuard packets after they have been framed as packet payloads. They must not terminate or inspect WireGuard traffic, and they must not introduce a separate application-layer encryption protocol for v0.2.

Transport authentication should be limited to:

- coordinator-issued session pairing where applicable
- relay access credentials if a relay service is used
- TLS verification for HTTPS/WebSocket endpoints

## Minimal Implementation Plan

1. Keep `transport.PacketTransport` unchanged.
2. Reuse `transport/framedstream` for packet framing.
3. Add strategy packages only after the proposal is accepted:
   - `pkg/solver/strategy/httpconnectframed`
   - `pkg/solver/strategy/websocketframed`
4. Add config as opt-in alpha fields, disabled by default.
5. Exchange endpoints or relay session metadata through strategy messages.
6. Return ordinary `solver.Result` values with `ConnectionType` set to a clear proxy/relay value.
7. Register strategies only when enabled in config and listed in `connectivity.strategy_order`.

## Strategy Messages

Likely message types:

- `proxy_offer`
- `proxy_answer`
- `proxy_endpoint`
- `relay_join`
- `relay_ready`
- `relay_error`

The exact schema should stay strategy-local and be carried through the generic solver message envelope.

## Observability

Path commits and observations should use the selected strategy name:

- `http_connect_framed`
- `websocket_framed`

They must not be reported as `legacy_ice_udp` or `tcp_framed`.

`wink doctor` should eventually explain:

- whether a proxy URL is configured
- whether the proxy is reachable
- whether TLS validation passed
- whether relay pairing succeeded
- whether framed packet counters are moving

## Testing Plan

Unit tests:

- config validation
- plan generation
- message encode/decode
- unsupported plan rejection
- framed PacketTransport behavior over an in-memory stream

Integration tests:

- local HTTP CONNECT proxy fixture
- local WebSocket server fixture
- two sessions bind through proxy/relay fixture
- fallback from failed UDP strategy to proxy-friendly strategy

Non-default tests:

- TLS verification failures
- proxy authentication failures
- blocked relay pairing
- packet counter and handshake visibility through `wink peers` and `wink doctor`

## Why Not v0.1

This is not part of v0.1 because v0.1 must first prove the self-host path, relay-only control, diagnostics, long-running client workflow, and release pipeline.

Adding proxy-friendly transports before v0.1 would expand the deployment and security matrix before the current operator path is stable.

## Exit Criteria

Before this proposal becomes implementation work:

- v0.1 freeze gate is satisfied.
- `tcp_framed` alpha evidence is reviewed.
- A concrete relay/proxy pairing model is selected.
- Tests can run locally without public infrastructure.
- `PacketTransport` remains sufficient without a V2 interface.
