# Connectivity Solver Baseline

## Status

This is the active architecture baseline for WinkYou.

- Active baseline: this file
- Legacy baseline notice: [`EXECUTION-BASELINE.md`](./EXECUTION-BASELINE.md)
- Frozen legacy tag: `legacy-ice-turn-baseline-2026-04-15`

All new architecture work should follow this document first.

## Project Definition

WinkYou is no longer defined as a fixed ICE/TURN workflow that happens to carry VPN traffic.

The active definition is:

> WinkYou = connectivity solver + secure WireGuard data plane

The system is responsible for:

- creating and managing rendezvous sessions
- exchanging capabilities and later observations
- selecting a usable connectivity path
- binding the selected packet path to the secure data plane
- re-solving when the current path degrades

Direct P2P is one possible result. Relay is a valid solved path, not a product failure state.

## Layer Boundaries

### Rendezvous Plane

Responsibilities:

- node discovery and registration
- session creation and shutdown
- message exchange for capability, observation, probe, result, and path commit

Constraints:

- it is not just an ICE signal forwarder
- it does not decide the final path by itself

### Observation Plane

Responsibilities:

- collecting path behavior samples
- recording success, failure, timeout, reachability, and filtering signals

Constraints:

- NAT type is only a hint
- failure data is still useful observation data

### Solver Plane

Responsibilities:

- planning candidate path attempts
- executing strategies
- comparing path outcomes
- deciding what to bind next

Constraints:

- the solver core must stay strategy-agnostic
- legacy protocol details must not leak into the solver core API

### Transport Plane

Responsibilities:

- providing a uniform packet-oriented transport abstraction
- adapting UDP, TURN, QUIC datagram, or framed stream transports into packet semantics

Constraints:

- the tunnel consumes packets, not raw streams
- raw `net.Conn` must not be treated as the tunnel’s generic transport abstraction

### Tunnel Plane

Responsibilities:

- secure data plane using `wireguard-go`
- binding selected packet transports to peers

Constraints:

- tunnel code must not make NAT decisions
- tunnel code must not own path solving

## Core Abstractions

### PacketTransport

The tunnel and bind layer consume `transport.PacketTransport`.

This is the stable packet boundary for all future path types.

### Strategy

The solver core admits multiple strategies.

Current Phase 1 compatibility strategy:

- `legacy_ice_udp`

Future strategies may include relay-first, TCP-assisted, QUIC, or other transports, but the solver core should not encode those details directly.

### Session

`pkg/session` owns:

- lifecycle
- state machine
- rendezvous v2 envelope handling
- binder coordination
- strategy invocation

`pkg/session` does not own NAT or ICE dependencies directly.

### Binder

The binder attaches the selected `PacketTransport` to the tunnel.

The session calls the binder. The strategy does not write tunnel details directly.

### Session Envelope

Session v2 messages use a generic envelope carried over the rendezvous plane.

The minimum envelope types are:

- `capability`
- `observation`
- `probe_script`
- `probe_result`
- `path_commit`

Phase 1.5 requires at least one real business message to flow through this path:

- capability exchange

## Current Phase Scope

### Phase 1

Required outcome:

- `PacketTransport` boundary exists
- tunnel consumes `PacketTransport`
- a session/solver/rendezvous skeleton exists
- the old ICE/UDP path remains runnable through a compatibility strategy

### Phase 1.5

Required outcome:

- session no longer imports legacy NAT/ICE types
- solver core message model is generic
- legacy message language is pushed back to strategy or client edge adapters
- capability exchange actually runs on session start

### Not In Scope Yet

- second fully implemented strategy
- full observation collection and scoring
- new coordinator transport or protobuf redesign
- GUI, daemon, no-admin, proxy, or userspace completion work

## Legacy Relationship

The old MVP execution baseline is retained only as legacy documentation.

Rules:

- do not delete the legacy tag
- do not treat the legacy execution baseline as the current architecture authority
- do not reintroduce legacy ICE semantics into `pkg/session` or `pkg/solver` core types

If an old document conflicts with this file, this file wins.
