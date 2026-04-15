# Architecture Notes

This file is a supplemental architecture note. It is not the active architecture baseline.

## Authority Order

1. Active architecture baseline: [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md)
2. Repository status and supported path: [`../README.md`](../README.md)
3. This file

## Current Package Map

- `pkg/rendezvous`
  - session v2 envelope types
  - coordinator-backed rendezvous channel adapter
- `pkg/session`
  - session lifecycle
  - state machine
  - capability envelope handling
  - binder coordination
- `pkg/solver`
  - generic solver contracts
  - strategy interface
- `pkg/solver/strategy/legacyice`
  - compatibility strategy for the current ICE/UDP path
- `pkg/transport`
  - generic packet transport abstraction
  - ICE/UDP compatibility adapter
- `pkg/tunnel`
  - WireGuard data plane
  - packet transport consumption and peer binding
- `pkg/client`
  - glue layer for session creation, signal routing, and runtime state

## Current Vertical Slice

The current working slice is:

- session start
- capability exchange over rendezvous v2 envelope
- legacy ICE strategy planning and execution
- packet transport adaptation
- tunnel bind
- handshake-driven connected state

This is intentionally a compatibility slice. The architecture has been cut, but the old UDP/ICE path still exists behind the `legacy_ice_udp` strategy so the system remains runnable.

## What This File Does Not Define

This file does not replace the active baseline and does not define Phase 2 behavior. In particular, it does not authorize:

- adding new solver strategies to the core by special case
- moving legacy NAT or ICE dependencies back into `pkg/session`
- moving legacy message kinds back into `pkg/solver` core
- treating raw `net.Conn` as the tunnel’s generic transport
