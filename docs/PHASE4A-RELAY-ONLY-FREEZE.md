# Phase 4A Relay-Only Freeze

## Status

Phase 4A is frozen.

The purpose of this freeze is narrow: `relay_only` is now the second real production strategy, and it is selectable through the production resolver without changing solver, session, transport, or tunnel boundaries.

## Architecture Authority

This document is a freeze gate for Phase 4A. It does not replace the active baseline:

- [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md)
- [`../README.md`](../README.md)
- [`../implementation_plan.md`](../implementation_plan.md)

If this document conflicts with the baseline, the baseline wins.

## Delivered Behavior

- `pkg/solver/strategy/relayonly` exists as a real strategy named `relay_only`.
- `relay_only` wraps the legacy ICE/TURN executor and forces relay-only ICE agent requests.
- `relay_only` emits one plan: `relayonly/turn_relay`.
- The plan metadata includes `mode=relay_only`.
- Production resolver registration includes:
  - `legacy_ice_udp`
  - `relay_only`
- Default production order remains compatible:
  - `legacy_ice_udp`
  - `relay_only`
- With `nat.force_relay=true`, production order becomes:
  - `relay_only`
  - `legacy_ice_udp`
- Empty remote capability still falls back to `legacy_ice_udp` for old peer compatibility.
- In force-relay mode, the legacy fallback still forces relay candidate gathering.
- When `relay_only` is selected, session `path_commit.strategy` remains `relay_only`.
- Candidate and path observations keep `Strategy=relay_only` when the relay-only strategy is selected.

## Configuration Entry

Phase 4A intentionally reuses the existing compatibility setting:

```yaml
nat:
  force_relay: true
```

This is the minimum production entry for proving relay-only selectability. The dedicated connectivity policy layer is deferred to the next phase.

## Regression Gate

Run:

```bash
go test ./pkg/solver/strategy/relayonly -count=10
go test ./pkg/session -run 'RelayOnly|StrategySelection|Portfolio|Resolver' -count=10
go test ./pkg/client -run 'RelayOnly|StrategyResolver|RelayWGGo' -count=3
go test ./... -count=1
```

The Makefile target is:

```bash
make test-phase4a
```

## Non-Goals

Phase 4A does not include:

- TCP framed transport
- QUIC datagram transport
- HTTP CONNECT or WebSocket fallback
- cross-strategy fallback after one selected strategy fails
- observation-driven strategy ordering
- changes to `transport.PacketTransport`
- a new data plane
- session-level NAT or ICE ownership

## Next Phase

The next phase should add an explicit connectivity policy layer with stable user-facing mode and strategy-order configuration. It should keep `nat.force_relay` compatible with existing users.
