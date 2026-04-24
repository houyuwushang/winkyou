# Phase 2D Freeze Gate

## Status

Phase 2D is completed and freeze-ready.

The freeze tag has not been created yet. The expected tag name for this gate is:

```bash
phase2d-freeze-2026-04-24
```

Create and push that tag only after the freeze gate commands pass and the release owner confirms the tag operation.

## Scope

Phase 2D moves probe and observation evidence from an ordering basis to a planning basis.

The current runnable slice remains:

- legacy ICE/UDP connectivity solving
- userspace `wireguard-go` secure data plane
- `PacketTransport` tunnel binding
- session-owned lifecycle and binder coordination
- rendezvous v2 capability, observation, probe, result, and path commit envelopes

Relay is a valid solved path, not a failure state. The only real strategy in this phase remains `legacy_ice_udp`.

## Delivered

- Strategy-authored preflight probe through `ProbePlanner`.
- Evidence-aware `SolveInput`, `ProbeInput`, and `RankInput`.
- `Plan(...)` can generate a different plan set from current evidence.
- `PlanRefiner` can prune `legacyice/direct_prefer` under strong scoped relay evidence.
- Destructive pruning requires evidence scoped to the current session and peer.
- Unscoped history may inform hints or ranking, but must not by itself remove viable plans.
- Probe result and observation history flow through generic solver inputs.
- Probing is represented as an explicit session state.
- `wink peers` and runtime state expose relay, ICE, transport, and WireGuard handshake diagnostics.
- Relay plus `wireguard-go` smoke coverage is part of CI.

## Freeze Gate Commands

Run these commands before creating a Phase 2D freeze tag:

```bash
go test ./pkg/solver/strategy/legacyice -count=10
go test ./pkg/session -count=10
WINKYOU_FORCE_RELAY=1 WINKYOU_NETIF_ALLOW_MEMORY=1 WINKYOU_TUNNEL_ALLOW_MEMORY=1 \
  go test ./pkg/client -run TestRelayWGGoTwoEnginesExchangeIPv4Packets -count=3 -v
go test ./... -count=1
```

The same gate is available as:

```bash
make test-phase2d
```

The `make test-phase2d` target uses POSIX-style environment assignment for the relay smoke command. Use Linux, macOS, or a compatible shell for that target. Windows CI still covers `go test ./...`; on Windows shells, run the relay smoke command with equivalent environment variables.

## Tag Procedure

Do not create or push the tag until the gate has passed and the release owner has confirmed the operation.

Suggested commands:

```bash
git switch main
git pull --ff-only origin main
git tag -a phase2d-freeze-2026-04-24 -m "Freeze Phase 2D evidence-driven planning baseline"
git push origin phase2d-freeze-2026-04-24
```

After tagging, update `docs/CONNECTIVITY-SOLVER-BASELINE.md` from freeze-ready to frozen-at-tag status in a follow-up change.

## Known Non-Goals

Phase 2D does not include:

- a second real solver strategy
- TCP/443, QUIC, WebSocket, HTTP CONNECT, peer relay, or other new transport paths
- full observation to scoring to learning closed loop
- concurrent candidate execution
- public probe infrastructure
- coordinator proto or rendezvous envelope redesign
- GUI, proxy, no-admin mode, or userspace completion

## Phase 3A Entry

Phase 3A should start as Strategy Portfolio Foundation.

Allowed work:

- document strategy portfolio boundaries
- use fake or mock strategies to test strategy selection behavior
- add small resolver or registry test scaffolding when it protects strategy boundaries
- keep solver core strategy-agnostic

Not allowed as Phase 3A entry work:

- real TCP or QUIC transport implementation
- real new data plane
- coordinator protocol changes
- large session or solver rewrites
