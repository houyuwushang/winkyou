# WinkYou

WinkYou is being refactored from an ICE/TURN-centric VPN implementation into a `connectivity solver + secure data plane` system.

## Active Architecture Baseline

- Active baseline: [`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- Frozen legacy MVP baseline notice: [`docs/EXECUTION-BASELINE.md`](./docs/EXECUTION-BASELINE.md)
- Historical legacy snapshot reference: [`docs/legacy/EXECUTION-BASELINE-legacy.md`](./docs/legacy/EXECUTION-BASELINE-legacy.md)

`docs/CONNECTIVITY-SOLVER-BASELINE.md` is the only active architecture baseline.  
`docs/EXECUTION-BASELINE.md` is no longer the architecture authority.

## Current Vertical Slice

The current runnable path is still:

- legacy ICE/UDP connectivity solving
- userspace `wireguard-go` secure data plane
- `PacketTransport`-based tunnel binding
- session-managed peer lifecycle
- rendezvous v2 capability / observation / probe / path-commit envelope exchange on the existing coordinator channel

This is now a Phase 2D runtime slice. The current work keeps the existing UDP/ICE/WireGuard vertical slice runnable while evolving probe/observation from "ordering basis" to "planning basis" — evidence now shapes plan generation and pruning, not just ranking.

## Current Deployable Path

The currently deployable path remains:

- Windows client with `TUN/Wintun`
- Linux client / peer
- Linux coordinator
- coturn relay recommended for public deployment

Not completed:

- `userspace`
- `proxy`
- no-admin mode
- second solver strategy and full observation/scoring/learning pipeline

## Repository Map

- Active architecture baseline: [`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- Supplemental architecture notes: [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)
- Documentation index: [`docs/README.md`](./docs/README.md)
- Quickstart assets: [`deploy/quickstart/`](./deploy/quickstart/)
- TURN deployment assets: [`deploy/coturn/`](./deploy/coturn/)

## Key Packages

- `pkg/transport`: generic packet transport abstraction
- `pkg/session`: session lifecycle, state machine, capability handling, binder coordination
- `pkg/solver`: generic solver interfaces
- `pkg/solver/strategy/legacyice`: compatibility strategy for the current ICE/UDP path
- `pkg/rendezvous/proto`: session v2 envelope types
- `pkg/rendezvous/client`: coordinator-backed rendezvous channel adapter
- `pkg/tunnel`: WireGuard data plane consuming `transport.PacketTransport`

## Legacy Freeze

The legacy ICE/TURN-centric baseline was frozen before the reboot:

- tag: `legacy-ice-turn-baseline-2026-04-15`

That tag remains for historical reference and rollback analysis. The current code should be judged against the connectivity-solver baseline instead.
