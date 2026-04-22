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

## Relay Handshake Troubleshooting

When relay is expected, use `wink peers` or `wink peers --json` first. The CLI surfaces the full chain from ICE selection to transport attachment to WireGuard handshake.

Example:

```text
Peer 1
  Name:        beta
  Node ID:     node-000002
  Virtual IP:  10.77.0.2
  Public Key:  BRWDltpykmj7xkz5mscwH82XtleebmfOtYvvaIxIRVQ=
  State:       connected
  Endpoint:    127.0.0.1:65042
  Conn Type:   relay
  ICE State:   connected
  Local Cand:  relay:127.0.0.1:65040
  Remote Cand: relay:127.0.0.1:65042
  Tx:          1.2 KiB
  Rx:          304 B
  Xport Tx:    13 pkts / 1.2 KiB
  Xport Rx:    4 pkts / 304 B
  Xport Err:   -
  Handshake:   2026-04-22T16:04:34Z
  Last Seen:   2026-04-22T16:04:34Z
```

Interpretation:

- `ICE State` is not `connected` or `completed`: the problem is still in ICE/TURN or candidate exchange.
- `Local Cand` / `Remote Cand` do not contain `relay` when relay is expected: the wrong path was selected or relay candidates were never gathered.
- `Local Cand` / `Remote Cand` show `relay`, but `Xport Tx` / `Xport Rx` stay at `0`: the ICE transport was selected, but the `PacketTransport` was not attached or did not stay alive.
- `Xport Tx` / `Xport Rx` grow and `Xport Err` is non-empty: transport/bind read or write failed after ICE connected.
- `Xport Tx` / `Xport Rx` grow and `Handshake` stays `-`: relay packets are moving, but WireGuard handshake has not completed.
- `Handshake` is non-`-`, but payload traffic still fails: check `AllowedIPs`, routes, firewall rules, and MTU on both peers.

## Legacy Freeze

The legacy ICE/TURN-centric baseline was frozen before the reboot:

- tag: `legacy-ice-turn-baseline-2026-04-15`

That tag remains for historical reference and rollback analysis. The current code should be judged against the connectivity-solver baseline instead.
