# Phase 3A Strategy Portfolio Foundation

## Goal

Phase 3A defines and tests the boundary for multiple connectivity solver strategies.

The goal is to prove that session and solver boundaries can safely register, advertise, negotiate, and select more than one strategy name while keeping the current production data path unchanged. The runnable path remains `legacy_ice_udp` plus userspace `wireguard-go` and `PacketTransport`.

Phase 3A keeps solver core strategy-agnostic. Capability negotiation belongs at the session boundary, and strategy-specific behavior stays inside strategy implementations or test fakes.

## Non-Goals

Phase 3A does not include:

- a real second transport strategy
- TCP/443, QUIC, WebSocket, HTTP CONNECT, proxy, peer relay, or no-admin mode
- a new data plane
- coordinator proto or rendezvous envelope schema changes
- broad solver or session rewrites
- concurrent candidate execution or a learning loop

## Reliability Invariants

- Strategy selection must be deterministic.
- Selection must choose only a strategy supported by both local and remote capabilities.
- If there is no mutually supported strategy, selection must fail fast and must not silently fall back to `legacy_ice_udp`.
- Registered strategy names must be unique.
- A registered entry name must match `strategy.Name()`.
- Fake strategies are allowed only in tests and must not enter the runtime deploy path.
- The existing Phase 2D `legacy_ice_udp` path remains the only real runtime strategy until a later phase explicitly adds another real transport.

## Portfolio Resolver Baseline

The Phase 3A resolver baseline uses registration order as priority. Maps may be used for lookup, but final selection order must come from the registered entry slice.

The resolver advertises all registered strategies through local capability. During resolution it scans local entries in registration order and selects the first strategy present in the remote capability.

The `initiator` flag is accepted through the existing session resolver interface but does not change selection in this baseline.

## Exit Criteria

Phase 3A entry is complete when:

- a strategy portfolio or resolver foundation exists at the session boundary
- fake strategies cover multi-strategy selection behavior
- no-mutual-strategy failure is covered by tests
- duplicate, nil, and mismatched strategy registrations are rejected
- a session-level test proves the session uses resolver selection instead of assuming `legacy_ice_udp`
- Phase 2D solver, session, and relay smoke regressions still pass

Future real strategies should plug into the same resolver boundary with explicit capability names, tests, and rollback behavior. They should not require `pkg/session` or `pkg/solver` core to know transport-specific details.
