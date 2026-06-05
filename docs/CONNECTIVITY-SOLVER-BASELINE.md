# Connectivity Solver Baseline

## Status

This is the active architecture baseline for WinkYou.

- Active baseline: this file
- Current v0.1 freeze gate: [`V0.1-FREEZE.md`](./V0.1-FREEZE.md)
- Current relay-only freeze gate: [`PHASE4A-RELAY-ONLY-FREEZE.md`](./PHASE4A-RELAY-ONLY-FREEZE.md)
- Legacy baseline notice: [`EXECUTION-BASELINE.md`](./EXECUTION-BASELINE.md)
- Frozen legacy tag: `legacy-ice-turn-baseline-2026-04-15`

All new architecture work should follow this document first.

## Project Definition

WinkYou is no longer defined as a fixed ICE/TURN workflow that happens to carry VPN traffic.

The active definition is:

> WinkYou = connectivity solver + secure WireGuard data plane

The system is responsible for:

- creating and managing rendezvous sessions
- exchanging capabilities, observations, probe messages, and path commits
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
- after a path is bound, rendezvous availability should be treated as control-plane health, not as proof that the data path must be torn down

Current gap:

- the client still treats peer offline/control-plane loss too aggressively in some paths
- v0.1 hardening should preserve already-bound tunnel peers while the WireGuard data plane remains healthy
- see [`CONTROL-PLANE-RESILIENCE.md`](./CONTROL-PLANE-RESILIENCE.md) for the deployment evidence and TODO list

### Observation Plane

Responsibilities:

- collecting path behavior samples
- recording success, failure, timeout, reachability, and filtering signals
- carrying probe and plan-ordering evidence forward into the solver

Constraints:

- NAT type is only a hint
- failure data is still useful observation data

### Solver Plane

Responsibilities:

- planning candidate path attempts
- executing strategies
- comparing path outcomes
- ordering candidate plans using generic context
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
- raw `net.Conn` must not be treated as the tunnel's generic transport abstraction

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

Current real strategies:

- `legacy_ice_udp`
- `relay_only`
- `tcp_framed` (alpha, explicit reachable TCP only)

Production registration remains compatible by default: `legacy_ice_udp` first, then `relay_only`. `tcp_framed` is disabled by default and is registered only when `tcp_framed.enabled=true` and it appears in `connectivity.strategy_order`.

`legacy_ice_udp` is still one production strategy name, but internally it may emit multiple execution plans:

- `legacyice/direct_prefer`: use normal ICE behavior and allow ICE to choose the best non-relay or relay candidate pair.
- `legacyice/public_direct`: exclude ambiguous local candidates and ignore ambiguous remote candidates, including private ranges, `100.64.0.0/10`, loopback, link-local, multicast, and benchmark/overlay ranges, then attempt a public direct ICE path.
- `legacyice/relay_only`: force relay-only candidate gathering and candidate selection.

`public_direct` exists to prove an independent public direct candidate instead of letting an existing overlay or CGN/100.64 candidate satisfy the generic ICE `direct` label. It is still best-effort NAT piercing: if STUN/public candidates are unavailable or the NAT/firewall blocks the mapping, it must fail normally and let later plans or strategies continue.

The connectivity policy layer controls production strategy priority:

- `connectivity.mode=auto`: use configured strategy order, defaulting to `legacy_ice_udp` -> `relay_only`
- `connectivity.mode=relay_only`: prefer `relay_only`, then fallback to `legacy_ice_udp`
- `connectivity.strategy_order`: optional priority list for known production strategies
- `tcp_framed.enabled=true`: allows the `tcp_framed` alpha strategy to be advertised and selected when listed in strategy order

The existing `nat.force_relay` setting remains a compatibility entry and maps to relay-only behavior. Legacy fallback remains available for old peers with empty capability, and the legacy ICE path must still force relay candidate gathering in relay-only mode.

Future strategies may include QUIC, proxy-friendly, or other transports, but the solver core should not encode those details directly.

### Session

`pkg/session` owns:

- lifecycle
- state machine
- rendezvous v2 envelope handling
- binder coordination
- strategy invocation
- probe business-message handling

`pkg/session` does not own NAT or ICE dependencies directly.

### Client Runtime

The client CLI owns operator workflow around the engine:

- `wink up` starts the long-running foreground client process
- `wink down` stops a running client and clears runtime state
- `wink status`, `wink peers`, `wink logs`, and `wink doctor` inspect runtime state, logs, and diagnostics

Runtime state and log files are operational artifacts, not solver inputs. By default runtime state is derived from the config path; service deployments can pass `--state` to store it under `/var/lib/wink` or another explicit runtime directory.

Client runtime must distinguish coordinator/control-plane state from data-plane state. The first peer-offline cleanup guard is already in place: a peer with recent WireGuard handshake evidence, packet counters, and no transport error should not be removed only because a peer update reports it offline. Runtime state now exposes `control_state`, `data_state`, and recent successful path cache fields for operator visibility. Coordinator client heartbeat `NotFound` now triggers signal-stream reset and re-registration. A basic real coordinator-process outage test has passed with an already-bound data plane: only the chen-win coordinator process was stopped for 15 seconds while `wink ping` remained successful. This does not yet complete control-plane resilience. Longer heartbeat failure, signaling stream failure, and cached path recovery remain v0.1 hardening work.

Coordinator-less operation has a strict boundary:

- after a path is bound, in-band peer control may carry heartbeat, path health, capability refresh, observation exchange, endpoint updates, or re-ICE requests
- before the first path is bound, arbitrary NATed peers still need coordinator/rendezvous, a stable bootstrap node, static endpoint/port mapping, an existing overlay, or manual candidate exchange
- disconnecting an underlay overlay such as natpierce is not equivalent to killing only the coordinator process, because it can also remove the selected data-path candidate

The in-band control message model is frozen in `pkg/peercontrol` and documented in [`INBAND-PEER-CONTROL.md`](./INBAND-PEER-CONTROL.md). It is not yet wired into the long-running client network loop.

NAT/ICE candidate filtering is owned by the NAT/legacy ICE boundary. Config supports candidate interface include/exclude and candidate CIDR include/exclude under `nat.*`; these filters are passed into the pion ICE agent. The `legacyice/public_direct` plan may add plan-local CIDR excludes on top of the user config and also filters remote candidates before handing them to the ICE agent. `pkg/session` and `pkg/solver` must remain unaware of interface or CIDR filtering details.

ICE `connection_type=direct` is a direct-like transport result, not a guarantee that the path is independent from existing overlays or jump-host underlays. Strategy implementations must annotate `PathSummary.Role` and `PathSummary.Dependencies` conservatively. A path may be exposed as `protected_direct` only when it is direct-like and has no explicit relay, peer, or unknown dependency. Candidates in `100.64.0.0/10`, loopback, link-local, private/VPN-like, or otherwise ambiguous ranges must not be used as proof of protected direct coverage. `legacyice/public_direct` reduces this ambiguity by excluding those candidates before the attempt; successful path metadata still has to be derived from the actually selected ICE pair.

### Binder

The binder attaches the selected `PacketTransport` to the tunnel.

The session calls the binder. The strategy does not write tunnel details directly.

### Session Envelope

Session v2 messages use a generic envelope carried over the rendezvous plane.

The active envelope types are:

- `capability`
- `observation`
- `probe_script`
- `probe_result`
- `path_commit`

Phase 2C requires all of the following to be real business traffic, not only schema:

- `capability`
- `observation`
- `probe_script`
- `probe_result`
- `path_commit`

## Phase Scope

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

**Status**: Frozen at tag `phase1.5-freeze-2026-04-16`

### Phase 2A (Frozen)

**Scope**: Upgrade solver core from single-plan execution to candidate loop with minimal observation vertical slice.

Delivered:

- solver core candidate loop, execution budget, and generic scoring
- multi-plan output from `legacy_ice_udp`
- observation persistence and exchange through session v2 envelopes
- framed-stream adapter and generic address cleanup across transport/tunnel glue

**Status**: Frozen at tag `phase2a-freeze-2026-04-16`

### Phase 2B (Completed)

**Scope**: Move Phase 2A from "structure exists" to "runtime is real".

Delivered:

- plan-scoped executor / candidate isolation
- `legacyice/direct_prefer` and `legacyice/relay_only` as real execution variants; current code also includes `legacyice/public_direct` as a later direct execution variant for overlay-excluded public ICE attempts
- observation emission integrated into real strategy execution
- observation sink/store injection through session and client glue
- remote observation visibility retained in session state
- minimal probe lab:
  - `pkg/probe/model`
  - `pkg/probe/lab`
  - `test/e2e/netprobe script-run`
- framed-stream bind/attach regression coverage

**Status**: Frozen at tag `phase2b-freeze-2026-04-17`

### Phase 2C (Completed)

**Scope**: Activate the probe business lane and let observation begin to shape plan ordering.

Delivered:

- capability explicitly negotiates probe features
- `probe_script` / `probe_result` are real session messages with send/receive/handle paths
- initiator can run a minimal preflight probe after capability exchange and before candidate execution
- preflight probe failure or timeout is observable and non-fatal
- strategy-side ranking can reorder existing plans using observation history and latest probe result
- the solver still runs only the existing `legacy_ice_udp` strategy

**Status**: Frozen at tag `phase2c-freeze-2026-04-17`

### Phase 2D (Completed / Frozen)

**Scope**: Evolve probe/observation from "ordering basis" to "planning basis" — let evidence shape plan generation and pruning, not just ranking.

Required outcome:

- preflight probe is strategy-authored, not session-hardcoded
- `solver.SolveInput` becomes evidence-aware (capabilities, observations, probe results)
- strategy `Plan(...)` receives evidence context and can adapt plan generation
- new `PlanRefiner` interface allows strategies to prune plans based on evidence
- `legacy_ice_udp` demonstrates real plan pruning (e.g., dropping direct execution plans under strong relay evidence)
- Evidence that prunes candidate plans must be scoped to the current session/peer; unscoped history may inform hints/ranking but must not by itself remove viable plans.
- probe result and observations flow through generic solver inputs, not strategy side-channels
- probing becomes an explicit state machine phase
- the solver still runs only the existing `legacy_ice_udp` strategy

**Not in Phase 2D**:

- second real strategy (TCP/443, QUIC, etc.)
- full observation -> scoring -> learning closed loop
- concurrent candidate execution
- complex public probe infrastructure
- coordinator proto redesign

**Status**: Frozen at tag `phase2d-freeze-2026-04-24`; see [`PHASE2D-FREEZE.md`](./PHASE2D-FREEZE.md) for the regression gate.

### Phase 3A (Completed)

**Scope**: Strategy Portfolio Foundation.

Required outcome:

- document the boundary for multiple solver strategies without implementing a second real transport path
- verify strategy selection and resolver behavior can support more than `legacy_ice_udp`
- keep solver core and session APIs strategy-agnostic
- use fake or mock strategies where tests need multiple strategy names

**Not in Phase 3A entry work**:

- real TCP/443, QUIC, HTTP CONNECT, WebSocket, or peer relay transport
- real new data plane
- coordinator proto or rendezvous envelope redesign
- broad solver/session rewrites

**Status**: Completed. The session boundary has a portfolio resolver foundation, production uses the session resolver implementation, and tests cover deterministic strategy selection.

### Phase 3B (Completed)

**Scope**: Code health before adding more real transport behavior.

Delivered:

- CI and Makefile quality gates for `go vet` and scoped race tests
- mechanical split of the large session implementation by concern
- minimal session state transition validation
- production resolver convergence on the session portfolio resolver
- bounded contexts for normal session operations and cleanup
- shared UDP address helpers
- safer observation history truncation
- latest probe-result retention

**Status**: Completed.

### Phase 4A (Completed / Frozen)

**Scope**: Make `relay_only` the second real strategy and freeze its production behavior.

Delivered:

- `pkg/solver/strategy/relayonly` wraps the legacy ICE/TURN executor in relay-only mode
- `relay_only` produces a single `relayonly/turn_relay` plan
- production resolver registers both `legacy_ice_udp` and `relay_only`
- default production order remains `legacy_ice_udp` -> `relay_only`
- `nat.force_relay=true` makes production selection prefer `relay_only` when both peers support it
- old peers with empty capability still fallback to `legacy_ice_udp`, with relay-only ICE candidate gathering preserved
- `path_commit.strategy` and candidate/path observations preserve `relay_only` when that strategy is selected
- `make test-phase4a` defines the Phase 4A regression gate

**Status**: Frozen by [`PHASE4A-RELAY-ONLY-FREEZE.md`](./PHASE4A-RELAY-ONLY-FREEZE.md).

### Phase 4B Alpha: `tcp_framed`

**Scope**: Prove a non-UDP `PacketTransport` strategy can bind through the existing solver/session/tunnel boundary.

Delivered:

- `pkg/solver/strategy/tcpframed` creates a single `tcpframed/direct` plan
- strategy messages exchange explicit TCP endpoints through the existing client signal path
- successful connections are wrapped with `transport/framedstream`
- production registration is opt-in through `tcp_framed.enabled=true`
- no `PacketTransport` interface change

Constraints:

- no TCP NAT hole punching guarantee
- no QUIC, WebSocket, or HTTP CONNECT implementation
- no rendezvous envelope schema change

**Status**: Alpha.

## Not In Scope Yet

- QUIC datagram, HTTP CONNECT, WebSocket, or proxy-friendly transports
- TCP NAT hole punching for `tcp_framed`
- full observation collection and scoring with learning feedback
- new coordinator transport or protobuf redesign
- coordinator-less first bootstrap for arbitrary NATed peers
- runtime wiring for the in-band peer control channel over an already established virtual network
- real-network validation of `legacyice/public_direct` and ICE interface/CIDR filters after excluding overlay interfaces
- GUI, daemon, no-admin, proxy, or userspace completion work

## Legacy Relationship

The old MVP execution baseline is retained only as legacy documentation.

Rules:

- do not delete the legacy tag
- do not treat the legacy execution baseline as the current architecture authority
- do not reintroduce legacy ICE semantics into `pkg/session` or `pkg/solver` core types

If an old document conflicts with this file, this file wins.

---

## Historical Freeze Tags

- `legacy-ice-turn-baseline-2026-04-15`
- `phase1.5-freeze-2026-04-16`
- `phase2a-freeze-2026-04-16`
- `phase2b-freeze-2026-04-17`
- `phase2c-freeze-2026-04-17`
- `phase2d-freeze-2026-04-24`
