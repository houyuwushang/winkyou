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

Current real strategy:

- `legacy_ice_udp`

Future strategies may include relay-first, TCP-assisted, QUIC, or other transports, but the solver core should not encode those details directly.

### Session

`pkg/session` owns:

- lifecycle
- state machine
- rendezvous v2 envelope handling
- binder coordination
- strategy invocation
- probe business-message handling

`pkg/session` does not own NAT or ICE dependencies directly.

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
- `legacyice/direct_prefer` and `legacyice/relay_only` as real execution variants
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
- `legacy_ice_udp` demonstrates real plan pruning (e.g., dropping `direct_prefer` under strong relay evidence)
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

### Phase 3A (Next)

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

## Not In Scope Yet

- second fully implemented strategy beyond `legacy_ice_udp`
- full observation collection and scoring with learning feedback
- new coordinator transport or protobuf redesign
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
