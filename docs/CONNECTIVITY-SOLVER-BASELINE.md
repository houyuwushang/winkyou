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

**Status**: Frozen at tag `phase1.5-freeze-2026-04-16`

### Phase 2A (Current)

**Scope**: Upgrade solver core from single-plan execution to candidate loop with minimal observation vertical slice.

Required outcome:

- solver core executes multiple candidate plans, not just `plans[0]`
- session collects outcomes, scores candidates, selects best path
- execution budget model (max candidates, time budget)
- `legacy_ice_udp` returns at least two plans (e.g., direct_prefer, relay_only)
- observation events flow: report -> persist -> exchange
- netprobe evolves to probe lab with script execution capability
- transport plane gains framed-stream adapter (net.Conn -> PacketTransport)
- tunnel/binder removes UDP-specific address assumptions

**Not in Phase 2A**:

- second real strategy (TCP/443, QUIC, etc.)
- full observation->scoring->learning closed loop
- concurrent candidate execution
- coordinator proto redesign

### Not In Scope Yet

- second fully implemented strategy beyond legacy_ice_udp multi-plan
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

## Phase 2A: Multi-Plan Candidate Loop (COMPLETED 2026-04-16)

**Goal**: Upgrade solver core from single-plan execution to candidate loop with scoring.

**Completed**:
- ✅ Solver core: candidate loop, budget, scoring
  - Added CandidateOutcome, ExecutionBudget to solver types
  - Added ScoreOutcome (generic: success>failure, direct>relay)
  - Added SelectBestOutcome for picking winning candidate
  - Rewrote session.selectAndExecute to execute candidate loop
  - Strategy returns multiple plans, session executes each within budget
  - Scores outcomes, selects best, cleans up non-winners
  - Added solver scoring unit tests
- ✅ legacy_ice_udp: two candidate plans
  - Returns legacyice/direct_prefer and legacyice/relay_only
  - Added ForceRelay to legacyice Config
  - Plan-scoped execution (shared state limitation noted for Phase 2B)
- ✅ Observation vertical slice
  - Enriched rproto.Observation with full event fields
  - Added solver.Observation type (generic, no ICE-specific fields)
  - Extended solver.SessionIO with ReportObservation method
  - Session records observations locally (capped at 100)
  - Session sends/receives observations via v2 envelope
  - Added pkg/solver/store with memory + JSONL file persistence
- ✅ Framed-stream adapter + remove UDP assumptions
  - Added pkg/transport/framedstream adapter (4-byte length prefix)
  - Changed transportEndpoint to store net.Addr (not *net.UDPAddr)
  - Keep UDP adapters for WireGuard IPC compatibility
  - Added tunnel.AddrMeta for generic address representation
  - Added PeerStatus.EndpointMeta field

**Known Limitations**:
- legacy_ice_udp plans share agent state (first execution wins)
- Full plan isolation deferred to Phase 2B
- Observation reporting not yet integrated into strategy execution
- No probe lab implementation (netprobe remains as-is)

**Commits**:
- a5660af: Solver core: candidate loop, multi-plan, budget, scoring
- 228f3d1: Observation vertical slice: report, persist, exchange
- dcb8f76: Framed-stream adapter + remove UDP assumptions

