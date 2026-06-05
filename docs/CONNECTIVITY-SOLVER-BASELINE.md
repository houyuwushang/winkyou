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
- `legacyice/public_direct`: gather only host/server-reflexive direct candidates, skip TURN/relay gathering, then advertise only public direct candidates and ignore ambiguous remote candidates, including private ranges, `100.64.0.0/10`, loopback, link-local, multicast, and benchmark/overlay ranges, before attempting a public direct ICE path. The public-direct ICE agent must also avoid likely external overlay interfaces by name, including natpierce, Tailscale, ZeroTier, Docker/vEthernet, Wintun/WinkYou, and similar virtual adapters; ordinary `direct_prefer` may still use those paths as a best-effort connectivity candidate, but they must not prove protected direct. A configured UDP TURN URL may be converted into an unauthenticated STUN binding URL on the same host/port for srflx gathering, but TURN relay allocation and relay candidates remain disabled in this plan. Operator-supplied `nat.public_endpoint_hints` may add local public UDP `ip:port` values as extra public-direct srflx candidates, and may bind them to a concrete local UDP base using `public_ip:public_port/local_ip:local_port`. By default, the client merges startup STUN mapping observations into those hints as best-effort candidates, including endpoint-dependent observations that should still be compared with natpierce/router evidence instead of treated as proven stable. `nat.public_endpoint_hint_port_window` is a bounded expansion around each hinted public port for predictable port drift; the default is a small window and it must remain at the NAT/legacy ICE boundary. When those mapped hints include local base addresses, the public-direct ICE agent should restrict gathering to those local IPs; when they contain exactly one unique local base port, it should also bind that port for the attempt so the advertised hint can match the actual local UDP socket. This is useful when another tool or router log has already observed the usable public endpoint for the same local socket. If public-direct gathering times out after the Pion agent has already prepared local host candidates, the NAT layer may return those partial local candidates so the strategy can append operator endpoint hints and start connectivity checks; private host candidates are still filtered before publication. This plan may use a more aggressive ICE check interval, a binding-request budget scaled to `nat.connect_timeout`, shorter srflx/prflx acceptance waits, and a failed-check timeout that is not shorter than `nat.connect_timeout`, so it behaves closer to sustained UDP punching without changing session or solver interfaces. Session candidate execution budget must scale with per-candidate execution timeout and candidate count so `direct_prefer`, `public_direct`, and relay fallback each get a real attempt window. During that ICE check window, if an incoming STUN Binding Request creates or validates a public peer-reflexive remote candidate pair, the NAT layer may switch to that public direct pair only when the local side is either public or an RFC1918 host NAT base and the remote side is public; relay, remote private, local or remote CGNAT/overlay, loopback, link-local, multicast, and benchmark addresses must not trigger this switch.
- `legacyice/relay_only`: force relay-only candidate gathering and candidate selection.

`public_direct` exists to prove an independent public direct candidate instead of letting an existing overlay or CGN/100.64 candidate satisfy the generic ICE `direct` label. If another tool can already punch a direct path between the same two devices, WinkYou should not treat the path as physically impossible; failure should be diagnosed as missing public candidates, filtering, ICE timing/nomination, selected-pair dependency, or firewall/NAT behavior. It is still best-effort NAT piercing: if STUN/public candidates are unavailable or the NAT/firewall blocks the mapping, it must fail normally and let later plans or strategies continue. Operators may explicitly configure `nat.direct_trusted_cidrs` for a controlled non-public underlay range that has been independently verified as reachable, such as a provider CGNAT segment observed by another puncher. The older `nat.public_direct_trusted_cidrs` remains a compatibility alias and is merged with `direct_trusted_cidrs`. This is an opt-in trust override: defaults must continue to reject private, CGN/100.64, loopback, link-local, multicast, and benchmark/overlay candidates.

When a dependent direct-like path and an independent protected direct path have the same base score, generic solver selection must prefer the less-dependent protected direct path. This prevents `legacyice/direct_prefer` overlay success from masking a later successful `legacyice/public_direct` attempt.

Strong recent relay evidence may prefer or execute relay first, but it must not prune `legacyice/public_direct` only because `legacyice/direct_prefer` failed. The relay path can keep the tunnel alive while `public_direct` still gets a chance to prove a protected direct standby.

When manual or runtime public endpoint hints are present, `legacyice/public_direct` may be ranked before ordinary `legacyice/direct_prefer` so the hinted public UDP socket gets an early punching window. If relay evidence is stronger, relay can still run first, but hinted `public_direct` should remain ahead of `direct_prefer` because stale NAT mappings are time-sensitive.

For `legacyice/public_direct`, a local RFC1918 host candidate may be treated as the NAT base only when it matches the related/base address of a public STUN/server-reflexive candidate advertised by the same plan, or when an operator-supplied public endpoint hint explicitly maps that local base. Legacy hint values without a local base remain a diagnostic compatibility path, but precise protected-direct evidence should prefer the mapped form. Remote candidates must remain public unless they match an explicit `nat.direct_trusted_cidrs` or compatibility `nat.public_direct_trusted_cidrs` entry. `legacyice/direct_prefer` may also treat selected local or remote candidates inside those explicit trusted CIDRs as dependency-free direct paths. Without that explicit trust override, local or remote `100.64.0.0/10`, loopback, link-local, multicast, benchmark/overlay, or relay candidates must not prove protected direct coverage.

Successful public-direct observations and path summaries should expose selected-pair candidate kinds and whether a peer-reflexive candidate pair was learned during ICE checks. `remote_candidate_kind=prflx` or `public_direct_learned_pair=true` is useful evidence that runtime punching discovered a path, but it is still only protected-direct proof when the committed path has `path_role=protected_direct` and no `path_dependencies`.

The connectivity policy layer controls production strategy priority:

- `connectivity.mode=auto`: use configured strategy order, defaulting to `legacy_ice_udp` -> `relay_only`
- `connectivity.mode=relay_only`: prefer `relay_only`, then fallback to `legacy_ice_udp`
- `connectivity.strategy_order`: optional priority list for known production strategies
- `tcp_framed.enabled=true`: allows the `tcp_framed` alpha strategy to be advertised and selected when listed in strategy order

When the local runtime has detected `nat_type=symmetric` and TURN servers are configured, `auto` mode may temporarily prefer `relay_only` before `legacy_ice_udp` without enabling force-relay. This keeps the data plane alive under endpoint-dependent mappings while preserving `legacyice/public_direct` as a later fallback/improvement candidate. If no TURN server is configured, `relay_only` is not a useful first candidate, so production order remains `legacy_ice_udp` first and the legacy strategy disables its internal relay-only plan unless the operator explicitly requests relay-only mode. The client still attempts `direct_prefer` / `public_direct` punching, and historical relay success must not push an unavailable relay plan ahead of public-direct punching. This is a client resolver policy decision; it must not leak NAT details into `pkg/session` or the solver core.

Protected-direct multipath is enabled by default in `auto` mode with bounded settings: at most two child paths, direct protection on, and shadow writes on so standby paths receive traffic and keep NAT/relay state warm. Candidate execution should evaluate the configured budget instead of stopping after the first protected direct success, so a lower-latency relay or other path can still compete for primary while protected direct remains available. Legacy ICE selected-pair RTT is recorded in path metrics as `rtt_ms` and participates in generic policy scoring. This preserves the `transport.PacketTransport` boundary while letting the client keep a lower-dependency direct path alive when both the primary path and a public/direct path are established. `relay_only` mode and legacy `nat.force_relay=true` keep single-path binding because there is no direct standby to protect. Operators can explicitly set `connectivity.multipath.enabled=false` to restore the older single-path binding behavior, or `connectivity.multipath.shadow_write=false` to keep standby paths passive.

If the initial bound path is relay or a direct-like path with dependencies, the client may schedule a post-bound protected-direct improvement attempt. This loop is a client/session orchestration feature, not a new solver or transport interface: the existing session resolver runs again under the same strategy-agnostic boundaries, temporary failed outcomes are closed, and the existing data plane remains bound unless a later outcome is explicitly classified as protected direct. Tunnel implementations may expose an optional peer replacement operation so the binder can swap the peer transport only after a protected-direct result is selected.

Runtime state must expose the latest path plan, role, dependencies, and child path summary. A direct-like ICE result is only evidence of protected direct when `last_path_role=protected_direct` and no `last_path_dependencies` are present; `connection_type=direct` alone is not sufficient.

Client runtime may publish explicit backend routes for operator-managed gateway peers through coordinator metadata using `route:<cidr>` endpoint entries derived from `node.advertise_routes`. Other peers may bind those published CIDRs into the gateway peer's WireGuard `AllowedIPs` and add local routes via the gateway peer virtual IP. This is a narrow routing feature for known backend networks, such as an `inner-gw` subnet behind a WinkYou peer; it is not automatic peer relay, does not move path selection into `pkg/tunnel`, and does not make the solver aware of route ownership. The gateway host remains responsible for OS IP forwarding and firewall policy.

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
- `wink doctor --route-target <ip>` may inspect the operating system route chosen for a concrete target IP and warn when the route is currently owned by an external overlay such as natpierce, Tailscale, Docker, or similar. This is an operator diagnostic only; it does not feed solver scoring or session state.

Runtime state and log files are operational artifacts, not solver inputs. By default runtime state is derived from the config path; service deployments can pass `--state` to store it under `/var/lib/wink` or another explicit runtime directory.

Client runtime must distinguish coordinator/control-plane state from data-plane state. The first peer-offline cleanup guard is already in place: a peer with recent WireGuard handshake evidence, packet counters, and no transport error should not be removed only because a peer update reports it offline. Runtime state now exposes `control_state`, `data_state`, and recent successful path cache fields for operator visibility. Coordinator client heartbeat `NotFound` now triggers signal-stream reset and re-registration. A bound peer whose latest path is not protected direct may continue protected-direct improvement attempts while the old data plane remains active. In-band heartbeat/path health is wired into the long-running client loop, in-band `re_ice_request` can trigger protected-direct improvement on an already-bound peer, and minimal in-band `session_signal` can carry existing session/strategy messages over an already-established virtual network. Recent in-band session signals are replayed for a short window and duplicate sequence numbers are ignored on receive, which makes post-bound re-ICE less sensitive to one dropped UDP control packet without turning this into a full reliable protocol. A basic real coordinator-process outage test has passed with an already-bound data plane: only the chen-win coordinator process was stopped for 15 seconds while `wink ping` remained successful. This does not yet complete control-plane resilience. Longer heartbeat failure, signaling stream failure, full in-band ACK/backoff, and cached path recovery remain hardening work.

Coordinator-less operation has a strict boundary:

- after a path is bound, in-band peer control may carry heartbeat, path health, capability refresh, observation exchange, endpoint updates, or re-ICE requests
- before the first path is bound, arbitrary NATed peers still need coordinator/rendezvous, a stable bootstrap node, static endpoint/port mapping, an existing overlay, or manual candidate exchange
- disconnecting an underlay overlay such as natpierce is not equivalent to killing only the coordinator process, because it can also remove the selected data-path candidate
- post-bound improvement can now be requested over in-band peer control, and current session/strategy messages are also sent over in-band control when an already-established virtual network path is available; this does not make first bootstrap coordinator-less

The in-band control message model is frozen in `pkg/peercontrol` and documented in [`INBAND-PEER-CONTROL.md`](./INBAND-PEER-CONTROL.md). The long-running client loop currently sends heartbeat/path health, maps `re_ice_request` to protected-direct improvement scheduling, and uses `session_signal` as a redundant channel for existing solver messages. `session_signal` is short-window replayed and sequence-deduplicated; endpoint update, capability refresh, observation exchange UX, ACK/backoff, and longer recovery policy remain future work.

NAT/ICE candidate filtering and public candidate hints are owned by the NAT/legacy ICE boundary. Config supports candidate interface include/exclude, candidate CIDR include/exclude, candidate UDP port range, optional Pion ICE NAT1To1 public candidate hints, public endpoint hints, runtime public endpoint hints from STUN mapping observations, bounded public endpoint hint port-window expansion, and explicit trusted direct CIDRs under `nat.*`; these user filters and hints are passed into the pion ICE agent or the legacy ICE strategy boundary. The `legacyice/public_direct` plan asks the NAT layer to skip TURN/relay candidate gathering, but it does not add its own agent-level CIDR excludes, because that can prevent STUN server-reflexive candidate gathering on common private local interfaces. Instead, it filters the local candidates it advertises and filters remote candidates before handing them to the ICE agent. Candidate gather/filter diagnostics are strategy observations (`candidate_gathered` and `remote_candidates_filtered`) with total/kept/rejected counts, rejection reasons, and bounded kept/rejected candidate samples. Samples should preserve related/base addresses when available, for example `srflx:public_ip:public_port<-local_ip:local_port`, so operators can distinguish missing public candidates from filtered overlay candidates and compare WinkYou's mapped endpoint with a natpierce-observed endpoint. `nat.direct_trusted_cidrs` is intentionally narrow: it lets operators test a proven non-public underlay CIDR without globally weakening the default protected-direct rules. `nat.public_direct_trusted_cidrs` remains accepted for compatibility and is merged with `direct_trusted_cidrs`. Manual endpoint hint validation and runtime STUN-derived endpoint hints must both honor those trusted CIDRs, while still rejecting non-public hints by default. `wink doctor` may probe the effective public-direct STUN sources, including configured STUN servers and UDP TURN URLs derived as unauthenticated STUN binding endpoints on the same host/port, reuse a single local UDP socket across those probes, report whether mapped endpoints are stable or symmetric, and render observed `nat.public_endpoint_hints` candidates when they are useful for operator comparison. `nat.auto_public_endpoint_hints` is enabled by default so startup observations become best-effort production hints, and `nat.public_endpoint_hint_port_window` defaults to a small bounded window for predictable port drift; symmetric or endpoint-dependent mappings must remain labeled as unproven rather than treated as stable. When those hints exist, the legacy ICE ranker may run `legacyice/public_direct` before ordinary `legacyice/direct_prefer` to avoid losing the mapped endpoint timing window. Operators may disable the automation or set the window to zero for conservative diagnostics. Doctor may also read persisted observation history to summarize `legacyice/public_direct` evidence for operators. Those diagnostics remain outside `pkg/session` and `pkg/solver`. NAT1To1 hints are operator-supplied external/local IP mappings for stable public mappings; they are not a replacement for STUN when the NAT rewrites UDP ports per socket. `pkg/session` and `pkg/solver` must remain unaware of interface, CIDR, port-range, NAT1To1, public endpoint hint, trusted CIDR, or candidate rejection details.

When a legacy ICE plan receives an offer or answer whose remote candidates are all filtered out, that plan should fail internally and let the session continue to the next plan or strategy. Empty filtered candidates must not bubble up as a peer-session-level `nat: no remote candidates provided` error that prevents relay or public-direct fallback attempts.

Session strategy messages may carry a top-level `plan_id`. When an executor is active, messages for a different plan must remain buffered for the matching future plan instead of being delivered to the current executor and ignored. This matters for sequential ICE plans such as `legacyice/direct_prefer` followed by `legacyice/public_direct`, where the two peers can advance at slightly different speeds.

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
