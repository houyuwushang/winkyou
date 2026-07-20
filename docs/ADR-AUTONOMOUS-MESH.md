# ADR: Autonomous Mesh Control and Peer Transit

- Status: accepted; Slices 1-4, the three-host edge rotation, direct routed SSH,
  a two-hour continuity hold, dynamic user-space service access, and the r12
  cached-endpoint public-NAT zero-seed rejoins are field-proven. Slice 4.5 now
  also has a completed C -> B -> A three-node field rollout: A/B/C run the
  explicitly enabled autonomous graph engine through managed `wink up`, with
  zero configured seeds, no infrastructure coordinator, and two one-hop
  protected packet edges per node. The Windows selected-port facade returned
  complete command output through all four A entry points. A follow-up 120-second
  monitor then observed all 44 SSH-carried probes exit with code zero despite a
  recurring Win32-OpenSSH close warning; no stream hang was reproduced in this
  rollout. A later hard-crash experiment killed only the A WinkYou process,
  retained B/C, and proved that a new A generation could safely adopt its two
  existing loopback ULA rows and restore the direct triangle without operator
  cleanup. Simultaneous cold start, OS autostart/reboot, and the public-IP-change
  matrix remain open; see `SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md` and
  `VIRTUAL-TCP-ALIAS-CRASH-RECOVERY-2026-07-20.md`
- Date: 2026-07-19
- Scope: control routing, graph routing, direct-edge improvement, and peer transit

## Context

WinkYou already has pairwise connectivity solvers and a no-Wintun birthday-punch
bridge. Those components can create and carry one direct edge, but the runtime
does not yet treat the set of established edges as a routable graph. In
particular, the current in-band control handler consumes messages addressed to
the local node and drops messages addressed to another node.

The product goal is an autonomous virtual network made from trusted,
equal-permission user nodes:

- central infrastructure may help with initial discovery, but a dedicated
  infrastructure user-data relay is outside the product;
- after at least one edge into the mesh exists, peer nodes carry control
  signaling, route data, and help create better direct edges;
- if the current edge graph remains connected, every node should remain
  reachable through peer transit;
- direct-edge solvers should continuously replace expensive multi-hop paths
  when the underlay permits a usable direct edge;
- loss of the ordinary peer that coordinated an attempt must not tear down
  healthy neighbor sessions or prevent connected peers from coordinating a new
  punch.

Security hardening, admission policy, hostile peers, and external attackers are
explicitly deferred while the functional graph is proven. Message framing and
stable node identity are still required because later slices depend on them.

## Decisions

### 1. Keep edge solving separate from graph solving

The existing strategy portfolio, including birthday punch, remains the edge
solver. It accepts evidence for one node pair and returns a direct
`transport.PacketTransport` or a failed attempt.

A new graph layer owns membership, adjacency, routes, shortcut selection, and
failure convergence. NAT details must not leak into its routing algorithm.

### 2. Route control messages over established neighbor sessions

`peercontrol.Message.From` and `To` are the logical origin and final
destination, not the immediate socket peer. Routed messages additionally carry:

- `seq`: origin-scoped duplicate identity;
- `hop_limit`: bounded forwarding lifetime;
- `path_vector`: visited node IDs for immediate loop rejection and diagnostics.

The next hop is session metadata and is not serialized as the logical sender.
An intermediate node may inspect the routing header but does not interpret the
message payload.

### 3. Use two graph records

- `MemberRecord` describes a node, its derived/configured virtual address,
  endpoint candidates, capabilities, and NAT observations.
- `LSA` describes current neighbor edges and damped quality metrics.

Both records will use origin sequence numbers and age limits. Topology changes
are flooded immediately. Continuous metrics such as RTT use EWMA plus a
threshold/minimum publication interval.

### 4. Use LSDB plus local shortest-path calculation

Each node builds a small link-state database from flooded LSAs and calculates
routes locally with Dijkstra. A routed control envelope retains a path vector
for per-message loop defense and observability, but path-vector advertisements
are not the routing protocol. Every future data frame also carries a hop limit.

The first metric is intentionally small: usable/transit-allowed edges only,
then hop count, then summed smoothed RTT. Capacity and congestion feedback are
deferred until real multi-flow measurements exist.

### 5. Coordinate punching with an attempt-scoped barrier

A punch attempt uses `PREPARE -> READY -> FIRE`. For A-B-C, B can be the
attempt-scoped rendezvous peer: it waits until A and C are ready, then triggers
both sides as closely together as possible. The punch window is much wider than
normal control-path jitter.

This is an ordinary trusted peer acting as coordinator only for the scoped
attempt, not a central/infrastructure coordinator, and it does not have to carry
the resulting direct data path. Absolute wall-clock synchronization and per-hop
relative countdown are not prerequisites.

Birthday-punch signaling will later depend on a routed signaler and punch
barrier rather than directly assuming a central `SessionIO` clock.

Completion is reconciled, not treated as a one-shot message exchange. The
coordinator repeats COMMIT for missing roles through the whole
probation/deadline window, and an endpoint already in Stable re-reports STABLE
after a duplicate COMMIT. This tolerates a lost COMMIT or STABLE without
changing the attempt-scoped trust model. A strict durable FINALIZE/ACK phase
remains separate future work.

### 6. Separate control and user data

A `NeighborSession` represents one established direct edge and multiplexes
control with independent data traffic. Control messages use the peer-control
codec. User traffic uses compact binary frames and never rides inside JSON
control payloads. Each stream neighbor has independent reliable control and
data streams; failure of either stream withdraws the whole adjacency. A
shortcut `PacketNeighbor` is datagram-oriented: periodic topology refresh
repairs control loss, while TCP-flow data adds explicit ACK, retransmission,
and duplicate suppression.

`routed.PacketTransport` implements `transport.PacketTransport`, looks up a
destination in the graph route table, and sends the frame through the selected
`NeighborSession`. An intermediate peer forwards by the binary destination and
hop-limit header; it does not decode the inner packet or TCP-flow payload.

### 7. Discovery and address assignment are separate

A node always needs one physical discovery input: a configured seed, manual
exchange, LAN discovery, an optional bootstrap service, or a persistent
last-known-good endpoint learned while a previous direct edge worked. Once it
reaches any mesh member, runtime membership and routing do not require that
bootstrap service to remain online.

A recovery card is retained discovery information, not discovery from nothing.
It can remove a live coordinator from later restarts while a cached endpoint is
still usable. If every cached destination has become stale and no LAN, IPv6,
static mapping, reachable peer, or external directory remains, the node still
has no address to which it can send the first packet.

The primary virtual address should eventually be a deterministic IPv6 ULA
derived from stable node identity. IPv4 may be explicitly configured first and
later use deterministic conflict resolution. Runtime coordinator IPAM is not a
long-term requirement.

### 8. Distinguish peer transit from dedicated infrastructure user-data relay

A dedicated infrastructure user-data relay is outside the product. Trusted
user nodes may advertise transit, routes, and exit capability. Peer transit is
required to make a connected graph routable and is the fallback while a better
direct edge is being solved.

An exit node is ordinary graph routing plus advertised default-route capability
and operating-system forwarding/NAT at that node. It is not a special central
data service.

### 9. Treat directness as an optimization, not a mathematical guarantee

Graph connectivity implies reachability only after edges carry bidirectional
traffic, intermediate nodes forward it, and routes converge. It does not imply
that every pair of NAT/firewall endpoints can create a physical direct edge.

Solvers may influence edge NAT mappings, firewall/conntrack state, and sample
existing ECMP alternatives. They cannot instruct public BGP/AS routing. Prefer
high-yield methods such as IPv6 and PCP/NAT-PMP/UPnP before expensive birthday
sweeps; keep TTL/ICMP and spoofing-derived ideas as bounded experiments rather
than public path-steering promises.

### 10. Do not make Wintun a prerequisite for graph work

Control routing, peer transit, edge improvement, and user-space port forwarding
can be proven without Wintun. Full transparent L3 ingress/egress for arbitrary
Windows applications is a later, replaceable backend and may use a WinkYou-owned
Windows packet path.

### 11. Treat dynamic TCP service access as a user-space facade, not L3

An already-running `meshnode` may publish one loopback TCP target and create
loopback listeners for remote node IDs through its local HTTP API. The target
surface is `GET/PUT/DELETE /v1/tcp/target`; the listener surface is
`GET/POST /v1/tcp/forwards` plus
`DELETE /v1/tcp/forwards/{forwardID}`. These operations configure only local
runtime state. User traffic continues through `routed.TCPForwarder` and the
mesh route selected for the remote node, so the HTTP control plane does not
become a user-data relay.

API-created dynamic state is intentionally process-scoped and is not
automatically persisted. Operators may separately place equivalent
`--tcp-target` and `--tcp-forward` flags in startup configuration; a later
process then recreates those objects with `source=config` rather than retaining
the former runtime objects. API calls cannot replace or delete such
startup-configured targets/listeners, both target and listener addresses must
be loopback, and each node is limited to 64 active dynamic listeners. These
constraints make the first service-access increment bounded while the nodes
are still trusted lab participants. They describe the ordinary
`--tcp-forward` and runtime-API surface; the separately bounded Windows ULA
listener uses `--virtual-tcp-forward` below.

This increment does not change the routed TCP wire format. A remote `OPEN`
still identifies the node/flow but carries no arbitrary target host or port;
the accepting node uses its one current local target. A later user-space
increment may add target-aware streams and expose them through SOCKS and/or a
`127/8` facade. Transparent participation by arbitrary TCP, UDP, and ICMP
applications still requires system packet ingress/egress through TUN, WFP, or a
WinkYou-owned driver. Therefore this API is phase one of driver-free user-space
mesh service access, not completion of Slice 5 transparent L3.

### 11a. Use a bounded Windows IPv6 TCP address facade before system L3

The driver-free increment is implemented as
`--virtual-tcp-forward [VIRTUAL_IP]:PORT=NODE_ID`. It accepts only an IPv6 ULA
host address (`/128`). While the listener is active, the runtime temporarily
adds that address to the Windows loopback with ActiveStore lifetime and
`SkipAsSource=true`, then removes the alias during verified graceful shutdown.
The low-level `meshnode` path retains that process-local lifecycle. Managed
autonomous `wink up` additionally persists a machine-wide, per-address ownership
journal and holds an OS lifecycle lock. After an abnormal exit, an externally
restarted process may adopt the existing row only when its cleaned absolute
state path, node ID, and complete virtual-forward mapping set produce the same
scope and fingerprint, the previous process generation is dead, and both the
address shape and Windows row-creation timestamp still match the journal. All
unverifiable or conflicting cases fail closed. This is crash-safe lifecycle
ownership, not a durable system address assignment or an in-process supervisor.

The facade deliberately keeps the existing fixed-target stream protocol. Its
`OPEN` frame still carries no caller-selected host or port, so it remains wire
compatible with r12. The remote node must still publish an explicit
`--tcp-target`, and only the locally configured virtual listener port is
available. A normal Windows TCP client can therefore use a selected address and
port directly without a per-application proxy setting; the accepted field
commands were `ssh -6 node-b-user@fd00::b` and `ssh -6 node-c-user@fd00::c`.

This slice is not arbitrary-port forwarding, UDP, ICMP, transparent system L3,
subnet routing, or exit-node support. It does not use Wintun or WireGuard. Full
IP participation remains a later packet-ingress/egress backend rather than an
implicit property of the virtual TCP listener.

On 2026-07-19, A-only field acceptance replaced A's prior runtime with candidate
PID `80524`, whose mesh runtime started at `2026-07-19T00:57:05Z`. A first
restored one-hop A-B by cached self-bootstrap. The first A-C punch coordinated
through ordinary peer B timed out; the next attempt succeeded and reached
`stable`. The final A-B and A-C neighbors were both one-hop protected-direct
packet edges.

The retained loopback listeners `127.0.0.1:22024/22022` and the new virtual
listeners `[fd00::b]:22/[fd00::c]:22` made four entry points. Two complete
banner rounds returned Windows OpenSSH 9.5 for B and Ubuntu OpenSSH 8.9 for C,
then the wrapper held the topology and listeners for 45 seconds. An independent
final acceptance increased A's `data_forwarded` counter from `40` to `60` while
`data_dropped` stayed `0`.

Normal Windows OpenSSH then completed authenticated commands through both ULA
addresses: B returned `node-b-host`, C returned `node-c-host`, and both
clients exited with status `0`.

Both ULA aliases existed only on Windows loopback interface index `1` as
ActiveStore `/128` addresses with `SkipAsSource=true`; PersistentStore contained
zero matching aliases, and the portproxy table was empty. Tailscale service and a
natpierce process were in fact running during the field check, but neither
carried the accepted path. The ULA destinations resolved locally through
loopback. A's public B/C packet sockets used candidate UDP ports `52507` and
`62451`, routed from physical Ethernet address `10.0.0.10` through gateway
`10.0.0.1`; natpierce separately held `58606 -> 203.0.113.40`.

This was the A-only facade acceptance checkpoint. The later guarded Slice 4.5
rollout replaced all three field processes with managed `wink up` runtimes while
revalidating complete command output through A's four facades. Its first
independent probes were conservatively stopped as soon as output arrived, so
they did not establish a clean client-exit result. A subsequent output-aware
monitor gave each client a close grace period: all 44 SSH-carried probes exited
with code zero, while Win32-OpenSSH still printed its known pending-I/O close
warning. That warning alone is not evidence of a WinkYou FIN defect. See
`SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md`. Neither result broadens the facade into
system L3, arbitrary TCP ports, UDP, ICMP, subnet routing, or exit-node support.

The 2026-07-20 A-process crash acceptance then used the managed owned alias
path. Only A was hard-killed; B and C retained their process generations and
direct edge. During the deliberate 40-second A outage, both ULA rows and
journals remained, while Windows released the runtime and per-address locks.
An independent test watchdog launched the new A generation once; it adopted
both unchanged row identities, restored the direct triangle in about 112
seconds, and held it for 120 seconds. No manual address cleanup or
infrastructure coordinator was used. Six directed mesh ping paths and both ULA
SSH facades completed after recovery, although transient active-ping loss means
this is not a zero-loss or SLA claim. See
`VIRTUAL-TCP-ALIAS-CRASH-RECOVERY-2026-07-20.md` for the exact evidence and
fail-closed boundary.

### 12. Use bilateral recovery cards only when the graph has no route

Normal maintained-edge repair remains graph-driven. While an alternate route
exists, the lexicographically smaller endpoint owns the repair and an ordinary
trusted node on that route is the attempt-scoped coordinator.

The post-r9 source candidate adds a lower recovery layer for the case where a
pair has neither a direct neighbor nor any graph route. Each endpoint persists
its own last successful local bind port, NAT port model, and the peer's observed
public UDP endpoint. Both endpoints derive the same pair schedule and punch in
the same bounded window; lower-node-ID ownership is deliberately not used for
this bilateral operation. A pair-key HMAC HELLO checks the expected node ID
before the winning UDP socket becomes a packet neighbor.

Self-bootstrap stops once any graph route appears. Its job is to recreate the
first usable edge; the normal r9 controller can then use that edge and ordinary
peer coordination to complete the desired direct topology. A missing recovery
card leaves the peer in a visible waiting state rather than fabricating an
edge.

Production cached bootstrap currently accepts IPv4 global-unicast candidates
after excluding private, loopback, link-local, and `100.64.0.0/10` addresses.
It therefore does not silently reuse natpierce, Tailscale, or ordinary private
overlay addresses. IPv6, LAN discovery, special-use IPv4 classification, and
multi-candidate rotation remain later discovery work.

No-secret mode derives pair material from public node IDs and is suitable only
for the trusted-node functional experiment. A provisioned shared secret rejects
wrong-key peers, but rotation, epochs, admission, replay hardening, and hostile
peer security remain outside this slice.

### 13. Quarantine candidate edges and make restart generations fresh

A packet socket may be installed for liveness/probation before it is safe to
enter the routing graph. Solver and self-bootstrap attachments therefore start
with topology advertisement deferred. The node omits that attachment from its
local LSA until the exact neighbor handle passes local probation or
authenticated self-bootstrap HELLO. Promotion by exact handle prevents a stale
close callback for the same peer ID from promoting or removing a replacement
session, and a probationary edge cannot become the alternate route used to
justify itself.

Each new process also initializes routed-message sequences and Member/LSA
revisions from a high time-derived boot generation. This lets a quick restart
supersede the old generation still present in peer caches. It assumes the wall
clock does not move backwards. A downgrade to an older binary that restarts at
low counters is intentionally non-immediate: field wrappers must wait at least
135 seconds for duplicate/topology caches to expire before launching and
validating the old runtime.

## Incremental slices

1. **Static routed control echo:** three independent node runtimes connected as
   A-B-C over real loopback stream sockets, static neighbor/routes, no
   coordinator. Prove forwarding, reply, hop-limit expiry, duplicate rejection,
   path-loop rejection, and unknown-route handling.
2. **Autonomous topology:** flood `MemberRecord` and LSA records, calculate
   routes, and withdraw them after an edge failure.
3. **Peer-transit data:** add binary routed data frames, overlay ping, and
   fixed-target TCP forwarding over A-B-C without a virtual adapter, then expose
   the same service path through bounded runtime target/listener management.
4. **Shortcut solving:** carry `PREPARE/READY/FIRE` through B, invoke the current
   edge solver for A-C, install the direct edge, switch new traffic, and retain
   the transit path during a probation window.
4.5. **Product lifecycle integration:** extract the executable graph runtime as
   `pkg/meshruntime`, select it through a default-off typed `autonomous_mesh`
   configuration, and adapt it to the existing `wink up/down/status/peers`
   lifecycle without starting the legacy coordinator/WireGuard engine.
5. **System packet backend and exits:** connect the routed transport to the
   WinkYou-owned Windows packet ingress/egress path, advertised subnets, and
   optional default-route exits.

Implementation status on 2026-07-19:

- Slice 1 is implemented in `pkg/mesh` and `cmd/meshecho --mode static`.
- Slice 2's functional core is implemented: flooded member/LSA records with
  leases and revisions, reciprocal-edge LSDB, local Dijkstra routes, automatic
  stream-down withdrawal, and `cmd/meshecho --mode dynamic`.
- Slice 3's functional core is implemented: versioned binary data frames,
  physically separate control/data streams, a graph-routed `PacketTransport`,
  overlay ping, and fixed-target TCP forwarding with per-flow
  `OPEN/OPEN_OK/OPEN_ERROR/DATA/FIN/RESET/ACK` state, bounded stop-and-wait
  retransmission, duplicate suppression, and bidirectional half-close. The
  executable proof is `cmd/meshecho --mode data`.
- Slice 4's functional core is implemented in `pkg/mesh/shortcut`: B coordinates
  an attempt-scoped `PREPARE/READY/FIRE` barrier, A/C exchange edge-solver
  messages over routed peer control, protected-direct `PacketTransport` results
  become liveness-checked graph neighbors, and a probation failure returns the
  route to retained A-B-C transit. The executable proof is
  `cmd/meshecho --mode shortcut`. Barrier completion now also reconciles a
  silently lost COMMIT or STABLE: the coordinator resends COMMIT to roles whose
  STABLE vote is missing, stable endpoints re-report STABLE, and Failed cannot
  be revived by late barrier messages or the probation timer. This improves the
  existing wire protocol without yet adding a strict FINALIZE/ACK phase.
- The rejoin/edge-rotation proof is implemented in
  `cmd/meshecho --mode rejoin`: an offline B attaches temporarily through C,
  C coordinates a new A-B edge, the temporary C-B edge is removed only after
  A-B is stable, and A then coordinates the replacement B-C edge. The graph is
  connected throughout both transitions.
- `pkg/meshruntime` now provides the reusable multi-host runtime: node-ID
  bootstrap streams, reconnect/removal control, status and ping APIs,
  peer-coordinated shortcut initiation, real `birthday_punch` packet-neighbor
  handoff, fixed-target TCP forwarding, and the bounded Windows IPv6 ULA facade.
  `cmd/meshnode` is a thin compatibility/field wrapper around that package. Its
  three-runtime integration test executes the rejoin rotation through real TCP
  listeners and HTTP control requests, then proves direct TCP data bypasses the
  coordinator; the ULA facade has the separate A-only field acceptance recorded
  above.
- Slice 4.5 adds a typed, default-off `autonomous_mesh` block to `pkg/config` and
  a separate autonomous `client.Engine` adapter. `client.NewEngine` keeps legacy
  behavior unless `autonomous_mesh.enabled=true`; when enabled, `wink up` starts
  `pkg/meshruntime` without registering an infrastructure coordinator or
  constructing the legacy netif/WireGuard engine. Runtime-state snapshots add
  mesh route, next-hop, neighbor, maintained-direct, and self-bootstrap fields
  without changing the legacy `peers --json` top-level array. `wink down` uses an
  authenticated loopback shutdown endpoint, verifies the process-start identity
  and runtime instance, and never falls back to PID killing for a managed
  autonomous runtime, including with `--force`. The source tests, isolated local
  CLI lifecycle, and guarded C -> B -> A field rollout are accepted. OS
  service/autostart and reboot remain unaccepted.
- The r9 source candidate adds event-driven maintained-direct-edge recovery.
  Symmetric `--maintain-peer` declarations elect the lexicographically smaller
  endpoint as repair owner. It selects an ordinary coordinator from an
  alternate graph path, serializes local automatic attempts, applies bounded
  backoff, retains bootstrap addresses as last-resort seeds, and reports its
  state in `maintained_direct_peers`. The integration test preserves one
  already-open routed TCP connection through a one-way failure and both
  endpoints' liveness windows; traffic falls back through the third node, the
  edge is repunched, and traffic returns to one hop. Control-only bootstrap
  capability is flooded in link state, so every r9 node removes those edges
  from the same global data topology even while control routing can use them.
  r12 later exercised this maintained-edge path once on the public-NAT field
  triangle when B coordinated C-A after C-B self-bootstrap; the full fault
  matrix remains open.
- The post-r9 source candidate adds `pkg/recoverycard` and
  `pkg/bootstrap/selfhosted`, wired into experimental `cmd/meshnode` behind
  `--recovery-card`. Two local engines with no route or coordinator establish a
  loopback packet neighbor from persisted hints, learn a one-sided stale port,
  and retain the edge beyond a liveness timeout. A new B runtime then rejoins A
  from the same on-disk card without `InitialPeers`, listener, infrastructure
  coordinator, or relay. A separate test creates two complete three-runtime
  generations: self-bootstrap supplies a spanning tree and an ordinary third
  node coordinates the final stable direct edge through an injected
  deterministic strategy backed by a real UDP broker. Both runtime tests passed
  five repetitions and race detection. Recovery-card validation,
  atomic/concurrent updates, pair scheduling, HELLO integrity, and wrong-secret
  rejection also have deterministic coverage. The loopback paths use a
  test-only non-public-address seam. The staged r9 binaries predate this slice;
  r12 later supplied the narrower public-NAT process-rejoin results below.
- r12 quarantines solver/self-bootstrap packet attachments from topology until
  exact-handle promotion, reconciles COMMIT/STABLE for the whole probation
  deadline, and starts routed-message and topology revisions at a fresh high
  boot generation. B migrated from r11 PID `10680` to r12 PID `32176`. C then
  migrated from r8 PID `88361` to r12 PID `45666` with `mesh-listen=off` and no
  peer seed, recovered C-B from its card at approximately `16:47:37Z`, and used
  ordinary B to coordinate stable C-A by approximately `16:48:59Z`. The fresh
  triangle passed the wrapper's 45-second hold at `16:49:44Z`; a later
  six-direction sample was all one hop at `35.2595-60.2421 ms`, and routed SSH
  passed A-B port `22024` plus B-C port `22025`. B's retained private C seed
  could reach only a restored r8 listener after the mandatory 135-second
  rollback wait; natpierce/SSH management was excluded from product recovery.
  At that checkpoint A remained r7: runtime `POST /v1/tcp/forwards` returned
  HTTP 404 and added no `22022=C` forward.
- A subsequently migrated from r7 PID `66860` to r12 PID `12004`, again with
  `mesh-listen=off` and no peer seed. The runtime started at
  `2026-07-18T20:56:03.5187613Z`; A-C self-bootstrap succeeded at
  `20:56:44.5138193Z`, then ordinary C coordinated stable A-B at
  `20:57:28.6869764Z`. The wrapper's 45-second hold completed at
  `20:58:21.967714Z`; all six directions were one hop at
  `34.8213-59.768838 ms`. A-owned routed listeners authenticated to B on
  `22024` and C on `22022`. natpierce and Tailscale were excluded from product
  success. This completes the rolling A/B/C r12 deployment, not a simultaneous
  cold-start, public-IP-change, or OS-autostart result.
- Dynamic user-space service access is implemented and covered by tests. The
  local API can publish/clear a runtime target and add/list/remove runtime
  listeners on a node that started without TCP flags. The three-node integration
  test publishes C's target, creates a B listener for C, transfers routed TCP
  data without A forwarding the direct B-C flow, then removes both runtime
  objects while configured objects remain intact. This changes runtime
  ownership only; it does not change the routed TCP wire protocol. The r8 field
  run then published C's `127.0.0.1:22` target, created B listener
  `runtime-001` at `127.0.0.1:22025`, authenticated to C, and completed five
  fresh SSH connections. This is field proof of the user-space facade, not
  transparent system L3. Equivalent `--tcp-target`/`--tcp-forward` flags were
  carried into the later B/C r12 launchers, whose post-restart status documents
  show the target/listener as config-owned; system-service and operating-system
  boot/autostart behavior remain unverified. The historical r8 binaries
  predated shortcut-barrier reconciliation; the subsequent A migration means
  A/B/C r12 now all include it.
- The public-NAT A-C-B rejoin rotation completed on three real hosts. Ordinary
  peer C coordinated the scoped attempt for a protected-direct A-B edge, the
  temporary natpierce B-C bootstrap was removed while B-C routed through A, and
  ordinary peer A then coordinated the scoped attempt for a protected-direct
  B-C edge. All final pairwise routes were one hop, and A-B
  plus B-C remained usable while B's natpierce adapter was disabled. Detailed
  evidence is in `MESH-REJOIN-FIELD-EXPERIMENT.md`.
- A subsequent r6 field extension exposed B's loopback SSH service through A's
  meshnode listener. Thirty fresh direct SSH connections completed 30/30 in
  648-980 ms; A forwarded 783 routed data frames while attempt coordinator C
  forwarded zero. The same path removed B's temporary C bootstrap and initiated
  the replacement B-C shortcut. This is a usable user-space service path, not
  yet transparent system L3.
- A further r6 rotation produced all three WinkYou-owned public-direct edges
  with no desired bootstrap peers. The full triangle was initially stable, but
  A-C and A-B hit packet-neighbor liveness timeouts only 276 ms apart while B-C
  and all three processes survived. The last good six-direction sample was
  approximately two minutes earlier, so the old five-second timeout was not a
  credible field hold policy.
- r7 uses a one-second packet keepalive, a 30-second peer timeout, and a
  35-second default probation; the field launchers also set 35 seconds
  explicitly.
  The planned observation-only two-hour soak began at 20:28:42 +08:00 on
  2026-07-17, but C then lost power and the run was interrupted at approximately
  21:39 after manual reconstruction changed C's process identity and the A-C/B-C
  attempts. It is incident evidence, not a completed clean soak. The restored
  baseline is described in `MESH-REJOIN-FIELD-EXPERIMENT.md`.
- The replacement `20260717-214434` observation completed its full 7200-second
  duration with zero topology/process continuity changes, `120/120` routed SSH
  probes, and zero missed schedule slots. Best-effort control ping was
  `954/960`, and management status was `1438/1440`; every isolated failure
  recovered in the next scheduled sample. It is a completed continuity hold,
  not a zero-loss clean soak.
- The autonomous node, routed endpoint, shortcut manager, recovery supervisor,
  and selected-port TCP facade are now wired into the long-running `wink up`
  lifecycle behind explicit opt-in. All three field processes have been
  replaced with that path, and A has additionally passed a process hard-crash
  and same-mapping alias-recovery experiment. OS-level supervision and reboot
  acceptance remain open. Slice 5 system packet ingress/exit routing remains
  open.

The routed TCP proof now has explicit directional FIN handling, a bounded
per-flow receive queue, and ACK-based retransmission over datagram neighbors.
This resolves close semantics and observed single-datagram loss for this
framed prototype; it does not retroactively resolve the separate long-soak
QUIC bridge stall or prove lossless live path switching.

## Slice 1 acceptance

- No coordinator process, API, or package participates.
- A sends `control_echo_request` to C; B forwards without consuming its payload.
- C observes path `[A, B, C]` and replies; A observes `[C, B, A]`.
- B forwards each direction using the destination-to-next-hop table.
- Replayed `(origin, seq)` messages, exhausted hop limits, path loops, and
  destinations without routes are dropped with distinct observable reasons.
- The integration test uses real TCP sockets, even when the three runtimes live
  in one test process.

## Slice 3 acceptance

- No coordinator, Tailscale, natpierce, WireGuard, or Wintun participates in
  the A-B-C executable proof. Its only underlay is four loopback TCP connections:
  independent control and data streams for A-B and B-C.
- A and C wait for reciprocal LSDB routes before user data begins. A packet
  ping and reply cross B through `routed.PacketTransport`.
- A local ordinary TCP connection maps to one flow ID. C dials only its locally
  configured fixed target; the remote OPEN frame cannot select an arbitrary
  host or port.
- TCP data is losslessly checked in both directions. Directional FIN maps to
  `CloseWrite`, so a request can end while its response continues. Protocol or
  local-I/O failure maps to RESET.
- OPEN, OPEN_OK, DATA, FIN, and RESET frames on a datagram neighbor are ACKed.
  The sender retries at 250 ms intervals for a bounded five-second window;
  duplicate frames are ACKed but not delivered twice. A rejected OPEN_ERROR
  uses a bounded redundant burst because no responder flow is retained. A
  loss-injection integration test drops OPEN, bidirectional DATA, FIN, and
  three ACKs while retaining byte-exact output.
- A long-running runtime uses a frame lifetime of at least two peer-liveness
  windows plus a convergence margin. OPEN result waiting includes target dial
  time and has one lock-protected terminal outcome; an exact pending sequence
  prevents future ACKs from confirming unsent data. Queue-full backpressure
  withholds ACK without advancing receive sequence, and repeated RESET is
  acknowledged idempotently.
- B has no routed application endpoint. It forwards binary frames using only
  destination, hop limit, and the graph next hop.
- Closing B-C withdraws C from A's topology and forwarding tables while C's
  member lease is still present.
- Package tests use real TCP sockets and pass the race detector. Packet ping
  plus TCP half-close integration also passed a 100-run repeat during Slice 3
  acceptance.

## Slice 4 acceptance

- B is an ordinary trusted mesh peer, not an infrastructure coordinator. A
  sends `PREPARE` to B; B waits for READY from both endpoints and sends FIRE to
  both. Attempt IDs make duplicate or late lifecycle messages attempt-scoped.
- Solver messages are wrapped in the shortcut envelope and routed logically
  A-to-C. B forwards them without importing or interpreting the selected edge
  strategy's payload.
- Each endpoint executes a fresh `solver.Strategy`. Only a successful
  `protected_direct` result may be installed as a shortcut; relay or
  dependency-bearing results are rejected.
- A solver-produced `PacketTransport` is adapted to a mesh neighbor with a
  compact outer frame for control, data, ping, and pong. Socket and Go-context
  timeout forms are both treated as normal liveness polls; sustained silence or
  real I/O failure withdraws the adjacency.
- The route starts as `[A,B,C]`, converges to `[A,C]` after both endpoint
  installs commit, and sends subsequent packet traffic without B. A-B and B-C
  remain attached throughout probation.
- A forced direct-edge loss during probation makes both endpoints abort the
  shortcut and reconverge to `[A,B,C]`; packet traffic succeeds through B again.
- The generic shortcut integration uses an injected protected-direct strategy.
  A second integration test executes the existing `birthday_punch.Strategy`,
  routes its real endpoint/start messages through B, and injects only the final
  local UDP punch result. This proves solver integration and edge promotion,
  but is not a claim that a fresh public-NAT punch occurred in the test runner.
- Probation must be at least as long as the packet-neighbor peer timeout, so an
  edge cannot be called stable before it has survived a complete liveness
  window.

## Field liveness policy and recovery boundary

The r6 full-triangle failure distinguishes tolerance from recovery. A five-
second silence threshold withdrew the A-C and A-B packet neighbors, two
distinct A-incident edges that share endpoint A, within 276 ms even though no
process restarted and the third edge remained usable. r7 therefore sends
keepalives every second and waits 30 seconds before declaring a peer dead. The
35-second field probation exceeds that liveness window.

This is an explicit tradeoff. It can mask a short scheduler, network, or NAT
stall, but a genuinely dead path can blackhole new traffic for up to roughly
30 seconds. The then-live r7/r8 field nodes did not reconstruct a hard-closed
edge.

The r9 source candidate now uses an ordinary reachable peer as the
attempt-scoped coordinator and repunches only while an alternate graph path
exists. Topology changes trigger a coalesced recovery worker; they do not start
solver work inside routing callbacks. A deterministic endpoint owns each pair,
the node runs at most one automatic repair at a time, and failed attempts use
bounded jittered exponential backoff. A whole-attempt watchdog, local pair
single-flight, and opaque neighbor attachment handles prevent zombie attempts
or delayed close callbacks from tearing down a replacement edge. This behavior
has deterministic three-runtime/race coverage plus r12 public-NAT C-A
completion through B and A-B completion through C, but has not yet passed the
full field fault matrix.

Configured bootstrap peers are retained as last-resort seeds. A connector does
not occupy the peer slot while the target remains reachable through another
graph path; a maintained bootstrap stream is removed only after an alternate
route is proven, then replaced by a protected-direct packet edge. This lets a
relaunched node re-enter through a known seed without making that seed a
permanent data relay.

The post-r9 source candidate adds a second last-resort input: a persistent
recovery card populated by successful direct edges. When no route exists, both
endpoints can use the cached public IPv4 endpoint, deterministic pair window,
and direct punch/HELLO to recreate an edge without first receiving fresh solver
metadata. Once that edge exists, normal r9 peer-coordinated recovery resumes.
The feature is absent from the staged r9 binaries. r12 has public-NAT zero-seed
process-rejoin results on C and A and a completed rolling three-node deployment;
public-IP change, simultaneous cold start, OS reboot, and autostart coverage
remain open.

The coordination protocol itself forwards endpoint and solver metadata and
does not require a dedicated infrastructure user-data relay service. The same
ordinary trusted peer may independently forward user packets as a normal mesh
transit or exit node when the routing policy selects it. A completely isolated
endpoint cannot receive *fresh* coordination metadata through the lost mesh,
but it may act on previously persisted endpoint information. If every known
public destination changes simultaneously, that retained information no longer
identifies a recipient; recovery then needs LAN/IPv6/static discovery, a
still-reachable peer, or an external metadata directory. This information
boundary does not justify making a dedicated infrastructure user-data relay a
required dependency.

The field monitor is `scripts/monitor-three-node-soak.ps1`. It pins expected
attempt IDs and process start times, samples status, runs all six directed
pings, and probes routed SSH. It is strictly observation-only: a detected
topology or process change is logged, never repaired. The original C
SSH/punchbridge management session shared C's host/process lifecycle and was
invalidated by C's confirmed power loss even though its local punchbridge
process survived. The post-restart monitor reaches C for management through B's
natpierce leg; neither management route is a mesh neighbor or proof of a
data-plane edge in the triangle under test.

The first r7 field stall sharpened the acceptance distinction. A had a
16.819-second gap in received B/C public control traffic, while both A edges and
all three exact shortcut attempts remained present. This outcome is consistent
with the configured 30-second liveness hysteresis, but the available logs do not
directly record the relevant `lastRx` value or individual keepalive delivery and
therefore do not prove that setting caused the outcome. The topology remained
continuous without coordinator or bootstrap intervention. The observation
still cannot be called zero-failure: four one-shot control-echo transactions
returned HTTP 409 before a later probe succeeded. That status proves transaction
timeout, not which individual request/reply packet was lost. Control echo is
intentionally best-effort and has no retry; routed TCP has its own
ACK/retransmission layer and its A-to-B SSH probes remained successful. Link
continuity, best-effort control-message delivery, and reliable application-flow
continuity must therefore be reported as separate acceptance dimensions.

The same run later observed C disappear from A-C, B-C, and the rescue management
path at the same time; the user confirmed that C had lost power. After 30
seconds of receive silence,
B and A withdrew their C edges within roughly three seconds of one another;
the A-B direct edge and both endpoint processes remained healthy. This is the
expected hard-dead behavior of the deployed r7 code, not an autonomous-recovery
result. Once C was fully isolated, the surviving A-B graph had no channel over
which an ordinary attempt-scoped peer coordinator could send C fresh endpoint
or solver metadata, and r7 had no recovery-card engine. The post-r9 source
candidate is intended to try previously persisted public endpoints in this
case, but no claim is made that it would have recovered this historical public-
NAT outage. The old remote punchbridge session ending with C's host/process is
an expected session-lifetime boundary, not an additional independent failure
domain.

After C restarted, its new process identity was
`2026-07-17T13:24:21.007985278Z`. A and B manually rebuilt A-C as
`A-1784294971670842100-2` through attempt-scoped coordinator B, then B-C as
`B-1784295097111354200-3` through attempt-scoped coordinator A; the existing
A-B attempt `A-1784290543788179400-1` remained established. The restored
baseline had no desired bootstrap peers, one-hop routes for every pair, six
successful directed pings, and a successful A-to-B routed SSH probe. C's
management sampling now traverses B's natpierce leg and is excluded from
data-plane acceptance. That restored baseline then completed the replacement
two-hour observation with zero continuity changes, `120/120` routed SSH,
`954/960` best-effort control pings, `1438/1440` management samples, and no
missed schedule slots. Detailed per-direction failures and the later r8 dynamic
C-through-B service proof are recorded in `MESH-REJOIN-FIELD-EXPERIMENT.md`.

## Consequences

Slices 1-4 deliberately did not edit the existing client in-band loop or claim
production mesh operation. They established a transport-neutral graph and data
forwarding core plus a solver-to-neighbor promotion path. Slice 4.5 adopts that
runtime through a separate client-engine adapter and shared runtime-state/CLI
lifecycle; it does not merge the legacy and autonomous resource state machines.
This keeps the frozen connectivity solver/session boundary intact while making
the graph behavior executable through normal commands. The guarded 2026-07-19
C -> B -> A product rollout accepted that integration on all three field nodes;
the 2026-07-20 A-process hard-crash accepted same-scope, same-mapping runtime and
ULA alias recovery while B/C remained online. OS autostart/reboot, simultaneous
cold start, and public-IP-change recovery are still separate acceptance work.

Run the executable Slice 1 proof with:

```bash
go run ./cmd/meshecho --payload hello
```

The JSON result must report `coordinator_started=false`, request path
`[A,B,C]`, reply path `[C,B,A]`, and two forwards by B.

Run the executable Slice 2 proof with:

```bash
go run ./cmd/meshecho --mode dynamic --payload hello
```

This mode has no static A-to-C route. The result must report that A learned C
and route `[A,B,C]` from flooded member/LSA state, successfully exchanged the
echo, then withdrew the route after the real B-C stream closed while C's member
lease was still retained.

Run the executable Slice 3 proof with:

```bash
go run ./cmd/meshecho --mode data --payload hello --timeout 10s
```

The JSON result must report `coordinator_started=false`,
`transport=dual-real-loopback-tcp`, `learned_route=[A,B,C]`, a successful
`PONG:PING:hello`, a successful `TCP-ECHO:TCP:hello`, separate control/data
channels, completed TCP half-close, B data-frame forwarding, and final route
withdrawal.

Run the executable Slice 4 proof with:

```bash
go run ./cmd/meshecho --mode shortcut --payload hello --timeout 8s
```

This deterministic proof does not run public NAT punching. It must report
`coordinator_started=false`, `peer_coordinator=B`, initial route `[A,B,C]`,
direct route `[A,C]`, `shortcut_phase=stable`, solver signals forwarded by B,
`direct_data_bypassed_b=true`, and `transit_path_retained=true`. The
`birthday_punch.Strategy` integration is covered separately by
`TestStrategyRunsThroughPeerCoordinatorAndInstallsMeshShortcut`.

Run the Slice 4.5 source acceptance with:

```bash
go test ./... -count=1
go test -race ./pkg/config ./pkg/meshruntime ./pkg/processidentity ./pkg/client ./cmd/wink/cmd -count=1
go vet ./...
```

An isolated CLI lifecycle smoke test may use the following non-field config:

```yaml
node:
  name: demo-a

autonomous_mesh:
  enabled: true
  node_id: demo-a
  virtual_ip: fd7a:115c:a1e0::a
  listen: off
  control_listen: 127.0.0.1:0
```

Use a new config path and a new state path. In terminal one:

```bash
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json up
```

In terminal two:

```bash
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json status
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json peers
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json down
```

Acceptance requires `Mode: autonomous_mesh`, `Infra Coord: not started`, a
loopback control endpoint with a dynamically assigned port, no shutdown token in
`status --json`, and `wink down: gracefully stopped` followed by removal of the
state file. This smoke test proves local product lifecycle only. It must not use
the config/state path or listen ports of an existing field runtime, and it is not
a three-host public-NAT, system-service, OS-restart, or transparent-L3 result.

Run the connectivity-preserving rejoin proof with:

```bash
go run ./cmd/meshecho --mode rejoin --payload hello --timeout 30s
```

The JSON result must show bootstrap route `[A,C,B]`, first coordinator C and
direct route `[A,B]`, replacement route `[B,A,C]`, second coordinator A and
direct route `[B,C]`, temporary-underlay removal, three final direct edges, and
data-bypass verification. The corresponding multi-host procedure is documented
in [`MESH-REJOIN-FIELD-EXPERIMENT.md`](./MESH-REJOIN-FIELD-EXPERIMENT.md).
