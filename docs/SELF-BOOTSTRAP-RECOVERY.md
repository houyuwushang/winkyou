# Cached-endpoint self-bootstrap and recovery cards

Status: implemented and locally covered, with real public-NAT zero-seed
executable rejoins accepted on C and A using r12. Each started with no mesh
listener and no configured peer seed, recovered its first edge from bilateral
cached endpoint information, then used that ordinary peer to coordinate its
second direct edge. A, B, and C are now running r12 after a rolling migration.
This is not yet a simultaneous three-node cold-start matrix, public-IP change,
or operating-system boot/autostart result.

## Purpose and recovery layers

`cmd/meshnode` now has two complementary direct-edge recovery paths:

1. If a maintained peer is still reachable through another mesh path, the r9
   recovery supervisor selects an ordinary trusted peer on that path as the
   attempt-scoped coordinator. User traffic may continue through normal peer
   transit while the missing direct edge is rebuilt.
2. If there is neither a direct neighbor nor any graph route to the peer, the
   post-r9 self-bootstrap engine can use a persistent recovery card. Both
   endpoints enter the same deterministic time window and punch their last
   known public IPv4 endpoints without a coordinator, STUN exchange, TURN, or
   a dedicated user-data relay.

Self-bootstrap is intended to restore the first usable mesh edge after a
process or machine has come back. Once any edge restores graph reachability,
the normal r9 peer-coordinated controller is responsible for completing the
remaining maintained direct edges. A full triangle therefore need not be
recreated by three independent cold-bootstrap punches.

An ordinary mesh peer may still forward user data as a normal transit or exit
node when routing policy selects it. That is different from making a dedicated
infrastructure relay a product dependency.

## Configuration

Configure the maintained pair symmetrically. Use one recovery-card file per
node and, when authentication matters, provision the same secret contents to
both endpoints:

```text
# node A
meshnode --id A \
  --maintain-peer B \
  --recovery-card /var/lib/winkyou/A-recovery.json \
  --self-bootstrap-secret-file /var/lib/winkyou/self-bootstrap.secret

# node B
meshnode --id B \
  --maintain-peer A \
  --recovery-card /var/lib/winkyou/B-recovery.json \
  --self-bootstrap-secret-file /var/lib/winkyou/self-bootstrap.secret
```

For a three-node triangle, repeat `--maintain-peer` for the other two node IDs
on every node. The relevant flags and production defaults are:

| Flag | Meaning | Default |
| --- | --- | --- |
| `--recovery-card PATH` | Enable persistent cached-endpoint self-bootstrap | disabled |
| `--self-bootstrap-secret-file PATH` | Shared secret used to derive pair-specific punch and HELLO keys | none |
| `--self-bootstrap-window DURATION` | Active cached-endpoint punch window | `45s` |
| `--self-bootstrap-cycle DURATION` | Pair-deterministic interval between windows | `1m` |
| `--self-bootstrap-hello-timeout DURATION` | Reserve at the end of a window for peer identity HELLO | `8s` |

`--recovery-card` requires at least one `--maintain-peer`.
`--self-bootstrap-secret-file` requires `--recovery-card`. The cycle must be
longer than the active window, and both endpoint clocks must be close enough
for their active windows to overlap.

The lexicographically smaller node ID owns normal r9 repairs that run over an
existing alternate graph route. That ownership rule does not apply to cold
self-bootstrap: when no route exists, both endpoints must punch during the
same pair window.

## How the recovery card is populated

The recovery card is versioned, strictly validated JSON. It records the local
node ID, successful local bind ports, the observed local NAT port-allocation
model, and a bounded history of successful remote endpoints for each
configured maintained peer. Writes use an atomic replacement; corrupt,
unsupported-version, and wrong-node files are rejected instead of guessed.
The card is state, not a credential, and is not encrypted.

The post-r9 runtime updates the card when:

- a normal coordinator-driven `birthday_punch` shortcut reaches `stable` and
  reports its actual local and remote UDP addresses and NAT observations; or
- a cached self-bootstrap punch completes its peer HELLO and the resulting
  packet transport is attached.

A missing card is not a startup error. The peer remains in `waiting_hint` and
no neighbor is invented. An invalid existing card is a startup error so the
operator cannot silently rely on ambiguous recovery state.

The current selector retains bounded endpoint history but attempts only the
newest usable endpoint for a peer. Older entries are diagnostic history, not a
fallback rotation policy yet.

### First migration from r7, r8, or the staged r9 build

The historical r7/r8 processes and the already staged r9 binaries predate the
recovery-card flags and the extra `birthday_punch` path details used to write a
card. An existing live edge owned by those binaries does not automatically
materialize a valid recovery card.

For the first rollout of a post-r9 build, retain a verified bootstrap seed or
other management path. Start the new runtime with `--recovery-card`, let fresh
direct shortcuts reach `stable`, and verify that each intended peer appears in
the card before testing a restart with no seed. This initial migration still
needs reachable information; the card removes that dependency from later
restarts only while its endpoint information remains usable. Do not stop a
live r7/r8 node merely because the new flags exist.

The controlled C r8-to-r12 migration used the equivalent evidence-import path:
while the old B-C public-direct edge was still alive, reciprocal B/C status and
the exact C UDP socket were captured and converted into a strictly validated C
seed card. C r8 did not create that card. The new C launcher then contained no
`--peer` and used `--mesh-listen off`, so the imported public endpoint, rather
than an incoming bootstrap stream, had to recover the first r12 edge.

File staging is also separate from product bootstrap. In this run, natpierce
and SSH were used to upload and observe the detached migration wrapper, but
were neither a mesh neighbor nor a solver coordinator. A single large routed
SSH transfer could hit the approximately 75-second routed-frame deadline; the
working operational workaround was to compress, split into bounded chunks,
transfer each chunk separately, reassemble, and verify both archive and binary
SHA-256 hashes before execution.

## Punch and attachment behavior

Self-bootstrap runs only while the maintained peer has neither a direct
neighbor nor any graph route. For each such peer it:

1. loads the newest cached IPv4 candidate;
2. derives the same pair key, punch session, and absolute attempt window on
   both endpoints;
3. tries the cached endpoint first;
4. uses bounded prediction for preserving/sequential port models, or combines
   the cached port with a fresh birthday spray for unknown/random models;
5. learns the peer's actual source address from a successful inbound punch;
6. exchanges a pair-key HMAC-protected node-ID HELLO/ACK; and
7. hands the exact winning UDP socket to a `PacketNeighbor` under path ID
   `selfbootstrap/direct`.

If a route appears while an attempt is running, the attempt is cancelled and
normal graph recovery takes over. Successfully learned addresses are written
back to the card.

`GET /v1/status` exposes `self_bootstrap_peers`. Its states are:

| State | Meaning |
| --- | --- |
| `waiting_hint` | No usable cached endpoint exists |
| `scheduled` | A candidate exists; the engine is waiting for its pair window |
| `punching` | Cached predictive/birthday punch is active |
| `peer_hello` | UDP reachability succeeded; peer identity is being checked |
| `installing` | The winning socket is being transferred to the mesh node |
| `attached` | The packet neighbor was attached in this attempt |
| `reachable` | A direct neighbor or any graph route now reaches the peer |

`reachable` is deliberately broader than “self-bootstrap direct succeeded.”
Acceptance must still inspect the node's neighbor kind and one-hop route and
hold them for at least the configured liveness window. State transitions are
also logged as `selfbootstrap_state` events.

### r12 topology and restart hardening

r12 treats attachment and graph admission as separate steps. A solver or
self-bootstrap engine can hand a live packet socket to the mesh with
advertisement deferred, but that candidate is not included in the node's LSA
or route graph during probation. After authenticated self-bootstrap HELLO or
successful local shortcut probation, the runtime promotes that exact neighbor
handle. Exact-handle promotion prevents an older attachment's delayed close
callback from promoting or removing a newer replacement for the same peer ID.

Coordinator-driven completion also reconciles COMMIT throughout the full
probation/deadline window. A stable endpoint that receives a duplicate COMMIT
re-sends STABLE. This removes the field-observed split-state case where the
first COMMIT or STABLE disappeared, while leaving a strict durable
FINALIZE/ACK phase as later protocol work.

Fresh r12 processes initialize routed-message sequences and Member/LSA
revisions from a high time-derived boot generation. A quick same-node restart
therefore supersedes the predecessor still held in peer caches instead of
starting again at revision one. Two operational constraints follow:

- the host wall clock must not move backwards across the restart; and
- downgrading to an older low-counter binary must wait at least 135 seconds for
  peer topology/duplicate caches to expire before the old process is started
  and convergence is judged.

The B and C field wrappers encode that downgrade as an explicit
`rollback_waiting_cache_expiry` state. An immediate r12-to-r11/r8 launch is not
a verified rollback path.

## Address and probability boundary

The production CLI currently considers only IPv4 candidates for cached
self-bootstrap. It requires Go's global-unicast classification and additionally
rejects private, loopback, link-local, and `100.64.0.0/10` CGNAT addresses.
There is no production flag that enables non-public candidates. Consequently a
natpierce, Tailscale, loopback, or ordinary RFC1918 address cannot silently
become the independent recovery path. The classifier is not yet a complete
registry of every special-use IPv4 range, so the status should be described as
“accepted cached IPv4 candidate,” not proof that an address is Internet-routable.

Endpoint learning can repair some stale-port cases, and in principle can learn
a changed address when the other direction still reaches a valid cached
endpoint. The current deterministic test proves a one-sided stale UDP port,
not a real public-IP change.

If every peer's public IP changes at the same time, all cached destinations are
stale, and no LAN discovery, usable IPv6 address, static mapping, still-reachable
peer, or external directory exists, the nodes have no information telling them
where to send the first packet. No graph algorithm or forged routing hint can
recover information that is absent. That case still requires a discovery
source; it does not require a dedicated user-data relay.

Birthday punching across random symmetric NAT is probabilistic. The default
`128` sockets, `48` fresh targets per round, and `300ms` round delay are a
field-derived bounded profile, not a connectivity guarantee. Firewall policy,
carrier filtering, clock skew, or an exhausted attempt window can still make a
pair fail and retry in a later cycle.

IPv6 cached bootstrap, LAN discovery, PCP/NAT-PMP/UPnP, multi-candidate
rotation, and an optional external directory remain future discovery methods.

## Security boundary

When no secret file is configured, the pair key is derived from the two node
IDs with an empty secret. Anyone who knows those IDs can derive the same key.
The runtime reports that mode as `trusted_node_ids_no_secret`. It separates
accidental cross-pair traffic in a trusted lab; it is not authentication
against an attacker.

With a shared secret, punch sessions and HELLO tags are pair-specific and a
wrong secret is rejected. The current protocol still uses stable pair material
across restarts and does not claim key rotation, epoch binding, admission
control, or complete replay hardening. Do not expose the experimental runtime
to hostile peers based on this HELLO alone.

Bootstrap stream trust, the loopback HTTP control API, peer admission, and
hostile-network hardening remain separate concerns. Keep the HTTP API on
loopback and protect the secret and card files with operating-system access
controls.

## Current evidence and pending acceptance

The local source tests prove:

- strict recovery-card round trip, atomic/concurrent update, and rejection of
  corrupt, unsupported, inconsistent, or wrong-node state;
- symmetric pair scheduling and pair-key separation;
- HELLO integrity and rejection of mismatched secrets; and
- two loopback mesh engines with no route or coordinator establishing a direct
  packet neighbor, retaining it beyond a liveness timeout, learning one stale
  cached port, and updating the card;
- replacement of B with a completely new `meshRuntime` instance using the same
  on-disk card and no `InitialPeers`, mesh listener, infrastructure
  coordinator, or relay; the real loopback UDP packet edge returns, both sides
  report a successful cached attempt, and B refreshes its card; and
- two complete generations of three fresh runtimes. Each generation starts
  without bootstrap connectors, cached self-bootstrap forms at least a
  two-edge spanning tree, and an ordinary third node coordinates the remaining
  direct edge to a stable full triangle. The final shortcut uses the injected
  deterministic `runtimeTestStrategy` over a real UDP test broker, so this
  proves lifecycle composition rather than a fresh public-NAT birthday punch.

The single-replacement and full-three-runtime tests each passed five repeated
runs and the race detector. Those cases remain in-process deterministic source
tests, but r12 now also has the narrower process-level field evidence below.

The older offline review package is
`.live-run/runs/mesh-selfbootstrap-20260718-r10`. Its manifest SHA256 is
`10E277A3B430702175ED6854D2F5AA8C3B922EE292ACD9AD42416F43BF40BB68`;
the Windows/amd64 and Linux/amd64 binaries were each rebuilt twice with
identical hashes. The package contains inert A/B/C launchers and migration
instructions, but deliberately contains no recovery card, secret, guessed
endpoint, or stop/restart rollout wrapper. No r10 launcher ran; it is a
historical review artifact, not the r12 binary used in the field.

The r12 evidence under
`.live-run/runs/mesh-selfbootstrap-20260718-r12/field-evidence` records three
guarded migrations:

The completed A/B/C field manifest is
`.live-run/runs/mesh-selfbootstrap-20260718-r12/r12-topologygate-manifest.json`,
SHA-256 `590C8C7ADA7C709C6C1C5546844449ADDC55CED67CF9D93253B7BEA66236FAA8`.

- B moved from r11 PID `10680` to r12 PID `32176`, rebuilt packet-direct B-A
  and B-C shortcuts, held the fresh one-hop triangle for 45 seconds, and
  completed successfully at `2026-07-18T15:43:24.9556977Z`. A subsequent
  pre-C-restart six-direction sample reported one-hop request/reply paths with
  RTTs from approximately `35.16` to `60.40 ms`.
- C moved from r8 PID `88361` to r12 PID `45666`. Its runtime started at
  `2026-07-18T16:46:46.292672054Z` with `mesh-listen=off`, no configured peer
  seed, and an empty desired-bootstrap map. Cached attempt
  `selfboot-C-B-1784393250-2` authenticated and attached C-B at
  approximately `16:47:37Z`. C then reached A over `[C,B,A]`, used ordinary B
  as the attempt-scoped coordinator for C-A shortcut
  `C-1784393259740351669-1`, observed that edge stable by approximately
  `16:48:59Z`, held both packet-direct edges for 45 seconds, and recorded
  success at `2026-07-18T16:49:44.285Z`. A separate post-success sample at
  `16:52:29-16:52:32Z` reported all six directions one hop with RTTs from
  `35.2595` to `60.2421 ms`. Routed SSH passed A-to-B on port `22024` and
  B-to-C on port `22025`, with the latter reaching C PID `45666`.
- A then moved from r7 PID `66860` to r12 PID `12004`. Its runtime started at
  `2026-07-18T20:56:03.5187613Z` with `mesh-listen=off`, no configured peer
  seed, and an empty desired-bootstrap map. Cached attempt
  `selfboot-A-C-1784408173-2` authenticated and restored A-C at
  `20:56:44.5138193Z`. A then used ordinary C as the attempt-scoped
  coordinator for A-B shortcut `A-1784408206309626300-1`, which reached
  `stable` at `20:57:28.6869764Z`. The wrapper held both one-hop direct edges
  for 45 seconds and recorded success at `20:58:21.967714Z`. A later
  six-direction sample reported every request/reply path as one hop, with RTTs
  from `34.8213` to `59.768838 ms`. New authenticated SSH connections passed
  from A to B through `127.0.0.1:22024` and from A to C through
  `127.0.0.1:22022`; both listeners were owned by A r12 PID `12004`.

Post-success readback also confirmed that all three live recovery cards learned
the new bilateral endpoints: A stored fresh B and C entries, B stored A at
`192.0.2.10:52507`, and C stored A at `192.0.2.10:5017`. The compact evidence
is `.live-run/runs/mesh-selfbootstrap-20260718-r12/field-evidence/A/reciprocal-recovery-cards-post-A-r12.json`;
this matters for the next process-restart experiment, but does not by itself
prove recovery after a public-IP change.

The post-success route check selected the physical Ethernet interface (source
`10.0.0.10`, gateway `10.0.0.1`) for both public peers. Tailscale reported
stopped. A natpierce UI process was present, but it owned none of A's two UDP
sockets or the `22022`/`22024`/`32110` listeners and was not the selected public
route. The snapshot is
`.live-run/runs/mesh-selfbootstrap-20260718-r12/field-evidence/A/underlay-route-check-post-A-r12.json`.

B retained `C=10.20.0.1:32100`, but C r12 deliberately had no mesh listener,
so that connector could not create the successful r12 edge. It existed solely
so an r8 rollback could listen again after the mandatory 135-second cache wait.
natpierce and SSH carried deployment commands and evidence retrieval only; they
were not accepted as a recovery edge, coordinator, or user-data relay.

These field runs prove two node-specific public-NAT executable rejoins with
still-usable cached endpoints, and complete the rolling A/B/C migration to r12.
They do not prove that a changed public IP can be recovered, simultaneous cold
start of all three nodes, or a machine reboot. Keep the earlier B-migration,
post-C-r12, and post-A-r12 acceptance samples separate when comparing results.

The loopback test still enables a test-only non-public-address seam. The r12 C
and A runs supply public-NAT reachability results; the following remain pending
and must not be reported as passed yet:

- B zero-seed rejoin and simultaneous cold-restart cases on the real A/B/C
  topology;
- one or more real public-IP changes;
- operating-system boot/autostart and process supervision; and
- hostile-peer security acceptance.

At the earlier post-C checkpoint, A was still on r7: its attempt to add
`127.0.0.1:22022=C` through runtime `POST /v1/tcp/forwards` received HTTP 404
and added nothing. The later guarded A migration replaced that process with r12
PID `12004` and configured both `127.0.0.1:22024=B` and
`127.0.0.1:22022=C` in the launcher. The current `22022` listener is therefore
the A r12 routed mesh service for C, not evidence that the earlier r7 runtime
API call succeeded and not the historical standalone `punchtest bridge`.

An established TCP connection terminates with the process that owns it. This
feature restores mesh connectivity and allows services to accept new
connections; it does not preserve an existing TCP flow across a process
restart.

Finally, this work belongs to the experimental `cmd/meshnode` graph runtime.
It does not wire the same lifecycle into the long-running `wink up` engine and
does not provide transparent system L3 ingress/egress. Wintun, WFP, TUN, or a
WinkYou-owned packet backend remains separate Slice 5 work.
