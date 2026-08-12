# Peer-coordinated mesh rejoin field experiment

> **PAUSED / NO-GO (2026-07-22):** this document preserves historical field
> evidence, not current deployment instructions. Automatic maintained-edge
> recovery and cached self-bootstrap are disabled at the product boundary after
> the UDP tuple/session storm. Current binaries reject `--maintain-peer` and
> `--recovery-card`; see
> [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md).

Status: edge rotation, routed SSH, a completed two-hour link-hold run, r8
dynamic C-through-B user-space service access, and two r12 cached-endpoint
public-NAT zero-seed rejoins are field-proven. C first recovered C-B and used B
to coordinate C-A; A later recovered A-C and used C to coordinate A-B. A, B,
and C now run r12 after a completed rolling migration. This is not a
simultaneous three-node cold start, operating-system reboot/autostart, or
public-IP-change result. The first r7 link-hold run remains an interrupted
C-power-loss incident record, 2026-07-18. Slice 4.5 later replaced all three
processes through a separate guarded product rollout recorded in
`SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md`; that successor result must not be
attributed retroactively to the historical results below.

## Goal and node identities

Prove that an offline peer can rejoin through a temporary reachable peer, then
replace that dependency with WinkYou-owned public-direct edges while the graph
stays connected. No central/infrastructure coordinator, dedicated
infrastructure user-data relay (including TURN), WireGuard, Wintun, or Tailscale
path is part of the experiment. Each punch coordinator below is an ordinary
trusted mesh peer whose role exists only for that attempt.

- `A`: the local Windows workstation;
- `B`: `node-b`, initially outside the WinkYou mesh;
- `C`: `inner-gw`;
- historical starting `A-C`: the public `punchbridge` path then exposed at local
  SSH port `127.0.0.1:22022` (after the later A r12 migration that same local
  port is owned by `meshnode` and routes to C);
- temporary `C-B`: the natpierce management underlay (`C=10.20.0.1`,
  `B=10.20.0.4`).

## Connectivity-preserving edge rotation

```text
G0: A === C ---temporary--- B

G1: A === C ---temporary--- B
     \=====================/    C coordinates the new A-B edge

G2: A === C                  B
     \=====================/    remove temporary C-B after A-B is stable

G3: A === C ================ B
     \=====================/    A coordinates the new C-B edge
```

The graph remains connected at every transition. The first new edge becomes
the signaling path used to create the second new edge.

## Implemented runtime

`pkg/meshruntime` provides the implementation below; `cmd/meshnode` is now a
thin compatibility wrapper that preserves the historical field flags:

- a TCP bootstrap listener with an explicit node-ID hello;
- desired bootstrap peers with reconnect and removable ownership;
- autonomous member/link-state flooding and shortest-path routing;
- the Slice 4 peer-coordinated shortcut manager;
- declared protected-direct edge maintenance (`--maintain-peer`), deterministic
  endpoint ownership, alternate-route coordinator selection, and bounded retry;
- optional persistent recovery cards and bilateral cached-endpoint punch when a
  maintained peer has neither a neighbor nor a graph route;
- the `birthday_punch` strategy and direct UDP `PacketNeighbor` handoff;
- a loopback HTTP API for status, control ping, peer removal, and shortcut
  initiation;
- an optional configured fixed-target routed TCP service (`--tcp-target`) and
  loopback listener (`--tcp-forward`), plus runtime HTTP APIs for adding and
  removing the same user-space service endpoints without restarting `meshnode`;
- JSON event logs containing shortcut phase and selected remote endpoint.

The r12 status API also exposes `self_bootstrap_peers`; cached-bootstrap state
transitions are logged as `selfbootstrap_state`. This capability is now running
on A, B, and C, but is not present in the historical prepared r9 package.

Bootstrap streams are trusted lab inputs, not evidence of a protected-direct
WinkYou edge. Security/authentication is intentionally deferred for this
trusted-node experiment. Keep the HTTP API on loopback.

## Deterministic local proof

```powershell
go run ./cmd/meshecho --mode rejoin --timeout 30s --payload field-plan
go test ./cmd/meshnode -count=10
go test ./pkg/bootstrap/selfhosted ./pkg/recoverycard
```

`meshecho --mode rejoin` asserts route transitions and data-forwarding deltas.
The `meshnode` test uses three real TCP listeners, HTTP control requests, and
two UDP packet-neighbor installations. The self-bootstrap package test starts
two loopback engines with no route or coordinator, recovers a direct packet
neighbor from persisted hints, learns a one-sided stale UDP port, and holds the
edge beyond a liveness timeout. It uses a test-only non-public-address seam and
is not evidence of a public-NAT result.

The post-r9 runtime tests additionally replace B with a completely new runtime
that has the same card but no `InitialPeers`, mesh listener, infrastructure
coordinator, or relay; the real loopback UDP edge and card update return. A
second test creates and closes one full three-runtime generation, then creates
a second generation from the same cards. Cached self-bootstrap forms at least a
two-edge spanning tree, after which an ordinary third node
coordinates the final stable direct edge. That final shortcut uses an injected
deterministic strategy backed by a real UDP test broker, not a fresh public-NAT
birthday punch. Both tests passed five repeated runs and the race detector.

## Source result: event-driven direct-edge maintenance (r9 candidate)

The r9 source candidate turns the previous observation-only recovery plan into
an executable controller. A node may declare each protected-direct peer with a
repeatable `--maintain-peer NODE_ID` flag. Operators should put the symmetric
declaration on both endpoints; the lexicographically smaller node ID is the
deterministic repair owner, so both endpoints cannot start competing automatic
attempts for the same pair.

For a full A/B/C triangle the declarations are:

```text
A: --maintain-peer B --maintain-peer C
B: --maintain-peer A --maintain-peer C
C: --maintain-peer A --maintain-peer B
```

The controller is event-driven. Actual member, link-state, neighbor, expiry,
and shortcut terminal changes coalesce a reconciliation wake-up; there is no
high-frequency health poll. When a maintained packet edge disappears, the
owner:

1. waits for the link-state graph to expose an alternate path;
2. chooses the first internal node on that path as an ordinary attempt-scoped
   coordinator;
3. keeps user traffic on the surviving multi-hop route;
4. runs at most one automatic attempt per local node;
5. applies bounded jittered exponential backoff after failure; and
6. keeps the repair owner's edge `attempting` until the shortcut reaches
   `stable`; a target/non-owner may expose `healthy` as soon as its packet
   neighbor is installed, so field acceptance must still correlate the same
   attempt across all three roles.

`GET /v1/status` now includes `maintained_direct_peers`, with owner, state,
neighbor kind, route path, coordinator, attempt, failure count, next retry, and
last error. Shortcut attempts also have a whole-lifecycle deadline, explicit
cancel, pair-level single-flight, and exact neighbor attachment handles. The
handle is important: a delayed close callback from an old attempt cannot remove
a replacement edge that now uses the same peer ID.

Bootstrap intent is retained rather than deleted during promotion. A `--peer`
connector dials only when the peer is neither a direct neighbor nor reachable
through the current graph. Therefore it acts as a last-resort rejoin seed after
process/network recovery, but leaves the peer slot free while an ordinary mesh
route can coordinate a protected-direct replacement. A maintained stream edge
is promoted only after `AlternateRoute` proves that removing it preserves a
route to the target.

Bootstrap streams are control-only and now advertise that capability in the
flooded link-state record. Every r9 node computes a separate, globally
consistent data topology that removes an undirected edge if either endpoint
marks it control-only. Thus a seed may carry coordination metadata without
silently attracting user packets, including packets originating at a third
node. Replacement-session identity/capability changes rebuild the route tables;
a delayed Down event cannot leave a new packet neighbor without routes.

The local three-runtime recovery test builds a full packet triangle, opens one
routed TCP flow from A to B, withdraws the exact A-B attachment at both
endpoints, and observes route `[A,C,B]`. The same already-open `net.Conn`
continues echo traffic through C. C then coordinates a new A-B attempt; after
it becomes stable, the same connection continues over `[A,B]` and C's data
forwarding counter stops increasing. The test also proves deterministic owner
selection and automatic bootstrap-to-packet promotion. Its injected UDP
strategy is deterministic protected-direct test infrastructure, not evidence
of a fresh public-NAT punch in the test runner.

Routed TCP frame ACK lifetime now defaults to `2 * peer-timeout + 15s`, instead
of the old fixed five seconds. The two detection windows matter for a one-way
failure: one endpoint may change route while the other still prefers a direct
edge kept alive by traffic in the surviving direction. The local test now drops
only B-to-A packets while an already-sent TCP frame is pending, lets A and then
B cross their respective liveness windows, and completes that same frame over
A-C-B before the direct edge is rebuilt. With the 30-second field peer timeout,
the explicit launcher value is therefore 75 seconds. This source-level result
does not claim that a TCP connection terminating in a process survives that
process restarting; the real public-NAT 30-second window remains field work.

The r9 controller's reachability boundary remains unchanged: it needs an
alternate route or retained bootstrap seed to deliver fresh solver metadata.
No dedicated coordinator or user-data relay is introduced. Operating-system
service installation, crash restart, boot autostart, and r9 public-NAT recovery
remain separate field acceptance work. The next section describes the post-r9
cached-information path for the narrower no-route case.

## Post-r9 source result: cached-endpoint self-bootstrap

The post-r9 source candidate adds `pkg/recoverycard` and
`pkg/bootstrap/selfhosted`, wired into `cmd/meshnode` with:

```text
--recovery-card PATH
--self-bootstrap-secret-file PATH
--self-bootstrap-window 45s
--self-bootstrap-cycle 1m
--self-bootstrap-hello-timeout 8s
```

`--recovery-card` requires at least one `--maintain-peer`; configure each pair
on both endpoints. The lower-node-ID rule still owns an r9 repair performed
over an alternate graph route. It does not own cold self-bootstrap: when no
route exists, both endpoints must enter the same pair-derived time window and
punch each other.

A stable coordinator-driven `birthday_punch` edge records its actual local and
remote UDP addresses plus the observed NAT port model. On a later no-route
start, the engine tries the cached port first, applies bounded prediction for a
preserving/sequential model, or combines that cached target with a fresh
birthday spray for unknown/random allocation. A successful inbound probe can
teach the other endpoint's actual source address. A pair-key HMAC HELLO checks
the expected node ID before the exact winning socket is installed as
`selfbootstrap/direct`.

Self-bootstrap stops as soon as the peer is reachable through any graph route.
Its purpose is to recover the first edge. The r9 maintained-edge controller can
then use ordinary peer coordination over the restored graph to build the
remaining direct edges. `self_bootstrap_peers.state=reachable` therefore means
“neighbor or route exists,” not by itself that a direct cached punch succeeded;
field acceptance must still inspect a packet neighbor and one-hop route.

The recovery card is strict, versioned, atomically replaced JSON. A missing
file produces `waiting_hint`; a corrupt, unsupported, or wrong-node file stops
startup rather than being guessed. The current selector keeps bounded endpoint
history but attempts only the newest usable entry.

Production cached bootstrap is IPv4-only. It accepts global-unicast candidates
after excluding private, loopback, link-local, and `100.64.0.0/10` addresses;
there is no CLI override for natpierce, Tailscale, or RFC1918 endpoints. This
prevents an external overlay from silently becoming the claimed independent
recovery path, but the classifier is not yet a complete special-use IPv4
registry and must not be described as proof of Internet routability.

Without a secret file, pair material is derived from public node IDs. That mode
is only accidental cross-pair separation for the trusted-node lab, not
authentication against an attacker. A shared secret rejects a wrong-key peer,
but key rotation, epoch binding, admission, and full replay hardening remain
future security work.

The current local proof covers a stale UDP port, not a changed public IP. If at
least one direction still reaches a valid cached endpoint, inbound learning may
repair additional stale information. If all peers' public IPs change together
and no LAN/IPv6/static mapping/still-reachable peer/external directory exists,
no node knows where to send the first packet. That information-theoretic case
still needs discovery, though not a dedicated user-data relay. Random
symmetric-NAT birthday punching is also probabilistic, never guaranteed.

The first migration from r7/r8 or the staged r9 build still requires a verified
seed or management path. Those binaries do not write recovery cards and their
historical path summaries lack the new local-address/NAT details. Launch the
post-r9 build with card persistence while the seed is retained, let fresh
direct edges reach `stable`, and verify every intended peer entry before a
later no-seed restart test. Flags alone do not create missing endpoint
information.

Local runtime-lifecycle acceptance covers one peer replacement and two complete
generations of a three-runtime direct triangle. The later r12 field runs also
cover real C and A public-NAT executable rejoins from prepared bilateral cards
and complete a rolling three-node r12 deployment. Public-IP change,
simultaneous cold start, and OS boot/autostart acceptance remain pending. See
[`SELF-BOOTSTRAP-RECOVERY.md`](./SELF-BOOTSTRAP-RECOVERY.md) for the operator
and security boundary.

A review-only r10 package is staged at
`.live-run/runs/mesh-selfbootstrap-20260718-r10`. Its manifest SHA256 is
`10E277A3B430702175ED6854D2F5AA8C3B922EE292ACD9AD42416F43BF40BB68`.
Both platform binaries reproduced byte-for-byte across two builds, and the
offline verifier passed. No r10 launcher ran, no card or secret is bundled, and
no rollout wrapper is present; r10 remains a historical review artifact and is
not the r12 binary used by the later field acceptance below.

## r12 hardening and public-NAT process-rejoin result

The r12 candidate closes four restart and promotion races found while preparing
the field migration:

1. A solver- or self-bootstrap-produced packet session is initially attached
   with topology advertisement deferred. During probation it may exchange
   liveness/control traffic, but it is absent from the local advertised LSA and
   cannot become a graph route or an alternate route used to justify itself.
2. Promotion is by the exact neighbor attachment handle. Only the candidate
   that passed local probation or authenticated self-bootstrap HELLO is made
   advertisable; a delayed callback from an older session cannot promote or
   tear down its replacement.
3. The shortcut coordinator reconciles COMMIT for the whole probation/deadline
   window, and an already-stable endpoint re-reports STABLE after a duplicate
   COMMIT. A lost COMMIT or endpoint STABLE therefore no longer leaves the three
   roles split merely because the first message was dropped.
4. Each fresh process initializes routed-message sequences and Member/LSA
   revisions from a high, time-derived boot generation instead of restarting
   at one. Surviving peers can accept the new process's topology immediately
   rather than rejecting it behind the previous generation still in cache.

The fourth change has an explicit downgrade cost. An older binary that restarts
its counters at one cannot immediately supersede r12's high revisions. The r12
field wrappers therefore enter `rollback_waiting_cache_expiry` and wait at
least 135 seconds before launching r11/r8 and validating convergence. An
immediate downgrade is not a supported rollback. The time-derived generation
also assumes the host wall clock does not move backwards across restarts; clock
rollback needs separate operational handling.

### B rolling field migration

B's guarded wrapper replaced r11 PID `10680` with r12 PID `32176`; the new
runtime started at `2026-07-18T15:40:25.2630996Z`. It rebuilt B-A as
`B-1784389256512129400-1` through ordinary coordinator C and B-C as
`B-1784389308775644700-2` through ordinary coordinator A, observed a fresh
packet-direct triangle, held both maintained one-hop edges for 45 seconds, and
recorded success at `2026-07-18T15:43:24.9556977Z`. The persisted B recovery
card snapshot hash was
`7DB5BC3A61C1385A00221BEDDC65CD7B50009044D2038F1227EC1A3803EB76B5`.

A six-direction sample after B's migration and before C's restart reported all
request and reply paths as one hop. RTTs were A-B `37.826 ms`, A-C
`35.162 ms`, B-A `36.178 ms`, B-C `59.980 ms`, C-A `36.519 ms`, and C-B
`60.396 ms`. This sample proves the mixed A-r7/B-r12/C-r8 triangle was direct;
it is retained as the pre-C-restart baseline and is distinct from the later
post-C-r12 sample below.

### C zero-seed r12 rejoin

The narrower no-live-coordinator trial then replaced C's r8 PID `88361` with
r12 PID `45666`. Before stopping r8, the migration tooling constructed and
strictly validated C's initial card from reciprocal evidence of the already
stable B-C public-direct edge. This is controlled first-migration input, not a
claim that r8 could write a recovery card itself.

C's r12 launcher deliberately used `--mesh-listen off`, contained no `--peer`,
and later reported an empty `desired_bootstrap_peers` map. B retained the legacy
seed `C=10.20.0.1:32100`, but that connector could not reach r12 because r12
opened no mesh listener. Its only purpose was to recover the old r8 listener if
verified rollback became necessary, so it cannot explain the successful r12
edge.

The observed sequence was:

- C r12 started at `2026-07-18T16:46:46.292672054Z` with no infrastructure
  coordinator;
- the second cached attempt reached authenticated HELLO and attached the fresh
  `selfbootstrap/direct` C-B packet edge at approximately `16:47:37Z`; C then
  had route `[C,B]` and reached A only through `[C,B,A]`;
- C requested shortcut `C-1784393259740351669-1` to A with ordinary peer B as
  attempt-scoped coordinator; it reached `stable` at `16:48:57Z`, and the
  wrapper recorded the stable response at approximately `16:48:59Z`; and
- both C-A and C-B were fresh protected-direct packet neighbors with one-hop
  routes for a continuous 45-second hold, after which the wrapper recorded
  success at `2026-07-18T16:49:44.285Z`.

An independent acceptance sample at `2026-07-18T16:52:29.9233302Z` through
`16:52:32.150Z`, after C's success, then reported all six request and reply
paths as one hop. RTTs were A-B `38.402 ms`, A-C `35.260 ms`, B-A
`36.879 ms`, B-C `60.242 ms`, C-A `35.420 ms`, and C-B `60.080 ms`.
Fresh routed SSH also passed from A to B through `127.0.0.1:22024` and from B
to C through `127.0.0.1:22025`; the latter terminated at C meshnode PID
`45666`. A's attempt to add `127.0.0.1:22022=C` dynamically returned HTTP 404,
as expected for r7, and no runtime forward was added.

This C-specific acceptance proves one real public-NAT executable restart can
recover its first edge from previously persisted peer information without a
live coordinator, then use that recovered ordinary peer to coordinate the rest
of its direct topology. During this checkpoint A remained the existing r7 peer;
the subsequent A migration below supersedes that deployment state. This check
alone did not prove three simultaneous cold starts, changed public IPs, OS
boot/autostart, or hostile-peer security.

natpierce and SSH were used only to stage files, arm the detached wrapper, and
retrieve evidence. They were not a C r12 bootstrap neighbor, coordinator, or
user-data path and are excluded from product success. Likewise, B's retained
private seed was rollback insurance for r8 only. The result depends on the
public cached UDP endpoints recorded in the recovery cards and the subsequent
WinkYou packet edges.

### A zero-seed r12 rejoin and completed rolling rollout

The guarded fail-forward migration later replaced A's r7 PID `66860` with r12
PID `12004`. A r12 started at `2026-07-18T20:56:03.5187613Z` with
`--mesh-listen off`, no `--peer`, and no infrastructure coordinator. Its first
fresh edge was cached attempt `selfboot-A-C-1784408173-2`, which authenticated
and restored direct A-C at `2026-07-18T20:56:44.5138193Z`. With C now reachable
as an ordinary mesh peer, A asked C to coordinate A-B shortcut
`A-1784408206309626300-1`; that edge reached `stable` at
`2026-07-18T20:57:28.6869764Z`.

Both A-C and A-B then remained protected-direct, packet-backed, and one hop for
the wrapper's continuous 45-second hold. It recorded success at
`2026-07-18T20:58:21.967714Z`. A separate post-success acceptance sample
reported all six directions one hop, with RTTs from `34.8213` to
`59.768838 ms`. Fresh authenticated SSH passed from A to B through
`127.0.0.1:22024` and from A to C through `127.0.0.1:22022`. The listeners and
control API on ports `22024`, `22022`, and `32110` were all owned by A r12 PID
`12004`.

Readback after acceptance found fresh reciprocal A-edge entries in all three
live recovery cards. A stored the new B/C endpoints, B stored A at
`192.0.2.10:52507`, and C stored A at `192.0.2.10:5017`; the compact snapshot
is `.live-run/runs/mesh-selfbootstrap-20260718-r12/field-evidence/A/reciprocal-recovery-cards-post-A-r12.json`.

The independent underlay check selected the physical Ethernet interface
(`10.0.0.10` via `10.0.0.1`) for both public remote IPs. Tailscale was stopped;
a present natpierce UI process owned none of A's WinkYou UDP sockets or local
listeners. The route evidence is
`.live-run/runs/mesh-selfbootstrap-20260718-r12/field-evidence/A/underlay-route-check-post-A-r12.json`.

This completes the rolling A/B/C deployment to r12 and provides a second real
public-NAT zero-seed process-rejoin result. It does not prove simultaneous cold
start, public-IP change, operating-system boot/autostart, or hostile-peer
security. The wrapper's failure policy was r12-only fail-forward because the old
r7 seed was no longer independently reachable; no unverified downgrade was
counted as rollback. natpierce and Tailscale were not counted as a bootstrap
edge, coordinator, or product-success path.

The staging run also exposed a separate routed-TCP limitation: a single large
copy over routed SSH could reach the configured approximately 75-second frame
deadline and end with a broken pipe even while the mesh remained connected.
The approximately 10.8 MB binary was compressed to a 5.96 MB archive, split
into six chunks, transferred in separate bounded connections, reassembled
remotely, and accepted only after the whole-archive and executable SHA-256
hashes matched.
Use the same chunk-and-hash workaround until the routed stream implements a
long-transfer window or progress-aware framing; do not diagnose this timeout as
loss of the direct mesh edge.

## Prepared r9 field package and rolling procedure

The r9 candidate package is staged in
`.live-run/runs/mesh-rejoin-20260717-r1` but is not running on A, B, or C. Its
artifacts are:

- `meshnode-windows-amd64-r9.exe`, SHA-256
  `2D94E70E63033B37605672EFBABD36678EBC5EA030E5EEBC7660B007222AEF63`;
- `meshnode-linux-amd64-r9`, SHA-256
  `A10DF2F1B6844AB07C30B250D7686A1DA651E97ABD4FF0BF2F45554CDA1A1CDE`;
- `A-launcher-r9.ps1`, `B-launcher-r9.ps1`, and `C-launcher-r9.sh`;
- `AB-rolling-restart-r9.ps1` and `C-rolling-restart-r9.sh`, which validate
  the exact old PID/executable, save pre-stop evidence, launch detached, verify
  the new PID/executable, and require both local maintained edges to stay
  healthy packet one-hop routes for 40 continuous seconds.

This prepared package is a frozen predecessor of the cached self-bootstrap
slice. Its binaries and launchers do not understand `--recovery-card` or any
`--self-bootstrap-*` flag and must not be deployed with the expectation that a
fully disconnected restart will use cached endpoints.

As a time-stamped observation, at `2026-07-18 20:28 +08:00` local node A was
still PID `66860`, executable `meshnode-windows-amd64-r7.exe`, with
`started_at=2026-07-17T12:11:49.2311071Z`, approximately 24 hours 16 minutes of
uptime, direct B/C neighbors, one-hop B/C routes, an empty desired-bootstrap
map, and `infrastructure_coordinator_started=false`. This is evidence, not a
PID protection instruction. The then-current B/C executable versions were not
revalidated by that local snapshot and must not be inferred from it.

The launchers preserve the existing routed SSH target/forward declarations and
retained A-C/B-C bootstrap seeds, add the symmetric maintained-peer policy, and
set the field recovery deadlines explicitly. The two PowerShell launchers pass
parser validation. The Linux launcher is intentionally only staged locally;
run `bash -n C-launcher-r9.sh` on C after upload and before execution.

The historical r9 rollout was blocked until its bootstrap preflight passed. At
the time this package was prepared, A's then-running r7 process still had direct
one-hop A-B/A-C
routes, but neither local TCP port `22022` nor `32101` had a listener and the
live process reported an empty desired-bootstrap map. Stopping A in that state
would strand the new process outside the surviving B-C graph. Before stopping
any node:

1. restore A's public management path at `127.0.0.1:22022`, start the separate
   A-C forwarding session shown below, and verify that `127.0.0.1:32101`
   accepts a TCP connection to C's actual `10.20.0.1:32100` listener;
2. from B, verify that the natpierce management route can connect to
   `10.20.0.1:32100` without using a WinkYou route;
3. copy r9, the matching launcher, the rolling wrapper, and
   `r9-manifest.json` into the same run directory that contains the old r7/r8
   binary and stdout/stderr pair; verify every manifest hash and run PowerShell
   parse validation or `bash -n` in place;
4. verify that the old executable, launcher, PID, and management path needed for
   a one-node rollback still exist; and
5. capture a clean full-triangle status/ping/SSH baseline.

Do not treat an existing direct WinkYou route as a substitute for this check:
that route disappears when its owning process is stopped. The seed is metadata
bootstrap for rejoin; it is not a dedicated user-data relay.

Use the rollout order **A, then B, then C**, one node at a time. A owns A-B and
A-C under deterministic pair ownership, while B owns B-C. Restarting A first
leaves B-C as the surviving coordinator path. After A has restored its two
one-hop packet edges, restarting B leaves A-C; after B is accepted, restarting
C leaves A-B. Do not advance merely because `/healthz` is green. At each stage:

1. record the old PID, executable hash, `/v1/status`, and all six directed ping
   results available before the restart;
2. invoke the matching rolling wrapper with that exact PID; it stops no other
   process and does not perform broad automatic cleanup if acceptance fails;
3. verify the wrapper's evidence directory, new PID, executable hash, and
   successful 40-second local maintained-edge hold;
4. wait until both entries in `maintained_direct_peers` are `state=healthy`,
   both have `neighbor_kind=packet`, and both routes are one hop;
5. require the same new repair attempt IDs to reach `phase=stable` in the
   initiator, target, and coordinator status documents; this is mandatory while
   r9 is mixed with the older r7/r8 barrier implementation; and
6. repeat all six directed pings plus both routed SSH paths, A's
   `127.0.0.1:22024` to B and B's `127.0.0.1:22025` to C, before moving on.

The expected retained seed intent after r9 launch is `A:{C}`, `B:{C}`, and
`C:{}`. The connectors stay dormant while their targets are already reachable;
do not delete these entries merely to make the map empty. Before restarting C,
confirm the A and B status documents still contain those C seeds so at least
one connector can reattach when C's old packet edges disappear.

Run A's Windows wrapper directly from the local console:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\AB-rolling-restart-r9.ps1 -Node A -OldPid <validated-old-pid>
```

When starting B through an in-band SSH session, detach the wrapper first so the
session can return before B's old mesh process is stopped:

```powershell
$script = 'D:\workspace\winkyou\.live-run\runs\mesh-rejoin-20260717-r1\AB-rolling-restart-r9.ps1'
Start-Process powershell.exe -WindowStyle Hidden -ArgumentList @(
  '-NoProfile', '-ExecutionPolicy', 'Bypass',
  '-File', ('"{0}"' -f $script), '-Node', 'B',
  '-OldPid', '<validated-old-pid>'
)
```

Immediately before C's stage, capture fresh A and B `/v1/status` documents,
copy them to C, and keep their C seed entries intact. The C wrapper rejects
proof files older than five minutes or without the matching `node_id` and
`desired_bootstrap_peers.C`. Then verify and detach the Linux wrapper. The PID
must be discovered and validated at maintenance time, not copied from this
document:

```bash
chmod +x meshnode-linux-amd64-r9 C-launcher-r9.sh C-rolling-restart-r9.sh
bash -n C-launcher-r9.sh
bash -n C-rolling-restart-r9.sh
python3 --version
nohup ./C-rolling-restart-r9.sh <validated-old-pid> \
  ./A-pre-C-status.json ./B-pre-C-status.json \
  >C-r9-wrapper.stdout.log 2>&1 </dev/null &
```

The wrappers validate only their local node. The cross-node same-attempt and
six-ping/two-SSH stage gate above remains an operator acceptance step.

If a stage does not reach that state within 30 minutes, or the surviving route
loses data, stop only the validated r9 PID and restart that node's recorded
r7/r8 launcher. Do not restart the other two nodes during rollback. Retain the
r9 stderr log, status snapshots, attempt IDs, and coordinator choices as the
fault record. The old artifacts and launchers remain in the same run directory.
Rollback restores a connected bootstrap/degraded graph; r7/r8 cannot
automatically recreate the rolled-back node's two packet edges. Stop the rollout
there and use the historical manual edge-rotation procedure below if the full
triangle must be restored. Back up the old stdout/stderr files before launch,
because the old launchers reuse their historical filenames.

This rollout validates mesh-edge continuity, not process supervision. The r9
controller keeps desired links repaired while `meshnode` is alive and allows a
relaunched node to rejoin through retained seeds. A Windows service, systemd
unit, or another process supervisor is still required to restart `meshnode`
after an operating-system reboot or process crash.

The package was built from the current working tree on baseline commit
`add6e7737f94a2cf53ec82b24aa56bf7194a88de`, which contains uncommitted and
untracked Slice work. Preserve that tree or commit/tag the exact candidate
before treating r9 as a reproducible production release.

## Field result: dynamic C-through-B user-space service access

The code, automated tests, and r8 field run can turn an already-running node
into a TCP service publisher or consumer without adding startup flags. The
control surface is:

- `GET`, `PUT`, and `DELETE /v1/tcp/target` to inspect, publish, or clear the
  node's one local target; `PUT` accepts `{"target":"127.0.0.1:22"}`;
- `GET` and `POST /v1/tcp/forwards` to inspect or add local listeners; `POST`
  accepts `{"listen":"127.0.0.1:22025","remote_id":"C"}`;
- `DELETE /v1/tcp/forwards/{forwardID}` to remove the runtime listener whose ID
  was returned by `POST`.

This runtime mutation surface is version-specific. At the time of the dynamic
r8 field operation below, A was still r7 (PID `66860`) and did not implement
runtime `POST /v1/tcp/forwards`; the successful dynamic operation was performed
on the then-r8 B and C processes. A's later r12 migration is documented above
and must not be retroactively attributed to this historical check.

The r8 field run used the following C-through-B sequence after both nodes
reported a one-hop route to one another.

On C, publish C's local SSH service:

```bash
curl -sS -X PUT http://127.0.0.1:32110/v1/tcp/target \
  -H 'Content-Type: application/json' \
  --data '{"target":"127.0.0.1:22"}'
```

On B, create a loopback listener whose mesh destination is C, then connect to
that listener as an ordinary SSH client:

```powershell
$forward = Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:32110/v1/tcp/forwards `
  -ContentType application/json `
  -Body '{"listen":"127.0.0.1:22025","remote_id":"C"}'

ssh -p 22025 node-c-user@127.0.0.1
```

The returned `$forward.id` is the runtime-owned listener ID. It can be removed
on B with:

```powershell
Invoke-RestMethod -Method Delete `
  -Uri "http://127.0.0.1:32110/v1/tcp/forwards/$($forward.id)"
```

C's `PUT` returned target `127.0.0.1:22` with `source=runtime`. B's `POST`
returned `id=runtime-001`, `source=runtime`, listener
`127.0.0.1:22025`, and `remote_id=C`. A B-to-C control ping immediately before
the SSH checks reported path `[B,C]` and RTT `60.3956 ms`.

Those two objects were `source=runtime` during the r8 API experiment.
Equivalent restart intent was then placed in the launchers. The later B/C r12
migrations recreated B's `127.0.0.1:22025=C` listener and C's
`127.0.0.1:22` target as `source=config`; their status documents confirm that
process-restart behavior. This is still not system-service or operating-system
boot/autostart acceptance.

The first ordinary SSH connection observed the ED25519 host-key fingerprint
`SHA256:VxRev6xvoIVmmWG575EkdW7ZuuWkXSlzVsWcZb/wf8c`, completed real
authentication, and returned:

```text
HOST=node-c-host
USER=node-c-user
```

Five consecutive fresh authenticated connections succeeded in
`2.673-2.883 s`. The user-facing command on B is therefore:

```powershell
ssh -p 22025 node-c-user@127.0.0.1
```

### r8 topology used by the service proof

C's r8 process started at `2026-07-17T16:01:32Z`, and B's r8 process started at
`2026-07-17T16:11:08Z`. The connectivity-preserving reconstruction produced:

| Edge | Final stable attempt and roles |
| --- | --- |
| A-C | `C-1784304214615426875-1`; C initiator, A target, ordinary peer B attempt-scoped coordinator |
| A-B | `A-1784305030263693600-3`; A initiator, B target, ordinary peer C attempt-scoped coordinator |
| B-C | `B-1784305929059776800-3`; B initiator, C target, ordinary peer A attempt-scoped coordinator |

B's first B-to-A punch failed; reversing the roles and initiating from A
created the stable A-B attempt above. The first B-C reconstruction then left
the endpoints with split shortcut state. The inconsistent edge was explicitly
removed and the attempt retried, after which the final B-C attempt became
stable on all three nodes. The final topology had three stable direct edges,
one-hop routes for every pair, and empty desired-bootstrap maps.

The successful retry does not erase the split-state defect. Post-field source
code now performs bounded coordinator COMMIT reconciliation, makes a stable
endpoint re-report STABLE after a duplicate COMMIT, and prevents late barrier
messages or the probation timer from reviving Failed. Packet-neighbor tests
silently drop the first COMMIT and the first STABLE and still require all three
roles to converge. The r8 binaries used in this historical service proof
predated that patch. B/C already included it at the C acceptance checkpoint,
and the subsequent A migration completed its deployment on all three r12
nodes. A strict protocol-level FINALIZE/ACK remains later work if endpoint
`stable` must mean that the coordinator has durably recorded global completion.

Runtime mutation deliberately has narrow lifecycle and exposure rules:

- API-created targets and listeners live only in the current `meshnode` process
  and are not automatically persisted. Without equivalent startup flags they
  disappear on restart; with such flags, startup recreates them as
  `source=config` rather than preserving the old runtime object;
- API calls cannot replace, clear, or delete entries whose `source` is
  `config` (setting the configured target to the same value is idempotent);
- both published targets and local listeners must be loopback TCP addresses;
- each node may have at most 64 active `runtime` listeners, in addition to its
  configured listeners.

The HTTP requests only alter local runtime state. User bytes still use the
existing routed TCP endpoint and the current mesh route to `remote_id`; when
B-C is the selected direct neighbor, the flow uses that edge. The existing
fixed-target `OPEN/OPEN_OK/DATA/FIN/RESET/ACK` protocol is unchanged: no target
host or port was added to an `OPEN` frame, and the control API never relays user
data.

## Field process layout

```text
A control:           127.0.0.1:32110
A -> C bootstrap:    127.0.0.1:32101 (SSH -L through port 22022)
A -> B routed SSH:   127.0.0.1:22024 (owned by meshnode)

C mesh listener:     10.20.0.1:32100
C control:           127.0.0.1:32110

B mesh listener:     off (outbound bootstrap only)
B control:           127.0.0.1:32110
B fixed TCP target:  127.0.0.1:22
```

Create a second A-C SSH stream without touching the existing interactive
session:

```powershell
ssh -o ProxyJump=none -p 22022 -N `
  -L 127.0.0.1:32101:10.20.0.1:32100 `
  node-c-user@127.0.0.1
```

A starts with `--peer C=127.0.0.1:32101`. In the historical r4-r8 experiment B
started with `--peer C=10.20.0.1:32100`; that desired peer was removed after A-B
became stable. r9 deliberately retains both configured seeds and must not use
that removal step. For the routed-management extension, A also starts with
`--tcp-forward 127.0.0.1:22024=B`, and B starts with
`--tcp-target 127.0.0.1:22`.

## Historical r4-r8 manual control sequence

This section records how the original triangle was constructed before the r9
controller existed. Do not execute its desired-peer deletion as part of the r9
rollout.

After all three status documents show `A-C-B` and `B-C-A` routes:

1. On A, start `target_id=B`, `coordinator_id=C`, and wait for `stable`.
2. Confirm A and B report a direct one-hop route and a public `remote_addr`;
   C must report forwarded solver signals.
3. On B, delete desired bootstrap peer C. Confirm B-C is no longer a direct
   neighbor but routes as `B-A-C` / `C-A-B`.
4. On C, start `target_id=B`, `coordinator_id=A`, and wait for `stable`.
5. Confirm every node has two neighbors and all pairwise routes are one hop.
6. In a controlled window, stop or disable B's natpierce underlay and repeat
   status/control pings. Do not count an adapter-enable task as recovery: in
   this run it did not reconnect the natpierce application session. The user
   restored that session manually.
7. Expose B's loopback SSH target through the A listener, then connect with
   `ssh -o ProxyJump=none -p 22024 node-b-user@127.0.0.1`. Do not configure a
   `ProxyCommand`; compare A and C data counters to prove C is not the data
   path.

Example shortcut request:

```powershell
$body = @{
  target_id = 'B'
  coordinator_id = 'C'
  wait = $true
  timeout = '180s'
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:32110/v1/shortcuts `
  -ContentType application/json `
  -Body $body `
  -TimeoutSec 190
```

## Field result: successful three-edge rotation

The public-NAT run completed on 2026-07-17 with `meshnode` r4. No
central/infrastructure coordinator, dedicated infrastructure user-data relay,
Tailscale, WireGuard, or Wintun path was started by these runtimes. The
coordinators named below were attempt-scoped ordinary peers. Every `/v1/status`
document reported `infrastructure_coordinator_started=false`.

| State | Direct neighbors / route evidence | Result |
| --- | --- | --- |
| G0 | A-C and temporary C-B; A-B path `[A,C,B]` | baseline ping succeeded |
| G1 | A-B promoted by attempt-scoped ordinary-peer coordinator C | `stable`, `[A,B]` |
| G2 | temporary B-C removed; B-C path `[B,A,C]` | routed ping succeeded in both directions |
| G3 | B-C promoted by attempt-scoped ordinary-peer coordinator A | A, B, and C each have two neighbors; every route is one hop |

Protected-direct evidence:

- A-B attempt `A-1784279842010855600-1` became `stable`. A selected
  `203.0.113.30:53841`; B selected `192.0.2.10:52283`.
- C-B attempt `C-1784280354536934055-1` became `stable`. C selected
  `203.0.113.30:56457`; B selected `198.51.100.20:15565`.
- Both attempts reported `path_role=protected_direct`, no explicit
  dependencies, and `path_id=birthdaypunch/direct`.
- Final one-hop control RTTs were approximately 37-39 ms for A-B, 37-38 ms
  for A-C, and 60-61 ms for B-C.

The temporary B-C desired peer was removed from B before the second shortcut.
B then reported `desired_bootstrap_peers={}`, neighbor A only, and route
`[B,A,C]`; the control request and reply paths were `[B,A,C]` and `[C,A,B]`.
After the second shortcut, B reported neighbors A and C and direct routes
`[B,A]` and `[B,C]`.

The bootstrap-removal check disabled B's `natpierce` adapter. C could no
longer ping `10.20.0.4`, including a delayed check more than two minutes after
disable, while WinkYou still returned one-hop A-B and C-B pings. The delayed
samples were about 37.8 ms and 60.8 ms respectively. One A-B control ping at
the instant of adapter transition timed out; the next five all succeeded and
the direct neighbor never withdrew. A later sample still succeeded at about
39.3 ms while C-B remained about 60.8 ms.

Re-enabling the Windows virtual adapter did not by itself restore the
natpierce application session. The scheduled disable/enable actions returned
success, but the application remained disconnected; the user manually clicked
reconnect. Therefore this run is **not** evidence that a watchdog recovered
natpierce. This did not affect either WinkYou direct edge, and it demonstrates
that a future recovery action must invoke and verify the application's real
reconnect operation rather than only calling `Enable-NetAdapter`.

The r4 artifacts used for the successful run were:

- Windows amd64 SHA-256:
  `69ABE983619914B1BFA65B48EA38A97557FC6F51246F12691FD1025856EBC585`;
- Linux amd64 SHA-256:
  `AF7C12E72DF65C0E0EED32F195C7F5EC880B2078DF64A2604D8DE56AA18D6959`.

## Field result: routed SSH over the A-B direct edge

The r4 run proved graph control and continued direct-edge operation after the
natpierce bootstrap was disabled, but it did not expose an ordinary operating-
system service over that edge. `meshnode` r5 added a
fixed-target routed TCP endpoint: A listened on `127.0.0.1:22024`, and B alone
was configured to dial `127.0.0.1:22`. An OPEN frame carries only a node ID and
flow ID; it cannot select an arbitrary host or port on B.

After ordinary peer C coordinated the scoped attempt for a fresh A-B
public-direct edge, this command reached B without a jump host or
`ProxyCommand`:

```powershell
ssh -o ProxyJump=none -o BatchMode=yes `
  -p 22024 node-b-user@127.0.0.1 hostname
```

It returned `node-b-host`. During the first direct-SSH checks, A's routed
data counter increased from 0 to 26 while C's counter remained 0. The same
direct session queried B's loopback control API and deleted B's temporary C
bootstrap peer. B then reported neighbor A only and route `[B,A,C]`. The two
one-shot adapter tasks were already absent; they had been removed after the
user's manual natpierce reconnect, not by a successful recovery watchdog.

The first 30-connection field sample exposed an important r5 defect: 29 SSH
connections succeeded, but one lost its SSH banner and timed out after eight
seconds. The public A-B edge itself remained stable. Its UDP packet-neighbor
transport is datagram-oriented, while the first TCP-flow protocol assumed
lossless ordered frame delivery.

r6 added per-flow stop-and-wait reliability. Every
`OPEN/OPEN_OK/DATA/FIN/RESET` frame now requires a compact ACK; an unacknowledged
frame is retransmitted every 250 ms for a bounded five-second window. A
duplicate is ACKed again without being delivered twice, and a future sequence
is not ACKed. The integration test deliberately drops the first OPEN, data in
both directions, FIN, and three consecutive ACKs; the byte-exact half-closed
TCP exchange still succeeds.

The r6 public field sample completed 30/30 fresh SSH connections. Durations
were 648-980 ms (713.7 ms average). A processed 783 routed data frames during
the sample, while C again processed zero. A direct SSH session then performed
the cleanup again, removed B's desired C bootstrap, observed `[B,A,C]`, and
started the replacement B-C shortcut. Attempt
`B-1784283574575610600-1`, coordinated by A, became `stable`; the final r6
topology again had two one-hop neighbors on every node.

The final r6 direct endpoints were:

- A-B attempt `A-1784283430187040400-1`: A selected
  `203.0.113.30:60275`; B selected `192.0.2.10:15212`;
- B-C attempt `B-1784283574575610600-1`: B selected
  `198.51.100.20:23450`; C selected `203.0.113.30:61208`.

Both attempts reported `stable`, `protected_direct`, and
`birthdaypunch/direct`. No central/infrastructure coordinator, dedicated
infrastructure user-data relay, Tailscale, WireGuard, Wintun, or C-routed
user-data path participated in these SSH flows. C and A were ordinary trusted
peers acting as attempt-scoped coordinators for their respective punches.
The adapter-off test was not repeated after r6 because it would discard the
natpierce session the user had manually restored; the earlier r4 adapter-off
run separately proves only that the already-established A-B and B-C direct
packet neighbors remained usable after the natpierce bootstrap was disabled.
It is not a general claim that those edges survive arbitrary underlay loss.

The r6 artifacts used for the routed-management run were:

- Windows amd64 SHA-256:
  `E6F2D5B1509E6B4CF5DE0FF4F03B50B6712EA570E9320802A23183EF25A57A6B`;
- Linux amd64 SHA-256:
  `93E73C54AEAA5DAC556CCD842F9AF70B0B9B3F0CCA3C6F690FE1D50F1D7A0CAC`.

## Field result: full direct triangle and r7 link-hold run

The next r6 rotation removed A's remaining desired C bootstrap and created the
third public-direct edge. A's first attempt to initiate A-C through coordinator
B timed out, but the reverse role succeeded: C initiated, A was the target,
and B forwarded only the attempt-scoped solver messages. The resulting r6
triangle had three `protected_direct` `birthdaypunch/direct` packet neighbors,
empty `desired_bootstrap_peers` on A, B, and C, and one-hop routes for all
three pairs. The retained rescue SSH/punchbridge path was management-only; it
was neither a mesh neighbor nor a WinkYou data path.

That initially stable triangle also exposed why a long observation run is
necessary. The last known-good six-direction ping round was at approximately
19:49 local time. At `2026-07-17T11:51:27.443Z`, A-C withdrew with a packet-
neighbor liveness timeout; A-B withdrew at `11:51:27.719Z`, only 276 ms later.
B-C survived and all three `meshnode` processes retained their original
`started_at` values. The evidence does not identify the transient's root cause,
but it does establish that the old five-second peer timeout was too brittle for
this field environment. A-C and A-B are distinct edges but share endpoint A;
they are not independent failure domains.

r7 changes the default packet-neighbor policy to a one-second keepalive, a
30-second peer timeout, and a 35-second probation. The field launchers also make
the 35-second probation explicit so a shortcut cannot become stable before a
complete liveness window has elapsed. This favors continuity through short
stalls, with two deliberate limitations: a genuinely failed edge may blackhole
traffic for up to about 30 seconds before withdrawal, and this change alone
does not repunch or recover a hard-closed direct socket.

The deployed r7 artifacts are:

- Windows amd64 SHA-256:
  `887290E6D61A0F774A59D86B1423C10623F018FC2BD97DEE04AC174744C06006`;
- Linux amd64 SHA-256:
  `399746D0D429AC693457D33E9A74F4DC90520909B93FE902E68054910131FD86`.

The pre-power-loss r7 process identities used as the original soak manifest are A
`2026-07-17T12:11:49.2311071Z`, B `2026-07-17T12:14:28.76403Z`, and C
`2026-07-17T12:09:15.140081064Z`. The original pre-power-loss direct attempts
were:

| Edge | Attempt and roles | Endpoint selected at each end |
| --- | --- | --- |
| A-B | `A-1784290543788179400-1`; A initiator, B target, ordinary peer C the attempt-scoped coordinator | A sees `203.0.113.30:61615`; B sees `192.0.2.10:43040` |
| B-C | `B-1784290678320154600-1`; B initiator, C target, ordinary peer A the attempt-scoped coordinator | B sees `198.51.100.20:49274`; C sees `203.0.113.30:57643` |
| A-C | `C-1784290922333431348-2`; C initiator, A target, ordinary peer B the attempt-scoped coordinator | C sees `192.0.2.10:21633`; A sees `198.51.100.20:32193` |

One earlier C-A retry failed with a remote-endpoint timeout; the next attempt
listed above became stable. At soak start, every node reported the other two
as packet neighbors, every pairwise route was one hop, and every desired-peer
map was empty.

`scripts/monitor-three-node-soak.ps1` is deliberately observation-only. By
default it samples all three status documents every 10 seconds, runs the six
directed control pings sequentially every 30 seconds, and opens a fresh A-to-B
routed SSH connection every 60 seconds. Its manifest pins the three attempt
IDs and three `started_at` values above. It never calls peer, neighbor, or
shortcut mutation endpoints and never reconnects, restarts, or repunches after
a failure. A 50-second smoke run passed before the formal run.

The planned two-hour observation began at `2026-07-17 20:28:42 +08:00` in
`.live-run/runs/three-node-soak-r7-20260717-202841` under monitor PID 65824;
its scheduled end was `22:28:42 +08:00`. The initial post-launch check contained
eight clean status samples, three clean six-direction ping rounds, and two
clean SSH probes. C then lost power, and the monitor was stopped at approximately
`21:39 +08:00` after C restarted and its two incident edges were manually
rebuilt. The pinned C process identity and A-C/B-C attempt IDs had necessarily
changed, so this is an interrupted incident record, not a completed clean
two-hour result.

The interrupted run is not eligible for a zero-failure verdict. The direct triangle
remained continuous through the first stall described below, before the later
C power-loss event. At `20:35:03-20:35:19 +08:00`, A's
local control API stayed responsive while both the routed B management path
and the C rescue management path failed twice. A's log has a
16.819-second gap in control traffic received from B and C, while the B and C
logs have no matching liveness gap. No Windows adapter-down event was recorded,
so the evidence is consistent with a short A-side public-network or upstream
stall, but it does not identify the exact underlay component.

r7's observed behavior during that stall is consistent with the configured
30-second liveness hysteresis: all three process `started_at` values,
packet-neighbor sets, one-hop routes, and shortcut attempt IDs remained
unchanged, and no desired bootstrap peer reappeared. Neither A edge was
withdrawn. The available logs do not directly record the relevant `lastRx`
value or individual keepalive delivery, so they do not prove that the 30-second
setting caused this outcome. The run then recorded one `POST /v1/ping` HTTP 409
timeout in each of three consecutive rounds: A-to-B, B-to-C, and C-to-B. Each
was a single-direction failure and the
other five directions in that round succeeded; every failed direction
succeeded again in its next round. A second isolated C-to-B timeout was recorded
at `20:45:51 +08:00` and was followed by success in the next round. HTTP 409
here means that a one-shot best-effort echo transaction did not complete before
its deadline. It does not, by itself, prove which individual request/reply
packet was lost, and it is not evidence that the neighbor or route was removed.
The routed TCP protocol does use ACK/retransmission, and the periodic A-to-B
SSH probe remained successful through this observation window. The failures
occurred about two minutes after the separate background smoke test ended, so
their timestamps do not overlap that extra load.

At approximately `21:03:24 +08:00`, C then became unreachable through both
direct edges and through the retained rescue management path. The user
confirmed that C had lost power. B
closed B-C at `21:03:54.364 +08:00` and A closed A-C at
`21:03:56.988 +08:00`, each with `mesh: packet neighbor liveness timeout` after
the configured 30-second receive-silence window. A-B remained a working direct
edge and neither A nor B restarted. The local punchbridge process and its
loopback listener also remained alive, but new C SSH sessions timed out during
banner exchange because the remote endpoint on C was no longer running. The two
WinkYou edges and that management session all shared C's host lifecycle; they
are not three independent failure domains. Loss of the old remote punchbridge
session when C's host/process powers off is an expected session-lifetime
boundary, even though the local punchbridge process survives.

This later event crossed the r7 tolerance boundary. The monitor did not repair
or repunch anything: it recorded A and B converging to the surviving A-B graph,
while C was fully isolated. With no remaining graph path to C, A or B cannot
deliver fresh solver metadata to it. If C's underlay returns after both packet
neighbors have hard-closed, the deployed r7 implementation has no automatic
metadata bootstrap or repunch path to reattach it. The later post-r9 recovery-
card source is intended to try retained endpoints in this state, but it has not
been applied retroactively to this incident or validated on the field NATs.

After C restarted, it was reachable for management through B's natpierce leg.
C's new `started_at` is `2026-07-17T13:24:21.007985278Z`. The triangle was then
manually reconstructed in connectivity-preserving order:

| Edge | Post-restart attempt and roles |
| --- | --- |
| A-B | Existing `A-1784290543788179400-1` remained established across C's outage; its original coordinator role was attempt-scoped and was not needed to keep the edge alive |
| A-C | `A-1784294971670842100-2`; A initiator, C target, ordinary peer B the attempt-scoped coordinator |
| B-C | `B-1784295097111354200-3`; B initiator, C target, ordinary peer A the attempt-scoped coordinator |

The post-restart baseline check found empty desired-peer maps on all three
nodes, all three pairwise routes one hop, successful pings in all six directed
pairs, and a successful fresh A-to-B routed SSH probe. C status/probe collection
was switched to the management route through B and the B-C natpierce leg. That
management-only access is how the experiment observes C; it is not counted as
a WinkYou data-plane edge or as evidence for A-C/B-C directness. This restored
baseline became the manifest for the replacement observation run.

### Completed two-hour post-rejoin soak

The replacement observation in
`.live-run/runs/three-node-soak-r7-rejoin-20260717-214434` ran from
`2026-07-17T13:44:36.5396924Z` through
`2026-07-17T15:44:36.5521555Z`. It ended with
`completion_reason=duration_completed` after `7200.012 s`; the monitor remained
observation-only and recorded zero continuity changes.

| Dimension | Result |
| --- | --- |
| Topology/process continuity | **pass**; every successful status document showed the complete direct triangle, all pinned processes/attempts remained unchanged, and continuity changes were `0` |
| Routed SSH | **pass**, `120/120` fresh A-to-B probes |
| Schedule | **pass**, `0` missed status, ping, or SSH slots |
| Best-effort control ping | `954/960`; A-to-B had 1 transient HTTP 409/timeout and B-to-C had 5, each with maximum streak 1 and success in the next scheduled round; the other four directions were `160/160` |
| Management status | `1438/1440`; both gaps were C SSH banner timeouts, each followed by success in the next scheduled sample |

This is a completed two-hour topology/process and reliable-routed-SSH hold, not
a zero-loss result. The overall summary remains
`verdict=observed_failures_or_changes` and `clean_soak=false` because the
best-effort ping and management zero-failure criteria were not met. The two
failed C management samples are observation gaps, not inferred topology
changes; the final synchronized status sample again showed the complete direct
triangle.

## Field-discovered fixes and remaining work

The topology run found and fixed five real-network defects before G3
succeeded:

1. endpoint exchange now waits 60 seconds so asymmetric STUN probe duration
   does not cause an early remote-endpoint timeout;
2. a birthday spray with no fixed target list is accepted when `BirthdayN` is
   configured;
3. a port-preserving endpoint re-binds its advertised STUN port for punching;
4. a directly addressed/no-NAT endpoint is treated as port-preserving even
   when only one allocation sample succeeds;
5. every STUN transaction is capped at three seconds even when the enclosing
   solve context has a much longer deadline.

The routed-management extensions then added and validated three more pieces:

6. `meshnode` can expose a locally fixed TCP target and a loopback-only
   listener over the routed data plane, so a direct edge is usable by an
   ordinary application without Wintun;
7. TCP-flow frames now have ACK, retransmission, and duplicate suppression, so
   an unreliable UDP packet neighbor does not turn one lost datagram into a
   failed SSH connection;
8. the r8 runtime target/listener API exposed C's SSH through B and completed
   five fresh authenticated connections without startup TCP flags;
9. shortcut barrier delivery now reconciles a silently lost COMMIT or STABLE,
   and terminal Failed state is protected from late-message/timer revival;
10. r12 quarantines a candidate packet edge from link-state advertisement until
    its exact attachment handle passes promotion; and
11. r12 uses high restart generations for control sequences and topology
    revisions so a fresh process is not hidden behind its predecessor's cache.

Four operational follow-ups remain after the completed rolling r12 rollout:

- the maintained-edge controller and `--maintain-peer` policy completed one
  real C-A reconstruction through ordinary peer B and one A-B reconstruction
  through ordinary peer C, but the full public-NAT failure matrix remains open;
- the recovery-card engine completed real C and A public-NAT executable rejoins,
  but still needs a B zero-seed case, simultaneous-restart coverage, real
  public-IP change tests, and operating-system boot/autostart supervision;
- the historical lab's natpierce management underlay needed its application
  reconnect command, not only virtual-adapter enablement; the 2026-07-17
  restoration was manual, and future WinkYou acceptance must not count this
  out-of-band path as product recovery;
- the COMMIT/STABLE reconciliation and topology gate are deployed on all three
  r12 nodes; strict global completion semantics would additionally require a
  FINALIZE/ACK phase. The first r8 B-C reconstruction remains the regression
  case because it split endpoint state and required explicit teardown before
  retry.

The r12 field runs exercised both recovery layers in sequence twice: cached
bilateral self-bootstrap restored C-B before B coordinated C-A, and later
restored A-C before C coordinated A-B. Cached bootstrap still cannot receive
fresh metadata over a lost graph. If all retained destinations become stale
together, recovery requires LAN/IPv6/static discovery, a reachable peer, or an
external metadata directory. Neither mechanism requires a dedicated
infrastructure user-data relay. This does not prohibit an ordinary trusted mesh
peer from forwarding user packets as normal transit or an exit node under
virtual-LAN routing policy; coordination and packet forwarding remain separate
roles.

The dynamic API is the first phase of driver-free, user-space mesh service
access. It remains a fixed-target TCP facade, not transparent L3 ingress for
arbitrary applications and not an exit-node implementation. The next
user-space increment is a target-aware stream protocol plus a SOCKS and/or
`127/8` facade. Full arbitrary TCP, UDP, and ICMP participation still requires
system packet ingress/egress such as TUN, WFP, or a WinkYou-owned driver.

Slice 4.5 has since extracted this runtime to `pkg/meshruntime` and connected it
to `wink up/down/status/peers` behind default-off typed `autonomous_mesh`
configuration. Its later C -> B -> A guarded rollout replaced all three field
processes; that is a separate successor acceptance recorded in
`SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md`, not a retroactive rerun of this
historical experiment and not OS-autostart evidence. The system packet backend
remains Slice 5 work.

## Acceptance evidence

Capture before removing any underlay:

- `/v1/status` from A, B, and C at G0, G1, G2, and G3;
- control-ping request and reply paths at every state;
- each shortcut's `phase=stable`, `path_role=protected_direct`, empty
  dependencies, and public `remote_addr`;
- coordinator `solver_signals_forwarded` increasing during its attempt;
- final UDP sockets owned by `meshnode`, not natpierce or Tailscale;
- successful probes after natpierce is stopped.

For routed TCP management, also capture:

- the A listener and B fixed target in `/v1/status`;
- a direct `ssh -p 22024` result with no `ProxyCommand`;
- A's data counter increasing while C's remains unchanged;
- a repeated-connection sample, including loss/retransmission results;
- the cleanup command executed through that direct SSH session.

The C r12 run supplies the first recorded public-NAT process-restart evidence
against the checklist below, and the later A r12 run supplies the second. They
do not satisfy every bilateral observability item, so retain the complete
checklist for subsequent pairs and failure-matrix runs:

- the pre-restart recovery-card hash and a parsed peer/local-bind summary on
  both endpoints, without copying the shared secret into evidence;
- absence of `--peer`, natpierce, Tailscale, coordinator, TURN, or another graph
  route from the pair's bootstrap/data path; separately label any management
  path that remains available for staging or rollback;
- overlapping `scheduled`/`punching` and authenticated `peer_hello` events on
  both endpoints, followed by the same learned UDP pair;
- a new process `started_at`, packet-neighbor attachment, one-hop route, and a
  hold longer than the peer liveness timeout;
- a post-success card update containing the learned endpoint; and
- in a three-node run, the distinction between the first self-bootstrapped edge
  and later r9 peer-coordinated direct-edge completion.

For C, the evidence records the seed-card hash and local UDP bind, zero peer
arguments and `mesh-listen=off`, fresh `punching`/`peer_hello`/`attached`
events, the new PID/start time, C-B one-hop packet attachment, post-success card
update, and later C-A peer-coordinated completion. The B-side private seed and
natpierce/SSH management path are separately identified as rollback/staging
inputs and are not counted as r12 product recovery.

For A, the evidence records the seed-card hash, zero peer arguments and
`mesh-listen=off`, r12 PID `12004` and start time, fresh A-C self-bootstrap,
post-success card state, C-coordinated A-B completion, the 45-second hold, all
six one-hop pings, and authenticated SSH through both A-owned routed listeners.
natpierce and Tailscale are explicitly excluded from product success.

The completed dynamic C-service-through-B field check captured C's
`source=runtime` target, B's `runtime-001` listener, route `[B,C]`, the SSH host
key/authenticated identity, and five successful `ssh -p 22025` connections.
This proves a runtime-configured user-space TCP service path. It does not turn
the current fixed-target protocol into transparent L3.

For the historical r7 observation-only link-hold run, the monitor pinned process
`started_at` values and exact shortcut attempt IDs, required desired-peer maps
to stay empty, and failed on any non-one-hop route. Those assertions are not an
r9 monitor specification: r9 intentionally expects `A:{C}`, `B:{C}`, `C:{}` and
must record automatic repair rather than treating it as contamination.

PID 73724 was the historical `punchbridge-windows-v2.exe` PID before C's power
cycle; it is no longer a live protection instruction. Never protect or stop a
process by stale PID alone. Revalidate executable path, hash, process start time,
and listening endpoint immediately before a maintenance action. The rescue
transport is not a mesh neighbor or data-plane edge.
