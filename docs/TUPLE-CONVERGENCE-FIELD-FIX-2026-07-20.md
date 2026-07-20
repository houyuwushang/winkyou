# Tuple Convergence Fix and Three-Node Field Rollout (2026-07-20)

Status: accepted in the A/B/C trusted-node field cohort. The defect was not an
operating-system permission failure.

## Symptom and root cause

The 12-hour soak completed with the final direct triangle alive and without
process restarts, but it contained intermittent failures: 246/4320 status
probes, 709/4320 ping probes, and 96/720 A-to-B SSH probes failed. Direct-edge
failures were dominated by packet-neighbor liveness timeouts.

The puncher previously let every local UDP socket report its first valid probe
ACK independently. A could therefore retain A0-to-B0 while B retained B1-to-A1.
The three-second grace period did not exchange or commit a shared winner; it
only delayed closing loser sockets. Each side could consequently close the
socket selected by its peer and fail about one liveness timeout later.

The large historical data-dropped value was not tens of thousands of lost user
packets. Most increments were repeated StreamOpen attempts while no route
existed. Ordinary loopback forwards retried the same OPEN every 250 ms for up
to 75 seconds.

## Code change

The fixed WPK1 envelope remains 21 bytes and retains PROBE and PROBE_ACK.
Coordinated production paths now add:

- explicit selector and receiver roles;
- SELECT, SELECT_ACK, DONE, and DONE_ACK messages;
- a random selection token bound to the exact local socket and remote tuple;
- atomic receiver-side adoption of one tuple across all candidate sockets; and
- retransmission and duplicate handling through the committed terminal state.

The selector cancels and joins ordinary probe senders before handing the socket
to the data plane. Readers remain active through the grace interval so
in-flight WPK1 frames are consumed and duplicate control messages can still be
acknowledged. This prevents punch-control frames leaking into the data plane.

Role assignment is deterministic: a birthday-punch initiator is the selector,
the target is the receiver, and self-bootstrap uses lexical node-ID ordering.
The zero-value API role retains explicit legacy behavior for source
compatibility. New endpoints do not silently fall back when paired with an old
endpoint, because fallback would reintroduce the crossed-winner defect. Field
deployment therefore used one guarded protocol cohort.

Ordinary TCP facades now consult the current graph route before sending
StreamOpen. A valid multi-hop route remains accepted; no-route connections
close before emitting StreamOpen. The soak monitor separately records known
Win32-OpenSSH close warnings and only treats complete-output forced termination
as a transport-close anomaly.

## Source validation

The final source tree passed:

    go test -p 1 ./... -count=1
    go vet ./...
    git diff --check

Changed packages also passed normal and race-enabled targeted tests. The full
coordinated Punch pair, crossed-winner, wrong-tuple/token, retransmission, and
context/terminal-race cases passed under the race detector. The full Punch pair
was additionally repeated 100 times without failure.

## Guarded field rollout

The successful attempt ID was field2-20260720t0338z. Each wrapper froze the old
PID, OS process-start identity, runtime instance ID, old/new executable hashes,
and config hash, and held an exclusive upgrade lock. A candidate could commit
only after:

1. PID, executable, process-start ID, instance ID, and runtime started-at
   remained exact;
2. both protected-direct packet edges and both one-hop routes remained healthy
   continuously for at least 120 seconds;
3. the same attempt-specific authorization was staged on all nodes; and
4. all nodes reached the common decision epoch.

Missing authorization, an identity change, a lost direct edge, or an operator
rollback marker would have restored the retained r13 cohort.

| Node | New PID | New runtime started at (UTC) | Result |
| --- | ---: | --- | --- |
| C | 18069 | 2026-07-20T03:42:13.487747096Z | success |
| B | 19076 | 2026-07-20T03:47:15.9701579Z | success |
| A | 84400 | 2026-07-20T03:47:20.6949262Z | success |

All three committed at approximately 2026-07-20T04:07:13Z. Windows used
SHA-256 564E9D4001576D59339A2A3AB949D0F188E06BFC92EB910DABA4605400AE99BA;
Linux used
3133B41FFAA8593260E169D243C41644A17DF17B576ECA9EEDDA4CFDE472B1F0.

The first wrapper attempt failed closed before mutation because generic
historical result names collided with the new run. Operational state was then
made attempt-specific. A separate C cancellation test armed a future switch,
received a rollback marker, wrote failed-before-mutation, and left the exact old
PID running. B used a verified SYSTEM Scheduled Task; its final task result was
zero and the temporary task was removed after commit.

## Data-plane acceptance

Final readback on every node showed exactly two packet neighbors, exactly two
one-hop routes, both maintained peers healthy and protected-direct, failure
count zero, and infrastructure-coordinator-started false.

All six POST /v1/ping directions returned exact two-node request and reply
paths. RTTs were approximately 36-60 ms. The six directions were repeated after
the common commit and again passed one hop.

Fresh SSH validation passed:

- A to B through 127.0.0.1:22024, three times;
- A to C through 127.0.0.1:22022, three times;
- B to C through B's 127.0.0.1:22025, three times; and
- A's virtual facades fd00::b port 22 and fd00::c port 22.

The Win32-OpenSSH close warning remained visible on successful probes, but all
commands exited zero with complete output. It was not counted as link failure.

During the mixed-version C-first window, natpierce was used only as an
out-of-band management route from B to C to verify C's new PID. It was not an
acceptance data path. After convergence, A's two Wink UDP sockets were owned by
PID 84400; the B and C public endpoints both selected physical Ethernet, source
10.3.9.11, and gateway 10.3.9.1. Tailscale and natpierce processes remained
present, but neither was the selected route for those Wink edges.

## Remaining boundary

This result field-validates deterministic tuple convergence and a roughly
20-minute post-convergence guarded hold. It does not yet prove machine reboot,
simultaneous three-node cold start, recovery after public-IP changes,
weeks-long retention, transparent system L3, arbitrary ports, subnet routing,
exit-node semantics, or mixed-version capability negotiation.

The product triangle remains coordinator-free after establishment. Ordinary
peers may perform attempt-scoped coordination, but no infrastructure
coordinator or user-data relay is running.
