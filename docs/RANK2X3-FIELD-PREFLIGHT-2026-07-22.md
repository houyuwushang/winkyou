# Rank-2 x Rank-3 field preflight (2026-07-22)

> **SUPERSEDED / PAUSED:** later on 2026-07-22, the managed A build generated
> a severe UDP tuple/session storm during cached self-bootstrap. The earlier
> isolated A-B gate below remains historical connectivity evidence, but is not
> authorization to continue the transaction or restart any managed node. The
> autonomous birthday-recovery work is paused for the short term. See
> [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md).

Status: **NO-GO for the full rank-2 x rank-3 transaction, but the isolated A-B
physical-underlay gate has passed**. The existing A-B-C mesh remains online and
B is manageable through WinkYou without natpierce. The persistent-task
lifecycle and explicit-underlay defects found during preflight are implemented
and covered by local/static tests. A fresh v2 transaction still has to freeze
the resulting cards, task identities, configs, and package before GO.
Separately, B's current normal public path is carried by an OpenVPN TAP adapter;
that production edge therefore cannot satisfy the final no-external-overlay
claim even though the isolated physical-underlay punch below does.

This note records a preflight result, not a completed rank-2 x rank-3 field
acceptance and not authorization to run the frozen 2026-07-20 transaction.

## Live topology established without natpierce

At preflight, A, B, and C each reported the other two nodes as one-hop packet
neighbors. The maintained edges were `protected_direct`, reachable, and had no
WinkYou infrastructure coordinator. A continued to expose B's SSH service at
`127.0.0.1:22024` and C's at `127.0.0.1:22022`.

On B, the natpierce process, adapter address `10.6.22.4`, and natpierce routes
were absent while a fresh SSH session through `127.0.0.1:22024` still worked.
The temporary collection task was also removed. Thus natpierce is no longer
needed for ordinary B administration in this live state.

B's persistent task is `WinkYou-Mesh-Rejoin-B-20260721-r2`. A controlled child
restart produced an A-observed withdrawal at `2026-07-22T02:00:59Z` and rejoin
at `02:01:23Z`. A mistakenly retained second trigger was detected and removed;
that second restart withdrew B at `02:06:23Z` and restored it at `02:07:03Z`.
Both rejoins occurred while natpierce was absent. They prove process re-entry
through retained WinkYou recovery information on the current IP underlay; they
do not prove operating-system reboot or physical-WAN independence.

## Candidate-card aggregation

A's latest normal card contains three distinct B endpoints at
`211.86.158.120`: ports `57118`, `62630`, and `52861`. Repeating B's normal
restart reused this group rather than producing a fourth distinct A-observed
port. C's immutable observation contains B at `211.86.158.120:63416`.

The field-card compiler now accepts an optional C card. It validates that card
as node C, takes only C's peer-B observations, and supplements A only when A
has fewer than four distinct real endpoints. The resulting four-port input is:

| Port | Witness |
| --- | --- |
| `57118` | A |
| `62630` | A |
| `52861` | A |
| `63416` | C |

The generated manifest binds all supplied input paths and hashes and records
per-endpoint provenance. Neither A's nor C's original card is modified.

## Persistent-task race found in the old transaction

The 2026-07-20 rank-2 x rank-3 scripts assumed B's normal process was started
directly. That assumption is no longer true: Task Scheduler owns B's current
normal generation and is configured to restart it. Disabling only the field
tasks would allow B's persistent task to relaunch the normal process while the
fixture generation was running. The old normalization path would then start B
directly and leave it outside its persistent task lifecycle.

The replacement protocol therefore treats B's persistent task as a frozen
resource:

1. arm and ready receipts bind the exact task definition, enabled XML, action,
   settings, sole COM task-instance GUID, `EnginePID`, and normal runtime
   process identity;
2. B's first lifecycle mutation writes an identity-bound intent and disables
   that exact task before quiescing its task-owned child;
3. normalization and deadman recovery restore the exact definition, enable and
   start the task, then require one new COM instance whose `EnginePID` equals
   the new normal runtime PID; and
4. cleanup removes only the one-shot primary/deadman tasks and never removes or
   rewrites B's persistent task.

The parser, synthetic evidence, activation-crash, task-supervisor/deadman, and
cleanup tests now cover these rules under Windows PowerShell 5.1. They reject
task-instance ambiguity, PID drift, failed disable operations, and underlay
evidence mismatches; cleanup preserves B's persistent task. No GO may be
published until fresh field inputs and a v2 plan/package have also been
generated and freeze-audited.

## OpenVPN underlay finding

The current B public address is not owned by natpierce, but it is not a
physical-WAN address either. Read-only inspection on B returned:

```text
211.86.158.120/24 -> OpenVPN TAP-Windows6 (ifIndex 6)
0.0.0.0/1        -> 211.86.158.1 via OpenVPN TAP-Windows6
128.0.0.0/1      -> 211.86.158.1 via OpenVPN TAP-Windows6
```

B also has ordinary candidate underlays at `192.168.1.5` on
`vEthernet (WAN-openwrt)` and `192.168.11.217` on
`vEthernet (LAN-openwrt)`, but the two more-specific `/1` routes currently send
public destinations through OpenVPN. Consequently, today's
`protected_direct` result means that WinkYou has a direct UDP peer edge with no
WinkYou coordinator or data relay **over the host's selected IP underlay**. It
does not prove independence from an external VPN/overlay.

The source previously filtered common overlay interfaces for legacy public ICE
but did not treat OpenVPN as suspicious, and autonomous birthday/self-bootstrap
sockets were bound to `0.0.0.0`, leaving route choice entirely to the operating
system. `nat.punch_interface` now pins STUN and punch sockets to a named
interface and exact source IPv4, fails closed when that binding cannot be
enforced, exposes the binding in path/event evidence, and is mandatory in the
strict field evaluator. The isolated run below exercised this implementation
without changing B's normal task or OpenVPN-carried production edge.

## Isolated physical-underlay A-B acceptance

Bound STUN probes first established independent, non-OpenVPN underlays:

| Node | Bound interface/source | Observed public IPv4 | Allocation evidence |
| --- | --- | --- | --- |
| A | `以太网` / `10.3.9.11` | `36.33.24.21` | random, confidence `0.285714` |
| B | `vEthernet (WAN-openwrt)` / `192.168.1.5` | `36.33.20.220` | sequential `+1`, confidence `0.857142` |

The isolated configs had no infrastructure coordinator, no bootstrap seed, and
no relay. Their only initial peer information was reciprocal recovery-card
evidence imported from those bound STUN observations. B ran under a uniquely
named disposable Scheduled Task; A ran as a local disposable process. The
existing B production task remained enabled and running throughout.

The first attempts exposed a solver defect rather than an underlay failure. A
treated B's old sequential mapping as permanently cheap to predict and retried
only the same narrow forward span. B's many punch sockets advanced that mapping
faster than A's stale prediction. Self-bootstrap now keeps the cheap predictive
first attempt, but after one deadline-confirmed miss retains those targets and
upgrades the same coordinated punch to
`cached_predictive_birthday_fallback`.

At pair-window ordinal `29744857` (start
`2026-07-22 11:37:53.931 +08:00`) the upgraded solver completed the direct
edge:

| Side | Winning local socket | Learned remote public socket | Result |
| --- | --- | --- | --- |
| A | `10.3.9.11:62885` on `以太网` | `36.33.20.220:35305` | `peer_hello -> installing -> attached` |
| B | `192.168.1.5:59766` on `vEthernet (WAN-openwrt)` | `36.33.24.21:14714` | `peer_hello -> installing -> attached` |

Both runtimes then reported one connected peer, a one-hop `A -> B` / `B -> A`
packet route, and `protected_direct`. A exposed B's SSH target at
`127.0.0.1:23024`; two independent SSH sessions returned the expected B host
account identity. The B runtime, log, and updated recovery card were also read
and copied through that same new link, not through natpierce. Successful
observations were persisted to both recovery cards.

After evidence capture, B was gracefully stopped through the physical WinkYou
link. The expected SSH control session disappeared with that link, and the old
WinkYou management edge confirmed that the isolated process had exited. The
disposable task was identity/action checked and removed; the production task
`WinkYou-Mesh-Rejoin-B-20260721-r2` remained `Running` and `Enabled`. A was then
stopped gracefully. This proves a real coordinator-free, explicitly bound A-B
public punch and usable TCP service path. It is not yet a full A-B-C rank-2 x
rank-3 acceptance, a simultaneous cold start, or an OS reboot/autostart test.

## Gates for the next live run

Completed preconditions:

- B persistent-task lifecycle v2 scripts and static crash/recovery tests pass;
- the binary pins STUN and punch sockets to selected non-OpenVPN underlays and
  records the actual interface/source in evidence; and
- a disposable, rollback-safe A-B run obtained fresh physical-underlay public
  endpoints and a usable WinkYou SSH path without natpierce product recovery.

Remaining before a live rank-2 x rank-3 GO:

- compile strict fresh A/B fixtures (including permitted C provenance) from the
  successful physical-underlay cards;
- capture fresh A/B/C task snapshots, runtime identities, config hashes, and
  clocks for the intended transaction;
- build the final binary once, deploy and hash the identical artifact required
  by the frozen package;
- generate and freeze-audit a new v2 plan/package; and
- only then install the B and A one-shot tasks and publish the four-step commit
  latch.

Until those gates pass, the live triangle should be preserved and the
historical freeze-v2 package kept immutable.
