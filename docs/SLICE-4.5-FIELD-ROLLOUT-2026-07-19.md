# Slice 4.5 three-node `wink up` field rollout (2026-07-19)

Status: accepted for the guarded C -> B -> A product-lifecycle rollout. All
three field nodes now run the default-off autonomous graph engine through the
normal managed `wink up` lifecycle. This record does not accept operating-system
autostart, a machine reboot, simultaneous three-node cold start, or recovery
after a public-IP change.

## Frozen build

- Source commit: `377e3f5ed310883bb494b97f73df4f0b1e86baa8`.
- Windows/amd64 SHA-256:
  `5C5A9ADB657F0BFCC1D4CEB1AA41FFB058BCCEE44F8984E9A0DB19A7CE8F40E5`.
- Linux/amd64 SHA-256:
  `AFFE6AB4309D56525B26F34FCF17986F44F3110B77E35FF2FC49CA3B56665065`.

The rollout used one frozen build and verified the staged executable hash on
each host before replacing its previous process.

## Rolling result

The guarded order was **C -> B -> A**. Each previous runtime was checked against
its frozen process identity and then replaced by a managed product `wink up`
runtime before the next node was changed. B and A used their guarded wrappers to
stop the exact legacy r12 process and launch the product runtime; this must not
be summarized as a product `wink down` on those two legacy processes. After its
replacement, C separately passed a clean product `wink down` -> `wink up`
canary.

| Node | Platform | New runtime `started_at` (UTC) | Result |
| --- | --- | --- | --- |
| C | Linux/amd64 | `2026-07-19T10:48:23.857471246Z` | accepted |
| B | Windows/amd64 | `2026-07-19T11:32:47.7118156Z` | accepted |
| A | Windows/amd64 | `2026-07-19T12:19:12.4071921Z` | accepted, PID `51248` |

Final readback on A, B, and C showed:

- no configured bootstrap seed and an empty desired-bootstrap map;
- `infrastructure_coordinator_started=false`;
- two packet neighbors per node, both `protected_direct`;
- one-hop routes to both other nodes; and
- no dedicated infrastructure user-data relay. Ordinary mesh peers still acted
  as attempt-scoped punch coordinators where needed; that is in-mesh control,
  not an infrastructure coordinator or data relay.

On A, actual SSH command payloads were also validated through all four
configured product facades:

- `127.0.0.1:22024` to B;
- `127.0.0.1:22022` to C;
- `[fd00::b]:22` to B; and
- `[fd00::c]:22` to C.

All four commands returned their complete expected stdout or status JSON, so
these were data/command-path checks rather than listener-only or banner-only
acceptance. Those first independent probes conservatively terminated only the
local SSH client as soon as output was captured, so they did not by themselves
establish whether the client would close normally. A follow-up 120-second
output-aware monitor gave each SSH process a 500ms close grace period: all 44
SSH-carried status, ping, and hostname probes exited with code zero, with no raw
transport failure or monitor-classified close anomaly. Win32-OpenSSH printed
`close - IO is still pending on closed socket` on those successful probes; that
known client warning is retained in stderr but is not evidence by itself of a
WinkYou FIN/stream failure. The historical M8 627th-stream hang remains a
separate regression target and was not reproduced here. The ULA aliases
remained ActiveStore-only loopback `/128` addresses, so this also does not claim
transparent system L3, arbitrary ports, UDP, ICMP, subnet routing, or exit-node
support.

## A wrapper incident and safety result

The first A attempt stopped before any mutation. PowerShell variable names are
case-insensitive, and a local `$oldLauncher` process variable shadowed the
frozen `$OldLauncher` path. Preflight consequently rejected a process object as
a missing path. The failed attempt was safely archived, while the old A runtime,
listeners, and aliases remained in place.

After correcting the name collision, wrapper SHA-256
`1582C65CD4CFA65638275962FE9820F614B6E1D0349F0CE67ACBC1E5EC68BA9C`
passed two independent final GO reviews: the wrapper/failure-path final review
and a separate PowerShell dynamic-scope audit. This incident is useful evidence
that the pre-mutation gate failed closed; it is not a failed mesh recovery
attempt.

## Evidence boundary and remaining work

Detailed process results, status snapshots, recovery cards, wrapper logs, and
SSH outputs remain in the test host's gitignored
`.live-run/runs/wink-autonomous-rollout-20260719-r1/` directory. They are local
field evidence, **not repository-tracked artifacts**. This checked-in record is
the durable summary; it must not be read as proof that the ignored evidence was
committed.

The next field acceptance matrix remains:

1. install and verify OS autostart/process supervision on all three nodes;
2. reboot each machine and verify managed rejoin;
3. perform a simultaneous three-node cold start; and
4. exercise one or more real public-IP changes; and
5. add a deterministic half-close/server-first-close regression that separates
   the historical M8 stream hang from Win32-OpenSSH's benign close warning.
