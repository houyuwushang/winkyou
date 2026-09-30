# Windows shortcut readiness/barrier flake investigation

Status: investigation in a test-only Draft PR. This document preserves the
first failures for #176 and #179; it does not change the caller deadline,
`SolveTimeout`, probation, packet-neighbor, workflow, or product code.

## First signatures

- #176: `TestShortcutReportsInstalledOnlyAfterPacketNeighborReady` failed in
  the Windows full-suite job with either packet-neighbor attachment timeout or
  `mesh: packet neighbor liveness timeout` after the attempt had started.
- #179: `TestShortcutReconcilesDroppedPacketBarrierSignal` failed in both
  `first_stable_after_initial_delivery_window` and
  `stable_through_new_direct_edge`; the 5-second caller saw neither a dropped
  barrier nor a complete alternate path, while the existing witness ended with
  an endpoint failure/abort.

The failures have not occurred in an isolated run of `pkg/mesh/shortcut`.
The required reproduction therefore models the full-suite CPU/I/O pressure
with two busy goroutines and concurrent heavy package test processes. A first
failure is retained as a fixed-label witness; it is not replaced by a rerun.

## Investigation contract

The witness records only relative nanoseconds and fixed enums. On a failed
wait it records all three manager phases/failure classes, observed packet
neighbor presence, fake-edge state, and the fake solver terminal state. It
must cover both failure points in #176 and the barrier wait in #179.

Classification is restricted to the approved choices:

1. fixture ordering: replace an eager start or wall-clock assumption with an
   existing readiness event;
2. a legal bounded terminal path: derive a caller window from existing
   constants and assert the unchanged terminal/count contract; or
3. product defect: stop this PR and open a separate issue.

No `skip`, retry, sleep, weakened assertion, workflow change, or frozen-number
change is allowed. `Closes #176, #179` is reserved for a reproduction with a
non-zero failure rate followed by zero failures under the same load; otherwise
the PR will reference the issues only.

## Local evidence and fixture classification

The first post-witness pressure batch used Go 1.23.1, `GOMAXPROCS=2`, two busy
goroutines, `-race`, and the shortcut target tests at `-count=100`. Both
signatures passed (`411.974s`). In the same batch the orchestrator and netif
packages passed; the governor leg reached its 25-minute test timeout in the
pre-existing #111 `TestLoopbackCarrierSlowFinishRevokesBeforeDurableIO` R1
case. Its complete stack is retained outside the repository and is not part
of this PR's diagnosis.

An unchanged full `pkg/mesh/shortcut` package run at `-race -count=20` under
the same stress variables also passed (`96.432s`). The recorded files and
hashes are:

| run | result | SHA-256 |
| --- | --- | --- |
| shortcut target `-count=100` (before fixture change) | PASS | `AB774730410796A3740260D1156ED5DD4BC8647687C3C14AEA46475AA9C5EEB5` |
| governor parallel leg (known #111 timeout) | TIMEOUT/RED | `843CFDE7DB3C420407640FA2CD3C92ED5C833E4C8FDDE6C1B8BC54609BFD3662` |
| gatecorchestrator parallel leg | PASS | `4A6A597791514CB4E571634F7780C60AE098CC06815C38914C99118C406D64BF` |
| netif parallel leg | PASS | `CDA3D32E4AAB4138723348E456CE2344416D5DF1C423096A5389E05EF2CAD954` |
| full shortcut package `-count=20` | PASS | `5C7490DBC6100261DE967DD1DE6175E85E0CFCF9C156C92881C0B013D1F85E2A` |

The witness and source inspection identify a fixture-ordering race, not a
production failure: the five-second operation context previously began before
node startup and route convergence, while the #176 gate waited for an
ephemeral neighbor entry with a five-millisecond polling loop. Under the
full-suite scheduler, a packet session could enter its pre-readiness timeout
before the poll observed both entries; #179 could spend the same caller budget
before its barrier sequence began. The fix keeps the same five-second protocol
window, makes setup use its own bounded context, and waits on the two direct
writer-entry events instead of polling a transient state. No liveness,
probation, solver, workflow, or production value changed.

After the fixture change, the focused pair passed `-race -count=20` in
`84.336s`, and the required `-race -count=100` batch passed in `413.680s`.
The post-fix log SHA-256 is
`24DA3D268ED281C95EFCDA64F8E7D4BF0C108BAEA769E8D9E6C9B9E266014479`.
Because the local reproduction rate was zero both before and after, issue
closure is intentionally not claimed here; this PR remains a test-only
root-cause fix with `Refs #176` and `Refs #179` until the hosted full-suite
first run supplies the same-load result.
