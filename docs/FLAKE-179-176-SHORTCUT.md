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
