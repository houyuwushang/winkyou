# Flake #179: shortcut barrier liveness budget

## First-red evidence

The first-red occurrence recorded after the #182 rebase is the Windows push
job `113215094012` from run `37748325379` (head `150398fc`). The pull-request
event for the same head passed; the push failure was not rerun.

The failing case was
`TestShortcutReconcilesDroppedPacketBarrierSignal/first_stable_after_initial_delivery_window`.
The barrier witness reached `installed` and `probation` on all three nodes,
but before the 1.5 s probation boundary all three managers reported
`packet_neighbor_liveness_timeout`. The two endpoint solver states were
`success`; no Stable signal could therefore be emitted or dropped. The
failure was observed at about 1.05 s, while the test's packet-neighbor
`PeerTimeout` is 100 ms.

This is registered against #179 and is intentionally outside the #182
change-set. The existing 5 s observation context, 1 s solve timeout, and
1.5 s probation are not changed by this evidence commit.

## Fix contract

The fixture must tolerate the scheduler pauses that are measurable under the
original full-suite Windows load while still failing fast for a real dead
packet neighbor. We will measure the largest observed keepalive/read gap in
the barrier fixture, derive a test-only `PeerTimeout` with documented margin,
and lock the derivation in a contract test. Product defaults and packet
neighbor implementation stay unchanged. No sleep is added and no observation
deadline is widened.

The witness must retain the terminal failure class and the observed gap so a
future recurrence can distinguish liveness starvation from a missing barrier
signal.

## Review supplement: shared fixture budget

The review-required packet-neighbor path now uses the single derived
`shortcutBarrierPeerTimeout` constant for both `PeerTimeout` and the three
short-probation fixtures that previously used a 150 ms `Probation` value:
`TestShortcutBecomesStableAfterProbation`,
`TestShortcutReportsInstalledOnlyAfterPacketNeighborReady`, and the `first
commit` case in `TestShortcutReconcilesDroppedPacketBarrierSignal`. The
probation floor is therefore 250 ms, matching the measured-gap derivation;
the two long-probation cases and all other fixture parameters are unchanged.

This is a test-only scheduler budget correction. It does not alter mesh
defaults, production timeouts, or any frozen product envelope.

## Measurement and derivation

The added witness was run with `GOMAXPROCS=2`, two busy workers, and the race
detector for 20 fresh executions of the affected subtest. The maximum observed
receive gap was 47.2091 ms (write gap was lower); the fixture rounds that
measurement up to 50 ms. The hosted first-red already proves that a 100 ms
peer budget can lose the session under the full-suite Windows scheduler, so a
fivefold fixture-only margin is used:

`50 ms measured ceiling × 5 = 250 ms PeerTimeout`.

This changes only the barrier test's `PacketNeighborConfig`; the mesh package
and all product defaults remain unchanged. The budget formula is locked by
`TestShortcutBarrierPeerTimeoutBudget`.

## Verification plan

1. Run the original package/full-suite command with the stress environment
   used by the registered Windows job and preserve the first result.
2. Run the focused barrier test with the same scheduler load and collect the
   measured gap distribution.
3. Apply only the derived fixture budget and its contract test, then run the
   focused race batch and the full Windows command. A new failure with a
   different terminal class is registered separately rather than folded into
   #179.


## Shared CI repair (2026-10-16)

The first push at `641dd967` retained a separate #180 failure in
[Test (Linux), job 113310183756](https://github.com/houyuwushang/winkyou/actions/runs/37776974153/job/113310183756):

```text
GATEB3_SELECTION_WITNESS label=delayed_write_not_reached delayed_triggered=false writes=6
```

The original check set finished with 70 successes, one selection-test failure
and one dependent skipped job. Both Windows test events passed. The Linux
failure was not rerun and does not invalidate the recorded shortcut witness.

The branch now integrates the shared test/CI fixes from
[PR #197](https://github.com/houyuwushang/winkyou/pull/197), head `e18249c`.
That investigation measured the complete Hard16 schedule before deriving the
candidate fixture window, identified the selection frame by type, and checked
both actual candidate deadlines. It also bounded Go installation using the
official distribution source. See
[the selection evidence](FLAKE-180-HARD16-SELECTION-MARGIN.md) and
[the provisioning evidence](CI-GO-PROVISIONING.md).

The shortcut fixture changes remain independently reviewable against that
shared head: this document and the two shortcut test files. The 250 ms budget,
three short-probation corrections, original observation windows, and packet
gap witnesses remain unchanged. Go production delta against current main is
zero. Refs #179 and #176; closure still requires the separate post-merge
Windows first-run observation period.
