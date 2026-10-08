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

## Verification plan

1. Run the original package/full-suite command with the stress environment
   used by the registered Windows job and preserve the first result.
2. Run the focused barrier test with the same scheduler load and collect the
   measured gap distribution.
3. Apply only the derived fixture budget and its contract test, then run the
   focused race batch and the full Windows command. A new failure with a
   different terminal class is registered separately rather than folded into
   #179.
