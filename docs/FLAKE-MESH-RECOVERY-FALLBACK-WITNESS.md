# Retain the fallback route before automatic repair replaces it

The first Windows push job for PR #199 at `bedac4c` failed in
`TestRecoverySupervisorRepunchesAndPreservesRoutedTCPFlow`:

```text
--- FAIL: TestRecoverySupervisorRepunchesAndPreservesRoutedTCPFlow (20.00s)
    recovery_test.go:254: wait route [A C B] on A: context deadline exceeded
```

[Original job 116948349590](https://github.com/houyuwushang/winkyou/actions/runs/38893492440/job/116948349590)
is preserved without a rerun. Its raw log is 24,625 bytes, SHA-256
`1b31e5a2ae12a975e6e742fd5161b9af461d70b9c1d73c7e33904b7665287c37`.
The complete first check set finished with 71 successes and this one failure.
The new preapproval file is tagged `fieldc1c` and was excluded from this
ordinary Windows test invocation. The mesh runtime and its fixture were
unchanged in that head.

The assertion sampled the current control route every 10 milliseconds after
injecting a one-way B-to-A packet loss. The recovery worker continues while
the test goroutine is not scheduled: it can first route through A-C-B and
then replace that route with a new direct A-B edge. The current route is not
a record of the earlier fallback. Once repair has completed, continuing to
poll for A-C-B can exhaust the original 20-second context even though the
same TCP flow survived.

Twenty focused diagnostic runs on Windows with Go 1.23.1 passed without
reproducing the hosted failure. The first log has no route history or fault
identity trace; its exact interleaving remains unproven. A separate source
overlay establishes a sufficient counterexample by synchronizing the test
observer with actual repair completion before evaluating the original
predicate. It does not pause the recovery worker or add a sleep. The real
loopback TCP/UDP fixture produced:

```text
RECOVERY_LATE_OBSERVER current_path=[A B] old_predicate=false forwarded_delta=4 same_tcp_payload=true repaired_new_attempt=true
```

The old predicate rejected that completed fallback and repunch. This is a
demonstrated defect in the test oracle, not a claim that the original hosted
failure followed the same schedule.

The fixture now registers a topology callback after bootstrap and before
injecting the fault. One buffered slot and `sync.Once` retain the first
matching A-C-B route. Nonmatching routes do not count, the callback does not
block the recovery worker, and cleanup unregisters it. The consumer uses the
same original context. No production source or timeout changes.

`TestRecoverySupervisorRetainsFallbackRouteAfterRepunch` runs the same full
fixture with observation deliberately deferred until the new A-B attempt
is stable at all three nodes and the packet triangle is restored. It checks
that the current route is A-B before consuming the retained A-C-B witness.
Both entry points still require C to forward the in-flight data, the exact
payload to return on the same TCP connection, a distinct repaired attempt,
exactly two initiator attempts, and healthy direct service after repair.

Source-overlay mutations restore the old snapshot wait or accept a
nonmatching route. Both must fail the delayed-observer regression; they are
restored individually and never enter the committed source.
