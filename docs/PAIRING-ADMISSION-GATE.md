# Pairing Admission Gate and Restart Witness (Phase 1a)

Status: implemented as a zero-network authority transition; deliberately not
connected to `connect_test`, `noisecore`, `probeio`, or any carrier.

This implementation follows
[`PAIRING-RESTART-SAFETY-CONTRACT.md`](./PAIRING-RESTART-SAFETY-CONTRACT.md)
and consumes the persistent policy in
[`PAIRING-ADMISSION-JOURNAL.md`](./PAIRING-ADMISSION-JOURNAL.md). It does not
authorize a live-network test.

## Authority flow

The only successful path is:

```text
live machine AttemptLease
  -> pre-check scope / owner / trip / cancellation / expiry / reserved cost
  -> register governor drain
  -> durable BURN_AND_ADMIT + fsync + reread verification
  -> post-check the same invariants
  -> one-time CommittedAttempt
  -> consume once for CommittedCarrierAuthorization
  -> mandatory check immediately before a future first byte
```

No later step can manufacture an earlier capability. `CommittedAttempt` and
`CommittedCarrierAuthorization` have only private fields; useful values can be
constructed only by the gate. Zero values fail closed. A token is bound to the
exact attempt lease, owner instance, credential, context digest, expiry, and
worst-case cost that were committed.

The gate requires `OperationConnectTest`, machine scope, and an envelope equal
to the live lease reservation. It rejects a caller that presents a different
attempt ID, scope, cost, expired bundle, cancelled context, closing lease,
changed owner, or blocking safety state. A machine journal that is missing,
truncated, modified, checksum-invalid, capacity-exhausted, or affected by a
clock rollback cannot produce a token.

## Cancellation and terminal ownership

The drain registered before the durable burn is transferred to the committed
token. A bounded watcher observes the original context, bundle expiry, and the
attempt's existing `Stopping` signal. Cancellation, safety trip, expiry, peer
close, governor close, or owner loss invalidates the token and appends one
terminal failure before completing the drain whenever the process remains
alive.

Only one terminal reason wins. A repeated identical finish is idempotent; a
different later reason is rejected. Success is rejected until the mandatory
first-emission check has passed. If the process crashes before a terminal
append, the durable burn remains and the next owner treats that unfinished
admission as a crash failure. No path refunds its reservation.

The authorization exposes the existing attempt `Stopping` channel and a
read-only `CheckActive` operation for a future controlled I/O boundary. It owns
no socket, file descriptor, packet connection, endpoint, or send function.

## Process-external emission witness

Crash tests do not trust the crashing child's logs or counters. The parent
process owns each child's stdout pipe and supplies a binary witness marker. The
child may write that marker only at the simulated first-emission boundary. The
parent counts markers independently after the child exits, including abrupt
exit paths.

This is deliberately not a network test. The pipe marker proves ordering
between durable admission and a process-external observable effect while the
architecture remains capability-free.

The fault-injection matrix is:

| Injected boundary | Parent witness | Durable result |
| --- | ---: | --- |
| crash after pre-check, before burn | 0 | initialization only; retry may admit |
| crash after a synchronized partial frame | 0 | `ledger_indeterminate` |
| crash after admission fsync, before receipt return | 0 | credential remains burned |
| crash immediately before post-check | 0 | credential remains burned |
| crash immediately after post-check | 0 | credential remains burned |
| crash immediately after simulated first byte | 1 | credential remains burned; retry emits 0 |
| crash during a synchronized partial terminal write | 1 | `ledger_indeterminate`; retry emits 0 |

Safety-trip tests place the trip before burn, after burn, before the simulated
first byte, and after it. The parent observes `0, 0, 0, 1` markers respectively;
the final case also proves that the existing drain signal is delivered.

A deliberate mutation writes the parent marker before calling the gate and
then crashes. The zero-emission assertion must fail, proving that the witness
would catch an implementation reordered to emit before burn.

## Cross-process and restart gates

The mandatory stress cases use real helper processes and the existing machine
governor OS owner lock:

- 32 simultaneous processes present the same credential; the parent observes
  exactly one first-emission marker;
- one supervisor launches 1000 fresh child processes with the same bundle; the
  parent observes exactly one marker across all restarts;
- fresh credentials in separate processes are evaluated under synthetic
  monotonic times; no more than 4 are admitted in one hour and no more than 12
  in a rolling 24-hour window;
- crash-after-admission cases are retried with the same bundle and observe zero
  additional markers.

The same helper and journal code runs on Windows and Linux. Platform-specific
owner-lock and journal-protection tests remain in `internal/governor`; no test
uses a public, private, or loopback socket.

## Current non-authority and next review

An architecture test fails if any production file outside the gate begins to
reference its constructor, committed token, carrier authorization, consume
method, or first-emission method. The existing raw-network capability inventory
must also remain unchanged. Consequently this slice cannot silently activate a
carrier or `connect_test`.

A future carrier PR requires separate expert approval and must:

- accept only a consumed `CommittedCarrierAuthorization`;
- perform `BeforeFirstEmission` at its controlled first-byte boundary and
  `CheckActive` before later emissions;
- register and prove its actual I/O drain, honor `Stopping`, and append a final
  result;
- route every network operation through reviewed `probeio` authority;
- retain all parent-process witness, mutation, trip, restart, and budget tests;
- update the no-production-consumer architecture gate explicitly as part of
  that review.

Until then, stdio v1 `connect_test` remains the stable `not_implemented` method.
This PR starts no daemon, creates no pairing material, changes no scheduled
task, and performs no live-network work.
