# Pairing Admission Journal (Phase 1a)

Status: implemented zero-network storage and policy evaluator; not connected to
`connect_test`, `noisecore`, a carrier, or any scheduler.

Normative safety rules remain in
[`PAIRING-RESTART-SAFETY-CONTRACT.md`](./PAIRING-RESTART-SAFETY-CONTRACT.md).
This document describes the reviewed implementation slice, not new authority
to perform active network work.

## Purpose and fixed limits

Changing a one-time credential must not reset the machine's attempt budget.
The journal therefore burns a credential and reserves its declared worst-case
attempt envelope in one durable record before a future admission gate may
return authority.

The compiled ceilings are:

| Limit | Value |
| --- | ---: |
| Minimum interval between admissions | 60 seconds |
| Admissions in a rolling hour | 4 |
| Admissions in rolling 24 hours | 12 |
| Reserved packets in rolling 24 hours | 2048 |
| Consecutive terminal failures before circuit lock | 3 |
| Minimum circuit horizon | 6 hours, followed by explicit reset |
| Tolerated local wall-clock rollback | 2 minutes, evaluated at the high-watermark |
| Journal capacity | 4 MiB and 8192 records, first ceiling wins |

Each envelope must also fit the compiled machine `PerAttempt` governor limits.
Runtime policy may lower these values but cannot raise them. Reservations are
never refunded because an attempt finished early, sent fewer packets, failed,
was cancelled, or crashed.

## Location and creation

The machine-only journal is the fixed
`pairing-admission-v1.journal` file inside the canonical machine safety
namespace. It is not derived from a Mesh, configuration, state directory,
environment variable, request, or caller-supplied path.

`wink setup-machine-scope` creates a missing journal with create-exclusive
semantics. This also provides a migration path for a valid safety namespace
installed before the journal existed. Repeating setup validates the existing
file and is otherwise idempotent. An existing malformed, truncated, linked,
reparsed, incorrectly owned, or incorrectly protected file is rejected; setup
does not truncate, adopt, or repair it.

Active journal APIs only open the existing file. A missing file is
`ledger_not_initialized`; an existing file that cannot be trusted is
`ledger_indeterminate`. Neither path creates or repairs anything.

The first version is deliberately machine-scope only. The
`user_acknowledged` namespace remains passive-observation-only and does not
contain this journal because its Linux location does not survive an OS restart.

## One authority and one writer

The existing machine governor OS owner lock is the only inter-process lock.
There is no second journal lock. An `Owner` exposes one in-process journal
handle, and an append holds that owner's mutex and OS-lock lifetime through the
write, `fsync`, and commit verification. `Owner.Close` therefore cannot release
the OS lock during a journal commit.

Only the process that holds that machine owner may append. Other official
processes fail at owner acquisition before they can become journal writers.
The file permissions intentionally reuse the machine namespace model described
in [`MACHINE-SAFETY-NAMESPACE.md`](./MACHINE-SAFETY-NAMESPACE.md).

## On-disk format

The file is append-only and begins with exactly one initialization record. Each
frame is:

```text
uint32_be(json_length) || JSON({ record, checksum })
```

The checksum is SHA-256 over the deterministic Go JSON encoding fixed by
schema v1.
Frames have a compiled 16 KiB maximum, records carry schema version `1`, and
sequences must increase by exactly one from `1`. JSON decoding rejects unknown
fields and trailing content. The reader validates the entire journal on every
operation; a torn prefix or body, checksum error, duplicate or skipped
sequence, invalid transition, over-capacity file, or unsupported schema makes
the complete journal indeterminate.

The record vocabulary is:

- `initialize`: first creation by explicit setup;
- `rebuild_baseline`: reserved for a future separately reviewed explicit
  rebuild workflow; it starts all rolling budgets fully consumed;
- `burn_and_admit`: credential ID, attempt ID, context digest, owner instance,
  machine scope, admission time, bundle expiry, and full worst-case envelope;
- `finish`: one terminal reason for a matching admission;
- `circuit_reset`: an explicit, sequence-bound operator reset after the
  six-hour minimum horizon.

The journal stores identifiers and a context digest, never a pairing token,
PSK, session key, endpoint, packet, or other credential material.

## Commit and crash semantics

`BURN_AND_ADMIT` is the atomic point of no return. The implementation appends
the complete frame, synchronizes the file, rereads the journal, and verifies
the new sequence before returning an unexported-field admission receipt. A
write or sync ambiguity returns no receipt and marks the operation
indeterminate; if bytes did persist, a retry still finds the credential burned.

`FINISH` is append-only. Failure to write it cannot undo the burn or refund the
reservation. An unfinished admission owned by the currently held owner is
treated as in flight. After a process restart changes the owner instance, an
unfinished prior admission is conservatively counted as a terminal crash
failure. Three consecutive failures latch the circuit. Later time or a late
success does not clear it; only an eligible explicit reset record does.

The wall-clock high-watermark never moves backward. A rollback beyond the
compiled tolerance blocks active work as `clock_rollback`; a smaller rollback
is evaluated at the durable high-watermark, so it cannot shorten an interval or
cooldown.

## Capacity and rebuild boundary

Phase 1a performs no garbage collection, compaction, rotation, deletion, or
automatic rebuild. Admission reserves room for both its burn record and one
maximum terminal record. When either fixed capacity ceiling is reached, new
admission fails closed.

No rebuild command is added by this slice. The format and evaluator contain a
tested rebuild baseline for a future explicit, separately reviewed workflow.
That baseline treats the one-hour count, 24-hour count, and 24-hour packet
budget as fully consumed at rebuild time. Rebuild therefore cannot become a
budget-reset shortcut.

## Stable read-only states

`PairingLedgerStatus` reports no credential, attempt, endpoint, or secret. Its
stable states are:

- `ready`;
- `ledger_not_initialized`;
- `ledger_indeterminate`;
- `admission_rate_limited`;
- `admission_circuit_open`;
- `ledger_capacity_exhausted`;
- `clock_rollback`.

Every state except `ready` blocks future active admission. These states are
independent from the persistent safety-trip latch even though
`ledger_indeterminate` has the same fail-closed force. The implementation
provides read-only inspection for later diagnostics, but this PR does not
change stdio v1 or activate `connect_test`.

## Threat boundary and current non-authority

The journal covers cooperative official-process concurrency, process crashes,
OS restarts, torn writes, replay of a previously burned credential, and attempts
to multiply budget by changing credentials or data directories. It does not
claim protection against administrator/root rollback, kernel compromise, or VM
snapshot rollback without a TPM or external monotonic anchor. Its checksum is
an accidental-corruption detector, not a MAC against a hostile privileged
writer.

This package creates no socket and imports no network capability. It does not
call an emission sink, create pairing material, run `noisecore`, start a
daemon, modify a scheduled task, or implement `connect_test`. A separate Draft
PR must still add and review the process-external admission gate and emission
witness before any carrier can consume this state.

## Verification

The test suite covers frame round trips, truncation, invalid lengths, checksum
damage, strict sequences, missing versus indeterminate state, exclusive setup,
no active-path repair, durable burn before receipt, interval and rolling-window
boundaries, packet reservations, restart-owned unfinished attempts, persistent
circuit reset, rebuild cold start, clock rollback, capacity, and owner-lock
lifetime through `fsync`. Platform tests validate Linux ownership/mode and
Windows owner/DACL behavior and prove that setup does not repair corruption.
