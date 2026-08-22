# Pairing restart-safety contract (Phase 1a)

Status: **Accepted design contract; durable admission is implemented, while
the exact loopback carrier remains subject to its independent Draft review.**

This document freezes the cross-process and cross-restart safety contract for
the Phase 1a test-only pairing path. It extends
[`TEST-ONLY-PAIRING-MINI-SPEC.md`](./TEST-ONLY-PAIRING-MINI-SPEC.md) with the
durable admission rules needed before any real carrier or `connect_test`
implementation can be reviewed.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are used as
normative requirements.

Nothing in this document by itself authorizes a socket, DNS lookup, live probe,
daemon, automatic retry, recovery controller, or non-loopback `connect_test`.
The separately reviewed loopback-only carrier must still obey every invariant
in this contract.

## 1. Safety properties

Two independent properties are REQUIRED.

### 1.1 One credential

For one complete bundle and `credential_id`, any number of processes and
process or operating-system restarts MUST admit at most one attempt. Once its
durable burn commits, every later process using that credential MUST emit zero
network bytes.

The credential lifecycle is strictly:

```text
fresh -> burned
```

There is no rollback to `fresh`. Success, failure, cancellation, timeout,
scope change, malformed peer input, process crash, and operating-system restart
do not change this rule.

### 1.2 Different credentials

Changing credentials MUST NOT reset the machine-wide safety budget. Within
every persistent admission window, the sum of the worst-case envelopes admitted
by every process and restart MUST remain within the compiled machine limits in
section 6.

This second property is required even when a caller, supervisor, or future bug
submits a new valid credential after every failure.

## 2. Attempt lifecycle

Process startup begins with zero active attempts. Startup code MUST NOT scan for,
resume, continue, reconstruct, or reschedule an attempt from ledger records,
diagnostic state, an earlier RPC, or a carrier failure.

One explicit operator-originated `connect_test` request may consume one complete
bundle and request one bounded attempt. The server MUST NOT create a replacement
OFFER, pairing secret, credential, or attempt automatically. A disconnect,
timeout, cancellation, process exit, or failed carrier operation is terminal for
that attempt.

The durable journal is an anti-replay and admission-accounting record. It MUST
NOT contain a runnable job, endpoint, retry instruction, wake-up deadline, or
recovery command, and MUST NOT be treated as a task queue.

Terminal state is append-only metadata. Recording a terminal reason never
changes a burned credential to fresh and never refunds its admission envelope.

## 3. Required admission order

Every future real adapter MUST use this order:

```text
explicit connect_test request
  -> parse and validate complete bundle without network I/O
  -> hold machine governor OS owner lock and acquire a live AttemptLease
  -> pre-check scope, owner, lease, safety trip, and ledger state
  -> append BURN_AND_ADMIT and fsync the journal
  -> post-check scope, owner, lease, safety trip, and committed receipt
  -> only then permit the first DNS, dial, socket, or carrier byte
  -> append terminal metadata and complete cancellation drain
  -> stop; never resume or reschedule
```

`BURN_AND_ADMIT` is the fail-closed commit point. It MUST atomically represent
both the permanent credential burn and reservation of the attempt's complete
declared worst-case envelope. It MUST be durable before an admission receipt is
returned. A process crash after this commit consumes the full envelope even if
the process emitted no bytes.

The post-check MUST immediately follow the durable commit. Any changed scope,
owner, lease, safety trip, or ledger state invalidates admission and produces
zero bytes. The burn and reservation remain committed.

## 4. Machine scope only

The first durable implementation supports only the canonical machine safety
namespace and a machine-scoped `AttemptLease`. The reviewed loopback
`connect_test` adapter MUST reject `user_acknowledged` locally before active
I/O and before durable burn.

The Linux user-acknowledged namespace is under `/run/user/<uid>` and does not
survive an operating-system restart. It therefore remains suitable for the
already reviewed observation-only boundary, not for a claim of durable pairing
replay protection. A persistent per-user design requires a separate review.

Peer-reported scope never raises local authority. The local machine owner and
its operating-system lock remain authoritative.

## 5. Journal ownership, provisioning, and format

### 5.1 Fixed namespace object

The journal is one fixed file in the canonical machine safety namespace. Its
path is selected by the platform implementation, never by configuration, an
RPC, a mesh data directory, or a caller.

Explicit namespace setup MUST pre-create the journal with create-exclusive
semantics (`O_EXCL` or the exact platform equivalent). The active path MUST open
the existing file without a create flag. It MUST NOT create, replace, truncate,
repair, adopt, or silently reinitialize a missing or untrusted journal.

Opening the journal MUST reuse the existing namespace ownership, DACL or mode,
link-count, and reparse/symlink validation mechanics. A journal with unexpected
identity, ownership, permissions, links, or type is untrusted.

### 5.2 One existing lock

Only the process holding the existing machine governor operating-system owner
lock may append to the journal. The journal is a single-writer object inside
that lock. Implementations MUST NOT add a second independent process lock or
claim that a Go mutex supplies cross-process exclusion.

Passive status code may read a validated snapshot, but it cannot grant
admission or repair state.

### 5.3 Append-only records

The format MUST be versioned, length-prefixed, checksummed, and strictly ordered
by an incrementing sequence number. It has these record classes:

- `BURN_AND_ADMIT`: credential and attempt IDs, context digest, local machine
  scope, burn/admission time, bundle expiry, and the complete reserved
  worst-case envelope;
- `FINISH`: a monotonic terminal reason referencing an earlier admission;
- implementation records needed for an explicit circuit reset or ledger
  rebuild baseline, without adding a resumable task.

No record contains the pairing secret, PSK, traffic key, endpoint, payload,
packet contents, or carrier credential. A credential has at most one
`BURN_AND_ADMIT` record and at most one effective terminal result.

The writer MUST append a complete frame and successfully synchronize the file
before returning an unforgeable admission receipt. `FINISH` failure never
undoes the burn. A partial frame, invalid checksum, unsupported version,
sequence gap or regression, inconsistent duplicate, or impossible transition
makes the complete journal indeterminate.

Phase 1a performs no garbage collection, deletion, rewrite, or compaction.

## 6. Compiled persistent admission limits

All limits are machine-wide and survive process and operating-system restart.
Runtime configuration may lower but never raise them.

| Limit | Compiled ceiling |
| --- | ---: |
| Minimum interval between admissions | 60 seconds |
| Admissions in a rolling 1-hour window | 4 |
| Admissions in a rolling 24-hour window | 12 |
| Reserved packets in a rolling 24-hour window | 2048 |
| Journal bytes | 4 MiB |
| Journal records | 8192 |
| Consecutive terminal failures before circuit opens | 3 |
| Circuit minimum lock horizon | 6 hours |

An admission reserves its declared worst-case envelope, not observed best-case
usage. The envelope MUST be within the compiled governor `PerAttempt` ceiling.
The one-hour count, 24-hour count, and 24-hour packet reservation are checked
before the record is committed; the first exhausted limit rejects admission.
Cancellation, failure, crash, or an attempt that emits no packets does not
refund any window.

The 4 MiB and 8192-record journal limits are independent; whichever is reached
first blocks further admission. A rejected admission performs zero active I/O.

## 7. Clock and circuit behavior

The journal maintains a wall-clock high-watermark. A current wall clock behind
the trusted high-watermark beyond the reviewed local skew policy blocks active
work. A smaller tolerated rollback uses the high-watermark conservatively and
MUST NOT shorten the 60-second interval, either rolling window, or the circuit
horizon.

A terminal success ends the current consecutive-failure streak. Every other
terminal result increments it. When a journal is reopened after process death,
an admitted attempt without a successful terminal record is conservatively a
failure and its budget remains charged.

Three consecutive terminal failures append a persistent circuit-open state with
a six-hour minimum lock horizon. Passage of time alone MUST NOT reopen the
circuit. Clearing it requires the explicit local safety-reset workflow, with
the existing expected-sequence and operator-note discipline; this does not
reclassify the journal as a safety trip. Reset cannot refund existing admission
windows or burns.

## 8. Stable blocking states and explicit rebuild

The durable pairing path exposes these distinct stable states:

- `ledger_not_initialized`: explicit setup has never created the fixed journal;
- `ledger_indeterminate`: a journal exists or previously existed but cannot be
  trusted because of corruption, torn write, unsafe metadata, unsupported
  format, unavailable synchronization, or another ambiguous state;
- ready, rate-limited, circuit-open, or capacity-exhausted states derived from a
  trusted journal.

`ledger_not_initialized` and `ledger_indeterminate` both block active work and
produce zero emission, but they are not a machine safety-trip state. They MUST
remain distinguishable in read-only diagnostics and stable error classes.

The active path never repairs either condition. Any future explicit rebuild
command MUST require local operator intent and MUST create the replacement with
create-exclusive semantics after preserving or explicitly quarantining the old
object. The new journal begins with a durable rebuild baseline that treats all
of the following budgets as fully consumed at rebuild time:

- the 60-second minimum interval;
- the four admissions in the 1-hour window;
- the twelve admissions in the 24-hour window; and
- the 2048 packets in the 24-hour window.

Consequently, rebuild cannot turn damage or deletion into a budget-reset
primitive. Circuit and safety-reset requirements remain independently
enforceable.

## 9. Cancellation and emission witness

Cancellation first rejects new messages and I/O, closes the future carrier,
waits for every admitted operation, completes the governor drain witness, and
then appends terminal metadata. A drain timeout follows the existing persistent
safety-trip contract.

Crash tests MUST use a process-external emission witness owned and observed by
the parent process. Child logs, deferred cleanup, in-memory counters, and the
child's own terminal report are not evidence after the child is killed.

The permanent suite MUST be capable of detecting a deliberate mutation that
invokes the emission witness before durable burn. The unmodified implementation
must keep that witness at zero for every rejected, corrupt, uninitialized,
rate-limited, circuit-open, or pre-commit crash path.

## 10. Required restart evidence

Before a carrier can consume an admission receipt, deterministic tests MUST
prove at least:

- 32 to 100 processes racing with one credential produce at most one winner;
- 1000 supervisor-style restarts with one bundle produce at most one admitted
  attempt and no later emission;
- restarts that use fresh credentials remain within every persistent admission
  window and packet reservation;
- a crash after admission does not refund budget;
- crashes before burn, during append, after synchronization, around post-check,
  after a simulated first byte, and during terminal write preserve the stated
  invariants;
- missing, truncated, modified, out-of-sequence, full, or rollback-affected
  journals produce zero emission;
- safety-trip activation before burn, after burn, and before first byte rejects
  or drains the attempt without permitting a later restart to continue it;
- Windows and Linux reopen the same logical journal state consistently; and
- the mutation described in section 9 is caught.

These tests remain zero-network tests. A later loopback carrier review must add
operating-system socket and packet observation before any live-network request.

## 11. Threat boundary

Phase 1a claims protection against ordinary concurrent processes, process
crashes, supervisor restarts, operating-system restarts on a supported local
filesystem, and torn or partial journal writes. It assumes the operating system
honors the reviewed exclusive lock and synchronization primitives.

Phase 1a does not claim resistance to an administrator or root user deliberately
rolling back or replacing the complete canonical safety namespace, storage or
hypervisor snapshots that restore the namespace and clock together, or a device
that falsely reports durable writes. Detecting those rollback classes requires
a TPM-backed or external monotonic anchor and is outside this phase.

Missing or visibly untrusted state still fails closed; the limitation is the
undetectable restoration of a previously valid older state.

On Linux, the canonical machine namespace deliberately keeps its files
world-writable so that any local user's safety trip can block machine-wide
active work. The journal checksum is unkeyed and detects corruption, not
malice. A hostile unprivileged local user on a shared Linux host can therefore
rewrite the journal wholesale and erase budget history, exactly as they could
already clear a safety trip file. Phase 1a accepts this: the supported
deployment for real connect-test admission is a single-operator machine.
Multi-user Linux hosts must be treated as outside the admission trust
boundary until a keyed or root-owned ledger design passes review. Windows
relies on the reviewed DACL and does not share this gap.

## 12. Non-goals

This contract does not implement or authorize:

- automatic reconnect or the Phase 3a recovery controller;
- automatic pairing-material generation;
- non-loopback `connect_test` behavior or a stdio version change beyond the
  additive loopback-only activation;
- promotion of `testpairing` or `punchsim` into a production dependency, or
  use of `noisecore` outside the exact reviewed loopback carrier;
- a socket, DNS lookup, live probe, public/home/shared-network test, daemon, or
  scheduled-task change; or
- birthday-punch re-enablement.

The stdio v1 schema may later receive additive read-only ledger and window
diagnostic fields. Activating `connect_test` remains a separate reviewed PR.
