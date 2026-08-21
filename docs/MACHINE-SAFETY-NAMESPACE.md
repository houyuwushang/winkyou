# Machine Safety Namespace (Phase 1a)

Status: implemented safety foundation; not yet wired to legacy or v2 active network paths.

## Decision

Official WinkYou processes that may perform active connectivity work will share one machine-wide governor authority. Its location is fixed by the build and operating system, not by `--config`, `--state`, an environment variable, a Mesh identifier, or a local API request:

| Platform | Canonical namespace |
| --- | --- |
| Windows | the OS-resolved ProgramData known folder plus `WinkYou-SafetyV2` |
| Linux | `/var/lib/winkyou-safety-v2` |

The machine directory contains four fixed files:

- `governor.lock`: the operating-system lock authority;
- `governor.owner.json`: best-effort diagnostic metadata only.
- `safety-trip.json`: a persistent fail-closed latch and checksummed diagnostic record.
- `pairing-admission-v1.journal`: the append-only, cross-process and
  cross-restart pairing admission budget.

Metadata never proves ownership. A stale, corrupt, or user-modified metadata file cannot override the OS lock.

## Setup and read-only inspection

An installed package should prepare this namespace. Portable users can do the same explicitly:

```text
wink setup-machine-scope
```

Creating the namespace requires an elevated terminal on Windows or root on Linux. Once it is valid, an ordinary user can run the command again as an idempotent validation. The command also create-exclusively adds a missing pairing journal to a valid namespace installed before that journal existed. A precreated path, permission drift, unexpected owner, symbolic link/reparse point, hard-linked fixed file, malformed existing journal, or unexpected ACL fails closed; setup does not silently repair or adopt it.

Inspection never changes the machine:

```text
wink setup-machine-scope --check
wink setup-machine-scope --check --json
```

Both modes explicitly report that no WinkYou runtime or network activity was started. The command does not open sockets, change routes, start a daemon, enable recovery, or remove the existing emergency stop.

## Permission model

### Windows

The namespace directory and all four machine files use protected, non-inherited DACLs and an `Administrators` owner:

- `LocalSystem` and built-in `Administrators`: full control;
- `Authenticated Users` on the directory: list, traverse, read attributes, synchronize, and read permissions;
- `Authenticated Users` on the four files: generic read and write, without delete, owner, or DACL rights.

This lets an ordinary official process acquire the lock and refresh diagnostic metadata while preventing it from creating, deleting, renaming, or replacing the fixed files. The ProgramData path comes from the Windows Known Folder API, so changing `%ProgramData%` cannot redirect the authority.

### Linux

The direct parent must be a real, root-owned directory that is not writable by group or others. The namespace is `root:root` mode `0755`; all four machine files are `root:root` mode `0666`. The validator rejects symbolic links, special files, extra hard links, special mode bits, and extended POSIX access ACLs.

World-writable fixed files are deliberate: an unprivileged official process must be able to lock and update them, while the non-writable directory prevents replacement or deletion. The lock file is retained after release so contenders never split across file identities.

## Persistent safety trip

The trip file begins with a one-byte latch followed by a checksummed, versioned JSON record. Trip commits and syncs the blocking latch before synchronously signaling attempt cancellation at that commit point and writing diagnostic detail. Registered drains then finish under the governor-owned timeout before leases are released. Reset writes and syncs a complete clear record while the latch remains tripped, then clears and syncs the latch last. A torn write, checksum mismatch, unknown schema, missing file, or latch/record disagreement is `indeterminate` and blocks active work.

The first valid trip reason is retained. A process restart, different CLI command, different Mesh, or different data directory cannot clear it. Reset is sequence-bound so an operator cannot accidentally clear a newer trip than the one inspected. Automated recovery and peer events never receive reset authority.

Read status before deciding whether to reset:

```text
wink safety status
wink safety status --json
```

A blocking status exits nonzero after printing the record. Reset requires the exact tripped sequence, a non-empty audit note, administrator/root privileges, and exclusive ownership (no official governor may still be running):

```text
wink safety reset --expected-sequence 7 --note "operator reviewed resource exhaustion"
```

Portable and non-privileged users can still collect a no-packet first-run
report before installing the scope:

```powershell
wink diagnose
wink diagnose --json
```

It reports `active_probe_blocked` plus a copyable setup action while continuing
to inspect configuration, interfaces, routes, lock state, and safety state. See
[`PASSIVE-DIAGNOSE.md`](./PASSIVE-DIAGNOSE.md).

Reset never starts a runtime or performs network activity. Corrupt or indeterminate state is not reset automatically.

## Persistent pairing admission journal

The machine-only pairing journal is initialized by explicit setup and is not
part of the lower `user_acknowledged` namespace. Active APIs never create,
truncate, repair, rotate, or compact it. Missing state is
`ledger_not_initialized`; untrusted existing state is `ledger_indeterminate`.
Both block future pairing admission without changing the independent safety
trip.

Journal writes are serialized by the existing machine governor OS owner lock.
There is no second process lock, and the owner cannot close until an append and
`fsync` complete. The fixed budgets, format, crash behavior, and current
zero-network integration boundary are documented in
[`PAIRING-ADMISSION-JOURNAL.md`](./PAIRING-ADMISSION-JOURNAL.md).

This slice intentionally does not expose a standalone operator trip command: without the future local control channel or a probe-I/O latch watcher, such a command could write a marker while falsely implying that an already-running process had stopped sending. Active authorities call `Governor.Trip` directly; an independent operator kill switch remains a separately reviewed integration.

## Threat boundary

This boundary prevents accidental budget multiplication across official WinkYou processes, Meshes, and configurable data directories. It is fail-safe against path and permission drift.

It does not defend against a malicious arbitrary local user, local administrator/root, kernel compromise, or a hostile host. Any authenticated local user can intentionally hold the lock or corrupt diagnostic metadata and thereby deny WinkYou service. Because ordinary official processes must be able to trip the writable fixed file, a malicious local user can also forge a new latch/record, including a clear one; the checksum detects torn or accidental corruption, not hostile modification. Such a user can already run an arbitrary network program and is outside this governor's threat boundary. This does not grant a cooperative official process a second governor or bypass another process's held OS lock. Containers do not constitute host-wide machine authority unless a future design provides a trusted shared host namespace.

There is intentionally no automatic fallback to a per-user or per-data-directory governor. The separately reviewed `user_acknowledged` foundation is now implemented only behind the local `wink diagnose --governor-scope=user-acknowledged` flag. It is a distinct lower capability, is rejected when machine scope is ready, and still performs no active network I/O. See [`USER-ACKNOWLEDGED-SCOPE.md`](./USER-ACKNOWLEDGED-SCOPE.md).

## Integration state

`internal/governor.AcquireMachineNamespace` validates the canonical namespace before acquiring ownership. Governor construction refuses tripped, corrupt, missing, or latch/record-mismatched safety-trip state. `Governor.Trip` persists the latch, synchronously signals every attempt to stop, and lets the governor's bounded drain controller revoke the leases only after registered I/O witnesses finish or time out; restart tests prove that a new governor remains blocked until an explicit sequence-bound reset. See [`CANCELLATION-DRAIN-CONTRACT.md`](./CANCELLATION-DRAIN-CONTRACT.md). The pairing journal now has a machine-owner-bound storage and policy evaluator, but no admission gate or carrier consumes it. The `wink diagnose` integration remains passive-only. Its explicit user-scope mode only prepares, acquires, proves, and releases the lower per-user authority. No legacy runtime, solver strategy, active `doctor` probe, STUN path, recovery loop, `noisecore` session, or `connect_test` is wired to the journal. Therefore this foundation alone does not make current active networking safe and does not authorize live or production testing.

The zero-network pairing admission gate and process-external emission witness
are now implemented and remain intentionally unconnected; see
[`PAIRING-ADMISSION-GATE.md`](./PAIRING-ADMISSION-GATE.md). Any later active-I/O
integration must fail before opening a socket if machine ownership, safety
state, ledger admission, or the governed attempt lease is unavailable, and
must route every permitted probe through `probeio`.
