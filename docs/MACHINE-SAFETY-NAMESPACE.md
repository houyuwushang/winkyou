# Machine Safety Namespace (Phase 1a)

Status: implemented safety foundation; not yet wired to legacy or v2 active network paths.

## Decision

Official WinkYou processes that may perform active connectivity work will share one machine-wide governor authority. Its location is fixed by the build and operating system, not by `--config`, `--state`, an environment variable, a Mesh identifier, or a local API request:

| Platform | Canonical namespace |
| --- | --- |
| Windows | the OS-resolved ProgramData known folder plus `WinkYou-SafetyV2` |
| Linux | `/var/lib/winkyou-safety-v2` |

The directory contains three fixed files:

- `governor.lock`: the operating-system lock authority;
- `governor.owner.json`: best-effort diagnostic metadata only.
- `safety-trip.json`: a persistent fail-closed latch and checksummed diagnostic record.

Metadata never proves ownership. A stale, corrupt, or user-modified metadata file cannot override the OS lock.

## Setup and read-only inspection

An installed package should prepare this namespace. Portable users can do the same explicitly:

```text
wink setup-machine-scope
```

Creating the namespace requires an elevated terminal on Windows or root on Linux. Once it is valid, an ordinary user can run the command again as an idempotent validation. A precreated path, permission drift, unexpected owner, symbolic link/reparse point, hard-linked owner file, or unexpected ACL fails closed; setup does not silently repair or adopt it.

Inspection never changes the machine:

```text
wink setup-machine-scope --check
wink setup-machine-scope --check --json
```

Both modes explicitly report that no WinkYou runtime or network activity was started. The command does not open sockets, change routes, start a daemon, enable recovery, or remove the existing emergency stop.

## Permission model

### Windows

The namespace directory and all three files use protected, non-inherited DACLs and an `Administrators` owner:

- `LocalSystem` and built-in `Administrators`: full control;
- `Authenticated Users` on the directory: list, traverse, read attributes, synchronize, and read permissions;
- `Authenticated Users` on the three files: generic read and write, without delete, owner, or DACL rights.

This lets an ordinary official process acquire the lock and refresh diagnostic metadata while preventing it from creating, deleting, renaming, or replacing the fixed files. The ProgramData path comes from the Windows Known Folder API, so changing `%ProgramData%` cannot redirect the authority.

### Linux

The direct parent must be a real, root-owned directory that is not writable by group or others. The namespace is `root:root` mode `0755`; all three fixed files are `root:root` mode `0666`. The validator rejects symbolic links, special files, extra hard links, special mode bits, and extended POSIX access ACLs.

World-writable fixed files are deliberate: an unprivileged official process must be able to lock and update them, while the non-writable directory prevents replacement or deletion. The lock file is retained after release so contenders never split across file identities.

## Persistent safety trip

The trip file begins with a one-byte latch followed by a checksummed, versioned JSON record. Trip commits the blocking latch and syncs it before closing attempt leases at that commit point and writing diagnostic detail. Reset writes and syncs a complete clear record while the latch remains tripped, then clears and syncs the latch last. A torn write, checksum mismatch, unknown schema, missing file, or latch/record disagreement is `indeterminate` and blocks active work.

The first valid trip reason is retained. A process restart, different CLI command, different Mesh, or different data directory cannot clear it. Reset is sequence-bound so an operator cannot accidentally clear a newer trip than the one inspected. Automated recovery and peer events never receive reset authority. The store exposes read-only inspection and an elevated, exclusive-owner, sequence-bound reset API; operator CLI commands are the next stacked slice.

This slice intentionally does not expose a standalone operator trip command: without the future local control channel or a probe-I/O latch watcher, such a command could write a marker while falsely implying that an already-running process had stopped sending. Active authorities call `Governor.Trip` directly; an independent operator kill switch remains a separately reviewed integration.

## Threat boundary

This boundary prevents accidental budget multiplication across official WinkYou processes, Meshes, and configurable data directories. It is fail-safe against path and permission drift.

It does not defend against a malicious arbitrary local user, local administrator/root, kernel compromise, or a hostile host. Any authenticated local user can intentionally hold the lock or corrupt diagnostic metadata and thereby deny WinkYou service. Because ordinary official processes must be able to trip the writable fixed file, a malicious local user can also forge a new latch/record, including a clear one; the checksum detects torn or accidental corruption, not hostile modification. Such a user can already run an arbitrary network program and is outside this governor's threat boundary. This does not grant a cooperative official process a second governor or bypass another process's held OS lock. Containers do not constitute host-wide machine authority unless a future design provides a trusted shared host namespace.

There is intentionally no automatic fallback to a per-user or per-data-directory governor. The separately reviewed `user_acknowledged` diagnostic scope has not been implemented in this slice.

## Integration state

`internal/governor.AcquireMachineNamespace` validates the canonical namespace before acquiring ownership. Governor construction refuses tripped, corrupt, missing, or latch/record-mismatched state. `Governor.Trip` persists the latch and closes all current attempt leases; restart tests prove that a new governor remains blocked until an explicit sequence-bound reset. No legacy runtime, solver strategy, `doctor` probe, or recovery loop is wired to this package yet. Therefore this foundation alone does not make current active networking safe and does not authorize live or production testing.

The next active-I/O integration must fail before opening a socket if machine ownership cannot be acquired, and must route every permitted probe through the future `probeio` enforcement point.
