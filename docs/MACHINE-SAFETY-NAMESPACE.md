# Machine Safety Namespace (Phase 1a)

Status: implemented safety foundation; not yet wired to legacy or v2 active network paths.

## Decision

Official WinkYou processes that may perform active connectivity work will share one machine-wide governor authority. Its location is fixed by the build and operating system, not by `--config`, `--state`, an environment variable, a Mesh identifier, or a local API request:

| Platform | Canonical namespace |
| --- | --- |
| Windows | the OS-resolved ProgramData known folder plus `WinkYou-SafetyV2` |
| Linux | `/var/lib/winkyou-safety-v2` |

The directory contains two fixed files:

- `governor.lock`: the operating-system lock authority;
- `governor.owner.json`: best-effort diagnostic metadata only.

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

The namespace directory and both files use protected, non-inherited DACLs and an `Administrators` owner:

- `LocalSystem` and built-in `Administrators`: full control;
- `Authenticated Users` on the directory: list, traverse, read attributes, synchronize, and read permissions;
- `Authenticated Users` on the two files: generic read and write, without delete, owner, or DACL rights.

This lets an ordinary official process acquire the lock and refresh diagnostic metadata while preventing it from creating, deleting, renaming, or replacing the fixed files. The ProgramData path comes from the Windows Known Folder API, so changing `%ProgramData%` cannot redirect the authority.

### Linux

The direct parent must be a real, root-owned directory that is not writable by group or others. The namespace is `root:root` mode `0755`; both fixed files are `root:root` mode `0666`. The validator rejects symbolic links, special files, extra hard links, special mode bits, and extended POSIX access ACLs.

World-writable fixed files are deliberate: an unprivileged official process must be able to lock and update them, while the non-writable directory prevents replacement or deletion. The lock file is retained after release so contenders never split across file identities.

## Threat boundary

This boundary prevents accidental budget multiplication across official WinkYou processes, Meshes, and configurable data directories. It is fail-safe against path and permission drift.

It does not defend against a malicious arbitrary local user, local administrator/root, kernel compromise, or a hostile host. Any authenticated local user can intentionally hold the lock or corrupt diagnostic metadata and thereby deny WinkYou service. That is a local denial of service, not permission to create a second official governor or to bypass a held OS lock. Containers do not constitute host-wide machine authority unless a future design provides a trusted shared host namespace.

There is intentionally no automatic fallback to a per-user or per-data-directory governor. The separately reviewed `user_acknowledged` diagnostic scope has not been implemented in this slice.

## Integration state

`internal/governor.AcquireMachineNamespace` validates the canonical namespace before acquiring ownership. The resource governor and lease hierarchy can consume that owner, but no legacy runtime, solver strategy, `doctor` probe, or recovery loop is wired to it yet. Therefore this foundation alone does not make current active networking safe and does not authorize live or production testing.

The next active-I/O integration must fail before opening a socket if machine ownership cannot be acquired, and must route every permitted probe through the future `probeio` enforcement point.
