# Explicit user-acknowledged safety scope (Phase 1a foundation)

Status: implemented as a no-network scope proof for `wink diagnose`; no STUN,
connect-test, runtime, recovery, mapping, prediction, or birthday-punch I/O is
wired to it.

## Why this scope exists

The machine governor remains the normal authority for any official WinkYou
process that can send packets. A portable tarball or restricted enterprise
account may be unable to install that namespace on its first run. The only
current downgrade is an explicit local command-line acknowledgement:

```text
wink diagnose --governor-scope=user-acknowledged
wink diagnose --governor-scope=user-acknowledged --json
```

The flag belongs only to `diagnose`. Configuration files, environment
variables, imported state, JSON-RPC, coordinator messages, and peer messages
cannot select it. It is never persisted and never becomes a default. Every
invocation prints a warning to stderr; JSON remains isolated on stdout.

If the canonical machine namespace is already ready, user scope acquisition is
rejected. A caller cannot deliberately create two official authorities by
choosing the weaker scope.

The implementation checks machine readiness both before and immediately after
acquiring the per-user authority. Installing machine scope concurrently after
those checks is still an administrator/installer race across two different OS
namespaces. It is harmless in this no-network slice, but must be closed by the
active-I/O design before user scope is allowed to send packets.

## Canonical per-user namespace

The path is derived from operating-system identity, not from WinkYou config or
a caller-controlled data directory:

| Platform | Canonical namespace |
| --- | --- |
| Windows | the OS-resolved LocalAppData known folder plus `WinkYou-SafetyUserV2` |
| Linux | `/run/user/<effective-uid>/winkyou-safety-v2` |

Windows uses a protected, non-inherited DACL. The current user, LocalSystem,
and built-in Administrators have full control, and the current user owns the
directory and its three fixed files. `%LOCALAPPDATA%` cannot redirect the path.

Linux requires the runtime parent to be a real directory owned by the effective
UID with exact mode `0700`; group identity is deliberately not an authority.
The namespace is also mode `0700`, and its fixed files are mode `0600`.
`XDG_RUNTIME_DIR`, `HOME`, and WinkYou configuration cannot redirect it.

Both platforms reject a precreated incomplete path, symbolic link or Windows
reparse point, unexpected owner or permission/ACL drift, special file, and
extra hard link. Preparation is create-only or idempotent; it never silently
repairs or adopts an unsafe path.

The fixed files have the same roles as machine scope:

- `governor.lock`: operating-system serialization authority;
- `governor.owner.json`: best-effort diagnostic metadata only;
- `safety-trip.json`: fail-closed state for this restricted authority.

On Linux `/run/user/<uid>` is normally tied to the login/runtime lifecycle, so
this state is not a reboot-persistent machine kill switch. In a container it is
only a user/container scope unless a future trusted host integration supplies a
shared authority. The report and warning state that limitation continuously.

## A distinct, lower capability

User scope is represented by `RestrictedUserGovernor`, not `*Governor`. The
generic constructor rejects the user-acknowledged profile. The restricted API
does not accept an arbitrary operation or a heavyweight bit; it exposes only
diagnostic and one-shot paired connect-test attempt constructors.

The compiled ceiling cannot be raised by runtime configuration:

| Limit | Ceiling |
| --- | ---: |
| active peers | 1 |
| active attempts | 1 |
| attempts per peer | 1 |
| heavyweight attempts | 0 |
| attempt duration | 15 seconds |
| cancellation drain | 1 second |
| sockets | 4 |
| targets | 8 |
| packets per second | 8 |
| total packets | 64 |
| five-tuples | 8 |

The only compiled operation names are `diagnose` and `connect_test`. Node
runtime, automatic recovery, port mapping, prediction, birthday punching,
background daemons, and parallel heavyweight attempts remain forbidden.

## Current diagnose behavior

The explicit invocation may create the protected per-user files, acquire the
OS lock, write owner metadata, and release the lock before returning. This is a
local safety-namespace mutation, not network activity. The structured report
records explicit acknowledgement, machine-wide=false, persistent-default=false,
the allowlist and hard limits, acquisition/policy-verification/release results,
selected per-user namespace state, and the separate machine namespace state.

It still always reports:

```text
active_probe.state = active_probe_blocked
network_activity_started = false
```

No production Datagram factory or third-party networking library is reachable
from this path. The next active-I/O slice must separately review same-socket
STUN and test-only pairing, route all socket creation through `probeio`, and add
per-user trip/reset operator semantics before sending any packet.

## Persistence and removal

Creating the namespace does not persist activation. The files remain so later
explicit invocations contend on the same identity and observe prior safety
state. Normal diagnose runs never delete or repair them.

There is no cleanup command in this slice. An installer/uninstaller may remove
the per-user namespace only as an explicit user-owned uninstall action after it
has proved that no authority holds the lock. Removal creates a fresh safety
identity on the next explicit invocation, so it must never be used as an
automatic error-recovery or trip-reset mechanism.

## Threat boundary

This scope prevents accidental multiplication among cooperative official
processes for one OS user in the same host/container namespace. It does not
serialize other users, host processes outside a container, arbitrary network
programs, an administrator/root actor, or a malicious process running as the
same user. It is an explicitly acknowledged first-run compromise, not a claim
of machine-wide safety and not authorization for production networking.
