# Phase 1a passive diagnose

`wink diagnose` is the first-run, no-packet entry point for the v2 plan. It is
separate from the legacy `wink doctor`, whose coordinator, STUN, and optional
TCP checks can perform active network operations.

```powershell
wink diagnose
wink diagnose --json
```

The command does not require a configuration file or an installed machine
scope. A missing or unsafe scope is part of the report rather than a reason to
discard all other local evidence. The command exits successfully when it can
produce the report, while the `active_probe` section remains fail-closed.

Restricted portable users can explicitly prove the separately bounded
per-user authority:

```powershell
wink diagnose --governor-scope=user-acknowledged
wink diagnose --governor-scope=user-acknowledged --json
```

This local flag is the only activation path. It cannot come from configuration,
environment, persisted state, JSON-RPC, coordinator, or peer input and is never
remembered as a default. It prints a non-machine-wide warning to stderr.

## Passive evidence

The current report includes:

- build and operating-system identity;
- canonical selected namespace validation and, in explicit user mode, the
  separate machine namespace state;
- actual OS lock state plus best-effort owner PID, instance, build, and scope;
- safety-trip state (machine-persistent for machine scope; subject to the
  documented OS-user runtime lifecycle for explicit user scope);
- configuration presence and validation state, without configuration values;
- local interface names, flags, MTU, and address classes, without IP or MAC
  addresses; and
- the IPv4 default-route interface, without the gateway address.

On Windows the default route is read with a bounded `Get-NetRoute` subprocess.
On Linux it is read from `/proc/net/route`. Neither path changes a route. Lock
inspection briefly takes and releases an idle OS lock only to prove that it is
available; it never creates an instance ID or rewrites owner metadata.

Explicit user mode is the exception to that last read-only property: after the
flag warning it may create the protected canonical per-user files, acquire the
lock, write diagnostic owner metadata, and release it. This remains local
filesystem safety setup; it does not start network activity. The report records
the acquisition and release result, compiled allowlist and hard limits, and
that the authority is neither machine-wide nor a persistent default. See
[`USER-ACKNOWLEDGED-SCOPE.md`](./USER-ACKNOWLEDGED-SCOPE.md).

## Active probe boundary

This slice always reports:

```text
active_probe.state = active_probe_blocked
network_activity_started = false
```

The reason and action distinguish a missing/unsafe machine scope, an existing
owner, a safety trip, invalid configuration, and the current `passive_only`
implementation boundary. A missing scope returns the copyable repair action:

```text
wink setup-machine-scope
```

There is no silent per-user or per-directory fallback. The explicit
`user-acknowledged` foundation now exists, but this slice still does not
implement STUN, NAT classification, connect-test I/O, a production Datagram
factory, or any recovery behavior. Its successful scope proof therefore ends
with reason `user_acknowledged_passive_only`; an unsafe or contended scope is
reported as `user_acknowledged_scope_unavailable`.

## Privacy status

The schema is `winkyou.diagnose/v1alpha1` and currently declares
`redaction: partial`. Raw interface addresses, MAC addresses, gateway addresses,
and configuration values are omitted. Interface names, the canonical namespace
path, and machine-owner diagnostics remain visible, so this output is not yet
the separately planned `export_redacted_report` artifact. Review it before
publishing.
