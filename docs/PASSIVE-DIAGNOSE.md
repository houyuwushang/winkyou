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

## Passive evidence

The current report includes:

- build and operating-system identity;
- canonical machine namespace validation;
- actual OS lock state plus best-effort owner PID, instance, build, and scope;
- persistent safety-trip state;
- configuration presence and validation state, without configuration values;
- local interface names, flags, MTU, and address classes, without IP or MAC
  addresses; and
- the IPv4 default-route interface, without the gateway address.

On Windows the default route is read with a bounded `Get-NetRoute` subprocess.
On Linux it is read from `/proc/net/route`. Neither path changes a route. Lock
inspection briefly takes and releases an idle OS lock only to prove that it is
available; it never creates an instance ID or rewrites owner metadata.

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

There is no silent per-user or per-directory fallback. This slice does not
implement `--governor-scope=user-acknowledged`, STUN, NAT classification,
connect-test, a production Datagram factory, or any recovery behavior.

## Privacy status

The schema is `winkyou.diagnose/v1alpha1` and currently declares
`redaction: partial`. Raw interface addresses, MAC addresses, gateway addresses,
and configuration values are omitted. Interface names, the canonical namespace
path, and machine-owner diagnostics remain visible, so this output is not yet
the separately planned `export_redacted_report` artifact. Review it before
publishing.
