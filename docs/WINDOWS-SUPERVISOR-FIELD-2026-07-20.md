# Windows Child-Supervisor Field Acceptance (2026-07-20)

Status: accepted for an A-only Wink process crash while B and C remained
running. The accepted path uses a Task Scheduler action that runs the bundled
PowerShell child supervisor; it does not rely on Task Scheduler directly
restarting a killed Wink action. Machine reboot and B/C rollout remain open.

## Scope

A was already running the managed autonomous product path with two selected
ULA TCP facades and recovery-card state. The test changed only A's local process
lifecycle. It did not restart B or C, power off a host, introduce an
infrastructure coordinator, enable a user-data relay, or use Wintun/WireGuard.

The tested Wink binary was built at `59083eb` (including parent `c8a689e`) and had
SHA-256:

```text
8C8230F7B0A9DC4387D130F5F42713E2CC0B32487A4C35839C06899B3DC49BAC
```

The installed task is `WinkYou-A`. It runs as `SYSTEM` at highest privilege,
uses an `AtStartup` trigger, has no execution time limit, and rejects parallel
task instances. The action launches `run-wink-supervisor.ps1`, which launches
the configured `wink ... up` child and records JSON-line lifecycle events next
to the runtime state.

## Rejected direct-action design

The first version made `wink.exe` the Task Scheduler action and configured
`RestartOnFailure` with a one-minute interval. The XML contained the requested
restart settings. A started under the task as PID `67104` and recovered both
direct edges before the failure test.

PID `67104` was force-terminated at `2026-07-20T20:15:29+08:00`. Task Scheduler
recorded action return code `4294967295` (`0xFFFFFFFF`) and moved the task to
Ready. The two owned ULA rows remained present, as intended, but no replacement
process appeared during more than three minutes of observation. This host
therefore does not support the product claim through direct-action
`RestartOnFailure`, regardless of the settings being present in exported XML.

The operator manually started the task only after that attempt had been marked
failed, to restore A while implementing the child supervisor. That manual
recovery is not counted as supervisor acceptance.

## Accepted two-process design

The accepted task action ran Windows PowerShell supervisor PID `76400`. It
started Wink child PID `46236`. After the ordinary autonomous recovery windows,
A again reached two one-hop `protected_direct` maintained edges.

PID `46236` was force-terminated at `2026-07-20T20:31:07+08:00`; the supervisor
was deliberately left alive. Its log then recorded:

1. child exit code `-1` after 292 seconds of runtime;
2. a restart scheduled after five seconds; and
3. new child PID `10992` at `20:31:12+08:00`.

The new runtime state, with a new instance ID, was observable about 9.1 seconds
after the kill command. Both `fd00::b` and `fd00::c` remained present throughout
the outage, and the task and supervisor stayed Running. No operator launch,
alias cleanup, peer restart, coordinator, or punch command occurred between the
kill and the new state publication.

The new A first recovered a direct edge to C and temporarily reached B through
C. At `20:32:38+08:00`, about 91 seconds after the kill, B also became a one-hop
healthy protected-direct edge. The resulting direct triangle then held for an
additional 149 seconds with the same child PID, supervisor PID, runtime
instance, and task instance.

At both ends of the hold:

- A-to-B `/v1/ping` used request/reply paths `A>B` and `B>A`;
- A-to-C `/v1/ping` used request/reply paths `A>C` and `C>A`; and
- TCP connects to `[fd00::b]:22` and `[fd00::c]:22` succeeded through the two
  loopback ULA facades.

## Clean-stop behavior

An isolated local autonomous node tested the opposite transition without
touching A/B/C. Supervisor PID `41300` started child PID `78972`; authenticated
`wink down` returned zero, removed the runtime state, and made the child exit
zero. The supervisor logged `clean_child_exit`, also returned zero, and did not
start another child. This preserves the existing `wink down` meaning.

For a reliable operator stop during the short interval between a crash and the
next child launch, disable the task and create the configured `.supervisor.stop`
marker before repeatedly calling authenticated `wink down` until the task action
and exact runtime process have both stopped. The reviewed supervisor source
observes the marker while a child is running as well as between launches. The
installer clears the marker only after a deliberate install or reinstall has
been registered and verified; an ordinary re-enable must remove it explicitly
after confirming the old task action has exited.

## Source validation

The deployment scripts passed their built-in self-tests. The installer also
passed a non-mutating `-WhatIf` construction check with the field paths, rejected
the field checkout's low-privilege-writable ACL by default, rejected conflicting
file roles, refused to replace the live A task, and accepted an
administrator-owned protected ProgramData probe with `Users` RX without creating
a task. These post-field hardening checks cover the installer guards. A separate
isolated runtime then proved that
a second supervisor for the same state exits nonzero, a marker created while the
child is running is observed before authenticated `down`, the child/state do not
return after seven seconds, the lock is released, and a pre-existing marker
suppresses startup with exit zero. The complete stop-marker timing matrix remains
a separate field test. Before this supervisor slice, the committed Go tree
passed serial `go test ./...`,
targeted race tests, `go vet ./...`, the monitor's 41 self-tests, and
`git diff --check`.

## Remaining boundary

This acceptance proves recovery from killing the Wink child while its
supervisor and Windows host remain alive. It does not yet prove:

- A machine reboot or power loss;
- failure or forced termination of the supervisor process itself;
- exhaustive stop-marker timing races and a permanent-uninstall field run;
- equivalent Task Scheduler installation on B or C;
- simultaneous cold start of all three nodes;
- public endpoint or public IP changes;
- recovery when every cached discovery candidate is stale; or
- transparent system L3, arbitrary ports, UDP/ICMP, subnet routing, or exit-node
  semantics.

The A task remains installed and running after this experiment. It was installed
before the source ACL guard and its paths point to the current field checkout and
gitignored binary. This is acceptable only for the explicitly trusted field host;
a release deployment must move the binary, supervisor, configuration, and state
directory to administrator-protected stable paths before using the same installer.
The still-live accepted supervisor was also launched before the post-field lock
and running-child marker hardening, so it does not hold the new `.supervisor.lock`;
those additions have isolated source acceptance only and will enter A on a later
controlled restart, not retroactively in PID `76400`.
