# Windows Virtual-TCP Alias Crash Recovery (2026-07-20)

Status: accepted for an A-process hard crash and same-scope, same-mapping
restart in the trusted A/B/C field cohort. B and C remained running throughout
the accepted experiment. This is not acceptance of machine reboot, OS
autostart, simultaneous cold start, or transparent system L3.

## Why A was the failure target

A was the operator-controlled Windows node and owned the two selected-port ULA
facades, `[fd00::b]:22` and `[fd00::c]:22`. Killing only A therefore exercised
the operationally relevant failure: the local WinkYou process disappeared
without running its alias cleanup, while B and C continued to maintain their
own direct mesh edge. No physical host was powered off and no B/C process was
restarted.

## Failure exposed by the first attempt

The pre-fix experiment hard-killed A PID `84400`. Windows correctly retained
the two ActiveStore loopback addresses because graceful cleanup never ran, but
the old alias manager had no durable proof that the new process was entitled to
adopt them. Four guarded launch attempts therefore failed closed with:

```text
system ingress ipalias: address already exists: fd00::b
```

This was an alias-lifecycle gap, not a Windows permission failure, a mesh
reachability failure, or a coordinator dependency. The failed attempt was
retained as `A-crash-rejoin-20260720t0650z` in the gitignored field evidence.

## Crash-safe ownership design

The managed autonomous `wink up` path now uses the Windows owned alias manager,
which stores one durable journal and one machine-wide lifecycle lock per
interface/address under:

```text
%ProgramData%\WinkYou\system-ingress-ipalias
```

The journal binds an alias to all of the following:

- a stable owner scope derived from the cleaned absolute runtime-state path and
  node ID;
- a canonical fingerprint of the complete `virtual_tcp_forwards` set;
- the current PID, Windows process-start identity, runtime instance ID, and a
  fresh random ownership token; and
- the loopback interface, address, required `/128` and `SkipAsSource=true`
  shape, lifecycle phase, and Windows address-row creation timestamp.

Creation is journaled as `intent -> active`; deletion is journaled as
`active -> deleting -> marker removal`. Marker replacement is atomic and
write-through. A never-deleted sidecar lock is held with `LockFileEx` while a
process owns the address and is released by Windows when that process dies.
The lower-level `meshnode --virtual-tcp-forward` path continues to use
process-local alias ownership and is not covered by this recovery claim.

A later process may adopt an existing address only when the stable scope and
virtual-forward mapping set match, the recorded process generation is no longer
alive, the address still has the exact owned shape, and the Windows row identity
matches the active journal. The new process keeps the same row and writes its
own generation identity and token. A live owner, markerless address, different
scope/mapping set, malformed journal, changed row, or unexpected address shape
fails closed without changing the alias.

Deletion performs the same token, shape, and row-identity preflight before
calling `netsh` and refuses a row that has already been replaced. This does not
close the privileged concurrent-replacement TOCTOU described below. A normal
`wink down` still removes the aliases and journals; durable ownership exists to
make abnormal-exit recovery safe, not to turn the ULA into a persistent system
address.

## Accepted field experiment

Candidate binary SHA-256:
`F6AE485151F8F94D1CEB573D9F7E7CA826E8278FDD2C64B37E64AAAE01E8DA23`.
The frozen A configuration SHA-256 was
`B63AF6AD5DD26E2F541356E6EB982599D81EA0A69D6EAE668FBB69D027C1C3A7`.

The accepted attempt was
`A-alias-crash-rejoin-20260720t0824z`:

| Checkpoint | Result |
| --- | --- |
| Old A generation | PID `75160`, instance `90127545777a295f620d981f3a209819` |
| Hard crash | confirmed at `2026-07-20T08:30:56Z` |
| Deliberate A outage | 40 seconds; no WinkYou process and no alias cleanup |
| Restart | one launch at `08:31:36Z`; new state published at `08:31:41Z` |
| New A generation | PID `71440`, instance `a142c6a4c394f80270fa168cbbf7a369` |
| Direct triangle healthy | `08:33:33Z`, about 112 seconds after new state |
| Stability hold | 120 seconds, completed at `08:35:35Z` |

During the outage, both ULA rows remained ActiveStore-only loopback `/128`
addresses with `SkipAsSource=true`. Their lifecycle locks were released by the
OS. After restart, the stable owner scope, configuration fingerprint, and both
row-creation identities were unchanged; PID, process-start identity, instance
ID, and random tokens changed to the new generation. There was no manual
`netsh` command, alias removal, or service cleanup between crash and restart,
and stderr contained no `address already exists` failure.

B PID `19076` and C PID `18069` were not restarted. C's completed independent
observer collected 509 samples, never reported an infrastructure coordinator,
and recorded zero B-direct status failures. It did record 18 active ping
failures to B and 72 expected ping failures to A around the outage, so this is
recovery evidence rather than a zero-packet-loss claim. The B observer left
valid samples showing B-C remained one-hop and reachable but its test wrapper
exited without a final receipt; its incomplete aggregate is not used as an
acceptance count.

After recovery, all six directed A/B/C WinkYou ping paths completed, with
observed successful RTTs roughly 37-61 ms; one B-to-C probe required a retry.
Normal IPv6 SSH also completed through A's `[fd00::b]:22` and `[fd00::c]:22`
facades and returned the expected remote hostnames. Final A status had direct
one-hop routes to B and C, `infrastructure_coordinator=false`, and
`data_dropped=0`.

## Source validation

The accepted source passed:

```text
go test -race ./pkg/systemingress/ipalias ./pkg/meshruntime ./pkg/client -count=1
go test -p 1 ./... -count=1
go vet ./...
git diff --check
```

The ownership tests cover hard-exit recovery without a second address-add,
cross-process lock exclusion, markerless and mismatched fail-closed behavior,
dead/live process generations, intent/deleting crash windows, address-row
replacement, cleanup retry, and refusal to delete a replacement row.

## Evidence and remaining boundary

The JSON snapshots, observers, stdout/stderr, and watchdog receipts remain under
the test host's gitignored
`.live-run/runs/wink-autonomous-rollout-20260719-r1/evidence/process-rejoin/`
directory. They are local field evidence, not committed repository artifacts.

The accepted threat model is still the project's current trusted/equal-node
stage. Windows DACL hardening against a hostile local administrator remains
future security work. In the narrow `intent` crash window, Windows has not yet
provided a row-creation timestamp, so recovery can verify only the journal and
the exact address shape. A privileged operator could also replace an address
between the final pre-delete check and `netsh`; preventing that TOCTOU requires
a stronger system backend. Pre-existing markerless/manual aliases are never
adopted and may require one-time operator cleanup after upgrading an older
build.

This change makes a supervised process restart viable but does not itself
provide a supervisor. Later on 2026-07-20, A completed an A-only field migration
to the repository's Task Scheduler child supervisor and passed a second
forced-child-exit test; see
`WINDOWS-SUPERVISOR-FIELD-2026-07-20.md`. B/C supervision, OS reboot,
simultaneous cold start, public-IP change, and longer retention remain open.
The facade remains selected-port userspace TCP and does not add arbitrary TCP,
UDP, ICMP, subnet routing, exit-node routing, Wintun, or WireGuard.
