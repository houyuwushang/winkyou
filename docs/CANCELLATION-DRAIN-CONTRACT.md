# Phase 1a cancellation drain contract

Status: implementation contract for the fake-only Phase 1a `probeio` boundary.
It does not authorize production sockets, live probing, daemon rollout, or
re-enabling any legacy recovery path.

## Why this exists

Cancelling a Go context or deleting an in-memory lease does not prove that a
socket, pending open, or goroutine has stopped. Releasing the machine namespace
before that proof would allow another official process to start with a fresh
budget while old I/O was still running. This contract makes the machine-wide
governor, rather than a solver or adapter, the cancellation timeout authority.

## Lifecycle

```text
Active
  |
  | Close, parent close, context cancellation, duration limit, or safety trip
  v
Stopping  -- all registered drains complete --> Done
  |
  +-- cancellation timeout --> durable machine safety trip --> forced Done
```

- `AttemptLease.RegisterDrain(name)` registers an attempt-owned cancellation
  witness before active work begins. Registrations are capped at eight.
- `AttemptLease.Stopping()` closes synchronously when cancellation begins. New
  drain registrations, trips through that capability, and active work are then
  rejected.
- Each `DrainHandle.Complete()` is idempotent. `Done()` does not close until all
  registered handles complete, or until the governor has durably failed closed
  after the timeout.
- Phase 1 machine scope has a compiled two-second timeout. The explicitly
  acknowledged user scope has a one-second timeout. Configuration may only
  lower these ceilings.
- `Governor.Close` retains the operating-system namespace owner throughout the
  drain and persists a cancellation safety trip before releasing it on timeout.
  A restart therefore remains blocked until an explicit sequence-bound reset.

The durable latch cannot stop a malicious adapter or a kernel operation that
ignores both cancellation and `Close`. Forced `Done` is logical revocation, not
proof that hostile code disappeared. After a cancellation timeout, an operator
must verify the recorded process is gone before resetting the latch.

## `probeio` witness

Every controller registers `probeio-controller` before it can open a Datagram.
On `Stopping`, it:

1. rejects new opens, sends, receives, registrations, and promotions;
2. cancels the controller lifecycle context;
3. detaches and closes every attempt-owned Datagram;
4. waits for pending factory opens and all admitted send/receive operations,
   including operations on a socket concurrently detached by its caller;
5. completes its drain handle.

The package still contains no production Datagram factory. Tests use fakes to
prove the contract without opening network sockets.

`Promote` is a deliberate ownership handoff: only a reply accepted by the
injected verifier can transfer one fixed-target Datagram; sibling Datagrams are
drained. The promoted transport is no longer attempt-owned. A future production
adapter must not enable this handoff until the receiving session layer has its
own reviewed resource lease and shutdown witness.

## Permanent regression gates

Changes to this boundary must keep tests for:

- normal close waiting for drain completion;
- safety trip waiting for drain completion;
- timeout trip persistence across namespace reacquisition;
- machine owner exclusion while a drain is pending;
- blocked factory opens and reads exiting on cancellation;
- idempotent completion and bounded registration;
- race-enabled governor and `probeio` suites; and
- the AST network capability gate, which keeps this slice fake-only.
