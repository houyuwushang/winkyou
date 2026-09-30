# Gate C childstream close investigation

Status: production fix authorized in an independent Draft PR (2026-09-30).
The change is limited to `Stream.Close()` and required private state; the
two-second `DrainTimeout`, stream signatures, and callers remain unchanged.

## First signature

The hosted Windows full-suite signature is
`TestWindowsPipeKeepsCloseBasedCancellationWithoutNativeDeadlines` hanging in
`Stream.Close` while `reader.Close()` waits for an in-flight Windows pipe read.
The first RED is retained externally; this PR adds a bounded close witness
before changing any implementation.

## Witness and reproduction contract

The Windows test runs `Stream.Close` in a goroutine with a five-second witness
deadline. A timeout records only a fixed failure class, a count of goroutines
whose stack is in `[syscall]`, and read-only pipe handle metadata (file type and
named-pipe information where available). Stack text, paths, handles, host
names, and user data are never logged. Independent `-race -count=500` and
full-suite-like `-race -count=50` batches retain their first results without
rerun-for-green behavior.

The investigation also records the Go 1.23.1 `internal/poll` `kindPipe`
close path and whether `CancelIoEx` is invoked and whether its result is
observed. This is evidence only; it does not alter the Windows or Linux code.

The relevant Go 1.23.1 source is `src/internal/poll/fd_windows.go`: `FD.Close`
calls `CancelIoEx` for `kindPipe`, evicts the poll descriptor, decrefs the
handle, and then synchronously waits on `runtime_Semacquire(&fd.csema)`
(lines 383-397 in the reviewed toolchain). A cancellation that does not finish
the in-flight `ReadFile` therefore blocks the caller before the old
`DrainTimeout` select is reached. The first hosted Windows RED showed exactly
that stack shape for ten minutes; the local native-pipe witness is retained as
a bounded observation because cancellation can also succeed on an individual
run.

The deterministic Windows regression keeps the real pipe `ReadFile` active and
uses a test-only Close gate to model the observed OS wait without sleeping or
depending on scheduler luck. Before the fix, `Stream.Close` remains blocked
past `DrainTimeout+500ms` in that fixture; after the fix, it returns
`ErrDrain` within the existing two-second bound with `Drained=false`, and the
released worker completes the operation witness. A separate native-pipe test
accepts either normal drain or bounded `ErrDrain`, but rejects an unbounded
return. The existing two-second drain number, Linux behavior, and all other
budgets remain unchanged.
