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

## RED/GREEN and mutation evidence

The pre-fix deterministic regression was run once with Go 1.23.1, Windows,
`GOMAXPROCS=2`, and `-race -count=20`. All 20 injected blocking-close cases
exceeded `DrainTimeout+500ms` and failed the bounded-return assertion; the
native-pipe cases in the same command did not fail. The first log is retained
outside the repository with SHA-256
`81D1381D1C07D05FAEF3ACB854E37355C62AF54C7157B594A8506CC4FF26B3B2`.
An earlier native-only `-race -count=500` run passed in 1.668s
(`E0AC4384AE816D9A8194B53E1EDF0BA5A451F3534B7F62B8989278CF24BB18C7`);
that result is why native cancellation is treated as either normal drain or
bounded `ErrDrain`, not as a deterministic failure.

After the `Close` worker implementation, the focused native/injected
`-race -count=20` batch passed in 41.794s. The full
`go test -race ./internal/v2/gatecchildstream -count=20` batch passed in
42.229s with final log SHA-256
`FC5DAFE25D67E3B0E45BA7DD82A7E0B035FC0D2E73B02228AECB4BC89F2559ED`.
The required Windows injected `-race -count=200` then passed in 401.248s
with log SHA-256
`15BAD8BDE6739F8FDDD6A5E24856CC2155881027C91313D80F92F22FAC08F92B`.

Three temporary mutations were each rejected by the injected regression and
were reverted before the production commit was finalized:

| Mutation | Result |
| --- | --- |
| remove the close worker goroutine | RED: outer witness timed out at 2.5s; `32D1673660993E9877F6A42D24A154DFFCBC8487469276126925E0A372A39277` |
| set timeout `closeErr` to `nil` | RED: returned nil instead of `ErrDrain`; `6254A5267BCF2B788EE71AE5D8E7867F609993F5FF3A1D698A8353FA2B6B7B57` |
| set timeout `Witness.Drained` to `true` | RED: drained witness contradicted `ErrDrain`; `A4B211E2AE34770F6E7A3DA57C37132DFAD730A1C9DC7E8C054AA999075599FB` |

## `Stream.Close` call-site treatment

- `internal/v2/gatecchildstream/stream.go`: internal deadline, budget, and
  constructor-failure paths. Budget/deadline goroutines deliberately ignore
  the returned error because the stream witness and caller-owned terminal path
  carry the result.
- `internal/v2/oobcarrier/carrier.go:927`: captures the returned error. Any
  `ErrDrain` is converted into the existing carrier transport/drain failure;
  it is not retried and does not mark the carrier drained.
- `internal/v2/gatecorchestrator/orchestrator.go:38`: only constructs the
  stream; ownership and close handling remain in the carrier.
- `internal/v2/gatecchildstream/*_test.go` and Linux diagnostic tests: direct
  assertions/cleanup only. They now accept the native bounded outcomes and
  require the injected timeout contract.

The similarly named `sshassembly.Stream.Close` calls are a different stream
type and are outside this fix's authorized scope; they were not changed.
