# Gate C childstream close investigation

Status: test-only witness/reproduction Draft PR. No production change is
authorized in this branch. If the witness proves that a Windows synchronous
pipe `reader.Close()` can block without a bound while a `ReadFile` is active,
work stops and the production fix is proposed for separate approval.

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

If `os.File.Close` returns within the witness deadline and all reads join,
the issue remains a fixture classification. If it does not, the result is a
production defect candidate: stop before a production commit and report the
smallest approved design (independent close worker, bounded `DrainTimeout`
wait, `ErrDrain`/`Drained=false`, and eventual background close) for explicit
authorization. The existing two-second drain number, Linux behavior, and all
other budgets remain unchanged.
