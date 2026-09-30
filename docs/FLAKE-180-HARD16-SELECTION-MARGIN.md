# Hard16 selection-margin fixture investigation

Status: investigation in a test-only Draft PR. This document preserves the
first `TestGateB3Hard16SelectionUsesActiveMarginAfterCandidateWindow` failure
and constrains the diagnosis before any change is made.

## First signature

The Windows/Linux governed-package signature is the selection-margin fixture
reporting `writes=6` while the delayed responder write ordinal 7 was never
reached. The existing assertion runs before either endpoint outcome is
printed, so this PR first adds only fixed-label endpoint, emission, delayed
write, and progress-stage evidence.

## Investigation contract

The witness records only error classes/types, terminal state, emission counters,
write ordinal and relative nanoseconds, and fixed progress stage names. It does
not print addresses, artifact material, stream bytes, IDs, paths, or raw error
text. Reproduction uses Go 1.23.1, `GOMAXPROCS=2`, two busy goroutines,
`-race -count=200`, followed by the required six-package race batch at
`-count=20`; the first RED is retained without a green-seeking rerun.

Classification is limited to the approved choices:

1. fixture compression: measured candidate completion exceeds the two-second
   test fixture window; derive only the test fixture window from the measured
   maximum (`ceil(max*1.5/0.5s)*0.5s`) and keep the production 38/45/2-second
   constants unchanged;
2. legal frame-shape variation: identify the first selection-status frame by
   frame type rather than assuming write ordinal 7;
3. production defect: stop this PR and open a separate issue if the evidence
   shows an incorrect production terminal inside the frozen two-second window.

No retry, sleep, candidate-count change, production budget change, or weakened
   assertion is permitted. Issue #180 is closed only if a non-zero reproduction
   rate becomes zero under the same load after an allowed test-only fix;
   otherwise this PR keeps `Refs #180`.

## Reproduction evidence

The focused selection-margin reproduction completed before the package batch. It
used Go 1.23.1, `GOMAXPROCS=2`, exactly two busy goroutines, the opt-in
`WINKYOU_FLAKE_180_CPU_STRESS=1`, and the required race count:

```text
go test -race ./internal/governor \
  -run '^TestGateB3Hard16SelectionUsesActiveMarginAfterCandidateWindow$' \
  -count=200 -failfast -timeout=25m
PASS (200/200), 924.602s
log SHA-256: BE24D52FD72A1252B431B288483D1F6F0DB6D60F7D87B4DCEA9A76D9DF42C2CC
```

No selection-margin witness was emitted because the target test did not fail;
therefore no fixture-window derivation or production diagnosis is authorized
by this run.

The required six-package first batch was then run once, with the same Go
version, `GOMAXPROCS=2`, stress setting, race detector, and `-count=20`:

```text
go test -race ./internal/v2/rendezvouscarrier ./internal/stunobserve \
  ./internal/probeio ./internal/governor ./internal/architecture \
  ./internal/v2/directattempt -count=20 -timeout=45m
```

The first three packages passed (`rendezvouscarrier` 106.276s,
`stunobserve` 13.604s, `probeio` 373.407s). `architecture` passed in
2075.696s and `directattempt` passed in 3.236s. The batch was RED because
`internal/governor` reached its 45-minute package timeout in
`TestLoopbackTwoPhaseStalledFinishHasBoundedVerdictAndRetainsOwner`; this is
the existing #111 absence/finish signature and is not a #180 failure. The
same batch also recorded the already-open B2 asymmetric admission/expiry
signature tracked by #156 (the `target_initiates` role in this run, rather
than #156's `mapping_initiates` role). It is recorded only and is not changed
in this PR. The batch log SHA-256 is
`7844D1C777D2A307540A50A2EDCB19C6BC6CEE790F5F25B50BD4449656010B33`.

Because the focused #180 test had zero failures and the six-package REDs are
independent registered signatures, this PR contains witness and evidence only:
no candidate window, packet budget, frozen production constant, retry, or
assertion was changed. The issue remains `Refs #180`; no rerun was performed
to replace the first RED.
