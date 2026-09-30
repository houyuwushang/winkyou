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
