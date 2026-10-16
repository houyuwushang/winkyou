# Hard16 selection-margin fixture investigation

Status (2026-10-16): test-only fixture correction based on hosted measurements;
final first-run validation pending. The original investigation and first REDs
remain below. No production budget or Go production code changes.

## Hosted diagnosis and fixture correction (2026-10-16)

[PR #195's first Linux race job](https://github.com/houyuwushang/winkyou/actions/runs/38836912109/job/116767978442)
recorded `delayed_triggered=false writes=6`, with initiator/responder candidate
counts `15980/15995`, winner counts `0/0`, and carrier reads/writes `6/6`.
The initiator returned `hard_nat_candidate_exhausted`; its peer returned
`oob_stream_closed`. Both reached candidates at approximately 1.167 seconds and
terminal at 3.462/3.464 seconds. The first raw log SHA-256 is
`589ba6a4e996fd5fb2b171f619700b3254755be4e8d3f6f9c331c9fa34c4d28b`.

The candidate deadline in `punchHardCampaign` is real wall time, even when
the test injects a virtual pacing clock. The compressed two-second fixture
deadline can expire under the six-package race load before both fixed 16,384
candidate schedules finish. The remaining 404/389 candidates were not emitted;
the production guard correctly prevents selection after an incomplete schedule.
This failure never exercised the intended selection-margin regression.

The measurement commit `a901d84ca904c9093c1dd3330e80be1815359d58` keeps
the original 10s/2s test unchanged and adds three diagnostic samples using the
existing full-shape fixture's 12s/8s envelope and original 2250ms selection hold.
It preserves the same label, topology, seeds, real protocol and fixed schedule.
The samples run in the original six-package race batch; only verbosity is
added. Both candidate-stage start and the structurally decoded responder
`FrameWinnerSelection` write are timestamped with the same monotonic clock.

[First hosted measurement job](https://github.com/houyuwushang/winkyou/actions/runs/38843908986/job/116789954089),
attempt 1, Go 1.23.1, Linux, default package concurrency:

| Sample | Setup (s) | Candidates through selection entry (s) | Fixed candidates per side |
| --- | ---: | ---: | ---: |
| 1 | 0.889961050 | 1.232937911 | 16384 |
| 2 | 0.911983304 | 1.146648398 | 16384 |
| 3 | 0.930273725 | 1.166400416 | 16384 |

The raw log SHA-256 is
`6255806826a150a7974e4191a046d0d8b0001412cde0978d6d515fb2b6cdf940`.
All samples reached selection ordinal 7, completed with carrier counts 8/8
and exactly one winner across the pair. This discovery job also passed the
original two-second regression; it is a timing sample, not a replacement for
the retained RED or a new deterministic reproduction of that RED.

The same commit's [PR-event first job](https://github.com/houyuwushang/winkyou/actions/runs/38843947881/job/116790077103)
also passed and supplied three slower samples. None are omitted from the bound:

| Sample | Setup (s) | Candidates through selection entry (s) | Fixed candidates per side |
| --- | ---: | ---: | ---: |
| 1 | 1.128995784 | 1.924011685 | 16384 |
| 2 | 1.143771526 | 1.873229526 | 16384 |
| 3 | 1.182657886 | 1.830477448 | 16384 |

Its raw log SHA-256 is
`655c7767d918bbfff3e1f28373886ac0069991beafc9b1738a71da45238e361b`.

Following #180's recorded rule, conservatively include setup as well as the
complete candidate phase across all six samples: maximum = 3.053007469s;
`ceil(max * 1.5 / 0.5s) * 0.5s = 5s`. Only this regression's candidate fixture
changes from 2s to 5s. Its active envelope remains 10s. The production
38s candidate / 45s active / 2s drain budgets and every packet/frame bound
remain unchanged. The diagnostic-only test is retained in its measurement
commit; ordinary CI does not run extra calibration attempts.

The delay wrapper now recognizes the first responder selection frame through
the bounded WYRC codec and HardNAT header, instead of assuming write number 7.
It forwards the original bytes without decrypting or altering them. Its one
existing intentional hold ends 250ms after the later endpoint's candidate
deadline, observed directly from each endpoint's first candidate I/O context.
The observation wrapper forwards the context, packet and target unchanged;
it neither advances a clock nor waits. Using the earlier progress callback
would leave a scheduling gap before the actual candidate deadline is created.
Merely increasing the candidate window while keeping a relative
2250ms hold could silently stop testing expired candidate contexts on a fast
runner; both endpoints now explicitly assert release after their deadline.
Success still requires complete schedules, carrier counts 8/8, exactly one
winner, burned/finished state, bidirectional handoff, and no safety trip.

Local mutation checks use Go source overlays, leaving production files intact:

- restoring ordinal-7 matching rejects selection at write 1 and mistakenly
  delays a non-selection frame at write 7;
- releasing before the candidate deadline fails the explicit margin assertion;
- giving selection the expired candidate context fails with
  `attempt_expired` / `oob_stream_closed` despite both full candidate schedules.

The existing #188 resource-trip test passed this hosted six-package batch.
Its first RED has zero candidate emissions and a different failure class;
there is no evidence here to classify it as this timeout or change its fixture.
Other two-second fixtures are unchanged. Keep `Refs #180`; no issue closure,
CI rerun, field-host operation, or production correction is implied.

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
