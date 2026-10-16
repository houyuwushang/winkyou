# Bounded Go provisioning for required CI proofs

On 2026-10-16, PR #197 head `57e5270` had 68 successful checks, three
cancelled jobs and one failed dependent aggregate. The three jobs exhausted
their whole-job deadlines while acquiring Go 1.23.1 from the GitHub
`actions/go-versions` release asset, before starting their tests:

| First job | Download started (UTC) | Cancellation (UTC) |
| --- | --- | --- |
| [N2d/N3b](https://github.com/houyuwushang/winkyou/actions/runs/38846908366/job/116799395217) | 03:49:18.655 | 03:55:29.255 |
| [Liveness loopback-idle](https://github.com/houyuwushang/winkyou/actions/runs/38846908486/job/116799395742) | 03:45:59.644 | 03:55:55.371 |
| [C1b Fresh100 Linux](https://github.com/houyuwushang/winkyou/actions/runs/38846903504/job/116799381298) | 03:53:08.180 | 03:58:03.887 |

Loopback-idle first logged `aborted` at 03:53:32.058, followed by a 15-second
retry delay. An earlier [WireGuard job](https://github.com/houyuwushang/winkyou/actions/runs/38845740522/job/116795752355)
spent 586 seconds acquiring the same asset, then passed idle/rekey and ran out
of job time during the subsequent blackhole proof. The
[required aggregate](https://github.com/houyuwushang/winkyou/actions/runs/38846908486/job/116805678809)
correctly failed with `NETNS: cancelled`. These are provisioning failures;
the selection-margin test's four corrected Linux first runs remain successful.

The old [installer](https://github.com/actions/setup-go/blob/40f1582b2485089dde7abd97c1529aa768e1baff/src/installer.ts)
tries the GitHub asset before the Go distribution, and only falls back after
the download returns an error. Thus a stalled acquisition can spend the entire
proof budget without reaching the fallback. The available logs do not identify
the underlying network fault; they do not establish a Node runtime regression.

All existing Go setup steps now pin setup-go v6.5.0 at commit
`924ae3a1cded613372ab5595356fb5720e22ba16` and explicitly set
`go-download-base-url: https://go.dev/dl`. This
[supported input](https://github.com/actions/setup-go/blob/924ae3a1cded613372ab5595356fb5720e22ba16/docs/advanced-usage.md#custom-download-url)
bypasses the GitHub release asset path. An explicitly empty token prevents
sending the GitHub token to the Go distribution endpoint. `go-version-file`
still selects the exact Go 1.23.1 specified in `go.mod`; module caching remains
enabled. A two-minute setup-step deadline makes an unavailable distribution
fail in provisioning rather than consume an entire proof job. It is a failure
bound, not a new allowance added to any job cap.

All job caps, test commands, repetition counts, isolation guards, and required
aggregate conditions are unchanged. Architecture tests reject returning to the
old installer, removing the setup bound, changing the source or version input,
forwarding a token, or making setup advisory/conditional. The numeric-fixture
contract normalizes only the exact new setup block to its historical spelling;
its original job digests continue to protect all other content.

The first failure logs remain attached to their original jobs. Validation of
this change uses new-commit first runs, never a rerun of the failed jobs. There
are no production Go changes or field-host operations.
