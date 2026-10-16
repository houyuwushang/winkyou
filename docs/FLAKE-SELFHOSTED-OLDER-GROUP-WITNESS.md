# Older recovery group: retain the attachment witness

The first Windows PR-event test at `ef3d117` failed in
`TestEnginesRecoverUsingOlderIPGroupWithoutRouteOrCoordinator`:

```text
neither endpoint selected the older usable IP group
```

[Original job 116852438127](https://github.com/houyuwushang/winkyou/actions/runs/38863974689/job/116852438127)
is preserved without rerunning it. The corresponding push event and the
shortcut package passed. This is separate from the shortcut liveness and
Hard16 selection fixtures.

The assertion inspected the latest `Engine.Snapshot` after both packet
neighbors and learned-remote statuses became visible. That snapshot is not a
history of the first successful connection: `runAttempt` emits `StateAttached`,
then `Observe` persists the learned endpoint and promotes it by recency. If a
later attempt reconnects through that endpoint, the same address now has rank
1 and replaces the original rank-2 status. A delayed test observer can reject
a recovery that did select the older group.

The deterministic regression exercises the real card persistence, candidate
selection, event emission and status code without starting an engine or
opening a socket. After the original rank-2 attachment, it persists the success
and selects the promoted group in a subsequent attempt. The old snapshot
predicate is false while the original attachment receipt still proves rank 2:

```text
SELFHOSTED_RANK_PROMOTION snapshot_index=1 first_attachment_index=2 old_snapshot_oracle=false
```

The hosted failure did not capture the attempt sequence or candidate ranks.
The exact hosted interleaving is therefore unproven; the deterministic test
establishes a sufficient counterexample to its snapshot assertion.

The fixture now retains one immutable successful `StateAttached` receipt per
endpoint through the existing callback, with a single buffered slot and
`sync.Once`. It still requires at least one actual successful attachment to
the older rank-2 group in the two-entry portfolio. Incomplete/error events do
not count. Receipt collection uses the original caller context. The original
neighbor, current-status, learned-endpoint persistence and 500 ms survival
checks remain, along with every product and fixture timeout.

Two source-overlay mutations must fail: replace the first receipt with the
latest event, and admit incomplete events. The regression uses memory and a
temporary recovery card; the unmodified transport portion of the full fixture
is validated by the isolated hosted job. No production Go files change.
