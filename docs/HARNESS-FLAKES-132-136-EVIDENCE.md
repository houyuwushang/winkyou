# Harness flake 收尾证据：#132–#136

基线 `ed9522b`，test/docs-only；生产、配置、工作流、冻结预算和所有现场权限均不变。
本批按 #133 → #135 → #132 → #134 → #136 串行处理，完成后一次推送，Draft 等独立复审。

- #133：维护者接受仅补 Fresh100 测量回归、原窗口不变、`Refs #133`；见
  [C1b 证据 §7.5](GATE-C1B-PRODUCT-COMPOSITION-EVIDENCE.md)。
- #135 / #132：等待预算与尾包分段见证见
  [Gate B3 证据](GATE-B3-HARD16-ISOLATED-EVIDENCE.md)。#132 未定位 OS 丢失点前仅 `Refs`。

## #134：expiry 观察顺序不改变持久不变量（设计先行）

原始 [Linux race RED](https://github.com/houyuwushang/winkyou/actions/runs/34561468857/job/103144896471)
保留：`ConsumeForCarrier` 返回 nil authorization / `ErrCommittedAttemptInvalid`，却未包含
测试要求的 `ErrPairingCredentialExpired`。watcher 先选 expired 终局时，生产
`terminalChosen` 分支返回前者；validate 先观察过期时同时包含后者。两者均无授权，
credential 都以 expired FINISH，不能把生产错误身份的现有差异判成权限泄漏。

先保留旧断言并记录实际 ordering，再改为裁决的不变量：authorization=nil、
`errors.Is(err, ErrCommittedAttemptInvalid)`、该 credential FINISH reason=expired、
journal sequence=3。类型化 expiry cause 只决定日志 `validate_first` / `watcher_first`，
不决定 PASS。原因为 cancelled/carrier_error、额外 journal 记录或非 nil authorization
仍必须拒绝；不加生产 hook、不改 watcher 或错误面。

验证预定：旧判据 race×200 首批、修订判据 race×200 首批，分别保留原日志与 ordering
计数；新批次两种顺序都必须实际覆盖，不以纯合成错误值代替真实持久 FINISH。
如果自然调度未覆盖某一顺序，只能补 test-only 调度控制，不能改生产去制造顺序。

P1 仍待维护者另行裁决：`terminalChosen` 按 `terminalReason` 拼接类型化 cause。
本批不实现 P1；issue 评论继续保留该待决项，不能把测试修复当成错误面已统一。

### #134 实测与修复

旧判据自然调度首批 race×200 **200/200 PASS（3.915s）**，但全部是 validate_first，
没有覆盖另一条路径；不把它称作根因修复。随后 `78bf98c` 增加两种顺序的确定性
test-only 控制：复用既有 beforeReturn hook，最终 postcheck 的一次时钟读取之后，
在唯一生产 watcher 首次读取测试时钟前设置屏障；不增加 watcher、不修改 committed
对象，也不伪造 FINISH。释放屏障与 Consume 的顺序决定谁先观察 expiry。

该控制首次 RED（0.612s）：validate_first PASS，watcher_first 被旧的类型化 cause
断言拒绝；**两条路径的真实 journal 都是 expired、sequence=3、authorization=nil、
ErrCommittedAttemptInvalid=true**。日志 SHA-256：
`50766fe3fdcbda542ed52422f58e3056fb2c85d5f47a5e29f6b6340e1ee89856`。

修复 `7231f72` 只把公共断言改为 `ErrCommittedAttemptInvalid`；原自然顺序用例仍在，
追加 FINISH reason 与 sequence=3 的精确检查。P1 生产错误身份没有改变。

```text
go test -race ./internal/governor -run '^TestCommittedAttempt(InvalidatesBeforeFirstEmission|ExpiryObserverOrderings)$/^(credential_expiry|validate_first|watcher_first)$' -count=200 -v -failfast -timeout=5m
```

修复后首批 PASS（12.773s），自然用例 200 次 + 两个受控顺序各 200 次；实际日志
validate_first=400、watcher_first=200，600 次真实 expired FINISH 的 sequence 均为 3。
绿日志 SHA-256：`0904a37fb7ab7b014c3d70502a5ed1a05268abfaee7f82a241e99f32c4dc77e5`。
全部控制在 `_test.go`，5s 只界定测试屏障等待，不变更任何产品 timer 或资源预算。

## #136：relay 回环 coordinator 的冷启动夹具预算（设计先行）

保留 [#136 原始 RED](https://github.com/houyuwushang/winkyou/issues/136)：新 race 进程
首个 alpha.Start 在约 0.29s `DeadlineExceeded`，此前无协议消息。当前夹具写死 200ms，
和同一夹具 30s transport 断言、10s stats 等待相比缺乏冷启动余量。

仅改 `pkg/client/relay_wggo_test.go`：将两个既有 10s stats 等待等价命名，coordinator
缺席快速失败预算取其五分之一 = 2s；生产 config.Default、所有 selection/transport
窗口及后续协议断言不变。新增纯夹具配置契约锁定该派生关系，构造 engine 但不 Start。

预定旧值与新值各 20 个全新测试进程，每个只运行一次原真实 relay/WireGuard 用例：
Go 1.23.1、race、GOMAXPROCS=28、无附加 CPU 压力，逐进程独立原始日志。
这不是同一进程 count=20 的热缓存证明；old/new 两组都不丢弃失败样本或重跑求绿。
旧组没有复现时如实报告 0/20，而不将契约 RED 冒称实际冷启动超时。

### #136 首批对照与实现证据

`92d3f00` 保持实际 200ms，新增派生预算契约首次 RED（0.974s）；仅证明旧配置不满足
2s 夹具契约，不是复现 alpha.Start 超时。`fbbe972` 将 coordinator timeout 接到
`relayWGGoFixtureStatsWait / 5`，两个原 10s stats 等待只做等价常量提取。
预算契约的修复后首批 race×20 PASS（1.944s）。

| 实际配置 | 新进程数 | Start deadline 失败 | 其它失败 | 完整用例通过 | 用例耗时 min / mean / max |
| --- | ---: | ---: | ---: | ---: | --- |
| 200ms 旧值 | 20 | 0/20 | 0 | 20/20 | 6.91 / 7.016 / 7.16s |
| 2s 派生值 | 20 | 0/20 | 0 | 20/20 | 8.12 / 8.1305 / 8.17s |

两组均为 Go 1.23.1、GOMAXPROCS=28、race、每个全新进程 count=1、无人工压力，串行
执行且各保留 20 份首次日志。本机 **未复现** 原始 hosted Start deadline；新值增加的是
夹具的有界冷启动余量，不能将本表解释为延迟优化或确定的旧值失败率上界。

```text
go test -race ./pkg/client -run '^TestRelayWGGoFixtureCoordinatorBudget$' -count=20 -failfast -v
# old/new 各启动 20 个全新进程；不是同一进程的 count=20：
go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=1 -failfast -v -timeout=2m
```

原始 RED / GREEN 预算日志 SHA-256 分别为
`9d6dcc56ffe7cca381b543d2cb4906839bb3ff5abf3f73358f5217fc02f6c514` /
`4d721f0b323ae1095a4f882b76a6c2171a1dc12bb86ec8dc8797178fdfd89d92`。
每组 20 份日志按文件名排序，以 `filename + space + sha256 + LF` 的 UTF-8 摘要清单
再次计算 SHA-256：old `8da513c2420f9dcd896f42415eb8432bb1c0f70779171071b878949ed374461e`；
new `ec0478ba15b8061bd20d57e9a702ef917263dd03240ce3687c75fd2af407cbc7`。
原始日志仅本地留存；独立 relay race×20、全仓和远端首次 CI 结果在批次验证节另记。
