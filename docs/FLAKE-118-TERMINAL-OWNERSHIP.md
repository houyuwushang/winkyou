# #118：等待排水不足以覆盖的持久终局所有权缺口

Status: **维护者已授权最小生产所有权修复（2026-09-09）；实现与 Windows 本地验证完成，CI 与独立复审待完成**。基线 `214ff2d`。

## 续行裁决与实现边界

维护者接受针对下述确定性反例扩大 #118 的范围；原提示词的 production delta=0
仅对此最小所有权修复不再适用。#120 仍为 test-only，#115 保持不变。

实现约束：只有 governor 在成功写入 durable FINISH 后才能构造内部终局见证，
并绑定原 `AttemptLease` 实例。失败结果继续保留既有 error text / `errors.Is` 因果。
Gate B 只能验证这个见证后更新 FINISH 状态并执行原有清理；不能从普通错误、
`burned`、journal 数量、另一个 attempt 或调用方自建值推断可释放。
FINISH 写失败、未完成或终局存疑一律不签发见证、不退款、不释放。
Commit 的 post-burn 失败与 token consume 的失败遵守相同规则。

不改变任何产品超时、PPS、包数、重试、scope、协议、产品入口或现场权限。
诊断 RED 原样保留为历史证据，并升级为默认永久回归；补慢 drain 和失败 FINISH 对照。
所有结果均等待独立复审，不自我合并。

## 原始记录与边界

保留 [#118 首次 Windows 失败](https://github.com/houyuwushang/winkyou/actions/runs/34187904476/job/101939851021)。
原记录只有零资源断言失败，不能据此断定历史失败必然发生在 candidates，
也不能认定是下面这个新复现的同一根因。

提示词要求 test-only 等待 runtime 的 terminal/drain 见证，生产改动必须为零。
源码核对却显示 `gateb.run` 已同步调用 `cleanup`、报告 terminal、收集结果后才返回；
原夹具又等双方 `Run` 返回后才检查资源。因此“只在 cancel 后立即断言”的描述不完整。
本次不添加轮询来把资源残留当作可忽略的调度误差。

## 确定性对照（2026-09-09）

首轮暂停时新增显式 `flake118diagnostic` 标签下的 **预期 RED** 诊断，当时默认测试不包含它。
授权后的红回归提交 `33fe74c` 已将其转为无标签永久测试
`TestGateB2FIREFreshnessBurnCrossesActiveEnvelope`；下面命令是保留的历史执行记录，
不是当前分支的验证命令。
复用原 active-envelope 夹具、真实 governor/journal、纯内存 NAT 与 `net.Pipe`。
只在现有 BURN `afterSync` 测试 hook 上等待 carrier 的真实 Close 信号：
原 500ms active timer 触发关闭后释放 hook，模拟 BURN 返回时 active envelope 已过期。
没有 sleep、重试、产品 deadline/预算变化，也没有真实网络收发。

```powershell
go test -tags=flake118diagnostic ./internal/governor -run '^TestGateB2FIREFreshnessBurnCrossesActiveEnvelopeDiagnostic$' -count=1 -v
```

首次执行 RED，包耗时 3.803s，子测试 2.92s。仅发布脱敏见证：

| 见证 | 受影响端 | 对端 |
| --- | --- | --- |
| class / stage | attempt_expired / burned | attempt_expired / activated |
| credential burned | true | true |
| runtime FINISH 标志 | **false** | true |
| carrier drained | true | true |
| candidates | 0 | 0 |
| persistent safety blocking | false | false |

受影响端再等待原 2s drain 上限 + 100ms 观察裕度：`AttemptLease.Done` **仍未关闭**。
journal 只读复检：`durable_unfinished=0`、`durable_packets=0`；
但 governor 仍保留 peer=1、attempt=1、heavyweight=1、完整 reservation。
这不是丢失 FINISH 落盘，也不是还在异步等待排水。
最终测试的 deferred machine Close 负责夹具回收，不冒充产品自动释放见证。

## 源码解释

1. `gateb/connect.go:285` 用 `context.WithoutCancel` 取得 attempt，让 FINISH 先于释放。
2. `CommittedAttempt.ConsumeForCarrier` 在 ctx 已到期时自行写入 FINISH，然后返回 nil authorization。
3. `gateb` 已置 `burned=true`，但没有取得 authorization，也未把这次已落盘终局带回 `finishRecorded`。
4. `cleanup` 的 `finishOK := !burned || finishRecorded` 为 false；无 authorization 可再次确认，
   因而跳过 controller/attempt/peer 释放。原 attempt 不受 active ctx 自动取消，不能靠多等来释放。

暂停时提出、现已获维护者授权的最小方向：保留 FINISH-before-release，给失败的 token 消费路径提供不可伪造的
durable terminal 见证，由 runtime 验证后释放；FINISH 写失败仍保留 fail-closed 资源。
不能仅凭普通错误、journal 计数或 `burned` 标志推断可释放。
这涉及生产所有权接口，超出原 test-only 提示词，因此先暂停并取得了上述单独授权。

## 首轮验证与暂停记录（历史）

- 未改基线的原 FIRE freshness 矩阵 `-race -count=20` 通过；不抵消新确定性 RED。
- #120 使用 EOF 预先可读的 memory stream，并以已过期 deadline 为相反因果对照；
  强错误类别、EOF/deadline/drained 与零注册 drain 断言保留。
- `go test -race ./internal/v2/oobcarrier -count=20` 通过，3.389s。
- production delta=0，未改产品时限/预算、#115 或其他 Gate。
- 首轮曾暂停提交/发布与后续 #111、#97 工作，请求 #118 范围裁决；
  不声明 #118 已修复，不使用 `Closes #118`，不创建虚假的全绿交付。

## 授权后实现与验证

生产改动只落在 `internal/governor/pairing_gate.go` 与
`internal/v2/directconnect/gateb/connect.go`。私有错误见证由成功 FINISH 的失败路径产生，
`PairingTerminalRecordedForAttempt` 只验证原 lease 实例，不执行 I/O、释放或授予发送权限。
Gate B 保留原 cleanup，只把得到证明的 FINISH 状态带入 cleanup。
架构测试精确限制唯一生产消费者，并对六条非法路径、三个见证符号执行 18 个变异对照。
既有永久门禁、loopback carrier 及其预算、#115、工作流未修改。

负面测试覆盖：FINISH sync 失败、FINISH 未完成、普通/仿造错误文本、nil/零 lease、
另一 namespace 中同名同成本 lease。成功见证本身不释放 attempt。
慢 Close 由通道屏障控制，证明 terminal 与 attempt 释放均等待真实 carrier 排水；没有新增 sleep。

Windows / Go 1.26.5 实测：

| 验证 | 结果 |
| --- | --- |
| 修复前重放确定性 RED | FAIL，3.111s；与首轮相同的 FINISH 已落盘但 attempt 未释放反例 |
| FIRE freshness 与 FINISH witness 全矩阵 `-race -count=20` | PASS，123.198s；6 个顶层测试各 20 次 |
| 修复后 BURN 越过 active envelope | 双端 `finish=true`、`carrier_drained=true`、candidate=0、safety clear；实际 attempt Done 已关闭，peer/attempt/reservation 均为零 |
| durable journal 只读复检 | unfinished=0、packets=0；不将 journal 计数用作运行时释放依据 |
| `go test ./internal/architecture -count=1` | PASS，含精确消费者与变异门禁 |
| `go vet ./...` | PASS |
| `go test ./... -count=1 -json`，Windows 首跑、无 skip | PASS，88 个包；governor 278.025s、client 52.427s，包含既有 relay 用例 |
| `go test -race ./internal/v2/oobcarrier -count=20` | PASS；EOF-first 与 deadline-first 均保持独立准确断言 |
| `git diff --check`、新增内容隐私检查 | PASS；不提交原始本机日志或身份信息 |

矩阵命令：

```powershell
go test -race ./internal/governor -run '^Test(GateB2FIREFreshness|PairingTerminalWitness)' -count=20 -timeout=8m -json
```

#120 选择原提示词方案 (a)：在调用前让 EOF 已可读，保留 EOF-first 的准确错误类；
另以调用前 deadline 已过期证明相反因果。两种情形分别断言 EOF/deadline/Closed/Drained，
不使用“任意错误都通过”的断言，也不改生产 carrier。

## 合 main 后重验证（2026-09-13）

本批仅刷新原 PR：先清理四个非维护者署名尾注，再以 merge 合入
`1c804d6ee2919f1bc2b00a63cad398f582857692`；不新增生产修复。
既有产品窗口、资源上限、错误因果与 FINISH-before-release 顺序均不变。
历史首次失败及上面的旧工具链证据保留，不由本节的新结果覆盖。

### 提交信息重写见证

重写限定 `214ff2d..fix/windows-terminal-flakes-118-120`，只删指定尾注行；
保留提交顺序、文件内容、作者与提交者。四个提交的两种身份均为维护者，
无关 refs 核对未变。合入 main 之前，分别保存并逐行比较
`git log --format=%T 214ff2d..HEAD` 的前后输出：**4/4 一致**。
下表按该命令的最新提交优先顺序排列。

前后原始 tree 清单的 SHA-256 也相同：
`381d0f2ba09782ea2120aad58db3de289284a23530d22903cfc5745b24957e46`。

| 原提交 | 重写后提交 | 重写前后相同的 tree |
| --- | --- | --- |
| `9205ee6` | `8454c551c25605ebf06109585e9c2a021bbb4019` | `5a4b428214b86da1cb836fca1df50ac7d8dce82f` |
| `b947629` | `e3dacdd2414b9b7ab701777d75fd1c95d83192f4` | `c6111c0808cf662ddf3442b44f312a0955a4efab` |
| `33fe74c` | `a194d37249af403e54de264772650fa5fdf11a14` | `48f95ac463bd2f3ba32cbf4984f2f17890f76734` |
| `cc00ac0` | `890f349e7f07b963b624436d629dcfb2cc7937e4` | `99457c6577f159ede1c784b488d8be129c8d89e3` |

随后生成 merge `7e8071688338bb4eee678338d12aeddf969b8ba9`，父提交为重写后的
`8454c55` 与 main `1c804d6`；没有 rebase/squash、没有冲突处理。
实际合并 tree `50d3cf5f621c7f9f3a35bfaa4b78764c83a03e17` 与事前 `git merge-tree` 一致。

相对新 main 的生产 diff 仍仅两文件：

```text
internal/governor/pairing_gate.go          | 38
internal/v2/directconnect/gateb/connect.go |  5
2 files changed, 40 insertions(+), 3 deletions(-)
```

`internal/governor/pairing_gate_test.go` 的 Git blob 与 main 完全相同。
#134 两个既有测试不作任何修改；合并后先运行 race×20，通过 3.936s。
其中 expiry 的 validate-first/watcher-first 分别观察到 40/20 次，均保留
`authorization=nil`、`errors.Is(err, ErrCommittedAttemptInvalid)`、FINISH reason=expired、sequence=3。

### 合并后的红回归与旧夹具对照

使用仓库外的 Go build overlay，不修改受验证工作树或提交任何变异实现。

| 对照 | 首跑结果 | 解释 |
| --- | --- | --- |
| #118：仅移除 Gate B 两处消费持久终局见证的赋值，运行 `TestGateB2FIREFreshnessBurnCrossesActiveEnvelope -race -count=1` | **RED**，3.859s | FINISH 已落盘、unfinished=0、packets=0，但 runtime finish=false，超过原 drain 观察界限后 attempt_done=false；peer/attempt/reservation 仍占用 |
| #120：使用 main 的原始测试文件，运行 `TestCarrierCancellationDeadlineAndEOFAreTerminalAndDrained/peer_EOF -race -count=50 -failfast` | **50/50 PASS**，2.284s | 本机未再次复现旧夹具计时竞争；不伪造 RED，不据此声称满足本批 RED→GREEN 的关闭条件 |

#118 对照是移除已授权修复中消费见证部分的行为变异，不是声明历史 #118 的
每一次资源残留都已被证明来自此根因。恢复正常构建后，由下列 FIRE ×50 验证绿色端。
#120 当前保留 EOF-first 与 deadline-first 的相反因果测试及所有 drain 断言，
本批使用 `Refs #120`，不使用关闭关键词。

原始日志完整留在本地，公开只列脱敏结果与 SHA-256：

- #134 兼容性：`4cb39cc59a073d80dcedb10fe45063a43fffb61c16eddc9cd1f257a1ed837a8e`。
- #118 行为变异 RED：`b9dd18cb865ccb4f6fe7d921cd9dbb4868c1ab8b877c1a286d8a3fb9aa1931bc`。
- #120 原夹具 50 次：`a58ec1662b6f4e4f1a778f2afbf216fa853eda091e7cf7e748b0d787bc2f4fa8`。
- #118 正常构建 FIRE ×50：`bea7a61f00506fac2c1ce680aab0dec275e8050211528cc92787219242439a21`。
- oobcarrier 正式 race×50：`45d1a0b4fb249b7e5ece1d37a0b8a3a7812081e934f15507af2d9f0fc1eb72e0`。
- 四个受影响包 race×20：`31270bd7a224391db7f29e56359177713ff53bff3a44cbaccc503b643e0003e5`。
- 全仓 #116 分区：`232ee346cbb9678d8e34ae41c1c75c41452dce88fb9d39286c175787e47f273a`。
- 独立 relay race×20：`0b8dc36256bf9f8a1b8489efc779d2a7fdcdc565ba065be993d82bdde1ab6eb3`。

### 串行验证与 CI 边界

本批工具链固定 Go 1.23.1。下表仅记录本地完成的串行首跑；CI 另以最终 head 的首跑记录为准。

| 正式批次 | 本地首跑 |
| --- | --- |
| `go test -race ./internal/governor -run '^TestGateB2FIRE' -count=50 -timeout=12m -v -failfast` | PASS，154.022s；三个顶层测试各 50 次，含 #118 对照的绿色端 |
| `go test -race ./internal/v2/oobcarrier -count=50 -timeout=8m -v -failfast` | PASS，205.565s；EOF-first/deadline-first 对照各 50 次 |
| `go test -race -p=1 ./internal/governor ./internal/v2/directconnect/gateb ./internal/v2/oobcarrier ./internal/architecture -count=20 -timeout=45m -v -failfast` | PASS；governor 1069.336s、gateb 2.687s、oobcarrier 82.761s、architecture 885.273s，含 architecture 变异门禁 |
| `go vet ./...` | PASS，15.558s；无诊断输出 |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -timeout=20m -v` | PASS，88 个有测试的包、11 个无测试包；1803 个顶层测试 PASS，governor 133.677s；独立 relay 在下一行补齐 |
| `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -timeout=10m -v -failfast` | PASS，164.880s；20/20，`observer_workers=0` 见证 20 次 |
| `GOOS=linux CGO_ENABLED=0 go vet -tags=natlab,c1bproof ./...` | PASS，13.269s；无诊断输出；交叉静态检查不冒充 Linux OS 实证 |

全仓命令沿用 #116 分区，不新增 skip 条件。原代码另有 13 个顶层 opt-in/平台条件 SKIP：
required CI 专用的 1000 次重启与 100 次拓扑证明、Windows symlink/alias 条件、
私有诊断/缺席测量、外部 TURN 与 Docker 环境条件。这些记录保留，不能计为本地已执行；
required CI 的专用证明须另以实际首跑结果核对。本机批次未命中其他已登记失败签名。

只作一次带精确旧 head 保护的 `--force-with-lease` 推送，独立保留该 head 的 CI 首跑记录。
`git diff --check`、新增内容隐私扫描、维护者身份与无额外署名核对均通过；
生产两个 blob 与原授权实现一致，配置/工作流 delta=0，未改冻结数字或扩大现场权限。

现有 N2d Repeat 工作流只有 pull_request 路径过滤，匹配 `test/natlab/n2d_*`
及其自身工作流文件，没有 workflow_dispatch；本批 PR 差异不含这些路径。
因此必须报告其是否实际触发，不能以常规 required N2d/N3b job 替代 Repeat 证明，
也不通过无关文件改动或历史 rerun 制造执行记录。
在请求的全部 CI 批次尚未获得实跑见证时，#118 同样暂用 `Refs`，
不因本地 RED→GREEN 即提前声称满足全部关闭条件。
