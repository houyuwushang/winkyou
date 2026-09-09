# #118：等待排水不足以覆盖的持久终局所有权缺口

Status: **维护者已授权最小生产所有权修复（2026-09-09），实现与独立复审尚未完成**。基线 `214ff2d`。

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

新增显式 `flake118diagnostic` 标签下的 **预期 RED** 诊断；默认测试不包含它。
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
