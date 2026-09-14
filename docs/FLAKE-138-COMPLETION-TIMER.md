# #138：完成阶段夹具的独立定时器竞争

## 范围与已知签名

状态：修复与首跑验证中。基线 `2864a18`，仅测试与证据文档；不改产品、配置、工作流或冻结数字。

[原始 issue #138](https://github.com/houyuwushang/winkyou/issues/138) 记录了 Windows required
memory job 的首跑失败：

```text
TestConsumerFinishedCompletionAfterChallengeDeadline/received
fixture did not cross only the original challenge deadline exactly once
```

历史失败与本批压力结果分别保存，不能用一次通过证明该竞争不存在，也不重跑 CI 求绿。

## 根因与修复契约

`waitCompletionBoundary(deadline.Add(...))` 创建独立于 context 的定时器。
它先唤醒并不证明 context 自身的定时器回调已经完成；随后断言 `challengeCtx.Err()`
等于 `DeadlineExceeded`，把两个独立定时器的调度顺序当成了契约。

需要断言 context 已到期的夹具改为观察它自己的 `Done()`，等待受原有 8s 测试 context
兜底约束，再检查原来的错误身份。原有真实 3s challenge deadline、absolute envelope、
`finishCalls == 1`、精确 3/3 packet 计数与关闭/排水见证不变。

按基线文件的五处调用逐一处理：

| 基线位置 | 调用用途 | 处理 |
| --- | --- | --- |
| `wireguard_completion_phase_test.go:40` | FINISH 回调等待后断言 challenge context 到期 | 等待 `challengeCtx.Done()`，保留准确错误断言 |
| `wireguard_completion_phase_test.go:132` | responder FINISHED 写入前等待，随后断言 context 已到期 | 同上 |
| `wireguard_completion_phase_test.go:154` | 延迟合成 FINISHED 到达的绝对时刻，不断言 context 状态 | 保留，并说明不推断 context 到期 |
| `wireguard_completion_phase_test.go:172` | 在标称边界之后调用已通过 challenge 的 completion admission，不断言 context 状态 | 保留，并说明不推断 context 到期 |
| `wireguard_completion_phase_test.go:253` | detach 屏障等待后断言 challenge context 到期 | 等待 `challengeCtx.Done()`，保留准确错误断言 |

## 红回归与源码门

1. 旧测试使用 Go 1.23.1、`GOMAXPROCS=2`、同进程两个 busy goroutine、`-race -count=200`
   首跑尝试复现。额外压力夹具通过仓库外 Go build overlay 注入，不进入提交；记录两个 worker 的启动与退出。
   失败为零时明确写零，不伪造动态 RED。
2. 新增 AST 契约：完成阶段测试不得在等待“context deadline + margin”的独立定时器之后，
   把同一 context 的 `Err()` 当作已经到期的证明。覆盖 deadline 变量、到达时间别名、直接调用与回调内等待。
   旧文件必须被拒绝；无 context 错误断言的绝对到达时间测试允许保留。
3. 合成源码变异证明该门能拒绝旧模式，不靠日志关键字、注释或行号做匹配。

## 验证计划

全部保持真实窗口与原 count，不启动任何现场网络或主机配置操作。

- 旧文件压力首跑：目标测试 `-race -count=200`，记录失败次数与原始日志哈希。
- AST 旧代码 RED、修复后 GREEN、合成变异自检。
- 与 CI 相同的完成阶段选择器：
  `go test -race ./internal/probeio -run '^Test(ConsumerFinished.*(Completion|ConfirmationAfterChallengeDeadline|DetachAfterChallengeDeadline)|WireGuardCompletion)' -count=20`。
- 相同压力配置下，完成阶段选择器 `-race -count=200`。
- `go vet ./...`、`go test ./internal/architecture`、全仓 #116 分区及独立 relay race×20。
- `git diff --check`、隐私扫描、生产/配置/工作流 delta=0 与提交身份核对。
- 单次推送 Draft PR，完整记录首轮 CI；不合并，不覆盖首轮 RED。

## 本批实测

待首跑完成后追加；未执行的验证不计为通过。
