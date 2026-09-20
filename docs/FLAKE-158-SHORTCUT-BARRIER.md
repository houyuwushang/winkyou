# #158：shortcut barrier 夹具见证与收敛

## 范围与首个 RED

基线 `f30a456`，仅测试与证据，不改生产、配置、工作流、probation、keepalive 或 peer timeout。
Windows 首跑的 `TestShortcutReconcilesDroppedPacketBarrierSignal/first_stable_after_initial_delivery_window`
在约 1.66s 报 `dropped stable count = 0, want 1`。
原始记录见 [#158](https://github.com/houyuwushang/winkyou/issues/158)。

源码核对：原 `dropFirstShortcutSignalTransport` 已使用原子 CAS 丢弃第一次匹配，
没有按墙钟关闭的武装窗口。尚不能把问题归因为“武装太晚”。
先用测试侧 `NodeConfig.OnEvent`、`Config.OnEvent` 及 transport 包装记录双向 barrier
的固定 type/hop、相对时间、dropper 武装与三个 manager 首次 stable 时刻。
不输出消息正文、attempt ID、地址或路径。失败保留完整见证。

## 验证计划

1. 保留原断言和执行顺序，`GOMAXPROCS=2`、两个 busy goroutine、Go 1.23.1，
   `go test -race ./pkg/mesh/shortcut -run '^TestShortcutReconcilesDroppedPacketBarrierSignal$' -count=200 -json`。
   测试侧压力开关 `WINKYOU_FLAKE_158_CPU_STRESS=1`，实际 0 次失败也照录。
2. 仅依据见证修改夹具顺序；首个指定跳信号必须丢弃，随后等待三方收敛。
   默认保持 `dropped == 1 && matched >= 2`。只有实际见证合法绕路时才评估提示词授权的替代断言。
3. 同 profile 新代码 200 次、`go test ./pkg/mesh/... -race -count=50`、
   `go vet ./...`、architecture、全仓 #116 分区与独立 relay 验证。
4. 原始日志留仓库外，仅发布计数、相对时间与 SHA-256。CI 首跑单列，不 rerun 求绿。

## 测量与结论

### 首轮压力与确定性反例

| 批次 | 条件与次数 | 首跑结果 |
| --- | --- | --- |
| 原逻辑，`153b725` | Windows / Go 1.23.1 / `GOMAXPROCS=2` / 两 busy / race×200，原两个子场景 | 每个 200/200；0/200 自然失败；包耗时 435.763s |
| 确定性绕路，`aa24335` | race×1，A 首次 `PhaseStable` 后、发送 STABLE 前撤下旧 A–B 测试边 | RED，三方稳定但 `dropped stable count = 0, want 1`；包耗时 2.253s |
| 新见证断言 | race×1，全部三个子场景及 11 个见证契约子例 | GREEN，包耗时 5.267s |
| 修复，`c31bfcc` | 与旧批次同 profile，原两个子场景各 race×200 | 每个 200/200；0/200 自然失败；包耗时 436.453s |

新压力批次选择器为
`^TestShortcutReconcilesDroppedPacketBarrierSignal$/^first_`，与旧批次的两个原子场景一一对应；
新增绕路场景另在 mesh 全包 race×50 中完整执行，没有减少原场景轮数。
旧/新自然失败率均为0，不声称旧 CI 的调度根因已被追溯。有效红→绿证明来自明确的合法拓扑变化。

反例由原 `Node.RemoveNeighbor` 测试侧操作产生，不更改生产路由、重播、超时或概率。
`completeProbation` 先 promote 新 A–C 边、发布本地 `PhaseStable`，再发送 STABLE；原 A–B
邻接在该边界消失时，信号可经 A→C→B，旧 A–B 包装器确实收不到它。
已向 [#158 发布完整路径与限制](https://github.com/houyuwushang/winkyou/issues/158#issuecomment-5750491318)。

```text
relative_ns=0          kind=armed          type=stable node=A inbound=none next=none
relative_ns=1533535100 kind=manager_stable type=stable node=A inbound=none next=none
relative_ns=1533535100 kind=cut_bootstrap  type=stable node=A inbound=none next=B
relative_ns=1533535100 kind=manager_stable type=stable node=C inbound=none next=none
relative_ns=1534442500 kind=forwarded     type=stable node=A inbound=none next=C
relative_ns=1535479700 kind=forwarded     type=stable node=C inbound=A    next=B
relative_ns=1535479700 kind=delivered     type=stable node=B inbound=C    next=none
relative_ns=1535996200 kind=manager_stable type=stable node=B inbound=none next=none
```

### 夹具修法与拒绝门

- dropper 保留原 CAS 首次匹配丢弃；先观察首次丢弃或完整绕路，再等待三方收敛。
- 原跳收敛仍要求 `dropped == 1 && matched >= 2`。
- 提示词授权的绕路例外要求 `0 <= dropped <= 1`，且同一条 A 发往 B 的 STABLE
  同时存在 A→C 发送、C→B 转发、B 从 C 投递三段见证。仅内部用消息序号关联，不输出序号或正文。
  只要该 dropper 匹配过消息，仍必须恰好丢过一次，不能借绕路掩盖失效的 dropper。
- 三方 `PhaseStable` 必须全部成立；没有路径见证的0次丢弃不会通过。
- Send 完成后的 callback 可能晚于对端投递 callback，因此只关联同一消息，不假定 callback 调度顺序。
  缺发送/转发/投递、不同消息/来源/目的/下一跳、零序号、投递实际失败、多丢包、COMMIT 冒充
  绕路全部拒绝。真实故障仍受原5s测试context约束，不变成“无限等待至通过”。

原始日志 SHA-256（仓库外保留，包括首次 RED）：

| 证据 | SHA-256 |
| --- | --- |
| 原压力200 | `f70b8ce0f4b0ae72b4ce0853cec64de6259a6b3a4b85942474b0a515a266261e` |
| 确定性 RED | `8714dec31f8b6b11fafdf84cff6e77655e68afa2214b749efce3bb6cce24db01` |
| 确定性 GREEN 与见证门 | `5b5d3932ceec7aa9883974de661c88c77869878f28bf0a643e239040d71647b0` |
| 新压力200 | `f52b3e6aa726cc6b2cdfdbb61cb9d4feefebf03c7cbbd44959fa25afec6e9c0d` |

### 其余验收

所有本地批次严格串行、Go 1.23.1，首跑结果：

| 命令 | 实测结果 |
| --- | --- |
| `go test ./pkg/mesh/... -race -count=50 -timeout=20m` | PASS；mesh 14.598s、shortcut 220.293s；新绕路场景50/50；wall 225.529s |
| `go vet ./...` | PASS；wall 22.015s |
| `go test ./internal/architecture -count=1` | PASS，11.698s（含隐私门） |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | PASS，88个有测试的包；wall 237.627s；其余11包无测试文件 |
| `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20` | PASS，20/20，165.973s；wall 180.405s |

20m 只是全包重复测试进程 watchdog；每例原5s context及全部产品/夹具数字不变。
全部首次日志保留，无 rerun、无命中其它已登记签名。上述验收的 SHA-256：

| 证据 | SHA-256 |
| --- | --- |
| mesh race50 | `947eb3ea2ce2bf49097371858190ff4609547803d912a1def38bbcfb67f6a2d1` |
| architecture | `16f2eb0e6652b4452de23d9d4dd49fe2e944fe8a6505b65a625bf2492daa33c4` |
| 全仓116分区 | `749e3be4419ceb483a94e171aed7ade79874a2c61a06a58cd66a6b314ddd6965` |
| relay race20 | `b854f1750246a5641560d5dcf02ac1306f9f56f987e4ff1705fca41f66be5209` |

CI 首跑在 PR 中另行记录；本地通过不替代 hosted Linux/Windows 或 required netns 证据。
保持 Draft/未合并，不授权任何现场操作。
