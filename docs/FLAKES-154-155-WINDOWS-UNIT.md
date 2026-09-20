# Windows 单元夹具：#154 / #155

## 范围与基线

基线为 `50c10e0177c5c481eb66a826b8d4ff276d13cfa1`。本批只改测试与本文档，不修改生产代码、配置、工作流或任何冻结窗口；独立复审前保持 Draft，不合并。

当前状态：#154 定向修复已得到 RED→GREEN 与整包验证；#155 的队列等待方案仍保留为 RED，维护者随后授权配对虚拟调度，正在验证。下面保留首次失败及测量限制，未改断言掩盖失败。

## 原始失败与假设

- #154：main 的 Windows 首跑中，`TestAuthenticatePeerOnPunchedConnection` 在写 HELLO 时出现 `i/o timeout`。成功夹具的 `Interval=10ms` 同时成为 `writeHello` 的写截止；拟仅将该成功夹具提高到 `200ms`，保留 `Settle=50ms` 和 caller context `3s`。生产 `protocol.go` 不变。
- #155：同一 main 的第二次 Windows 尝试中，`TestGateB3Hard16NATSimFullShapeHandoff` 双侧候选耗尽，`adapter_candidate_reads=0`。原手动时钟将每批 governed 间隔压为真实 `2ms`。拟使用该夹具自己的 natsim 队列见证，等待队列归零或真实 `20ms` 上限；`duration >= 7s` 的 `100ms` 分支不变。

natsim 的入队在发送调用中同步发生，并不存在独立的投递后台线程；队列归零只证明数据已出队，不等价于协议接受。实际候选读取必须另由 adapter witness 核对，不能从发送数量推导。

## 测量与验收计划

固定 Go `1.23.1`，串行执行，保留各批原始日志与退出码。压力测量固定 `GOMAXPROCS=2`、两个 busy goroutine，旧值与新值使用同一条件；未复现记为零，不补造 RED。

| 项目 | 旧值 | 新值 | 验收 |
| --- | --- | --- | --- |
| #154 成功认证 | 压力 `-count=200` | 同条件 `-count=200` | 零失败，逐样本完成时间小于 `1s` |
| #155 Hard16 burst | 压力与实际候选读取见证 | 同条件 `-count=50` | 全部通过且两端合计至少读取一个候选 |
| Gate B2/B3 整包 | `-race -count=20` 基线 | 同命令、同负载 | 全绿，耗时增长不超过 `25%` |

另执行 selfhosted `-race -count=100`、`go vet ./...`、architecture、全仓 #116 分区及独立 relay `-race -count=20`。CI 首跑与本地结果分别记录，不用重跑替换首次失败。

## 执行记录

### #154：首轮旧值与新值压力对照

使用同一个不入库的 Go overlay，仅在测试包追加 `TestMain`：设置 `GOMAXPROCS(2)`，启动两个连续读取 `atomic.Bool` 的 busy goroutine，确认两个 worker 已启动后执行 `m.Run()`，结束时置停止标志、等待两个 worker 并恢复并行度。原测试主体的旧值来自基线，新值仅替换该成功夹具的两个 Interval 并添加说明。overlay 不关闭 vet。

两批都执行 `go test -json -race ./pkg/bootstrap/selfhosted -run '^TestAuthenticatePeerOnPunchedConnection$' -count=200 -timeout=10m`，另指定对应 overlay；Go `1.23.1`、Windows、串行、相同的双 worker 负载。

| 首轮批次 | 通过 / 失败 | 样本耗时 min / mean / max | 命令墙钟 |
| --- | --- | --- | --- |
| 旧 `10ms` | 199 / 1（0.5% 失败） | 0.05 / 0.0876 / 0.19s | 29.389s |
| 新 `200ms` | 200 / 0 | 0.05 / 0.0920 / 0.17s | 28.737s |

旧值失败为 `selfbootstrap: write peer hello: write udp4 <LOOPBACK_PAIR>: i/o timeout`，与 #154 一致。全部新值样本小于 `1s`，因此不调整 `Settle=50ms` 或 caller context `3s`。上述样本耗时来自 `go test -json` 的 `Elapsed`，保留其报告精度；墙钟包括构建及测试进程开销。

原始日志保留在仓库外，不以新值结果覆盖首次 RED。SHA-256：

- 旧值：`a4db2899f3ad1f3eae548ea86c560e3d8b1a1d5d03740762c23154af4b51748e`。
- 新值：`8fa13353b326dc081297962e8b96e7ca7b1e59d6a4f83e78060e1e46b2027195`。

整包 `go test -json -race ./pkg/bootstrap/selfhosted -count=100 -timeout=20m` 首跑 PASS，package `961.743s`，墙钟 `966.440s`；原始日志 SHA-256：`bf5c2f8b893f0aabc091297e592bdcdce1b2ede373585181f5f4494463c293a8`。

### #155：接线范围与授权

原测试创建时钟位于 `gate_b3_integration_test.go`。维护者于本批明确允许额外修改该测试文件，仅给现有夹具保存并向手动时钟传入其所属 network；原断言、预算和时间窗口不变，不借用全局 network 注册表。基线耗时批次使用未修改的 governor 测试代码，固定 `GOMAXPROCS=2`，不叠加 busy workers；修复后须按相同条件比较。

基线首跑命令：`go test -json -race ./internal/governor -run 'GateB2|GateB3' -count=20 -timeout=45m`。结果 PASS，测试/子测试 PASS 事件合计 `400`、FAIL `0`；package 报告 `470.528s`，命令墙钟 `479.116s`。比较统一采用 package 时间（不含增量编译差异），修复后上限为 `470.528 × 1.25 = 588.160s`。原始日志 SHA-256：`d6165950e08a806717cf4d73c9b844065cdea73e709d11e74357e3ce37528353`。

压力采集的首版附加断言曾错误要求两端分别读到候选：实际出现 `0/1` 读取且双方成功的样本。该断言不符合现有单 winner 协议，首版采集不能作为 #155 的 RED 证据；原日志保留，不以其 FAIL 数推导复现率。正确判据为两端合计至少一次真实 candidate adapter read，并保留双侧成功终局断言。

### #155：有效旧值对照与未通过的实现

修正上述测量断言后，使用同一 `GOMAXPROCS=2`、两个 busy goroutine、Go `1.23.1`、`-race -count=50`。busy workers 只在首次 candidate Write 时启动，preflight/evidence 不施压；两个端点结束后停止并等待 workers。复用原完整 fixture、seed 与 `8s/12s` 窗口，不减少候选。

| 批次 | 通过 / 失败 | package / 墙钟 | 结论 |
| --- | --- | --- | --- |
| 旧固定 `2ms`，正确读取断言 | 49 / 1 | 149.827 / 154.804s | 两端读取 `0/0`，双方 `hard_nat_candidate_exhausted`；有效 RED |
| 第一版：`Gosched` 后检查队列，`20ms` 上限 | 44 / 6 | 146.874 / 152.216s | 同签名；不能作为修复 |

第一版实际去掉了旧有定时等待。当前工作稿恢复 `2ms` 定时采样，只有队列非空才继续等，仍受单一绝对 `20ms` 上限约束；保留 `>=7s` 的 `100ms` 分支及不绑定 network 的 C1b 时钟路径。该稿也未达到成功门槛。

原始日志 SHA-256：

- 正确断言的旧值：`af067fd9aed7759dd14b84a09b1c00bde6d86c2f9853aa68490787953e653788`。
- 第一版队列等待：`3e563e9b3897edf240b8a3561ea9bf8e00b76d4dfaf43b72077796a2566368c0`。

### #155：迟到候选的测试侧见证

纯测试 overlay 在 `ReadFrom` 因 context 取消退出时记录队列是否为空；在既有 `Close` 即将丢弃队列内容时识别 candidate，仅统计 discard，不交给协议、不计作 adapter 成功读取、不产生新发送。最后一次 ReadFrom 进入会清除旧标志，避免用 evidence 阶段的取消冒充 candidate 阶段取消。

观测到同一失败端以下三个计数同时成立：

```text
adapter_candidate_reads=0
late_candidate_discard_at_close=1
arrived_after_empty_read_cancel=1
```

这证明至少部分失败不是“已有队列等待不够”，而是读者取消时队列尚空，候选随后才入队。生产路径在完成本侧 schedule 后调用 `waitForHardWinnerSlot`，再停止 candidate readers（`connect.go` 的 `1356` / `1381` 附近）；harness 把这个完整 PPS 间隔同样交给压缩时钟（`1506` 附近）。两个独立压缩时钟没有证明对端 schedule 已完成，队列空不能代替这项见证。本结论不等于已证明真实生产时序有缺陷，生产代码未改。

采集纪律偏差也保留：timeline 诊断末段与定时采样版压力批次意外重叠约 `65.54s`；因此这两整批均不作为串行失败率或验收批次。timeline 有四个上述反例发生在重叠开始之前。定时采样版仍有四个失败样本，其各自完整执行区间都在 timeline 诊断退出之后；这是反例证据，不把整批 `46/50` 当成合格的对照统计，也不以重跑抹去它。

诊断日志 SHA-256：

- 关闭丢弃见证：`6d07c56f4722098805617ae646dbb4b243755ca8b2b86d9be96608100cc87e70`。
- 取消时序见证：`f5394d056cc262b4d0c7ede323ed48aa90ef72461d57e70334bc7b6f0e2cd4f4`。
- 定时采样版反例：`ff2ca03d1e6d2ca73063caeee0339e35c724719198a808db8732c65801d0de64`。

### #155：配对虚拟调度修订

仅增加 network 传参和“队列空 / `20ms`”判据不能满足 `50/50`。失败证据发布于 [#155 调查记录](https://github.com/houyuwushang/winkyou/issues/155#issuecomment-5749343041) 后，维护者明确授权扩展为双方实际发送进度约束的配对虚拟调度，仍限定测试侧，产品、原成功断言、包数与窗口不变。

每个 Hard16 fixture 拥有独立的 `gateB2PairedSchedule`，显式绑定两侧 clock 与 factory，无全局注册表、无跨 attempt 复用。规则如下：

1. factory 包在故障注入层外。仅 candidate 的完整成功 Write 返回增加 `completed[side]`；实际在途调用由 `inFlight[side]` 见证。人为网络 drop 仍是成功发送，但不伪称投递；短写或错误不增加完成数，STUN/control/data 不计入候选进度。
2. clock 在推进虚拟时间之前等待对端完成至少同样长的候选前缀，且对端不处于 Write 调用中。零候选的前置步骤不建立配对屏障。最后一批后的接收等待因此不能越过对端尚未结束的候选 schedule。
3. 配对等待只使用原 caller/candidate context，不创建新窗口或定时器、不延长 `8s/12s`、不补发、不修改 NAT 模型。对端失败导致既有 context 取消后退出；虚拟时间不再推进。
4. 此后才推进原虚拟间隔并做队列采样；真实 `2ms` 调度轮、单次 `20ms` 队列排水上限以及 `>=7s` 的 `100ms` 分支保持不变。配对调度不等同于协议成功，仍由真实 adapter reads、原加密协议及双端结果判断。
5. 只有 Hard16 的配对 helper 接入新屏障。B2 的既有非对称角色先后规则仅获得队列观察；C1b 使用不绑定 network 的旧构造器，其独立 timing policy 不变。

新增确定性回归观察屏障本身：本侧完成、对端仍在发送且队列为空时不得推进时钟；完成后只前进原间隔，取消则不前进。另测跨 fixture 不借用进度、丢弃/短写/错误/非 candidate 的计数规则。压力回归已入库，沿用上述两个 worker 与真实读取断言，并纳入完整 `GateB2|GateB3` 验收选择器，不隐去其时间成本。

### 其余验收

已执行：当前队列单元契约 `-race -count=20` PASS（`4.469s`）；将队列观察移回旧固定等待的变异被确定性拒绝（`queue reads=0`，RED `0.828s`）；`go vet ./...` PASS；architecture（含隐私门）PASS（`11.216s`）；`git diff --check` 干净。上述单元/静态结果不能覆盖压力批次的反例。

完整新值 Gate B2/B3 race×20 耗时验收、全仓 #116 分区、独立 relay 与 CI 未执行；#155 已有反例，不能声称本批通过。上述定向数据不代替最终整包与 CI 验收。
