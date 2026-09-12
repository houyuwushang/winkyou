# PR #124：stdio 与 fresh-evidence 首跑故障见证

2026-09-13，维护者授权继续定位、修复并验证；沿用原 Draft PR，不自行合并。
此切片只修复测试诊断信息丢失，不改产品协议、配置、工作流或资源/时间上限。

## 原始 RED（不被后续 PASS 覆盖）

- [N3b 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34707131912/job/103589102460)：
  `n3b_stdio_v2_eim_eim_product_entry` 在 0.41s 报 `N2d endpoint returned a harness failure`。
  RPC 的已脱敏 class/stage 被解析器丢弃，父端又合并 wait error 与 `OK=false`，子进程
  stdout/stderr 被丢弃，故不能从该日志推断 TLS/STUN/ledger 等具体故障源。
- [Windows liveness 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34707131913/job/103589102667)：
  hard-16k responder 为 `hard_nat_evidence_insufficient@fresh_evidence`，initiator 为
  `oob_stream_closed@plan_committed`；两端 liveness 尚未 armed，子用例 3.93s。
  两个 run 均无上传的现场 artifact。required 汇总失败是派生状态，不是第三个根因。

原始日志 SHA-256：

| 证据 | SHA-256 |
| --- | --- |
| N3b | `784e47f6fa5ab6d043cb5c4186def93e73ac90272a56460ffc4bfbd9dcaefca5` |
| Windows owner | `b58cc6407128b805448b93bda72dd6ce20e14e2cb6d5540017e7a80f20bd312a` |

## 已完成的诊断与归因边界

原 N3b parser 的纯内存提取实验：8 个不同 RPCError 均缩为同一错误。Windows 原样
hard-16k race 首例及仅加 cause 见证的 race×20 通过，不能抵销原 RED。

仅在测试 responder 暂缓最后一条必需回复，实测 256,653,700ns（350ms 为注入上限，
排水取消提前结束），原 250ms 回复 deadline 即产生与 CI 相同的双端 class/stage。
下层 cause 为 `ErrRequiredReplyAbsent`，不是模型的 `ErrEvidenceInsufficient`；双端各
13 次证据发射、零 candidate。该受控样本 0.85s，**只证明一个足够原因，不证明 CI 当时
就是该原因**，不能据此归因 CPU/Windows/杀毒/NAT，更不能调大 deadline。

## 此切片

- N3b 在清理响应 buffer 前采集有界输出摘要；只保留白名单 class/stage、burned 是否
  已知、帧数与 progress。原 parser 和全部成功断言保持不变。
- 父端记录结构化结果是否可读、子进程是否已退出、脱敏退出类别和固定 runtime marker
  布尔值。子进程输出只由有界接收器识别 marker，尾部随后清零；不日志化原文。
- N3b 失败路径先取双方结果，再逐项排水、采集 packet/socket/process/conntrack/topology
  见证；查询失败与真实零值分开，不改变原失败结论。
- required N3b 用例增加为 20 次 fresh namespace 串行执行、首次失败即停止该序列。
  不重试原 attempt、不修改单次预算、协议或现有 CI timeout。
- liveness 内存夹具的观测见证为固定 `2 × 13 × 6` 表，仅失败时输出。phase 依次为
  `0=send_begin / 1=send_end / 2=responder_read / 3=reply_begin / 4=reply_end / 5=adapter_read`。
  ordinal 为本夹具已签发事务 1–13，不打印事务 ID/目标。共享进程单调时钟与产品证据
  manual clock 分离；adapter_read 不冒充产品已经完成解析/接受。
- 相同 stage 的 first witness 不被后续写覆盖。单元测试覆盖隐私、容量、并发、跨 write
  runtime marker，以及真实 harness 接线的变异拒绝。

## 验证记录

本地命令/结果与新 head 的 CI 首跑分开记录。Linux OS/netns 证据仅以 required CI 为准，
Windows 的交叉 vet 不冒充实际执行；失败原文留仓库外，公开只给脱敏摘要与哈希。
本页 SHA-256 对应封存的首跑文本文件；PowerShell `Tee-Object` 捕获文件为带 BOM 的
UTF-16LE，不是 GitHub 下载压缩包或 UTF-8 HTTP 响应的字节哈希。内容与批次不被后续 PASS 覆盖。

本地 Go 1.23.1 / Windows，未加人工压力：

| 命令/范围 | 首跑结果 |
| --- | --- |
| `go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessBusinessCoexistsWithTap$' -count=20 -failfast -v -timeout=8m` | PASS，220.163s；3 profile 各 20/20，60 次业务双向 3/3，tap_stole=0、extra_socket=0。 |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | PASS，88 个有测试包 + 11 个无测试包。 |
| 独立 `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast -v -timeout=6m` | PASS，142.343s；20/20，20 次 observer join。 |
| `go vet ./...`、`go test ./internal/architecture -count=1` | PASS；未改架构门禁。初版诊断文件缺少 linux/natlab 标签被门禁拒绝，随后为文件加回标签而非豁免。 |
| 纯观测存储 race×20 | PASS，1.435s。 |
| 最终 N3b 纯诊断契约 race×20 | PASS，1.563s；仓库外 overlay 仅移除两个纯测试文件的标签以执行单元函数，不运行 Linux harness、不进入产品。实际源码仍严格 linux/natlab；同一契约进入 required Linux 矩阵。 |
| Linux tagged 交叉 vet | PASS，显式 `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`；本机不能用 Windows C 编译器验证 Linux cgo，实际 race OS 证明留给 CI。 |

| 新本地原始日志 | SHA-256 |
| --- | --- |
| 完整业务 race×20 | `4cb8be33931efa7474d26b3f7c041ce28466e43387858a14abf9dfdde4bd1c22` |
| 全仓分区 | `ac7b5a002db1364aacb376510d3de251911ded5f0138d88765fc879662b8a2ec` |
| 独立 relay race×20 | `38b7fca11188e91bbec9af337c1c2c54749f5c06c976cb596a7d27e79ceccb61` |

新 head 的 CI 首跑仍待执行；不得据此声称两个历史 CI 根因均已解决。

## 后续首跑：NAT 转发积压与稀疏存储修复

`f073ecb` 的 [Mapping Lifetime 推送侧首跑](https://github.com/houyuwushang/winkyou/actions/runs/34710914297/job/103599434035)
在 `M_X_single_side_filter_before_winner` 失败（67.26s，整包 440.26s），原日志
SHA-256 为 `ad73f6167c72aa2f37e361e6ce80bc92e0014df6e752ff4da1eba0bcb1b12dc4`。
该失败不被同 head 的 PR 侧 PASS 或后续批次覆盖。

- 两侧 `CandidateRead=16384`，所有 slot/tail 已读；TUN 丢包计数为 0。
  超时见证为 `got=12499 want=16397`，两路 router 仍在转发、未记录运行错误。
- 首包 mapping barrier/deny 协调约 13ms 完成，不能把此次积压归因于旧的首包等待故障。
  后续 `context_canceled` 在失败清理时才出现，不冒充最初根因。
- 失败路径独立完成七项清理：发包计数不再增长、socket=0、process=0、
  conntrack `58786 → 0`、namespace/veth 与原配置恢复均成功。`ledger_acceptance=false`、
  `scenario_pass=false` 保留，清理通过不等于场景通过。

源码确认一项独立的无效分配：每条 APDM 映射仅对应一个目标，却为 `allowed` 预留 512 个目标。
改为按需增长的空 map；EIM 仍可增长，不增加目标上限，不改变过滤、过期 `clear`、mapping/端口分配、
每映射 UDP socket 或报文缓冲区。新增真实构造点检查、恢复 512 hint 的变异拒绝、
1024 个纯值目标的增长/所有权/清空测试，两个 required Gate B3 矩阵均调用这些回归。

Windows / Go 1.23.1，固定 1000 次、单目标、零 socket 的 `-benchmem` 首跑：

| 构造表达式 | B/op | allocs/op |
| --- | ---: | ---: |
| 原 `make(map[netip.AddrPort]struct{}, 512)` | 41042 | 3 |
| 实际新构造器 `newGateB2AllowedSources()` | 336 | 2 |

这是本地分配量测量；按双端 32768 条 candidate mapping 推算可避免约 1.24 GiB 分配，
**不是原 CI 的 RSS/GC 测量，也不能单凭它认定原超时的唯一原因**。保留原 RED，并在 router
诊断中加入进程级时点 `heap_alloc/heap_inuse/stack_inuse/total_alloc/num_gc/pause_total_ns/goroutines`，
不强制 GC、不启新 worker，不把时点数值宣称为每 attempt 峰值。

验证首跑：`go vet ./...`、全仓 #116 分区（88 个测试包）、架构门禁（8.522s）与 Linux tagged vet 均 PASS；
独立 relay race×20 为 20/20 PASS（143.243s），20 次 observer join；natlab 原生纯测试 race×20
PASS（3.847s），新存储回归单独 race×20 PASS（1.589s）。没有修改生产代码、工作流、47s envelope、
router witness 等待界、目标/包/PPS 预算或任何现场配置；Linux OS 组合效果等待新提交的首跑 CI。

## `4957d29` 首跑与第二次诊断切片

该 head 首跑最终为 **55 PASS / 4 FAIL**：3 个实质失败与 1 个 liveness 汇总失败，未 rerun。
前一 head `f073ecb` 最终为 58 PASS / 1 FAIL。新 head 的两个 Mapping Lifetime required
矩阵均通过（389.68s / 391.13s；原失败用例 48.66s / 48.91s），不覆盖原 RED，也不倒推
稀疏存储就是历史转发积压的唯一原因。两份新 PASS 日志 SHA-256 分别为
`8115c1dd1785258bcb39bb5fd0f57b4bd45d08663c9f4022ff826c78f419f15e`、
`304491e31fead339f345cd61dce2dc892b90f9c1709ec0c63092f72902b42a7d`。

### N3b：已缩小范围，未确定底层原因

[PR 侧 required 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34712057986/job/103602472924)
第 9 次 fresh N3b 用例失败（此前 8 次通过，失败即停）：initiator 为
`verification_failed@verify`（148ms），responder 为 `punch_timeout@punch`（137ms）。
两端均已 burn；initiator 已到 `punch`，responder 只到 `punch_sent`。实际 UDP 为
STUN `1/1`、direct `2/1`，结束后计数不增长；socket/process=0，conntrack `7 → 0`，
server 与 topology 清理检查均通过。错误结果没有成功 result；其中缺省的 FINISH 布尔值
不能作为 journal 缺少 FINISH 的证据。

该短耗时不是耗尽 punch deadline 的证据：公开 `punch_timeout` 合并了多种底层错误。
本切片仅给 `linux && natlab` 的既有 stdio harness 增加值类型 observer，委托原
`machineAuthority.ConnectDirect`，不替换 connector/参数/结果，不改公开 schema。
记录白名单 typed cause、caller context、I/O operation 与 timeout 布尔值；不调用原始
error/endpoint 的字符串方法。若 cleanup 另附 cancellation，优先保留原 Failure.Cause。
新增 poison 隐私、原结果不变、后续清理不覆盖首因与真实接线变异回归。

原日志 SHA-256：`ed4df1a2862a5fad409885cf2e41f852e403d55c5a3975f2c93a3d62af40a772`。
这是为下一次首跑补齐原因见证，**不是已修复 N3b 根因的声明**。

### Predictive：测试时钟破坏角色先后顺序

[Linux WireGuard 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34712057980/job/103602472884)
在 `m3/rx-responder` 的 liveness 启动前失败：双方均
`hard_nat_candidate_exhausted@candidates`，outbound `45/45`，fault 尚未 armed。
13 条证据均完成，不能归入旧的 hard-16k 证据不足。日志 SHA-256：
`2af733f0fd8348de40e7eb12668236bc04e8bf4e049e7b5dcb104a6a87062872`。

零网络本地对照（Windows / Go 1.23.1，`GOMAXPROCS=4`、4 个并行 fresh fixture、race、
每组失败即停，无额外 CPU worker）：

- 初批第 4 组失败；双方真实 source/target 配对的反向交集为 32，不是预测窗口不相交。
- 增加实际 adapter candidate-read 计数后，第 7 组再现：initiator 读到 0、responder 读到 32，
  两端各发 32；只有 initiator 是协议 chooser，因此没有任何 winner。
- 原测试时钟把产品已有的 250ms responder lead 缩为 2ms。新永久回归在旧代码实测
  `elapsed_ns=2544700 required_ns=250000000` 而 RED，证明模拟时钟丢失了角色排序语义。
- 修复只在所有 C1b/liveness 共用的 `memoryFixtureClock` 中保留调用方原本要求的亚秒 wait；
  独立 Gate B 快速模拟的原时钟及 100/200/250ms 窗口不继承这一变化。
  整秒 PPS 窗仍按原规则压缩、逻辑时间推进不变。
  不更改产品 250ms、1s predictive candidate 窗、10s active 窗、plan、seed、候选与包数，
  不添加同步握手、重试或额外发送。取消仍立即拒绝。
- 相同 25×4 fresh 预条件对照 **100/100 PASS，84.388s**。该短测不是 65s/85s 断流证明；
  原完整断流场景另行验证。旧 timing 输出中的 `busy_workers=2` 是压力报告的固定标签，
  本次未启动这些 worker，不能据它宣称有额外 CPU 压力。

最初直接修改公共 Gate B 测试时钟的版本虽通过本地全仓（governor 257.571s），
源码审计仍发现它会影响上述独立快速模拟。最终把相同等待语义收窄到 C1b 共用时钟，
真实构造点与绕回旧时钟的变异受门禁约束；中间版本的 PASS 不冒充最终版本验证。

保留首批、方向见证批、旧时钟单元 RED、新时钟 100 次 PASS，SHA-256 依次为：

| 证据 | SHA-256 |
| --- | --- |
| 首次预条件 RED | `ca994a7a3e0d1f4f528c0f6ce5480dedca23f97152e4c97cf681b666457e90e0` |
| 双方向读计数 RED | `3bdcd9ec75abf6cba743e8ba5fcc32aa09986bebbf78a828e4a2676ec46149d0` |
| 原时钟永久回归 RED | `85fbdd786480d9f6aeb7dce0ebd1b7f146df82ddc60b1554228e5f0cf738c26e` |
| 修复后预条件 100 次 PASS | `11e6c987c58a9d428f20285ef98c5c8979c5c31347b6ee16cd2e3503872f34fc` |

上述复现证明一个足够原因，历史 CI 没有双向 read 计数，不据此宣称唯一历史归因。

### Windows READY：独立未闭合项

[Windows model/owner 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34712057980/job/103602472927)
最后在业务 race×20 的 asymmetric 子例失败（11.52s）：两端
`attempt_expired@ready`、outbound `13/13`、零 candidate，非 predictive 角色排序问题，
也不是已启动数据面被 tap 抢包。第 13 条证据 adapter_read 时点为 658,956,100ns / 369,184,000ns；
现有日志不能定位此后至 READY 终止之间的等待，不猜测 CPU、磁盘或协议锁。

增加仅测试侧的固定 `2×32` progress 时点表，使用现有回调、共享单调时钟，
首个观测不可覆盖，未知 stage 不进入日志，无新 worker 或生产 hook。
原日志 SHA-256：`9eaa2253c42400a7d8d36bd66782eee22823cd43a7125d49f4214485064dc4bf`。

### 收窄后版本的验证

以下均为各命名批次的首次执行，失败即停；未 rerun GitHub 的旧 RED。

| 范围 | 结果 |
| --- | --- |
| C1b 共用时钟、构造点变异、阶段时点存储，`-race -count=20` | PASS，14.265s。 |
| N3b typed cause、首因、隐私、接线变异，`-race -count=20` | PASS，solverstdio 1.904s / natlab 1.722s。仓库外 overlay 仅移除 build tag；四份函数体与实际源码一致。Go 1.23 的 virtual-file vet 限制仅使该 overlay 使用 `-vet=off`，不关闭仓库或 CI vet。 |
| 最终 C1b clock 的 25×4 fresh 预条件对照 | PASS，100/100，83.749s；GOMAXPROCS=4，未启动额外 CPU worker。 |
| `TestSessionLivenessBusinessCoexistsWithTap`，`-race -count=20` | PASS，285.958s；三 profile 共 60/60，原双向业务与所有权断言不变。 |
| `go vet ./...`、`go test ./internal/architecture -count=1` | PASS；架构 8.404s，未扩大包准入。 |
| Linux `-tags=natlab,c1bproof` 交叉 vet | PASS；不冒充实际 Linux OS 执行。 |
| 最终全仓 #116 分区 | PASS，88 个测试包 + 11 个无测试包；governor 253.683s。 |
| 完整 stdio 包 `go test -race ./internal/solverstdio -count=20` | PASS，5.683s；包括原 v1/v2 schema 回归，Linux-only helper 另由上述同源码 overlay 验证。 |
| 独立 relay `-race -count=20` | PASS，146.007s，20/20；该产品路径和依赖在本切片零改动。 |

同一 C1b 等待语义在收窄封装前已完成六种原断流场景（91.589s）：M2 排水 40000ms，
M3 60001ms，均在原 47s/67s 上限内、原 residue=0 断言通过。收窄后最终 OS 组合仍须由
新 head 的 required CI 复核，不把中间版结果写成最终 head 的 CI PASS。

| 最终本地封存文件 | SHA-256 |
| --- | --- |
| scoped fresh100 | `a3b241dde39ad241c5faaae40a38fe67f9cfa8028e0c7fcc33223044327097e4` |
| scoped business race×20 | `3bbbb23fa0b3fa939bfb13dd53e714a91bf1652f6649fdf48ffaaab4ad10ea62` |
| scoped full suite | `de268df693079da4e3b84717aab0a403d5030ef12a3c36eec955ad0e175eae3d` |
| independent relay race×20 | `ba23f12a855465d322d39fc29432a5545e795b0ac5d112a91417b202a90afd0a` |

stdio 与 Windows READY 的历史原因仍未闭合；新 head 首跑与后续诊断继续记录在 PR 描述，
不能以单次绿灯替代上述归因边界。
