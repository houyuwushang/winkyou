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
