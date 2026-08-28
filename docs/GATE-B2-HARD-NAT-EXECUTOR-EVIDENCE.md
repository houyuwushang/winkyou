# Gate B2：困难 NAT executor 与隔离证据

状态：**Draft implementation evidence；只覆盖 memory、loopback、natsim 与 required Linux
network namespace，不授权 Gate B3、stdio/CLI/runtime、SSH/WireGuard、LAN/公网或现场 I/O。**

权限来源：[`ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md`](./adr/ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md)
§12 第 4 步与 §16 的完整执行 envelope 裁决。Gate B1 的 bilateral plan、128×512 shape 与
63.3926065852% 条件概率保持不变；Gate A 的 lease-bound handoff 顺序保持不变。

## 1. 交付边界

本实现增加一个断开产品入口的 `internal/v2/directconnect/gateb` 组合器。它只接受：

- 一份独立的 `winkyou-test-hard-nat-attempt/1` artifact；
- caller 已持有的 machine governor、durable pairing ledger 与单一 bounded OOB stream；
- 固定的两地址、两端口 RFC 5780 observer topology；
- `predictive_edm/1` 或 `asymmetric_birthday/1`，未知 profile/resource class 零 I/O 拒绝。

artifact 不含 endpoint、candidate list、port span、packet count、命令、hostname、用户名、路径
或 TLS 设置。Gate A、N3b 与 Gate B2 三套 parser 互相拒绝；runtime fallback 固定 disabled，
Noise prologue 绑定 artifact/profile/resource/role/attempt/generation，PSK 只能取用一次。

没有任何 stdio、CLI、runtime、scheduler、legacy、`wink-signal` 或 WireGuard consumer 导入该包。
本 PR 不生成现场 artifact，不配置服务、计划任务、防火墙或 daemon。

## 2. 精确资源 envelope

完整 attempt 在任何 stream/socket I/O 前由 ledger 预留；B1 `Cost` 仍只描述 candidate-search
slice，不被误当成完整执行成本。

| profile | sockets | targets | five-tuples | outbound UDP | PPS | active + drain |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `predictive_edm/1` | 8 | 64 | 64 | 64 | 32 | 20s + 2s |
| `asymmetric_birthday/1` | 128 | 516 | 523 | 526 | 64 | 20s + 2s |

两者的 fresh evidence 都固定为 5 次 RFC 5780 exchange 加 8 次 allocation sample，共 13 包；
evidence 最长 3 秒，candidate/winner 窗口最长 9 秒。predictive 最多 32 candidate + 1 winner；
asymmetric 每侧对称预留 512 candidate + 1 winner，其中 mapping-set 实际 plan 为 128 个
source socket，target-set 实际 plan 为 1 个 reusable endpoint 对 512 个 target port。预留只可
少用，不可跨 profile 借用、退款、扩窗或自动重试。

ordinary durable ledger 的 2,048 packets/24h 不变：三次完整 asymmetric admission 计 1,578
包，第四次在任何 I/O 前返回 `hard_nat_campaign_rate_limited`。三次连续失败后的 circuit 使用
独立稳定类 `hard_nat_campaign_circuit_open`，不会与普通 admission error 混淆。

第 129 个 socket、第 517 个 target、第 524 个 five-tuple、第 527 个 asymmetric packet、
第 65 个 predictive packet、未登记 tuple，以及第二个 manual-traversal heavyweight attempt
都在底层 I/O 前 fail-closed 并持久化 `hard_limit_exceeded` safety trip。

## 3. 固定协议与执行顺序

进度序列固定为：

```text
preflight -> oob_adopt -> present -> burned -> activated -> handshake -> prepare
  -> sockets -> fresh_evidence -> plan_committed -> ready -> fire -> candidates
  -> winner -> verify -> transport_lease -> handoff -> data_plane_challenge -> terminal
```

执行顺序固定为：

```text
ledger preflight -> attempt reservation -> OOB presence -> durable burn -> ACTIVATE
  -> Noise NNpsk0 -> PREPARE -> exact socket set -> fresh RFC 5780/allocation evidence
  -> independent bilateral recomputation -> authenticated joint/envelope commitment
  -> READY -> FIRE -> fixed one-shot schedule -> authenticated winner -> bidirectional VERIFY
  -> inactive TransportLease -> PromoteToHardNATLease -> adopt/standby
  -> bidirectional 3-packet data-plane challenge -> durable FINISH -> attempt release -> drain
```

双方独立重算 local/peer source commitment、bilateral plan、joint digest 与
`ExecutionEnvelopeDigest`。FIRE 前任一 profile、role、attempt、generation、public address、
source/plan/cost/evidence/envelope digest 不一致均零 direct 发射。remote 不能上传 candidate
list/span/packet count，也不能只提交一个自报 digest 取得执行权。

predictive 使用 role-separated one-shot 顺序，双方各自的 32-source schedule 与对端 target
schedule 成对互认。asymmetric 的 target-set 先以 8 个固定 64-packet batch 打开 APDF pinhole，
mapping-set 随后用 128 个 socket 各发一次；target-set 的唯一 winner ACK 位于独立 PPS slot。
两类 profile 都没有 retry、fallback、seed rotation、自动扩窗或失败后换 profile。

## 4. 终局与 handoff

至少冻结以下 Gate B 稳定失败类：

```text
hard_nat_profile_unsupported
hard_nat_evidence_insufficient
hard_nat_evidence_drifted
hard_nat_plan_mismatch
insufficient_authorized_search_budget
hard_nat_candidate_exhausted
hard_nat_campaign_rate_limited
hard_nat_campaign_circuit_open
hard_nat_packet_rejected
```

错误只公开 class、stage、credential_burned 与 `retryable=false`；不公开 endpoint、candidate
port、socket slot、seed、原始 delta、底层 OS error 或 credential。普通 absence、evidence 不足、
candidate exhaustion、cancel 和 timeout 会 durable FINISH、释放资源且不触发 safety trip；
hard-cap、stale generation、ownership 或未登记 tuple 违规才进入持久 trip。

命中后只把已认证 winner 对应的同一个 socket 原子交给 `GateB2TestConsumer`。TransportLease
绑定 peer、attempt、generation、path 和 fixed target；旧 ProbeSocket/Controller 被毒化，siblings
关闭。VERIFY 后残留的、已认证且属于 frozen plan 的 candidate 必须先排空，再执行 3/3 合成
数据面 challenge。FINISH 始终先于 attempt release，consumer 不能换 endpoint、开 socket、
注册 target 或触发新 attempt。

## 5. 自动化与隔离证据

- `hardnatattempt` 覆盖 artifact round-trip、profile/fallback/unknown-field 拒绝、三套 parser
  互拒、PSK single-take 与 secret-free manifest；
- `hardnatcontrol` 覆盖 independent bilateral recomputation、joint/envelope binding、固定 sequence
  与 AD domain、candidate/winner/VERIFY、replay、跨域篡改、wrong plan/role/generation；candidate
  header 与两种 exact execution-envelope digest 均有字节级 golden；
- `hardnatobserve` 只消费 caller-owned 的恰好 8 个 ProbeSocket，固定 13 个 transaction、4 个
  target/11 个 observation tuple；不拥有 Factory、不开 socket、不接受远端 evidence authority；
- natsim predictive APDM×APDM 完成真实 bilateral handoff；attempt 中途 mapping generation
  改变时 frozen candidate 全部耗尽、有界 FINISH、零 retry、零 data packet、无 trip；
- natsim asymmetric EDM×EIM 覆盖两个真实 carrier/planner role orientation，target-set 实际
  516 target/523 tuple，mapping-set 使用 128 个 source socket，成功后 governor、journal、
  PacketConn、mapping 与队列全部归零；
- architecture/mutation gate 禁止 product/stdio/CLI/runtime/legacy/scheduler 导入 Gate B2，
  禁止 Gate B2/observer 获得 `net`、`os/exec`、Pion/legacy、Factory ownership、第二 socket
  opener或非白名单 TransportLease consumer；
- Gate A、N3b、loopback parser/成本/golden 由原有回归保持不变。

## 6. Required Linux namespace 设计

`linux && natlab` required harness 使用两个 endpoint 子进程、各自独立的真实 machine governor
与 durable ledger，以及 inherited Unix socketpair 模拟 caller 已有 OOB stream。endpoint 的所有
探测与 candidate 都经过生产 `probeio.NewUDPFactory` 的 wildcard-ephemeral real UDP socket。

五个 namespace 沿用 RFC 5737 TEST-NET 拓扑。public namespace 内运行四 socket 的最小 RFC
5780 responder；两个 NAT namespace 各运行一个测试专用 TUN router，提供可重复的 APDM
sequential 或 EIM mapping/filtering，同时数据仍穿过真实 namespace、veth、UDP socket 和 OS
packet path。TUN router 只编译进 natlab test binary，产品包不能导入。

required matrix 固定三项：

| 场景 | 证明边界 |
| --- | --- |
| predictive APDM×APDM | 双侧独立递增 allocation；32-slot bilateral schedule；双向 handoff |
| asymmetric EDM×EIM，mapping planner role 为 channel initiator | 固定有利 128×512 collision sample；target 先发、mapping 后发 |
| asymmetric EIM×EDM，target planner role 为 channel initiator | 物理与 carrier/planner role 完整反转；同一固定成本 |

asymmetric required case 只证明 executor 能消费一个预先固定的**有利碰撞样本**，不把它冒充
63.39% 概率统计；独立 natsim 高重复矩阵才负责验证分布。每个终局必须核对 application/iptables
packet prefix 一致、socket/process 为 0、packet counter 静止、machine lock 可重取、conntrack
清理后为 0，并删除全部 netns/veth。日志只输出 profile 与聚合计数。

缺少 root/netns/TUN 权限时本地明确 skip；required job 设置 `WINKYOU_GATE_B2_REQUIRED=1`，
任何缺失都会失败，不能静默跳过。job 使用 race binary，test timeout 5 分钟、job timeout 6 分钟。

## 7. Required CI 实测

实现 SHA `4553e67add7fc4bb459ce56868a3304116d605ea` 的 PR CI run `33150175416` 中，required
Gate B2 job `98780079367` 使用 race-enabled binary 完成三场矩阵；场景执行耗时 30.40 秒：

| 场景 | application/OS 发射见证 | NAT/终局见证 |
| --- | --- | --- |
| predictive APDM×APDM | evidence 13/13；candidate 31/32；winner 1；socket 8/8 | NAT mapping peak 41/42；conntrack 166→0 |
| asymmetric，mapping role 为 initiator | mapping candidate 64、data 3；target candidate 512、winner 1、data 3；OS total 80/529 | favorable set 512；NAT peak 74/8；conntrack 1192→0 |
| asymmetric，target role 为 initiator | target candidate 512、winner 1、data 3；mapping candidate 64、data 3；OS total 529/80 | 物理角色反转；NAT peak 8/74；conntrack 1192→0 |

三场终局均为：双方 3/3 data-plane challenge、safety trip clear、socket/process 0、packet counter
静止、conntrack 清理后 0、machine lock 可重取、netns/veth 无残留。mapping-set 在第 64 个
one-shot candidate 已命中后停止尚未发送的固定后缀；这只降低实际发射，不生成替代 candidate，
不退款、不重试、不扩窗。

首次 required run 还实际抓住并闭合两项问题：

1. 继承拓扑的 EIM DNAT 会先于 TUN router 抢走入站包；底层 netfilter 现固定为无静态 DNAT
   的 EDM，EIM/APDM 语义只由本 harness 的 TUN router 定义；
2. winner ACK 原按 batch 起点留 PPS 间隔，忽略最后一批 64 包的真实发送耗时；现先见证冻结
   sender 完成，再从最后一包实际发送时刻留满 1 秒，真实 required run 不再触发第 65 包 trip。

两项修正都没有改变 B1 plan、candidate 数量、9 秒窗口、PPS、envelope 或 0-retry 规则。

Windows 已通过 Gate B2 聚焦测试、candidate exhaustion、hard-limit mutation、architecture、
Linux tagged cross-compile 与 tagged vet；`go vet ./...` 和 `go test ./... -count=1` 均完整通过。
受影响包 race×20 已通过，其中 asymmetric 双 role orientation 在 winner 调度修复后再次完成
race×20。该 PR CI 的 Linux、Windows、N1、N2d/N3b、Gate A 与 Gate B2 required jobs 均通过；
本 PR 未触碰已隔离的 #31/#33/#46 代码或期望。

## 8. 未证明事项

本实现不证明 random EDM×EDM 的现场成功，不实现 Gate B3 `hard_16k_lab/1`，不发布产品入口，
不启动任何 observer/rendezvous/daemon，也不签发 live authorization。README 仍不得声称
“universal symmetric NAT traversal”。

## 9. PR #93 首轮独立评审阻断修正

首轮 head `661c21f1d48ff2193de8cc04e46b17466519ea6a` 的 21 项 CI 虽全部通过，独立评审仍用最小
动态复现证明：配置可把真实 UDP target 扩到任意 global-unicast；OOB 在 candidates 阶段断开
后仍会完成 31 个 candidate 与 1 个 winner 发射；READY 后等待 6 秒可让五秒 evidence 过期，
但单向 FIRE 仍继续直连。该 head 不构成可合并证据。

修正后的实现证据边界为：

- 删除 `gateb.Config.AllowNonLoopback`。默认 factory 逐项拒绝非 loopback topology；普通 harness
  seam 拒绝原始 `*probeio.UDPFactory`。唯一真实非回环 factory 由 `linux && natlab` 文件提供，
  在构造与每次 Open/地址核验时确认 netns，并把 observer/local/peer/WriteTo 全部限制在固定
  TEST-NET topology；architecture mutation gate 同时禁止产品注入 factory 或恢复布尔开关。
- Gate B2 建立一个 adoption-to-challenge 的绝对 active context，并把同一个 deadline 交给
  `oobcarrier`。握手后 carrier 的受控 reader 在没有业务 `Receive` 调用时仍能发现 EOF/terminal，
  立即取消所有候选 sender/reader；durable FINISH 使用独立的单写终局顺序，随后才释放 attempt。
- FIRE 使用双方各一帧的认证 barrier；`hardnatcontrol` 只有在两方向 FIRE 都完成后才允许
  candidate。READY 前、FIRE 交换中和交换后均复核本地 evidence，过期稳定落入
  `hard_nat_evidence_drifted`。

新增纯内存/natsim 回归已本地证明三种终局均无越界发射：StageCandidates 强制关闭 OOB 时
candidate/winner/data=`0/0/0`；把共享 active envelope 下调为 500ms 并停在 StageCandidates 时
candidate/winner/data=`0/0/0`；StageReady 后把可信时钟推进 6 秒时在 FIRE 返回
`hard_nat_evidence_drifted`，candidate/winner/data=`0/0/0`。三者均 durable FINISH、资源归零且
safety trip 保持 clear。最终 head 的 required Linux netns 与公开 CI run 编号须在推送后补录；
在此之前本节不替代独立复审。
