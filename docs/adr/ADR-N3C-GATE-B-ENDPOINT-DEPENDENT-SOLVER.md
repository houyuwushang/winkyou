# ADR：N3c Gate B 困难 NAT 有界求解器

- 状态：**Accepted（含 §15 纠错增补、§16 Gate B2 资源裁决、§17 安全阻断处置、§18 Gate B3
  隔离实现裁决与 §19 conntrack ceiling 可实现性纠错）；Gate B1、Gate A、Gate B2 与 Gate B3a docs-only 裁决已合并。2026-08-30
  维护者明确授权一个 §18 Gate B3 Draft 实现 PR，仅限 memory/natsim/required Linux netns；
  产品入口、Gate C、disposable router 与任何现场 I/O 仍未授权**
- 实现复审：§20 为本 Draft PR 暴露问题后的协议闭合提案，尚未独立接受，不改变上述授权边界。
- 日期：2026-08-25
- 基线：`main` = `dc59d73bdc643e1a230d32acb82d97bfd3cb6d65`
- 跟踪议题：[#87](https://github.com/houyuwushang/winkyou/issues/87)
- 上位决策：[`ADR-N3C-OOB-DIRECT-HANDOFF.md`](./ADR-N3C-OOB-DIRECT-HANDOFF.md)、
  [`PAIRING-RESTART-SAFETY-CONTRACT.md`](../PAIRING-RESTART-SAFETY-CONTRACT.md)、
  [`STUN-OBSERVATION-CLIENT.md`](../STUN-OBSERVATION-CLIENT.md)

> Gate A 是资源所有权与 transport handoff 的安全底座，不是 WinkYou 的产品终点。
> Gate B 的验收对象就是普通 fixed-endpoint hole punch 无法处理的 endpoint-dependent NAT。
> 本 ADR 不复活 legacy puncher，不启用自动恢复，也不签发 live authorization。

## 1. 产品裁决

WinkYou 面向的用户是：两台身份已确认的设备分别位于用户无法配置的 NAT 后，已有一个
低带宽带外管理信道可交换控制消息，但不希望最终数据继续经过 relay。

Gate B 的 observable success 是：

1. 在任何 socket 或 packet 之前选定一个不可扩大的求解 profile；
2. 给出双方完整 worst-case cost、候选集合摘要和有前提的命中概率；
3. 只经 machine governor 与 `probeio` 执行一次；
4. 命中后把同一个 verified UDP socket 交给 Gate A 的 `TransportLease`；
5. 最终数据面不经过 OOB carrier；
6. 未命中则有界终止、credential 不退款、不自动换 profile 或再试。

因此，`mapping_not_directly_usable` 只能是 Gate A 的合法终局，不能成为 WinkYou 整体的
产品定义。Gate C 不得只交付 easy-NAT UX 后宣称 direct solver 完成。

Gate B 仍不承诺“所有 NAT 必通”。真正均匀随机、address-and-port-dependent mapping 与
filtering 的两端组合具有不可消除的搜索成本；产品必须显示成本与概率，而不是把 timeout
伪装成求解。

## 2. 术语与证据边界

本文使用 RFC 4787 的独立行为术语，不把一个节点永久标成“对称 NAT”：

- EIM：endpoint-independent mapping；
- ADM：address-dependent mapping；
- APDM：address-and-port-dependent mapping；
- EIF / ADF / APDF：对应的 filtering behavior；
- EDM：本文仅作 ADM/APDM 的集合简称，wire/schema 中仍记录精确证据；
- allocation behavior：同一短时间窗内观察到的端口分配序列；
- search universe：本 attempt 明确获准覆盖的候选公网端口集合。

RFC 4787 明确区分 mapping 与 filtering；只观察 mapped endpoint 不能推出入站过滤规则。
RFC 5128 也指出：端口预测依赖短时序列，在 NAT 负载、非顺序分配和多层 endpoint-dependent
NAT 下会快速失效。参考：

- <https://datatracker.ietf.org/doc/rfc4787/>
- <https://www.rfc-editor.org/rfc/rfc5128.html#section-3.5>

所有 evidence 必须绑定：

- local machine scope；
- peer、attempt 与 generation；
- observation service 集合摘要；
- socket ownership；
- started/finished 时间窗；
- mapped public address 是否在目标间保持一致；
- mapping、allocation 分类及其 limitation；
- 成功/失败样本总数；
- 原始 evidence digest。

它最多在本次 attempt 内有效，不写入节点永久属性，不允许触发未来后台任务。

### 2.1 把中间状态建模为未知物理函数

Gate B 的首选方法不是先撒候选，而是做一次有界 system identification。把出站 mapping
抽象为：

```text
F(local_socket, destination_ip, destination_port, time, competing_allocations)
  -> public_ip, public_port
```

solver 通过不同 observation node 取得 `F` 的样本，估计以下状态：

- mapping 对 destination address/port 的依赖；
- filtering 是否允许 alternate address/port 返回；
- public IP pooling 是否稳定；
- 同 socket 与多 socket 的 allocation delta、wrap、重复和离散度；
- mapping lifetime、port reuse 与并发 allocation stealing；
- 多级 NAT 组合后是否仍存在低熵预测窗口。

输出不是一个永久 NAT type，而是本 attempt 的 `StateModel`：候选端口分布、模型条件下的
残余熵、证据覆盖和过期时刻。有限样本不能证明真实 allocator 的熵上界；没有编译期认可的
模型证据时必须退回 full-range/unknown，而不能因为 3–8 个样本“看起来顺序”就缩小
admission。planner 可优先枚举高概率候选，但 birthday 只消除有明确前提的模型剩余熵。

### 2.2 可用的状态来源

按证据强度从高到低：

1. **协作网关状态。** PCP MAP、NAT-PMP 或明确授权的 UPnP 能直接分配/返回公网 mapping，
   这是最接近“读取物理状态”的路径。PCP MAP 创建的 mapping 按 RFC 6887 具有明确语义；
   但它是单独的 `OperationPortMapping` 权限，Gate B v1 只消费已授权证据，不顺手启用。
2. **RFC 5780 behavior observer。** 支持 `OTHER-ADDRESS`、`RESPONSE-ORIGIN` 与
   `CHANGE-REQUEST` 的 observation node 可从 alternate IP/port 返回，分别测 mapping 与
   filtering。它比普通 STUN 只看 `XOR-MAPPED-ADDRESS` 提供更多物理状态。
3. **分布式 peer observer。** 已存在、可直接接收 UDP 的 WinkYou peer 可以充当有界
   reflector；至少两个不同 public address、一个 address 的两个 port，形成 observation
   quorum。它只返回自己观察到的源 endpoint，不转发最终数据，也不成为 trust anchor。
4. **本机 allocation tomography。** 同一 target 的 3–8 个并存 socket 与同一 socket 的
   多 target 样本，推断端口 allocator 的短时行为。
5. **TTL/ICMP path feedback。** 让 probe 在本端 NAT 之后、到达 peer 之前过期，理论上可能
   从 quoted header 获得更接近 peer-destination mapping 的证据，同时减少对远端端口的触达；
   但 raw ICMP、权限、NAT quote rewrite 和中间路由器限速都不稳定。它只进入后续 research
   profile，不能成为 Gate B v1 的必要条件或隐式 raw-socket 入口。

参考协议：

- RFC 5780 NAT Behavior Discovery：<https://www.rfc-editor.org/rfc/rfc5780.html>
- RFC 6887 PCP：<https://www.rfc-editor.org/rfc/rfc6887.html>
- RFC 6886 NAT-PMP：<https://www.rfc-editor.org/rfc/rfc6886.html>

observer 收集 public endpoint 与 timing，存在隐私成本。它不得接收 pairing secret，默认零
持久化；公开 diagnostics 只保留 evidence class、样本数、熵区间与脱敏地址前缀。

### 2.3 物理可观测性的上限

一个普通 STUN/peer observer 只能看到 NAT 对**该 observer 自己**的 mapping。除非：

- 网关主动暴露或分配 mapping；或
- observer 能从与真实 peer 完全相同的 destination IP:port 身份返回；

否则它不能直接读取将来发往 peer tuple 的隐藏 conntrack 项。确定性、顺序型或低熵 NAT
可以从样本逼近；使用随机 salt、受其他用户竞争影响的 CGNAT 或多级 EDM 只能得到概率
分布。这里不存在能够绕过信息缺失的纯算法：状态收集减少搜索空间，但不会凭空产生未被
观测的 router state。

## 3. 搜索数学

### 3.1 非对称 16-bit 集合碰撞

当一侧是 EDM、另一侧具有可复用的 EIM mapping 时：

- EDM 侧用 `a` 个 socket 向 EIM 的一个 endpoint 各发一次，产生 `a` 个并存公网端口；
- EIM 侧用一个 socket 对 EDM 公网地址发送 `b` 个不重复候选端口；
- 若 EDM 公网端口近似均匀落在大小为 `R` 的 universe，近似命中率为：

```text
P_asymmetric ~= 1 - exp(-(a*b)/R)
```

`a=128`、`b=512`、`R=65535` 时约为 `63.21%`。这正好落在现有 machine profile 的
128 sockets、512 packets、512 targets/five-tuples 上限内，因而是 Gate B 的第一个实际
birthday 目标，而不是普通无 NAT 直连。

### 3.2 双 EDM 32-bit tuple 碰撞

当两侧都按目标改变 mapping，且 filtering 要求精确反向 endpoint 时，每个发射形成一个
`(public_source_port, remote_destination_port)` tuple。双方各发出 `qA`、`qB` 个不重复的
本地 `(socket_slot, target_port)` probe；假设 NAT 产生近似独立、不过载的公网 tuple，完整
端口 universe 分别为 `RA`、`RB` 时：

```text
P_hard ~= 1 - exp(-(qA*qB)/(RA*RB))
```

在两侧都近似均匀使用全部非零 UDP 端口时：

| 每侧 tuple/packet | 近似命中率 |
| ---: | ---: |
| 512 | 0.006104% |
| 2,048 | 0.097612% |
| 8,192 | 1.550403% |
| 16,384 | 6.058873% |
| 32,768 | 22.120516% |
| 49,152 | 43.022696% |
| 65,535 | 63.212056% |

因此现有 512-packet attempt 对随机 EDM×EDM 没有产品意义。danderson 的原始示例也指出，
hard case 需要双方各约 65,536 probes 才能回到约 64%：
<https://github.com/danderson/nat-birthday-paradox>。

表中数值是指定均匀、独立、无 port-overloading 模型下的估计，不是成功保证。NAT 对不同
destination 复用公网 port、分配池漂移或 filtering 变化都会降低有效 `q`。实现必须提供
高精度/精确的 without-replacement 计算和 golden vectors；不得用近似值做 admission 的
上取整依据。

### 3.3 缩小 universe 的条件概率

若短时 evidence 显示双方公网源端口都落在一个大小为 `16,384` 的已命名 universe，双方
各覆盖该 universe 的 16,384 个目标端口，则条件命中率约为 63.21%。但少量样本不能证明
未来 mapping 必在该区间：

- planner 必须同时显示“在模型成立条件下的概率”和“模型覆盖未知”；
- mapped source 一旦落在 universe 外，本 attempt 不得临时扩窗；
- v1 不接受远端提供任意 port list；只接受编译期命名 universe；
- 公网 IP 可能由 CGNAT 多用户共享，广泛 target coverage 会触达并非本 peer 的端口，必须
  视为高风险 campaign，而不是普通探测。

## 4. 三个明确 profile

每个 artifact 固定一个 profile。双方 parser、Noise prologue、control AD、plan digest 与
ledger record 都包含 exact identifier；未知值零 I/O 拒绝，不协商、不 fallback。

### 4.1 `predictive_edm/1`

目标：两侧或一侧为 endpoint-dependent mapping，但 fresh allocation evidence 为
`sequential_uniform`，或在独立评审阈值内为低离散 `monotonic_nonuniform`。

约束提案：

- 至少 8 个成功 allocation sample；不足或 `apparently_random` 终止；
- 两个 observation address、其中一个 address 的两个 port，验证 public IP 稳定性；
- RFC 5780 filtering evidence 可提高置信度但不能提高 resource ceiling；observer 不支持时
  明确保留 `filtering_unknown`，按 APDF 最坏情况规划；
- candidate window 每侧最多 32；窗口由相邻 delta、并发 stealing allowance 和一次 wrap
  纯函数生成；
- 最多 8 sockets、64 direct packets、64 five-tuples、32 PPS、13 秒 active；
- 固定 FIRE 时刻与 role-separated target order；收到首个认证 packet 后从同一 socket 回打；
- prediction miss 终局，不升级 asymmetric 或 hard birthday。

这是“困难 NAT 的低成本求解”，不是 fixed endpoint 直连。

### 4.2 `asymmetric_birthday/1`

目标：fresh multi-address evidence 证明一侧 mapping 与 EIM 一致，另一侧为 EDM 或
mapping 不可预测；filtering 按最保守 APDF 处理。

角色由 artifact 固定：

- `mapping_set_role`：最多 128 sockets，每 socket 向 EIM fixed endpoint 发一个认证 probe；
- `target_set_role`：1 socket，对 EDM public address 的 512 个不重复端口各发一个认证 probe；
- candidate 由 attempt key 派生的 role-separated permutation 生成，远端不能指定；
- B1 搜索片段每侧冻结 512 candidate packets/targets/five-tuples，尽管 mapping-set 一侧通常
  只消费 128；完整 B2 attempt 的观测与 winner ACK 预算按 §16 单独冻结；
- 总 PPS 64、active 13 秒、0 retry；
- 模型前提成立时声明约 63.21%，evidence 漂移则在 FIRE 前终止。

该 profile 的 128×512 搜索片段可在原数值 ceiling 内证明算法；完整 attempt 还必须支付观测
与 winner ACK 成本，因此使用 §16 修订后的 explicit operation/profile。`phase1_machine`
继续不允许 `OperationBirthday`。

### 4.3 `hard_birthday_campaign/1`

目标：双方 fresh evidence 均显示 endpoint-dependent 且 allocation `apparently_random`，或
prediction evidence 不足；这是用户所说的最困难 NAT，也是 Gate B 的最终目标。

第一版只冻结两个资源 class 供评审，均不得在本 ADR 合并后自动启用：

| class | 每侧 tuple | sockets × targets/socket | PPS | full-range 模型 | 16K-universe 条件模型 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `hard_16k_lab/1` | 16,384 | 16 × 1,024 | 512 | 6.06% | 63.21% |
| `hard_32k_candidate/1` | 32,768 | 32 × 1,024 | 512 | 22.12% | 98.17% |

`hard_16k_lab/1` 是推荐的首个 isolated implementation ceiling。它已比旧版无限轮询小得多，
但仍可能创建约 16K NAT/conntrack 状态并表现为对一个公网地址的大范围 UDP 扫描。因此它
只在 netns、受限 conntrack 和 disposable router 证据通过后，才有资格被讨论为具名 live
campaign。`hard_32k_candidate/1` 只用于比较负载/概率，不在首个实现 PR 中拥有 I/O 权限。

覆盖完整 65,535 端口虽然在均匀模型中约为 63%，但会触达 well-known/registered services、
可能影响共享 CGNAT 用户并逼近消费级网关 conntrack 上限。Gate B v1 明确拒绝把它变成
live profile；它只保留为数学基准。

## 5. Candidate planner

首个实现包暂定为 `internal/v2/hardnatplan`，是 zero-network-capability zone，只包含纯函数：

```text
EvidenceGraph + Profile + ResourceClass + AttemptContext
  -> ValidateEvidence
  -> InferStateModelAndEntropy
  -> ComputeSearchSpace
  -> ComputeProbability
  -> RankCandidatesOrBuildRoleSeparatedPermutation
  -> FreezeCost
  -> Plan + PlanDigest
```

必须满足：

- 使用 cryptographic PRF/PRP 从 handshake-derived planner key 派生顺序；
- 本地 `(socket_slot, target_port)` 候选对无重复，port 0 永不出现；同一 target port 可在
  不同 socket slot 中出现，但必须是 plan 明确列出的不同 tuple；
- profile 决定命名 universe，RPC/OOB/peer 不能上传 candidate list、span 或 packet count；
- candidate ranking 只能来自有 digest 的本地观测模型；远端 observer report 是不可信样本，
  必须由本地发出的 transaction 与收到的协议响应绑定，不能直接变成控制指令；
- role、socket slot、ordinal 与 target port 全部进入 plan digest；
- 双方在 FIRE 前交换并认证 plan digest、cost digest、evidence digest；不一致终局；
- planner 先证明完整 cost 可 admission，再返回任何 candidate；
- 概率输出包括 model、universe、assumptions、conditional flag 和精度；
- 无法达到 profile 声明的最低概率时返回 `insufficient_authorized_search_budget`，不是 timeout。

跨语言 golden 至少冻结：seed、role、universe、前后 16 个 candidate、完整 digest、cost 与
概率有理数/高精度十进制。测试不得依赖 map iteration 或浮点平台差异。

## 6. Wire 与执行状态机

Gate B 使用新的 exact identifiers，不修改 N3b 或 Gate A parser：

```text
artifact_profile: winkyou-test-hard-nat-attempt/1
direct_attempt_profile: winkyou-test-hard-nat-control/1
planner_profile: predictive_edm/1 | asymmetric_birthday/1 | hard_birthday_campaign/1
resource_class: profile-specific exact identifier
runtime_fallback: disabled
```

固定顺序：

```text
artifact/scope/profile/cost preflight
  -> acquire machine owner + complete reservation
  -> OOB presence
  -> durable BURN_AND_ADMIT
  -> Noise handshake
  -> PREPARE(profile, resource_class)
  -> open the predeclared governed sockets
  -> fresh bounded observation/allocation evidence
  -> freeze plan and exchange authenticated digests
  -> READY
  -> FIRE at one agreed monotonic offset
  -> emit every predeclared tuple at most once
  -> endpoint learning + authenticated ACK/VERIFY
  -> Gate A TransportLease handoff or terminal drain
  -> durable FINISH
```

hard campaign 可分批调度以满足 PPS，但 batch、顺序、数量在 FIRE 前已经固定。收到 hit 后可
停止尚未发出的 tuple；这只降低实际成本，不退款，也不允许生成替代 candidate。

所有 UDP payload 使用 Noise session 派生的独立 AEAD key，至少绑定 attempt、generation、
profile、role、socket slot、ordinal 与 plan digest。任意未认证 packet 不产生回复；认证通过
但不属于本 plan 的 packet 仍终局，不动态登记来源。

## 7. Governor 与持久 ledger

不得提高 `ProfilePhase1Machine`，否则普通 diagnose/N3b 路径会无意继承 birthday 权限。

### 7.1 低成本 manual traversal profile

新增 exact machine-only profile `phase1_manual_traversal`：

- 只允许 `OperationPrediction` 与 `OperationBirthday`；
- hard ceiling 为 1 active peer/attempt/heavyweight、128 sockets、516 targets、523 five-tuples、
  526 packets、64 PPS、20 秒 active + 2 秒 drain；
- 每个 artifact 仍须使用 §16 的 profile-specific exact envelope；不得因为 profile hard ceiling
  更高而让 `predictive_edm/1` 取得 asymmetric 额度；
- 只允许 `predictive_edm/1` 与 `asymmetric_birthday/1`；
- 仍由同一个 machine OS owner lock 与 pairing journal 单写者负责；
- user-acknowledged、runtime、scheduler、recovery 永远不能取得。

### 7.2 高成本 campaign profile

`hard_16k_lab/1` 需要独立 exact profile 与 record class，候选上限提案为：

| 资源 | ceiling |
| --- | ---: |
| active peers / attempts / heavyweight | 1 / 1 / 1 |
| sockets | 16 |
| targets / five-tuples | 16,400 |
| packets | 16,432（含最坏 observation） |
| packets per second | 512 |
| active / drain | 45s / 2s |

它继续复用**同一个** machine owner lock，不增加第二个预算权威。高成本 record 进入同一个
append-only journal，但使用独立更严格窗口：

- 每 24 小时最多一次 campaign admission；
- 24 小时最多预留 16,432 packets；
- 一个未成功 terminal 即打开 campaign circuit；
- passage of time 不自动清 circuit；显式 reset 不退款；
- journal indeterminate 与 safety trip 继续零发射；
- ordinary pairing 的 2,048-packet window 不被提高，也不能支付 campaign。

以上数值仍是 review candidate；§18 给出把它们冻结为 isolated implementation ceiling 时必须
同时接受的非可互换计费、ledger 与 capability 条件。在 §18 独立复审闭合前不得实现；任何
live 提升仍需要新的 exact-SHA 授权。

## 8. 稳定失败类

至少冻结：

| class | 语义 | 发射 |
| --- | --- | ---: |
| `hard_nat_profile_unsupported` | identifier/resource class 不支持 | 0 |
| `hard_nat_evidence_insufficient` | 成功样本/地址/时间窗不足 | 0 direct |
| `hard_nat_evidence_drifted` | fresh 复核不再满足 artifact profile | 0 direct |
| `hard_nat_plan_mismatch` | 双方 digest/cost/universe 不同 | 0 direct |
| `insufficient_authorized_search_budget` | 授权 cost 达不到声明概率门 | 0 |
| `hard_nat_candidate_exhausted` | 固定集合发完未命中 | 精确上限内 |
| `hard_nat_campaign_rate_limited` | 持久窗口已满 | 0 |
| `hard_nat_campaign_circuit_open` | 上次 campaign 未成功并已开路 | 0 |
| `hard_nat_packet_rejected` | AEAD/plan/role/ordinal 不合法 | 以此前实际值 |

错误和 progress 不含公网地址、candidate 端口、socket slot、原始 delta、seed 或底层 OS error。
诊断只显示 profile、resource class、model probability、实际 packet/socket 计数与稳定 class。

## 9. 必过测试

### 9.1 纯函数与数学

- exact/高精度 easy 16-bit、hard 32-bit probability golden；
- `StateModel` 对 mapping/filtering/IP-pooling/allocation evidence 的确定性归并与 entropy golden；
- RFC 5780 `OTHER-ADDRESS`/`RESPONSE-ORIGIN`/`CHANGE-REQUEST` 只做 codec 与状态机向量，
  observer 缺失能力时返回 `unsupported_evidence` 而不是猜测；
- monotonicity、symmetry、边界 `0/1/65535`、overflow 与 fuzz；
- permutation 无重复、role/domain 分离、跨语言一致；
- cost 在 candidate 生成前冻结，任一维不足零 candidate；
- 任意远端 candidate list/span/packet-count 字段 parser 拒绝。

### 9.2 NAT simulation

- sequential APDM×APDM：`predictive_edm/1` 在窗口内成功；插入 stealing allocation 时有界失败；
- RFC 5780 的 EIM/ADM/APDM × EIF/ADF/APDF 组合分别进入模型，mapping 与 filtering 不混淆；
- observer 缺席、说谎、重复地址、跨 attempt replay 或 quorum 不足只能降低 evidence；
- EDM×EIM 与 EIM×EDM：角色固定、关键组合高重复，概率统计落在预先定义置信区间；
- random APDM×APDM：16K universe 全覆盖达到模型分布；full-range 16K 只按约 6% 解释；
- ADF/EIF 比 APDF 更容易时仍不越界；mapping/filtering 独立变化时不复用旧 evidence；
- duplicate、reorder、loss、tamper、replay、wrong plan/role/generation 全部终局或按固定集合继续，
  永不扩窗。

### 9.3 进程与资源

- 32–100 process 同 credential 只有一个 admission；
- 1,000 restart 后零续跑；
- candidate exhaustion、cancel、writer error、parent/child kill 后 socket/goroutine/process 为零；
- 进程外 packet/socket/conntrack witness 精确等于 plan 已发前缀；
- predictive 第 65 个总 packet、asymmetric 第 527 个总 packet、asymmetric 第 517 个
  target / 第 524 个 five-tuple、任一 profile 的超计划 candidate、第二个 heavyweight attempt 与任一
  未登记 tuple 均在 OS I/O 前拒绝并触发持久 trip；
- campaign 第 16,433 个 packet、16,401 个 tuple、17th socket、513 PPS 触发持久 trip；
- mutation tests 抓住 direct `net.ListenUDP`、legacy/Pion import、candidate API、fallback/retry 与
  journal bypass。

### 9.4 隔离负载门

在任何 disposable-router/live 讨论前，required Linux CI 必须：

- netns NAT 限制 conntrack ceiling，验证 16K profile 不越界且排水归零；
- 注入 ENOBUFS、conntrack full、50% loss、OOB EOF 与 process kill；
- 证明 soft failure 不导致未声明重发，hard limit 触发持久 trip；
- 记录 wall time、PPS、packet、tuple、socket、conntrack peak 与 drain latency；
- 100 次 fresh topology 无 residue，race-enabled binary，超时硬杀仍由父进程见证。

## 10. 产品与现场验收

Gate B 不能以“代码能跑”完成。至少需要：

1. required netns 中 predictive APDM×APDM 成功；
2. required netns 中 asymmetric EDM×EIM 双角色成功；
3. hard random simulation 的实测分布与模型一致；
4. `hard_16k_lab/1` 在 disposable router/受限 conntrack 环境完成负载与 teardown 复核；
5. 独立安全审查接受 exact profile 与 ledger；
6. 具名 live campaign 用一个 credential、一次 attempt、一个 fixed plan；
7. 最终 PacketTransport 证明不经过 OOB relay，并在关闭后零 residue。

只有新 v2 路径在至少一个 endpoint-dependent 现场环境建立直连，README 才能声称
“solves selected hard NAT cases”。随机 EDM×EDM 未通过前必须标为 experimental campaign，
不能写“universal symmetric NAT traversal”。

## 11. 明确拒绝

- 复用 `pkg/nat/puncher`、Pion ICE 或 legacy `birthdaypunch` strategy；
- 让 stdio/peer 上传 IP range、port list、socket 数、PPS 或 packet count；
- 对未认证、未具名或共享目标地址运行 campaign；
- 同 attempt 从 predictive 自动升级 birthday，或失败后换 seed/扩大 universe；
- supervisor、daemon、cached card、启动项或重启后继续发送；
- 以平均实际包数代替 worst-case reservation；
- 把一个成功样本写成永久 NAT 类型或未来自动选择依据；
- 为提高随机 EDM×EDM 概率而默认覆盖全部 65,535 UDP ports。

## 12. 实施顺序

1. **本 PR：**docs-only ADR 与数学/资源评审；
2. **Gate B1：**`StateModel` + `hardnatplan` 纯函数、RFC 5780 codec golden、natsim，不开 socket；
3. **Gate A：**OOB carrier、`TransportLease` 与 test consumer；
4. **Gate B2：**`predictive_edm/1` + `asymmetric_birthday/1` probeio executor；
5. **Gate B3：**`hard_16k_lab/1` 独立 profile、ledger、required netns 负载；
6. **Gate C：**SSH assembly、产品入口与分别签发的现场窗口。

Gate A 是代码依赖，但 Gate B1 应先冻结 planner 与 cost，以免 Gate A 的接口只能表达 easy
endpoint。Gate C 不得跳过 Gate B2 后只发布普通直连。

## 13. 评审问题

1. 是否接受 Gate B，而非 Gate A easy path，作为 direct solver 的产品验收目标？
2. `predictive_edm/1` 的 8-sample、32-candidate window 是否足以进入实现？
3. 是否接受 128×512、约 63% 的 asymmetric birthday 作为首个联网 Gate B profile？
4. `hard_16k_lab/1` 应固定 IANA dynamic universe，还是只允许 operator 在私有授权中选择一个
   编译期形状、但不进入 artifact 的 16K universe？
5. 一个 campaign 失败即开 circuit 是否过严；若放宽，如何避免重复制造 conntrack 压力？
6. 高成本 record 复用同一 journal、独立计数窗口是否满足“唯一预算权威”？
7. 是否明确拒绝 full 65,535-port live profile，直到有更强的目标归属与网关容量证明？
8. Gate B1 planner 是否应先于 Gate A 实现，以反向校验 handoff/carrier 接口？
9. 是否接受“多 observation node 状态层析优先、birthday 只覆盖残余熵”作为默认 solver
   结构；首批 observer 是否只做 RFC 5780 与 peer-reflector 两类？

这些问题未接受前，只允许 docs、pure function 与 memory/natsim 工作；不创建 machine scope、
不部署 binary、不运行 active STUN、不修改 firewall，也不向 LAN/公网发出 birthday packet。

## 14. 独立评审答复（2026-08-26）

数学基准已复核：表中双 EDM 概率与 1−exp(−q²/(R²)) 模型精确一致（含
16,384→6.06%、32,768→22.12%、65,535→63.21%），无非一致性。

1. **接受。** Gate B 就是 direct solver 的验收目标；Gate A easy path 只是底座。但兑现
   现有“失败是正常结果”产品承诺：artifact 必须把求解 profile 作为显式用户可见选择，
   不允许发起后默默跑 birthday 而用户只看到“连接中”。
2. **8 样本/32 窗口可进入实现**，但 §4.1 原文的条件用语必须强制化：证据低于阈值或
   分类超出 sequential_uniform/低离散 monotonic_nonuniform 时**零 direct 发射**，不是
   降级重试的输入。
3. **接受 128×512 作为首个联网 profile**。本答复当时把 512 candidate packets 误作完整
   attempt packets；§16 已纠正观测与 winner ACK 的遗漏。128×512 搜索形状和 63.21% 条件
   概率保持不变，且必须始终带“模型前提成立”条件标注展示。
4. **`hard_16k_lab/1` 使用编译期固定 universe**：IANA dynamic/private 段
   49152–65535（避开 well-known 49151 及以下的注册服务面），不在私有授权中选择形状、
   不进入 artifact。universe 形状只能由新 ADR 修订改变。
5. **失败即开 circuit 不过严，保持原文。** 松动的替代方案无一不与“一次失败即终局”
   冲突；compensating 机制是 Gate C 的 campaign 排期纪律，不是代码路径。circuit 只能靠
   显式人工 reset（现有 safety 语义）解除。
6. **接受同一 journal、独立更严窗口。** 单写者不变量是核心；但实现测试必须证明
   campaign record 不挤占普通 pairing 的 2,048 包窗口，且 campaign 窗口与 ordinary 窗口
   互相独立计数、互不低偿。
7. **明确拒绝 full 65,535 live profile**，保留为纯数学基准（本文 §3.2 表格）。解锁条件
   只可能是：CGNAT/网关容量外证 + 新 ADR，永不靠实现 PR 解锁。
8. **接受 B1 先于 Gate A 实现**（§12 顺序正确）。planner 冻结后 Gate A 接口才不至于
   只能表达 easy endpoint；Gate A 实现时应携带 B1 的冻结 cost/plan 类型。
9. **接受“状态层析优先、birthday 只覆盖残余熵”为默认结构。** 首批 observer 只有
   RFC 5780 与 peer-reflector 两类；TTL/ICMP 保持 research 标签、不得进 v1；PCP/NAT-PMP
   只在已有 `OperationPortMapping` 显式授权时**消费既有 mapping 证据**，Gate B 不获得
   主动分配或配置网关的任何权限。

附一条冻结增补：planner 的 without-replacement 精确概率计算使用高精度有理数
（big.Rat 或等价），golden 覆盖均匀近似的偏差量级；admission 判定只接受下取整。

## 15. Gate B1 独立复审纠错增补（Accepted，2026-08-27）

本节响应 PR #90 第一轮独立复审。复审用八个临时最小复现证明：原实现把本机预测窗口
误当作本机发送目标、把双方必然不同的 directional digest 互相判等、接受自报/过期 evidence、
不兼容 RFC 5780 的双 mapped-address 要求、让诊断/重放改变 plan，以及输出不包围真值的
概率区间。八个复现已转成永久回归测试。

本节最初为待独立接受的纠错提案，不得由实现者自行翻转为 Accepted；2026-08-27 由未参与
实现提交的独立复审方在维护者明确授权下执行裁决并接受（见 §15.7）。它覆盖 §5 中与下述
语义冲突的解释，但不授权 Gate A、Gate B2、executor、carrier 或任何网络 I/O。

### 15.1 双边 source commitment 与 directional schedule

单侧 tomography 的输出是该侧对自己未来 public source mapping 的
`LocalSourceCommitment`，**不是该侧要发送的 target list**。对 predictive profile：

```text
left local evidence  -> left ordered source schedule
right local evidence -> right ordered source schedule

pairing p = shared-key PRP; responder uses inverse p^-1

left directional plan[i]  = (left source slot[i],  right expected source port[p(i)])
right directional plan[j] = (right source slot[j], left expected source port[p^-1(j)])
```

因此 A 预测自己的下一 source 为 50000、B 预测自己的下一 source 为 60000 时，A 必须向
B 的 60000 schedule 发射，B 必须向 A 的 50000 schedule 发射。任何仍向本机窗口发射的
plan 都是错误实现，即使其条件概率显示 100%。

`LocalSourceCommitment` 只允许固定 schema：profile、resource class、role、attempt、
generation、evidence/cost digest，以及 profile 决定的有界 source shape。它不允许携带
packet count、PPS、span 或任意 target candidate：

- `predictive_edm/1`：恰好 32 个有 ordinal 的 expected-source slots；共享 planner key 生成一个
  固定 PRP，initiator 使用正向置换、responder 使用逆置换。由此每一个
  `left_source[i] -> right_source[p(i)]` 都有严格互逆的
  `right_source[p(i)] -> left_source[i]`，不会因两侧各自独立 shuffle 而破坏 reciprocal APDF；
- `asymmetric_birthday/1`：`target_set_role` 只承诺一个已认证、可复用的 receive endpoint；
  该 endpoint 不接受 caller/peer 另行填写，必须由本 attempt 的 RFC 5780 transcript 产生 EIM
  结论，并与同一 socket slot 的成功 allocation sample 精确一致；
  `mapping_set_role` 的 128 个 slot 与 `target_set_role` 的 512 个 target 仍由共享 planner key
  的 role-separated PRP 决定；
- `hard_birthday_campaign/1`：不接受远端自报 source window；两侧 target permutation 仍只由
  编译期 universe、固定 shape 与共享 planner key 生成。

这是对“远端不得上传 candidate list”的窄化澄清：对端可以在后续认证 wire 中提交自己的
固定形状 source commitment，不能提交本机 target plan，也不能改变任何 cost/admission 维度。
虚假 source commitment 最多使本 attempt 失败，不得扩窗、重试或提高预算。B1 只冻结值类型
与确定性编码，wire/authentication 仍由后续 gate 评审。

### 15.2 directional triples 与 joint commitment

两侧 role、evidence 与 directional candidates 本来就不同，因此双方的
`plan/cost/evidence` triple **不得互相判等**。双方交换的是两个不同的 directional triples，
再按 profile 固定 role 顺序组成同一个 `JointPlanCommitment`：

```text
JointPlanDigest = H(profile || resource || attempt || generation ||
                    left-source-commitment || left-directional-triple ||
                    right-source-commitment || right-directional-triple)
```

双方只比较完整 joint commitment 与 joint digest；缺一侧、role 重复、attempt/generation
不一致、source commitment 不一致或任一 directional triple 不一致均为终局。旧的
`VerifyDigestTriple(local, remote)` 相等语义必须删除。FIRE 前必须完成 joint 互认。

`Executable` 是 PlanDigest 的显式字段，不得只依赖 resource class 或 source digest 间接推导。
执行方还必须用 source commitment 与已认证 joint commitment 重算 profile/resource shape、
canonical probability、cost、candidate tuple、PlanDigest 与 directional triple；只比较已经
存储的 digest 不构成执行授权。peer 提交的 probability report 不能只凭 floor 过门，除
`model_coverage` 诊断文本外的全部数学字段必须由固定 profile/resource/source shape 重算。

### 15.3 trusted evidence validation context

`EvidenceGraph` 中的非零 digest 只是被验证对象，不是信任来源。B1 必须另外接收调用者提供的
纯值 `TrustedValidationContext`，且该 context 不得从待验证 graph 自动派生。它至少固定：

- expected machine scope、peer、attempt、generation、observation-service set 与 socket-owner
  digest；
- trusted started/finished/expires 时间与当前 evaluation time；
- 预先签发的 transaction manifest：evidence kind、transaction ID、source class、destination
  endpoint、socket slot、ordinal 与允许响应时间窗。

RFC 5780 的 mapping/filtering 不接受 `MappingEvidence.Behavior` 或
`FilteringEvidence.Behavior` 直接填枚举。actionable 输入必须保留五步固定 transcript：
每步的 request bytes、transaction ID、request destination、实际 datagram response source、
response bytes、socket slot、ordinal 与 observation time。归一化过程重新解析 request/response，
核对 manifest、`MAPPED-ADDRESS`/`XOR-MAPPED-ADDRESS`、实际 source 与四地址 topology，再由
状态机生成 mapping/filtering。直接标记为 `SourceRFC5780` 的结论记录稳定拒绝。

v1 提案冻结 acquisition window 不超过 5 秒、finished 到 evaluation 不超过 5 秒；evaluation
必须早于 trusted expiry，trusted expiry 不得晚于 finished 后 5 秒。任一 graph header、record
或时间与 trusted context 不一致均零 candidate。

allocation 分类只使用以最高已签发 ordinal 结尾的**连续成功后缀**；后缀至少 8 个、ordinal
逐一递增、observed time 不回退。`0,100,...,700`、缺失 transaction、末尾失败或跨 socket-owner
样本都返回 `hard_nat_evidence_insufficient`，不得按 sequential 分类。

归一化顺序固定为：绑定校验 -> transaction 冲突检查 -> 完全相同重放去重 -> 生成 actionable
graph/digest -> 状态归并。remote report 和 remote report 数量只进入 `RawEvidenceDigest` 及本地
诊断，不进入 actionable evidence digest、model coverage、probability 或 plan digest。

### 15.4 RFC 5780 兼容性纠错

RFC 5780 success response 必须同时包含 `MAPPED-ADDRESS` 与 `XOR-MAPPED-ADDRESS`，解析后两者
必须表示同一个 endpoint；缺少任一属性为 `unsupported_evidence`，不一致为协议错误。
behavior topology 必须验证四个地址身份：primary=`A1:P1`、same-address-other-port=`A1:P2`、
other-address-same-port=`A2:P1`、change-IP-and-port=`A2:P2`，其中 `A1 != A2` 且 `P1 != P2`。
`OTHER-ADDRESS` 不满足双 IP/双端口时不得猜测 mapping/filtering。

### 15.5 数学契约纠错

- 对外序列化的 decimal lower 必须向负无穷取整、upper 必须向正无穷取整，并用独立 exact
  `big.Rat` 证明 `lower <= exact <= upper`；内部 lower 仍是 admission 唯一输入；
- Poisson approximation 对任意合法 `uint64` 输入保持 `[0,1]`，使用高精度 range reduction，
  不得依赖固定长度、在大指数下发散的直接 Taylor 多项式；
- 在不做溢出加法的前提下先判定强制相交。`N=MaxUint64, left=MaxUint64, right=1`
  必须返回精确 1，而不是 overflow；真正的乘法 overflow 继续稳定拒绝。

### 15.6 重新进入评审的最低证据

1. 两个 disjoint predictive windows 的 natsim APDM×APDM 测试，使用两个真实 natsim NAT
   与 reciprocal APDF filtering，证明双方按 peer source schedule 互通；candidate tuple 每个
   只发一次，endpoint learning 后只允许选中的一个 winner tuple 发 ACK/VERIFY；旧的“本机
   next mapping 位于本机 plan”测试删除或改为 source-commitment 单元测试；
2. trusted context 的外来 machine/socket、过期、未来时间、manifest 缺失/篡改、稀疏 ordinal、
   末尾失败全部零 candidate；
3. remote diagnostics 与完全相同 transaction replay 只改变 raw digest；
4. RFC 5780 双 mapped-address 与四地址 topology 正/负 golden；
5. 128×512 decimal interval 包含 exact rational、large-exponent Poisson 有界、MaxUint64 强制相交；
6. 双方不同 directional triples 组成相同 joint digest，任一 side mutation 均被拒绝；
   `Executable` mutation、非 canonical probability 与执行前 Plan 重算失败均被拒绝；
7. architecture zero-network 门禁、全仓、race×20 与跨语言 golden 重新通过。

以上全部通过仍只表示 Gate B1 可重新送审；必须由独立评审明确接受本节后，PR #90 才可合并，
且不得据此自动进入 Gate A/B2。

### 15.7 独立复审裁决（Accepted，2026-08-27）

- 复审方式：针对最终 head `d2d7fdeb3578913872bc06abebf7eb282c3fae8f` 的完整 main..HEAD
  差异执行第三轮对抗式独立复审，重点攻击最新的 transcript 派生、归一化去重、endpoint
  witness、plan-v3 digest 与执行前 verifier；复审方未参与实现提交，裁决经维护者明确授权。
- 攻击结论：全部 fail-closed，无阻断项。验证包括：篡改 CHANGE-REQUEST 标志、跨 transcript
  部分重放、transcript SocketSlot 伪造、不同 slot 双 EIM transcript 冲突、manifest 缺漏与
  多余 transaction、直接自报 `SourceRFC5780` mapping/filtering 枚举、伪造 probability report、
  `Executable` mutation、诚实重算 digest 的 in-shape 伪造 target 经 joint triple 拒绝、双写序
  natsim 双向 schedule 互通与单 winner ACK、架构门禁覆盖新增文件、race×20 与 `go vet`。
- §15.6 七项最低证据全部满足；接受 §15.1–15.6 为规范性语义，PR #90 解除 Blocked 并可合并。
- 六项非阻断观察及处置（不阻塞本裁决）：
  1. `VerifyPlanAgainstCommitment` 设计上不重算 TargetPort；目标正确性依赖双方各自独立
     运行 `BuildBilateralPlan` 并互认 joint digest（§15.2 设计）。Gate B2 wire 评审必须
     显式携带并验证此前提。
  2. transcript 五步未强制 `ObservedAtMilli` 跨步单调；未发现错误分类路径，列为 Gate B2
     前的防御纵深候选。
  3. socket slot 超出 profile socket 上限的合法 EIM transcript 会在 verifier 处 fail-closed；
     仅可用性怪癖，不要求改动。
  4. IPPooling 证据仍可携带 `SourceRFC5780` 标签而无 transcript 派生；当前 pooling 无正向
     权威，Gate B2 若赋予 pooling 更强权威必须先收紧到 transcript 派生。
  5. asymmetric natsim 的两个 orientation 子测试仅差 PRP key label、物理角色相同；覆盖度
     命名偏高，Gate B2 应补真实反向角色测试。
  6. golden 仅通过 PlanDigest 与 schema v3 隐式冻结 `Executable`；后续 golden 修订应显式化。
- 本裁决不授权 Gate A、Gate B2、B3、executor、carrier、stdio/CLI/runtime 接线或任何
  现场/网络 I/O；上述均需按 §12 顺序另行评审。

## 16. Gate B2 完整执行 envelope 裁决（Accepted，2026-08-28）

Gate B2 开工审计发现，§4.2/§7.1/§14.3 把 B1 的 512 个 candidate packets 同时当成完整
attempt packet ceiling，但固定状态机又要求在 candidate 生成前采集 fresh evidence。按已合并
B1 的最小证据，完整 asymmetric attempt 需要五次 RFC 5780 exchange、八次独立 allocation
sample、512 个 one-shot candidate，以及最多一个 authenticated winner ACK。若仍用 512 总包
上限，合法执行会在第 500 个 candidate 前后触发持久 hard-limit safety trip；把候选静默减到
498 又会改变已冻结的 plan、joint digest、golden 与条件概率。维护者因此作出以下约束性裁决：

1. B1 的 `asymmetric_birthday/1`、128×512 candidate shape、概率、plan、directional triple 与
   joint commitment 全部保持不变。B1 `Cost` 描述 candidate-search slice，不是完整 B2 attempt
   envelope。
2. `predictive_edm/1` 的完整 exact envelope 为 8 sockets、64 targets、64 five-tuples、
   64 outbound UDP packets、32 PPS。至少八个 allocation sample、可选五步 RFC 5780 evidence、
   最多 32 个 candidate 与一个 winner ACK 必须共同装入该总量，不得另行借额。
3. `asymmetric_birthday/1` 的完整、双侧对称 exact envelope 为 128 sockets、516 targets、
   523 five-tuples、526 outbound UDP packets、64 PPS：13 个 fresh evidence packets +
   512 个 one-shot candidates + 最多 1 个 authenticated winner ACK。RFC 5780 向三个
   observer endpoint 发请求，但合法的 change-IP-and-port 响应来自第四个 endpoint，四者都必须
   预登记；八个 allocation socket 与 slot 0 的三个额外 alternate-source tuple 合计最坏 11 个
   observation five-tuples，target-set role 再登记 512 个 candidate five-tuples。candidate、
   observer 与 ACK 不得产生未计费 target 或发送。
4. `phase1_manual_traversal` 是唯一能取得上述 envelope 的 machine-only profile；
   `ProfilePhase1Machine`、user-acknowledged、Gate A/N3b、diagnose、stdio/CLI/runtime、scheduler、
   recovery 均不得继承。ordinary pairing ledger 按 exact envelope 计费且继续使用
   2,048 packets/24h 上限，因此最多容纳三次完整 asymmetric admission，第四次零 I/O 拒绝；
   不提高或重置任何 rolling window。
5. B1 的 13 秒是 governed UDP execution slice。B2 从 adopt OOB stream 到 handoff/terminal 的
   完整 active envelope 为 20 秒，另有 2 秒 drain；fresh evidence 最长 3 秒，candidate
   emission 与 winner ACK 最长 9 秒。0 retry、0 fallback、0 扩窗，证据丢失或漂移即终局。
   Gate A 原有 13 秒 active + 2 秒 drain 不变。
6. B2 在 FIRE 前必须交换并认证 `ExecutionEnvelopeDigest`，并与双方独立重算的 B1
   `JointPlanCommitment` 一起核验。profile、role、attempt、generation、plan/cost/evidence、
   envelope 任一不一致均零 direct 发射；只比较 peer 提交的 digest 不构成执行授权。
7. 普通 absence、证据不足、candidate exhaustion、cancel 或 timeout 是干净终局，不触发持久
   trip；超 candidate shape、packet/target/five-tuple/PPS ceiling、未登记 tuple、第二 attempt
   或 ownership/generation 违规仍须在 OS I/O 前触发持久 trip并排水。
8. 本裁决只授权 Gate B2 的 disconnected memory、loopback、natsim 与 required Linux netns
   实现和一个未合并 Draft PR。它不授权 Gate B3、stdio/CLI/runtime、SSH/WireGuard、daemon、
   scheduler、LAN/公网、现场 STUN/observer 或任何 live authorization。

## 17. Gate B2 独立评审安全阻断处置（Accepted，2026-08-28）

PR #93 首轮实现虽然 21/21 CI 全绿，独立评审仍复现了三项模型级阻断：生产配置中的
`AllowNonLoopback` 可创建面向任意 global-unicast 的 wildcard UDP factory；OOB stream 在
candidate 阶段断开或 20 秒到期时没有取消独立 UDP executor；fresh evidence 只在 READY 前
复核，READY 与单向 FIRE 之间可过期。维护者接受以下约束性修正，PR 仍须保持 Draft 并重新
通过独立复审：

1. **删除生产非回环布尔能力。** Gate B2 的 nil factory 默认只能绑定和访问 loopback；普通
   `ProbeFactory` 只允许仓库内 `_test.go` 的纯内存/natsim consumer，直接注入
   `*probeio.UDPFactory` 必须拒绝。真实非回环 OS socket 只能由 `linux && natlab` 编译的密封
   `probeio.IsolatedNATLabFactory` 提供。其构造必须用 `os.SameFile` 证明当前进程位于调用方声明
   的 netns，并固定现有 N2d TEST-NET observer、两侧 NAT public address、wildcard-ephemeral
   bind 与 target allowlist；任意远端 `SourcePayload.PublicAddress` 在注册 target 前必须同时
   通过本地/对端固定地址核验。私网、其他 TEST-NET 地址或公网地址均不能借此成为 target。
2. **一个绝对 active lifetime。** 从成功取得 attempt 后、adopt 单一 OOB stream 之前创建一个
   最长 20 秒的绝对 context；同一个 deadline 必须传给 carrier，并一直覆盖 presence、burn、
   handshake、observation、plan、READY/FIRE、candidate、VERIFY、handoff 与 data-plane
   challenge。握手完成后 carrier 使用单一受控 read worker 持续观察 EOF、deadline、非法域帧
   与 transport terminal；任一 terminal 立即以 cause 取消 active context。candidate 的 9 秒
   timeout 与 probeio 的 22 秒 reservation 只能进一步收窄，不能成为独立存活期。2 秒只用于
   FINISH 后排水，绝不授权继续发包。durable FINISH 的稳定 reason 仍由 cleanup 单写，并先于
   attempt release，active context 取消不得抢先写入另一个 terminal reason。
3. **FIRE 改为双方认证 barrier。** initiator 与 responder 都必须发送并接收 sequence 3 的
   authenticated FIRE；两方向 key 独立，因此可使用相同固定 sequence。协议只有在
   `sentFire && receivedFire` 后才允许封装或接收任何 direct candidate。两端在进入 barrier
   前复核本地 evidence；responder 收到 initiator FIRE 后、发送自己的 FIRE 前再次复核；双方
   在完成双向交换后立即再复核。FIRE 的 AD 继续绑定 exact profile、attempt、generation、
   bilateral joint digest、双方 evidence/source commitment 与 execution-envelope digest。
   任一复核过期或漂移稳定返回 `hard_nat_evidence_drifted`，direct packet 必须为 0。双向 FIRE
   使两端 OOB frame 使用量都恰好达到既有 8 frame ceiling，不提高 frame/byte 成本。

永久回归必须至少覆盖：产品默认/普通 factory 无法取得非回环 OS 能力；natlab namespace、固定
topology 与 target allowlist 变异失败；StageCandidates 关闭 OOB 后 candidate/winner/data 均为
0；压缩 active envelope 到期后 direct=0；READY 后推进证据时钟超过五秒时 FIRE 前
`hard_nat_evidence_drifted` 且 direct=0；单向 FIRE 后封装 candidate 必须终局。以上修正仍只在
memory、loopback、natsim 与 required netns 范围内，不新增 Gate B3、产品入口或现场授权。

## 18. Gate B3 `hard_16k_lab/1` 隔离实现裁决（Accepted，2026-08-30）

本节以 docs-only Gate B3a 经独立复审后由 PR #95 合入 `main`。维护者于 2026-08-30 另行明确
授权一个 Gate B3 实现 Draft PR，实施基线为
`main` = `3b40c4cf82f24604a52d4e8f2f861d2f46154602`。授权只覆盖本节冻结的 memory、natsim 与
required Linux netns 证据；不授权 disposable router、产品入口、Gate C 或现场 I/O。

### 18.1 用户任务与可观察成功

目标用户仍是两台已完成身份核对、位于不可配置 endpoint-dependent NAT 后、已有低带宽 OOB
控制信道的设备所有者。Gate B3 要回答的不是“能否提供另一个反向代理”，而是：在双方 fresh
evidence 均支持 `apparently_random` 模型时，一个固定、一次性的 16K search 是否能在不扩大
资源、不经 OOB relay 承载数据的前提下得到 verified `PacketTransport`。

本 gate 的可观察成功仅限隔离证据：late-hit 与 exhaustion 都精确落在冻结前缀内；命中后沿用
Gate A `TransportLease` 完成三报文 data-plane challenge；未命中、取消、崩溃和 fault injection
均写入 durable terminal 并排水为零。它不构成现场成功、产品可用或“通用对称 NAT 穿透”声明。

### 18.2 exact identifiers 与 plan gate transition

Gate B3 只接受以下固定组合：

```text
artifact_profile: winkyou-test-hard-nat-attempt/1
direct_attempt_profile: winkyou-test-hard-nat-control/1
planner_profile: hard_birthday_campaign/1
resource_class: hard_16k_lab/1
governor_profile: phase1_hard_nat_campaign
ledger_record_class: hard_nat_campaign/1
roles: initiator | responder
runtime_fallback: disabled
```

- 现有 artifact 增加这一组 exact arm，不改 Gate B2 两组 arm，也不新建兼容 parser；未知值、
  交叉 profile/resource、错误 role 与 `hard_32k_candidate/1` 均在 stream/socket I/O 前拒绝；
- `hard_16k_lab/1` 的 B1 `Executable` 可在 Gate B3 实现中从 `false` 翻为 `true`，并显式更新
  PlanDigest 与跨语言 golden。这是一次有审查记录的 gate transition；旧/新 build 互联必须因
  joint commitment 不同而在 direct emission 前失败，不得协商或回退；
- `hard_32k_candidate/1` 永久保持 plan/probability-only；本 gate 不为它增加 artifact、budget、
  executor 或网络能力；
- 双方仍分别重算 local source commitment、directional plan、conditional/full-range probability、
  cost 与 evidence，再互认 joint commitment 和 `ExecutionEnvelopeDigest`。peer 不能提交地址、
  port list、candidate、socket/PPS/packet count 或把 `Executable` 改为 true。

### 18.3 reservation ceiling 与不可互换的实际发射

`phase1_hard_nat_campaign` 是新的 machine-only exact profile，只允许 `OperationBirthday`。它不
提高或继承 `phase1_machine`、`phase1_manual_traversal` 或 user-acknowledged 的任何额度：

| 资源 | exact reservation ceiling |
| --- | ---: |
| active peers / attempts / heavyweight | 1 / 1 / 1 |
| OOB stream / child process | 1 / 0 |
| UDP sockets | 16 |
| targets / five-tuples | 16,400 / 16,400 |
| establishment outbound UDP | 16,432 |
| packets per second | 512 |
| absolute active / drain-only | 45s / 2s |
| governor max attempt duration | 47s |
| OOB frames / application bytes（每方向） | 8 / 8,256 |

16,432 是必须完整预留的 hard ceiling，不是可由 executor 自由花费的 token balance。Gate B3
实际协议只允许下列分解：

| slice | packets | targets | five-tuples | 说明 |
| --- | ---: | ---: | ---: | --- |
| fresh evidence | 13 | 4 | 11 | 复用已审查的五步 RFC 5780 + 八个 allocation sample；0 retry |
| fixed candidates | 16,384 | 16,384 | 16,384 | 16 sockets × 1,024；每个 tuple 至多一次 |
| winner ACK | 0 或 1 | 0 | 0 | 只复用已认证 winner tuple |
| establishment 实际最大值 | 16,398 | 16,388 | 16,395 | 不含 handoff 后 challenge |

因此预留中的 34 packets、12 targets 与 5 five-tuples 是**不可消费 headroom**：不得转换成 STUN
重传、额外 observer、替代 candidate、winner retry、第二轮、fallback 或数据面流量。成功
handoff 后的 test consumer 仍只允许每方向三个 fixed-target challenge packets；它们属于
`TransportLease` 数据面见证，不计入 512 PPS probe ceiling，但必须在进程外 OS packet witness
中单列。任一实现把 headroom 当成可发送额度，architecture/mutation test 必须失败。

所有 16 个 socket 在 candidate 前一次性打开；fresh evidence 只消费其中前八个已声明 slot，
不得为 observation 新开 socket。全部 public mapping sample 必须位于编译期 universe
49152–65535，且 StateModel 必须重新得到 endpoint-dependent + `apparently_random`；样本落在
universe 外、evidence 不足或漂移分别在 plan/FIRE 前零 candidate 终止，不能扩展到端口 1–49151。

### 18.4 campaign ledger 与 circuit

- 继续使用同一个 machine OS owner lock 与同一个 append-only pairing journal；不得创建第二
  ledger 文件、sidecar 计数器或多写者 IPC。journal schema 新增 exact record class，现有
  4 MiB / 8,192-record 容量、`O_EXCL`、校验和、时钟回退与 indeterminate 语义不提高；
- `BURN_AND_ADMIT` 原子预留完整 16,432 packets。每 24 小时最多一次 campaign admission，
  campaign 的 24 小时 packet window 也固定为 16,432；未发送 headroom、提前命中、显式 reset
  和进程崩溃均不退款；
- “成功 terminal”只指双向 VERIFY、`PromoteToLease`、consumer adopt、三报文 challenge、
  durable FINISH 全部完成。BURN 后任何其他终局——evidence drift、candidate exhaustion、cancel、
  timeout、OOB EOF、writer error 或重启发现 pending——都先 durable FINISH，再打开 campaign
  circuit，最后释放 attempt；
- preflight/presence 在 BURN 前失败不产生 admission 或 campaign circuit。普通 exhausted/cancel/
  timeout 不触发 machine safety trip，但仍因已 burn 的失败打开 campaign circuit；未登记 tuple、
  超 hard ceiling、第二 attempt、ownership/generation 违规或 OS 连续写失败同时触发持久 safety
  trip；
- passage of time 不清 circuit。显式人工 reset 必须核对 expected sequence 并留 note，只清
  campaign circuit，不退款、不清 24 小时窗口；Gate B3 PR 不增加 CLI/RPC/reset 产品入口；
- ordinary pairing 的计数与 campaign 计数双向独立、不可代偿。ordinary circuit 或全局 safety
  trip/ledger indeterminate 会阻断 campaign；campaign circuit 不提高、重置或消耗 ordinary
  2,048-packet window，只阻断后续 `phase1_hard_nat_campaign`。这允许仍在自身低额度和 circuit
  下的 ordinary attempt 工作，但禁止用高成本 campaign 绕过已经打开的 ordinary circuit。

### 18.5 单一 lifetime、FIRE 与终局顺序

Gate B3 逐字沿用 §17 的安全修正：从 attempt 取得后、adopt OOB 前创建一个最长 45 秒的绝对
context，覆盖 presence、burn、handshake、evidence、plan、双向 FIRE、candidate、VERIFY、
handoff 与 challenge。carrier EOF/deadline/terminal 立即取消同一 context；额外 2 秒只用于
FINISH 后 drain，绝不继续 emission。

FIRE 必须是双方认证 barrier。两端在进入、交换中和交换后复核五秒 freshness、universe、
source commitment、joint plan 与 execution envelope；任何一项变化都返回
`hard_nat_evidence_drifted` 或 `hard_nat_plan_mismatch`，candidate=0。FIRE 后只按冻结 batch/
ordinal 发射，每个 tuple 至多一次；命中可停止未发 tuple，但不退款、不补位。FINISH 仍先于
attempt release；Promote/lease/adopt/challenge 任一步失败都关闭 UDP transport 与 OOB 子流，
不关闭调用方拥有的父管理信道。

### 18.6 唯一允许的 capability 边界

- production、stdio v1/v2、CLI、runtime、scheduler、legacy、`wink-signal`、WireGuard 与 daemon
  都不能导入或构造 Gate B3 executor/profile；普通 build 不获得 hard-campaign non-loopback
  factory；
- memory/natsim consumer 只能注入无 OS capability 的 fake。真实 UDP 只允许
  `linux && natlab` 密封 helper，必须验证当前 netns，并把 local/observer/peer 固定为仓库
  TEST-NET topology；peer 地址由 harness 预置，不能来自 artifact/OOB 字段；
- natlab target allowlist 只允许该 exact peer TEST-NET 地址的编译期 49152–65535 universe 和
  exact observer endpoints；loopback、私网、其他 TEST-NET 地址与公网地址不能借通配布尔值、
  raw `UDPFactory` 或 remote source payload 进入；
- 不授权 disposable router、LAN、公网、真实 STUN/peer reflector、SSH assembly、WireGuard、
  产品生成工具、服务部署、route/firewall 修改、计划任务或 live authorization。

### 18.7 Gate B3 实现 PR 的必过证据

一个后续独立 Draft PR 必须同时交付 profile、ledger、executor 与 required netns load；不得把
高成本 profile 拆成“先合 capability、以后补门禁”的 stacked PR：

1. artifact/parser/golden：三套既有 artifact 继续互拒；只接受 hard-16K exact arm；
   `hard_32k_candidate/1`、unknown/duplicate field、wrong role/profile/resource 全部零 I/O；
2. memory/natsim：late-hit、最后 ordinal hit、full exhaustion、50% loss、duplicate/reorder/replay、
   evidence drift、OOB EOF/cancel 与 winner ACK 边界；固定 plan 不产生第二 attempt 或替代 tuple；
3. ledger：32–100 process 同 credential 只有一个 admission，1,000 restart 零续跑；campaign 与
   ordinary window 独立；pending crash、失败 circuit、expected-sequence reset、indeterminate 与
   capacity/clock rollback 全部 fail-closed；
4. required Linux netns：至少一个接近尾部命中的完整 16K load、一个完整 exhaustion，以及
   ENOBUFS、conntrack full、50% loss、OOB EOF、parent/child kill。正常 topology 的 conntrack
   hard cap 每个 endpoint NAT namespace 不得超过 40,000；实现可根据实测降低，不能在代码 PR
   中提高；若 runner kernel 不支持可验证的 per-netns cap，该 required job 必须 fail-closed，不能
   退化为 advisory 或沿用 host 未知上限；packet/socket/process/conntrack/governor lock 在 drain
   后全部为零；
5. 重复门：100 次 full-shape natsim 使用 fresh key/topology；required netns 的完整 16K load 不得
   偷偷缩小，另做 100 次 pre-FIRE fresh-namespace create/cancel/teardown 证明生命周期零 residue。
   这澄清 §9.4 的“100 次 fresh topology”：它不是要求 CI 连续制造 100 × 16K kernel flows；
6. required job 使用 race-enabled endpoint binary、`WINKYOU_GATE_B3_REQUIRED=1` 防静默 skip、
   总 timeout 不超过 10 分钟；记录实际 wall time、每秒最大 PPS、packet/target/five-tuple/socket、
   conntrack peak 与 drain latency，artifact/log 不含地址、hostname、用户名或本机路径；
7. architecture + mutation：product import、非 natlab unicast、raw factory、任意地址/端口、
   第 16,385 个 candidate、协议实际第 16,399 个 establishment packet、governor hard ceiling
   后的第 16,433 个 packet、16,401st target/five-tuple、17th socket、513 PPS、retry/fallback、
   第二 attempt 与 journal bypass 均在 OS I/O 前失败；hard violation 还必须落持久 trip。

本节复审通过只会授权 memory/natsim/required netns 的一个 Gate B3 Draft 实现。Gate C、
disposable router 和具名现场 campaign 仍分别需要 implementation review、exact-SHA、具名环境、
kill switch、teardown 见证、第二人复核与维护者新授权，不能从本节继承。

## 19. Gate B3 conntrack ceiling 可实现性纠错（Accepted，2026-08-30）

Gate B3 开工核验发现，§18.7 第 4 条把“每个 NAT namespace 的可验证 hard cap”误写成了可以
分别在两个 non-init network namespace 中写入 `nf_conntrack_max`。当前上游 Linux 的实际语义是：

- `nf_conntrack_max` 指向一个全局值，non-init network namespace 的该 sysctl 条目被内核显式
  改为只读；只有 init network namespace 可以修改；
- `nf_conntrack_count` 属于各 network namespace；conntrack 分配把该 namespace 自己的 count
  与共同的 `nf_conntrack_max` 值比较；
- 因此该值既不是“两侧可独立写入的 sysctl”，也不是“把所有 namespace count 相加后的聚合
  计数上限”。它是从 init namespace 一次设置、对各 namespace 统一生效的 ceiling 值。

证据来自上游 Linux 的
[`nf_conntrack_standalone.c`](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_standalone.c#L993-L998)、
[`nf_conntrack_core.c`](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_core.c#L1660-L1682)
与[内核 conntrack sysctl 文档](https://docs.kernel.org/networking/nf_conntrack-sysctl.html)。这一纠错不
提高任何资源额度，也不把 host sysctl 权限带进产品；§18 的 40,000 上限按以下组合证据实现：

1. 每个 test-only NAT router 在创建 OS mapping socket **之前**独立执行 40,000 mapping hard cap；
   该 guard 不能被 candidate 数、端口复用或另一个 router 的余量绕过；
2. required job 只能在明确标记的 GitHub-hosted disposable runner、init network namespace 和
   独占 host guard 下运行。外层 guardian 保存原始 `nf_conntrack_max`，只允许把不低于 40,000
   的原值暂时降低为 40,000，绝不提高原值；安装与恢复都逐值回读；
3. guardian 在 signal、测试失败和普通进程崩溃路径恢复原值。测试进程遭 `SIGKILL` 时由仍存活的
   guardian 恢复；整个 runner 丢失时由一次性 VM 销毁提供最终边界。无法取得独占锁、无法证明
   位于 init namespace、无法安装或无法精确恢复时 required job 失败；
4. 两个 NAT namespace 分别读取真实 `nf_conntrack_count`。上游分配路径先执行
   `atomic_inc_return(&cnet->count)`，再比较 `ct_count > nf_conntrack_max` 并回退失败分配；因此
   conntrack-full 的并发采样可以诚实看到被拒绝分配造成的瞬时 `max+1`，不能把它伪装成始终
   `<= max`。本 harness 每个 router 只有一个 mapping-open writer，故只允许该一个瞬时计数；
   terminal 必须回落到 `<= max`，`max+2` 或 terminal `max+1` 均失败。正常 load 的共同 ceiling
   为 40,000；conntrack-full fault 在 guardian 内短暂降为 1,024，要求 init namespace 事前至少
   保留 50% headroom，并在子测试终局立即恢复 40,000；
5. 每个终局仍须证明 router mapping、per-netns conntrack、packet、socket、process、governor
   lock、namespace 与 veth 零残留。产品、stdio/CLI/runtime、daemon、scheduler、Gate C 与现场
   路径不得导入 guardian、写 sysctl 或构造 test router。16K topology 删除、零残留断言及全部
   LIFO cleanup callback 完成后，test-only harness 可留固定 1s 给内核回收已删除 namespace 的
   conntrack/RCU 对象；这不是 attempt retry，不得重建 campaign、补发 packet 或改变任何预算。
   setup 失败日志只能暴露稳定阶段类。

因此 §18.7 的“runner 不支持可验证的 per-netns cap 则 fail-closed”按本节解释为：必须同时证明
test-router 独立 mapping cap、init-owned 共同内核 ceiling、两侧各自的真实 count 与精确恢复；不再
尝试 non-init sysctl 写入，也不得把共同 ceiling 谎称为 per-netns 独立配置或全机聚合计数。

## 20. Gate B3 实现期协议闭合（Draft implementation correction，2026-08-30）

required Linux 双跑第一次把 16K 真正压到尾部后暴露了两项不能靠放宽测试处理的实现问题：

1. 原实现用“initiator 立即 winner、responder 完整 schedule 后定时 deferred winner”处理双向
   命中；对称尾部命中时，定时器与 initiator winner 的内核交付存在竞态，双方可能各发一个
   winner，随后按 fail-closed 规则终局。延长定时器只能降低概率，不能证明单 winner；
2. initiator 为 winner 预留一个 PPS 槽而按 511-packet batch 发射，完整 16,384 candidate 实际
   需要 33 个 batch；OS 发包开销会在 34 秒子窗口边缘留下 32 个未发 candidate。该行为没有
   超预算，但不满足“完整 exhaustion 精确发完固定集合”的证据门。

Draft 实现采用以下窄化闭合，等待独立实现复审；它不改变 §18 的 45s、512 PPS、16,384
candidate、0/1 winner、8 frame 或 8,256-byte ceiling：

- Gate B3 独有 `READY_FIRE` 把原 READY 的 joint/execution commitment 与 bilateral FIRE barrier
  合成一个认证 rendezvous-control frame。双方仍在 barrier 前、中、后复核 fresh evidence；只有
  双向 `READY_FIRE` 都认证后才可封装 candidate。Gate B2 wire、状态机与 golden 逐字节不变；
- 双方都完成 16 × 1,024 one-shot schedule 后，responder 用每方向第 7 个 post-activation frame
  提交“首个已认证 candidate 或 absence”，initiator 按固定优先级选择自己的 observation、否则
  responder observation、否则 none，并用对应方向同一序号的 selection frame确认。该 payload
  只含 role/ordinal/socket-slot/digest，不含 endpoint、candidate list、span、seed、packet count
  或 secret；
- selection 纳入 Noise AD、joint plan 与 execution envelope；重复、错 role、错 digest、非完整
  schedule、selection 后新增 candidate 或第二 winner 均终局。只有 selection 指定的 receiver
  可以复用已认证 tuple 发一个 winner；双方随后仍执行原有双向 VERIFY。含 VERIFY 在内每方向
  恰好 8 个 carrier frame；
- bilateral selection 确认为 no-winner 时，responder 必须在关闭 carrier 前发送认证
  `EXHAUSTED` terminal acknowledgement，initiator 收到后才返回 `candidate_exhausted`。该确认复用
  no-winner 路径不会使用的 VERIFY sequence 和第 8 个 responder frame，不增加 UDP、target、tuple、
  attempt 或 byte ceiling；缺少确认仍按 `oob_stream_closed` fail-closed；
- 512 个 rolling-PPS lane 分别以真实 UDP commit point 锚定：packet `N+512` 必须等待 packet `N`
  满一个 interval 并留出 1ms clearance。不能在每个完整 batch 结束后再等一秒并把系统调用/
  调度耗时累计 31 次，也不能只按 batch start 锚定而忽略 512 个 packet 自身的非零发送跨度。
  winner 仍必须等待最后 candidate 后一个完整 rolling-PPS interval，第 513 个同秒 packet 仍由
  probeio 在 I/O 前拒绝。candidate 子窗口从 34 秒校正为 38 秒，只是在既有 45 秒 absolute
  context 内给 OS scheduling、PPS-clear 与 selection 留界；不提高 governor duration、packet/
  target/tuple、ledger reservation 或 drain；
- absence、OOB terminal 或 38 秒子窗口到期继续有界失败；没有 retry、补位、第二轮、扩窗、
  fallback 或第二 attempt。`hard_32k_candidate/1` 仍无 executor。
- OOB async reader 必须按字节流顺序交付已经完整解码并入队的 frame，随后才报告 EOF/terminal。
  调用 `ReceiveControl` 前由 caller 取消的 context 仍优先且不得消费队列；仅当 cancel cause 正是
  同一 carrier 随后的 transport terminal 时，才先排空该 terminal 之前已解码的 frame。由此
  no-winner 的认证 `EXHAUSTED` 不会因为紧随其后的 peer close 在 `select` 中胜出而被丢弃；这不
  延长 carrier envelope 或 drain。public Gate B receive gate 在 state 已 Closed 时也只对该 async
  transport-terminal queue drain 开放；协议错误、同步 reader 与所有 write 仍 fail-closed。
- probeio 的 UDP 系统调用成功返回是该 datagram 的 emission commit point；系统调用成功后才发生
  的 context cancel 不得把结果重写为失败并造成 application/OS packet witness 相差一包。调用前
  已取消或系统调用实际返回 timeout/cancel/error 时仍按原规则失败，ENOBUFS 仍为零发射并触发
  持久 safety trip；该修正不增加任何 packet、PPS、target、tuple 或时长预算。
- 100 次 fresh namespace teardown 的每轮都先显式删除并证明 namespace/veth 名称零残留，再等待
  §19 已冻结的 1s kernel-release margin 后创建下一组唯一名称 topology。该等待只隔离内核不可见的
  netdevice/RCU 尾部生命周期；不重试失败的 setup、attempt 或 packet，也不进入 attempt envelope。
  veth 两端由一个 setup 操作直接创建进各自 owner namespace，不在 init namespace 暴露临时 pair
  后再做两次 move；
- active attempt 使用共享 caller/absolute deadline 下的两个单向职责 context：carrier terminal 立即
  取消 active emission context，保证后续 UDP 发射为零；no-winner initiator 只用 sibling terminal-drain
  context 接收已经认证且在 EOF 前发送的 `EXHAUSTED`。后者仍受同一 caller、candidate deadline 与
  active-envelope deadline 约束，不能用于任何 socket/packet 操作；由此不再让“EOF 停止发包”和
  “交付 EOF 前最后一帧”争用同一个 cancellation edge。若下层只返回通用 `context.Canceled`，
  分类器只在 active context 带非通用 carrier cause 时恢复该 cause，保证 child death/OOB EOF 稳定
  为 `oob_stream_closed`；本地 caller cancel/deadline 仍为 `attempt_expired`。双端同一绝对 deadline
  中先到期的一端关闭子流时，peer 可先观察到 `oob_stream_closed`，但回归门必须同时证明至少一端
  保留本地 deadline witness，且两端 terminal barrier 后 UDP emission 均为零。

本节是 PR 内实现纠错与评审输入，不自行授权合并、Gate C、产品入口或现场 I/O。
