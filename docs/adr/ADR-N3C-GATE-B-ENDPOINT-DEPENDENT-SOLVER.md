# ADR：N3c Gate B 困难 NAT 有界求解器

- 状态：**Accepted baseline；Gate B1 独立复审发现模型错误，§15 纠错增补为 Draft，未获独立接受前 PR #90、Gate A 与 Gate B2 均为 Blocked。不授权任何现场 I/O**
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
- 每侧都预留 512 packets/targets/five-tuples，尽管 mapping-set 一侧通常只消费 128；
- 总 PPS 64、active 13 秒、0 retry；
- 模型前提成立时声明约 63.21%，evidence 漂移则在 FIRE 前终止。

该 profile 可在现有数值 ceiling 内证明算法，但仍需要新的 explicit operation/profile，因为
`phase1_machine` 当前刻意不允许 `OperationBirthday`。

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

新增 exact machine-only profile（暂名 `phase1_manual_traversal`）：

- 只允许 `OperationPrediction` 与 `OperationBirthday`；
- 复用现有 machine 数值 ceiling：128 sockets、512 targets/five-tuples、512 packets、64 PPS、
  60 秒；
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

以上数值是 review candidate，不是已接受配置。首个实现只能在 zero-network/natsim/netns
中证明它们；任何 live 提升需要新的 exact-SHA 授权。

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
- 第 513 个低成本 packet、第二个 heavyweight attempt 与任一未登记 tuple 在 OS I/O 前拒绝；
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
3. **接受 128×512 作为首个联网 profile**，理由正确：它恰好落进现有 machine 数值
   ceiling（128/512/512/64PPS/60s），证明算法不抬高任何既有上限。63.21% 必须始终带
   “模型前提成立”条件标注展示。
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

## 15. Gate B1 独立复审纠错增补（Draft，2026-08-26）

本节响应 PR #90 第一轮独立复审。复审用八个临时最小复现证明：原实现把本机预测窗口
误当作本机发送目标、把双方必然不同的 directional digest 互相判等、接受自报/过期 evidence、
不兼容 RFC 5780 的双 mapped-address 要求、让诊断/重放改变 plan，以及输出不包围真值的
概率区间。八个复现已转成永久回归测试。

本节目前是**待独立接受的纠错提案**，不得由实现者自行翻转为 Accepted。它在评审期间覆盖
§5 中与下述语义冲突的解释，但不授权 Gate A、Gate B2、executor、carrier 或任何网络 I/O。

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

### 15.3 trusted evidence validation context

`EvidenceGraph` 中的非零 digest 只是被验证对象，不是信任来源。B1 必须另外接收调用者提供的
纯值 `TrustedValidationContext`，且该 context 不得从待验证 graph 自动派生。它至少固定：

- expected machine scope、peer、attempt、generation、observation-service set 与 socket-owner
  digest；
- trusted started/finished/expires 时间与当前 evaluation time；
- 预先签发的 transaction manifest：evidence kind、transaction ID、source class、destination
  endpoint、socket slot、ordinal 与允许响应时间窗。

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
   与 reciprocal APDF filtering，证明双方按 peer source schedule 互通；旧的“本机 next mapping
   位于本机 plan”测试删除或改为 source-commitment 单元测试；
2. trusted context 的外来 machine/socket、过期、未来时间、manifest 缺失/篡改、稀疏 ordinal、
   末尾失败全部零 candidate；
3. remote diagnostics 与完全相同 transaction replay 只改变 raw digest；
4. RFC 5780 双 mapped-address 与四地址 topology 正/负 golden；
5. 128×512 decimal interval 包含 exact rational、large-exponent Poisson 有界、MaxUint64 强制相交；
6. 双方不同 directional triples 组成相同 joint digest，任一 side mutation 均被拒绝；
7. architecture zero-network 门禁、全仓、race×20 与跨语言 golden 重新通过。

以上全部通过仍只表示 Gate B1 可重新送审；必须由独立评审明确接受本节后，PR #90 才可合并，
且不得据此自动进入 Gate A/B2。
