# ADR：legacy session 策略选择的确定性收敛

Status: **维护者接受 S3（含 S1 前置），阶段3按 R-a.1 澄清裁决收尾；实现 PR 仍为 Draft，待独立复审**（2026-09-11）。
原设计基线 `main = 214ff2d`；阶段3基线 `main = b53f8c8`。Refs #97；不关闭 issue。
首个设计 commit 已按要求停下；维护者随后明确接受。§9 在代码前具体化本次实现契约，
不扩大网络、时限或重试权限。

## 1. 问题与证据

实现权威仍为 [CONNECTIVITY-SOLVER-BASELINE](../CONNECTIVITY-SOLVER-BASELINE.md)。
本设计只处理 legacy coordinator + session + WireGuard runtime，不接 v2 Gate。

[#116 的阶段证据](../FLAKE-97-RELAY-TIMELINE.md)记录同一轮：

| 相对时间 | 观察 |
| --- | --- |
| 12,371ms | side 2 已进入 selecting，capability 仍缺失 |
| 16,021ms | side 2 才收到 capability |
| 23,971ms | side 2 仍为 legacy_ice_udp，negotiated=false |
| 25,172–25,871ms | side 1 进入 relay_only 的 probing/planning |
| 27,571ms 后 | 两侧执行不同策略，随后 session 重建/移除，未取得 binding 见证 |

这些是 50ms 尽力采样，不是精确 transition 时间。它证明存在错误选择路径，
不证明所有历史 #97 失败只有这个根因，也不证明重建时一定丢了哪条消息。

当前调用链：

```text
waitForRemoteCapability
  -> 超时返回 remoteCapability(), nil（可能从未收到）
  -> resolveStrategyCandidates / ResolveAll
  -> AllowImplicitLegacy + CompatibilityDefault
  -> legacy_ice_udp，Negotiated=false
```

已经取得的候选不会因为后来收到 capability 自动更新。仅延长外部 transport 等待不能
撤销这个决定。`Resolve` 与 `ResolveAll` 两个入口都有空能力回退；`AllowImplicitOrder`
还是另一条空能力扩展为整组本地策略的路径，不能只堵一个入口。

### 1.1 额外核对，防止在设计里依赖不存在的保证

- 实际 resolver 位于 `pkg/session/strategy_portfolio.go`；client 的
  `strategy_factory.go` 组装 policy。候选顺序还受本地顺序、PinnedFirstStrategy 和
  observation 影响。因此“双方都收到非空 capability”不等于任意配置下选择必然相同。
- `planning.go` 的 `sendPathCommit` 在 Binder.Bind **之后**；接收方只更新
  LastPathCommit 快照。它目前既不是 pre-execution agreement，也没有确认/重传协议。
- 两侧 SessionID 是排序后的节点对，值相同，不能用“较小 SessionID”选 leader。
  既有 initiator 规则是 LocalNodeID < PeerID，可以作为确定性 tie-breaker。
- SessionID 在 runner 重建后仍相同，Seq 也属于各自实例；新确认不能只绑定 SessionID。
- 25s 是该 relay fixture 的单 candidate RunTimeout（5+15+5），不是整个 session 的统一
  总时限。多 plan / 多 strategy 会另有执行窗口，不能据此承诺整次重试必在 25s 内结束。

## 2. 冻结边界

不改 30s transport 测试死线、capability 2s、fixture RunTimeout 25s、既有
2/4/8/10s 退避数字；不新增独立自动重试循环，不用 sleep 协调状态。
更严格的前置确认若消耗现有执行窗口，是本 ADR 的显式提案，不暗中加长窗口。

保留 #94 的 engine 就绪屏障及 session 原子路由。保留 #116 的精确 required CI 分区、
普通/race 次数与平台覆盖。不改策略内部、WireGuard、v2、任何探测权限或现场配置。
不混修 #101/#111/#117–#120；已有 RED 不删除。

## 3. 候选比较

| 方案 | #94 防线 | 退避/消息成本 | 失败模式与可证明范围 |
| --- | --- | --- | --- |
| S1：缺 capability 时超时即失败，不进入 selecting | 两道防线原样保留 | 不新增消息；原 OnError → 既有退避 | 最小地消除空能力猜测。但一侧可能已执行，且非空能力下仍可能因不同 policy/observation 选不同策略。不能单独充当一般双边一致性证明 |
| S2：leader 提交，follower 验证采纳 | 保留，提交消息另有有界队列与轮次归属 | 增加提交/确认；丢失或迟到走既有退避 | follower 必须验证本地许可，不能盲从；leader 单方面发送成功不证明采纳。复用现有 post-bind PathCommit 会改变语义或形成循环依赖，必须用不同消息/明确阶段 |
| S3：双方绑定同轮 proposal，一致后才允许 executing | 保留；选择确认独立于 strategy pending 队列 | 增加有界双向 proposal/确认；不一致用确定性规则得出共同选择，未闭合则失败退避 | 可证明“同轮执行的策略承诺相同”。需轮次隔离、后续策略切换确认、超时/丢失的局部终局；不能承诺不可靠传输上的原子同时启动 |

**推荐 S3，包含 S1 作为必要前置；不把 S1 单独宣称为双边一致性修复。**
这比只修空值多一层选择协议，但符合本任务“选择一致性”的目标。
若维护者希望先交付 S1，需明确把验收收窄为“消除缺失 capability 的 implicit fallback”，
并把非空能力分歧与双边确认保留为后续项，不能沿用本 ADR 的完整收敛声明。

## 4. 已接受方案的协议轮廓（实现证据另行登记）

### 4.1 输入冻结与兼容性

1. 新 runner 的 capability 交换携带一个新鲜 selection epoch，以及显式的选择协议版本。
   epoch 只用于 legacy 会话实例隔离，不是 v2 身份，也不授予任何网络权限。
2. 在现有 capability 2s 窗口内必须取得真实、非空的远端能力。timeout、空列表、
   没有共同策略、缺少新协议支持均返回明确的选择失败，不执行策略。
3. 新 runtime 路径彻底禁止“未收到/空能力 → implicit legacy/implicit order”回退。
   老 peer 即使支持 legacy_ice_udp，但不支持本次选择确认，也不静默降级；升级兼容性
   代价须由维护者明确接受。公共 resolver 的兼容 policy 是否删除，不能替代生产路径门禁。
4. 每侧冻结本轮 capability、有效候选顺序及本地硬约束；迟到 observation 不改已确认选择。
   不把 observation 值强行伪造成对称输入，也不修改 solver 策略内部。

### 4.2 共同选择与轮次绑定

轮次标识必须覆盖：规范化节点对、双方新鲜 epoch、双方 capability/offer digest，
以及本轮 strategy ordinal。只使用共享 SessionID 或一侧自报 counter 不足以隔离重建。

双方分别提供受本地硬约束过滤后的候选序列；固定由既有 initiator 的顺序排列双方
交集。这个 tie-breaker 不越过 follower 的硬约束，交集为空则失败。
双方独立计算同一个规范编码/digest，不接受仅转抄对方 digest 的“确认”。
交换的确认绑定完整轮次、选中策略及前一策略的终止状态。字段、最大长度与每方向
消息上限必须在实现前随本 ADR 的评审冻结；不能把未有上限的 proposal 列表交给生产。

每方向每轮只有一个不可变 proposal 和一个对应确认；不得反复发送新选择直至对方接受。
相同重复可幂等忽略，冲突、未来/过期 epoch、错方向和已终止轮次均不能进入 executor。
两侧初始排序不同，由上述共同交集规则收敛一次；仍不一致直接失败，不在本轮循环重提。

### 4.3 执行、策略切换与时限

- 执行门：本地发送完成、收到匹配的对端 proposal/确认、本轮未终止且 deadline 未到，
  才能安装/启动 executor。不能仅看 Selection.Negotiated 或 LastPathCommit 非零。
- 后续 strategy 切换也要经过同一门；不能只确认第一策略，再各自走不同的 fallback。
  任何下一 ordinal 的确认，都以前一 executor 取消/关闭完成为前置。关闭无见证则整轮
  失败，不允许新旧不同策略并发。策略内部多个 plan 的原路由规则不重写。
- 首轮按 R-a.1 显式拆为两段：capability 窗口仍为2s，从 Start 首次发送前起算；
  confirm 子窗口不超过2s，从 max(passStart, 本地首次收到有效远端 capability) 起算，
  从 passStart 起两段之和不超过4s；提前接收不能削短 pass 开始后的确认子窗口。
  proposal/confirm 共享后一子窗口；重复 capability 不重置起点，接收方的本地时间才是依据。
  首轮选择的实际耗时从既有首个 candidate 的 RunTimeout（relay fixture为25s）扣除，
  首个 plan/并发 group 与 candidate-loop 的 TimeBudget 同步扣除，不增加总 session 预算。
  后续 ordinal 仍采用 min(2s, 剩余执行预算)，不改候选数量、后续 plan 或退避数字。
- 超时进入不可逆的本地终局，清理本轮队列/活动 executor，再交给现有 OnError/退避。
  双方退避时刻可以不同；不增加第二套 retry，不用无限 ACK/重发弥补丢包。
- 已健康绑定的数据面不因选择消息丢失而拆除。受保护路径改善失败继续遵守 baseline
  的保留现有数据面规则；不将初次启动修复扩展成控制面失联即拆链。

### 4.4 消息路由与旧 PathCommit

新选择消息由 session 的专用、有界状态处理，不进入可被
discardPendingStrategyMessagesForPlan 清掉的 strategy 队列。
队列消费/关停须和对应 runner/epoch 原子绑定；不能在解锁后的旧快照上投递。
生产入口必须校验已认证 sender 与 envelope 方向、节点对及 epoch 的一致性。

旧 PathCommit 继续是绑定后的结果报告，字义与发送顺序不变；丢失它不能回滚已完成
的选择承诺，也不能据此改选。S2 所谓“复用 PathCommit”若被选中，需另作版本化裁决，
不是在此处把旧消息提前发送。

## 5. 收敛证明草案与限制

证明对象是**同一绑定轮次的策略一致性**，不是不可达网络上的必然成功、同时启动，
也不是无限 CPU 饥饿下的硬墙钟保证。需要诚实的 peer、完整校验、可运行的调度器，
以及在成功样本中有足够消息送达预算。

不变量：

1. 每个 (epoch pair, ordinal) 只有一个本地不可变承诺。
2. local executing 只可能指向双方各自计算并确认的相同 digest/strategy。
3. 下一 ordinal 不能绕过本地上一 executor 的终止与关闭见证。
4. 本地终局不被迟到消息复活，旧 epoch 不能承诺新 runner 的选择。

故同一轮不会因 capability 一侧迟到而分别执行 legacy_ice_udp 与 relay_only。
丢失最终确认可能使一侧短暂 executing、另一侧尚在等待：有限交换不能创造“双方知道
对方也知道”的原子启动。这里保证没有**冲突承诺**，不是同一瞬间状态相同。
若评审要求任意丢包下原子双端 executing / 完全相同终局原因，应拒绝这个承诺而重定义
验收，不能通过多加一轮 ACK 假装证明完成。

| 场景 | 预期结果（初次 relay fixture） | 防错依据 |
| --- | --- | --- |
| 双方 capability/确认均在窗口内到达 | 同一 relay_only executing；原传输验收判定是否 bound | 独立计算共同选择，双向确认 |
| 一侧 capability 延迟 4–16s | 本轮未确认方零执行；在已有时限内终止/退避。只有后续完整新轮双方及时送达才可共同执行，不保证首轮或30s内必成功 | 不读空快照继续；晚到不复活终局 |
| 一侧 capability 永不到 | 无完整双边承诺，最终两侧失败并进入各自既有退避 | 不触发 implicit fallback；确认有界 |
| PathCommit 丢失 | 若选择/数据路径已完成，继续同一策略，不因报告丢失另选；发送报错仍走原清理 | PathCommit 不承担选择共识 |
| 重建窗口内 strategy 消息被旧 plan 丢弃 | 新选择确认不在该队列；若旧 offer 确已丢失，相关执行有界失败并退避，不能以裸等待宣称成功 | #94 原子路由保留，epoch 隔离；不声称修复所有策略消息可靠性 |
| 双方同时 capability 超时 | 双方不进入 selecting/executing，失败后各自既有退避；不承诺同步重试时刻 | 终局不可逆，无默认能力 |

表中的“一致失败”表示本轮未形成双边可用连接、双方各自有界终止；不要求错误字符串
或终止时间完全相同。具体策略若可在没有对端时单方构造 transport，不得把 local Bind
误报为双边成功；本次真实验收仍以双方 WireGuard packet exchange 为准。
原有多 plan 总预算不是25s，完整矩阵必须记录各段实际 deadline，不能虚报总界。

## 6. 与 #94 的关系与预计改动范围

保留 engine 的 solverDispatchReady 屏障（10s）和 session 的
routeStrategyMessage 原子判定/入队。这两项解决消息启动就绪与 lost-wakeup；
本 ADR 增加的是选择一致性，不能替代前两项，也不提供新的可靠传输层。

批准后生产改动主要位于 `pkg/session` 的 envelope、selection、lifecycle、执行门及
`pkg/client/strategy_factory.go` 的 policy。需要的 wire 字段放在 session adapter 边界；
不向 solver domain 注入 wire DTO，不改 `pkg/solver/strategy/*` 或 v2 Gate。
若实现必须改 coordinator 传输、策略协议、既有绑定存活语义或扩大截止时间，停下另行裁决。

## 7. 验收计划（实测与未闭合项见§10/§11）

- R-a“confirm 子窗口单独计时”：纯内存投递 capability 在1.9s到达、proposal/confirm
  往返再需0.6s，旧共享2s实现必须 selection_timeout，修复后双方一致 executing。
  capability 2.1s才到必须 capability_missing；confirm 子窗口内未闭合必须 selection_timeout。
  核对两个本地起点、首个 plan/group 的 RunTimeout 与 TimeBudget 实际扣减，重复能力不续期。
  mutation 必须拒绝合回单一2s、子窗口超过2s、未扣RunTimeout与 implicit fallback复活。
- 先红后绿：双端确定性 transport/时钟调度，重放 side 2 capability 延迟4、8、16s及
  #116 的阶段关系。基线必须出现缺能力下 implicit 执行/分歧；新实现同轮选择一致，
  或准确的有界失败，不能用“任何错误都过”代替状态断言。
- 六格矩阵逐格覆盖；追加不同本地顺序/observations/pin、旧 epoch、重复/冲突确认、
  最后一条确认丢失、close 与安装竞态、后续策略切换及健康绑定路径保留。
- 所有失败见证：策略构造/执行次数、选择 digest、candidate ordinal、终局/退避、
  队列清空、executor 关闭；日志只有合成 side、相对时间和类别，不含身份或 endpoint。
- 原真实 loopback relay 测试保持30s与 #116 分区：受控 CPU 压力≥50、无压力≥100；
  registration 和 transport-phase 压力分别标记，首次 RED 原样留存，不 rerun 求绿。
- focused race×20、全仓分区 + 独立 relay、go vet、architecture/mutation 全部通过。
  mutation 必须捕获 timeout→nil、implicit legacy/order 重新启用、确认门绕过、
  旧轮次接纳、破坏 #94 ready/route 与 #116 分区；v2 Gate 回归原样通过。

## 8. 首个设计提交时的裁决请求（历史记录，后续见§9）

- 是否接受推荐 S3（含 S1 前置），及移除新 runtime 的旧 peer 静默兼容回退。
- 是否接受 §5 的“无冲突承诺 + 局部有界终局”，而非不可能由有限不可靠消息证明的
  原子同时执行；若只要最小 S1 修复，应明确收窄交付声明。
- 在代码前冻结 §4 的新字段/字节与消息上限、epoch 编码及共享 deadline 起算方式。
  当前未填具体 wire 数值，不属于可直接开工的 Accepted 协议。

本设计 commit 不修改 baseline 原文或任何实现，不激活兼容性变化。
等待确认后再增加红回归、实现与测量；不凭本 Draft 进入其他 Gate 或现场。

## 9. S3 实现契约（2026-09-09，代码前记录）

### 9.1 组装与兼容边界

唯一产品构造点 `client.newPeerRunner` 改用 `session.NewConverging`，无配置开关。
公共 `session.New`/resolver 的既有独立库兼容接口不删除，但仓库生产代码不得使用它们
绕过确认；架构扫描与变异测试守住构造点和消息投递。两类 session 都拒绝缺失或空 capability。
旧的单侧策略契约测试不伪装成双边证明；新增双端协议测试与真实 relay 验收才证明 S3。

产品以信令通知的 peer 身份调用 `HandleMessageFrom`，再核对 envelope 的节点对/方向；
不把新字段当成密码学认证，也不扩大既有 coordinator/peercontrol 的信任保证。
`selection_version=winkyou.legacy-selection/1` 与每 runner 的 crypto/rand 16-byte epoch
放在 session 边界的 capability DTO，不进入 solver domain。epoch 编码为32位小写 hex，
首次接受后不可替换。重复相同 capability 不重置 deadline；不支持版本的旧 peer 明确失败。

### 9.2 有界交换与规范编码

增加两个 envelope 类型 `selection_proposal` / `selection_confirm`，不复用 PathCommit。
每方向每 ordinal 恰一份 proposal、一份 confirm；不重传、不反复提案。
proposal 绑定 version、sender/receiver epoch、十进制字符串 ordinal（uint64，0起，溢出拒绝）、
双方 capability digest、previous digest、previous_closed=true 与本地许可的有序 strategy 列表。
confirm 绑定同轮 header、共同首选 strategy 与双方独立重算的 joint digest。

编译期上限：外层选择/capability envelope 8192 bytes、payload 4096 bytes；
strategy 最多8个、feature 最多32个、每 token 64 ASCII bytes；节点 ID 各128 bytes、
SessionID 512 bytes。列表不得重复，空 strategy 列表拒绝。未知字段、重复 JSON key、
非法/超长 hex、非规范 ordinal、方向/epoch/previous digest 不符均失败，不回显输入。
每轮只保存两种远端消息及同样的本地承诺；最多当前与下一 ordinal 两槽。
同内容重复幂等，但每槽接收计数上限16，超限失败；已完成 ordinal 的迟到副本丢弃，
不能复活或改变承诺。终局清空缓存，后续消息不触发 executor。

digest 使用 SHA-256；输入是固定字段顺序的 Go JSON 规范编码（ASCII token、紧凑、无空白、
数组保持声明顺序），带 `winkyou.legacy-selection/1` 标签。先按 initiator/responder 角色
排列节点、epoch、规范 capability 和双方 proposal，再编码共同交集顺序、ordinal 与 previous digest。
capability 的 strategy/feature 以既有 Normalize 排序；proposal 的候选顺序不能排序。
不声称采用 RFC8785；字节级 golden 单独冻结。capability/offer 均在本轮冻结，
只传两份列表的交集，由 initiator 顺序决定；不把候选未许可项重新插回 fallback。

### 9.3 时限、切换与失败

R-a.1 首轮 capabilityDeadline 在 Start 首次发送 capability **之前**建立：passStart+2s，
测试配置只能缩短。confirmDeadline 独立于该能力截止点，从
max(passStart, 本地首次收到有效远端 capability 的 capabilityReceivedAt) 起算。
令该锚点为 anchor，confirmDeadline = anchor + min(window, 2s, passStart+RunTimeout-anchor)。
提前接收不得削短 pass 开始后的确认窗口；剩余执行预算仍从 passStart 计算。
重复 capability、远端自报的接收/发送时间或消息积压均不能延长本地冻结的子窗口。
capability 与 confirm 两段之和不超过4s；首个 plan/group 的绝对执行截止点仍是
passStart+其既有执行预算（单plan为原RunTimeout，group沿用原合计预算），
实际选择耗时同时从 candidate-loop 的 TimeBudget 扣除。
能力缺失使用 capabilityDeadline；proposal/confirm 使用 confirmDeadline；超时不退款、不续窗。
后续 ordinal 的 proposal 起点同时是首个 plan/并发 plan group 的执行预算起点：
确认有 min(2s, 既有执行预算) 子上限，首个 plan/group 的 RunTimeout 按实际确认耗时扣除；
整个 candidate-loop 的既有 TimeBudget 同样扣除。多个 plan 的原总预算与后续 plan 窗口不扩大。
执行门再次检查本轮确认、选中 name、deadline 与本地终局，不能只依赖 resolver 的 Negotiated。

下一 ordinal 必须见证前一 executor 关闭返回；cleanup timeout/error 使选择永久失败，
不得因旧代码已清空 executor 指针而当作排水完成。没有独立 executor 的 strategy，
需要 Strategy.Close 的真实完成；若它仍持有可用 transport，则不能伪造关闭见证来切换。
选择失败保留已绑定的 healthy path；丢失确认不引入第二套自动重试。
初次失败由既有 OnError/退避处理。已 bound 的 runner 若选择层终局，仅停止后续改善选择，
保留数据面，直至既有机制更换 runner；不因迟到的选择消息直接调用拆链错误路径。

错误类别为 capability_missing、selection_unsupported、selection_invalid、selection_conflict、
selection_timeout、selection_closed、selection_previous_active；错误文本不附 peer/epoch/原文。
deadline 类仍支持 errors.Is(context.DeadlineExceeded)，取消保留 context.Canceled。
快照只增 selection ordinal/digest；这些不是 v2 schema，也不修改 PathCommit 字义。

§8 的方向裁决已经完成。以上是该方向的显式实现细化，不代表测试已通过或 PR 可合并；
后续提交逐项登记 RED、实现、矩阵、首次失败和实测成本，不以 CI 重跑替代修复。

### 9.4 实现边界的补充说明

1. `NewConverging` 要求正的既有 RunTimeout；不修改产品提供的值。可用 transport仍归
   数据面所有者；关闭 executor 的见证用独立集合记录，不能用清空指针代替。
2. 有效 proposal 已导致对方发出有效 confirm 后，随后注入的冲突副本/重复洪泛可使接收方
   终止，而另一侧已持有有效确认。负面测试要求接收侧零执行、发送侧至多执行既有相同承诺；
   校验其digest确实等于对方已发的confirm，不把“合法前缀之后出错”误写成原子双边零启动。
3. 永久测试须兼容 go.mod / CI 的 Go1.23.1。首个RED曾用本机Go1.26虚拟时钟复现；
   随后发现 testing/synctest 不属于最低版本，最终测试改为实际2s计时与4/8/16s延迟的
   纯内存投递、显式终局channel、独立用例并行。无sleep、生产clock seam、工具链升级或CI覆盖减少。
4. 字节golden：capability162、proposal406、confirm461、joint1150 bytes（合成样例），
   joint SHA-256为 `082326e4b522b5b55161914b849619749b48125f3f94c667c5dff3d4cd22f071`。
   Python独立核对JSON字节重编码与SHA；这不是两个独立网络实现的互操作宣称。
5. 三个取消/绑定及两个Start库单测补显式非空capability消息，原断言/时限不变；
   四个产品implicit-fallback测试的期望按已接受的兼容性决策改为拒绝；#94就绪夹具只更新
   有效capability的版本/epoch字段。真实relay夹具未注入capability、未修改预算或30s断言。

## 10. 实现验证与首次压力反例（2026-09-09）

实现提交 `5efdcc8`，独立于#111测试修正。保留Draft，未达到完整验收，不授权合并。

### 10.1 已完成的确定性与本地回归

- 原RED提交 `541a459`：4/8/16s迟到capability均触发旧implicit选择，与对端relay不同。
  首次RED与后续自测失败日志均保留在仓库外；不以最后一次通过覆盖第一次失败。
- Go1.23.1（与go.mod/CI一致）：`go vet ./...` PASS；沿用#116精确分区的全仓测试
  88个有测试包PASS（session36.497s、client2.263s、governor97.801s、architecture14.795s）。
  分区命令仍为 `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'`；
  独立relay矩阵见下，不把skip当成覆盖完成。
- `go test -race ./pkg/session ./pkg/client -count=20 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'`
  PASS：session725.652s、client12.599s；首轮实际2s/4/8/16s迟到测试也包含在20轮内。
- `go test ./internal/architecture -count=20` PASS257.195s，包含新旧门禁与变异自检。
  #94 route/readiness及原2s函数的规范化AST另与main基线独立对照一致。
- §9.4合成字节golden经Python独立JSON重编码/SHA核对通过。SHA承诺不提供新的
  密码学消息认证，不将它称为AEAD或独立网络实现的互操作验证。

### 10.2 压力50批次：首例失败即停，0/1，未达标

Go1.23.1、GOMAXPROCS=28，复用#116的56 CPU worker，仍在两个engine Start后才施压；
不与其他本地重测试并行。执行：

```text
WINKYOU_FLAKE_97_CPU_STRESS=1
go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=50 -failfast -v -timeout=45m
```

首个用例在原30s transport断言失败，总测试39.03s；余下49次未执行。45m仅为整批测试
进程上限，不变更单例或产品时限。结束见证为observer_workers=0、cpu workers_remaining=0；
不能扩写成未测的所有OS资源清零。

50ms尽力采样观察到：1,975/2,005ms双方selecting；2,150ms side2只收到proposal；
2,457ms side2失败、side1已有confirm；2,462ms side1选relay_only，2,500ms也失败。
后续原退避/runner重建仍未取得transport。样本未出现原来的implicit legacy与relay冲突，
**但安全拒绝不等于可用性通过**。采样不是精确Start/deadline见证，不能据此断言
每个后续失败的原因，也不能未经裁决将2s窗口加长或重跑同批求绿。

无人工压力100与独立relay race20的结果须另行记录，不能与本次失败合并成成功率声明。
若后续修复需要改确认窗口、既有传输/退避或消息可靠性语义，须遵守§6/§7先行裁决；
本提交不提出隐式放宽，也不将压力门视作advisory。

### 10.3 无人工压力100：100/100通过

同一Go1.23.1与GOMAXPROCS=28，关闭可选CPU helper，无其他本地重测试并行；
仅有轻量源码/日志核对与远端CI查询，不声称操作系统完全无其他工作。

```text
go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=100 -failfast -v -timeout=60m
```

100/100 PASS，共713.694s，单次最长7.42s；100次observer_workers=0。
每次均执行既有双向WireGuard数据、runtime状态与计数增长断言；原30s transport门及
其他既有分阶段时限不变。该结果不覆盖或抵销§10.2压力反例。

### 10.4 独立relay race与只读归因采样

- 同版本、同GOMAXPROCS，未开CPU helper的独立relay `-race -count=20 -failfast`
  20/20 PASS，共149.717s，单次最长12.56s，20次observer退出；未报告数据竞争。
  与§10.1分区后的受影响包race组合，独立relay没有被遗漏。
- 源码线索：状态hook同步调用runtime快照写入，后者有Sync/replace；这些操作占用
  已有的绝对窗口。但源码调用关系本身不能证明它导致了§10.2的失败。
- 使用仓库外临时overlay，只给两个已有文件插入计时；移除插入须恢复原文本，
  物理源码不写入，不换clock、不去除Sync、不改变context/消息/原断言，vet保持开启。
  只记录固定state/type、role布尔值、稳定错误类、相对耗时，无身份、地址或路径。
- 首次单例诊断PASS（测试11.34s），runtime写入最大95,316µs；随后一组预定上限20、
  fail-fast的采样20/20 PASS167.352s，选择错误0。runtime写入最大603,443µs，
  capability/selecting hook最大42,349µs，capability/proposal/confirm发送调用最大1,489µs。
  发送调用返回不证明远端投递已完成；新增日志也可能改变调度，不作为无扰动因果证明。
  20次observer与CPU worker退出；不推导未测的完整OS残留。
- 诊断未捕获原失败，故准确根因仍未闭合。不把21个带观察器的成功例与正式压力批次
  拼成验收，不重跑原批求绿，不凭猜测改变2s、25s、30s或退避/持久化语义。

### 10.5 实现head首次CI与剩余门

`5efdcc8` 的56项检查全部结束：52 SUCCESS、3 FAILURE、1 CANCELLED，非全绿。
独立relay两系统、全仓分区与本次架构门均通过；以下是未改v2/liveness路径的真实失败，
不在本PR混修，也不使用本地通过来抵销：

- [Mapping Lifetime（PR事件）](https://github.com/houyuwushang/winkyou/actions/runs/34313241432/job/102344047329)：
  M_E_initiator_winner_unmeasured_contract的独立observer排水报告reverse-flow command unavailable。
- [Mapping Lifetime（push事件）](https://github.com/houyuwushang/winkyou/actions/runs/34313238299/job/102344037718)：
  M_S_tail双方hard_nat_candidate_exhausted、candidate入站1/1、winner0/0；成功断言失败，
  teardown报告socket/process/conntrack/lock/veth残留0。未据此推定所有历史M失败同源。
- [Windows real WireGuard](https://github.com/houyuwushang/winkyou/actions/runs/34313241248/job/102344046719)：
  annotation为既有12分钟作业上限。此轮三个测试步骤日志均PASS，末尾作业仍被标为CANCELLED，
  不能将job改报成功；[required聚合](https://github.com/houyuwushang/winkyou/actions/runs/34313241248/job/102347876853)因此失败。

本次证据提交不改实现。压力门与上述CI门尚未闭合，ADR方向裁决不等于实现验收。
后续必须保留首轮RED，独立审查原窗口下的进度与重建问题；没有证据支持自行放宽或
将失败标为advisory。本PR保持Draft，不合并、不关闭#97，不据此进入任何v2或现场Gate。

## 11. 阶段3：R-a 裁决与重新验收（2026-09-11）

### 11.1 裁决来源与边界（实现前单独提交）

维护者在[PR #124 R-a 裁决](https://github.com/houyuwushang/winkyou/pull/124#issuecomment-5596740481)
明确接受能力2s与确认最多2s的拆分，并要求从原执行额度扣除；
[独立复审](https://github.com/houyuwushang/winkyou/pull/124#issuecomment-5596542546)
指出旧共享窗口下的压力失败是设计后果，不能靠重复诊断或恢复 implicit fallback规避。
阶段3提示词已明确解冻，基线为#123合入后的`b53f8c8`；其4个push workflow首跑均成功。
本分支先merge main，不rebase/squash；本节在红回归与实现之前独立提交。

§4.3/§9.3及§7按上述裁决修订；§10全部原文与首次压力0/1 RED保留，不追溯改判。
本次只调整首轮选择窗口的语义与预算扣除，capability2s、RunTimeout25s、测试30s、
消息上限及2/4/8/10s退避数字不变；后续ordinal规则不变。整体session原预算不增加，
不新增消息、自动重试、配置开关或网络权限，不触碰#111待裁决的O1/O2/O3。

重新验收使用Go1.23.1：压力至少50（既有56 worker、fail-fast、完整时间线）、无压力至少100、
独立relay race×20、session/client race×20、#116全仓分区、architecture×20与全仓vet。
首次RED单列；命中已登记的CI签名时在对应issue记录并停止，不rerun或混修。
保持原Draft PR、不合并、Refs #97；是否关闭issue由维护者在独立复审后决定。

### 11.2 R-a 红回归（旧共享窗口实现，原始结果保留）

设计提交`acc5eee`之后，仅添加纯内存延迟投递测试，未修改生产。Go1.23.1、
GOMAXPROCS=28，首跑命令：

```text
go test ./pkg/session -run '^TestSelectionConfirmWindowStartsAtCapabilityReceipt$' -count=1 -failfast -timeout=30s -json
```

预期RED命中：单测2.01s、package2.552s；两侧capability均在1,900,457,000ns收到，
双侧`state=failed class=selection_timeout executions=0`。两份proposal已入延迟队列，
但共享2s窗口先终止；cleanup见证`workers=0 queued=4`。这是精确错误类的旧模型反例，
不是编译失败，也不以“任意错误”当作成功复现。

另一次旧实现负向对照首跑2/2 PASS4.180s：capability约2.1003334s才到，双侧
capability_missing且零执行；缺少confirm时双侧selection_timeout且零执行。
投递/终局逐侧记录，worker全部join。后续GREEN须使用同一正向测试，且保留这些首跑日志。

### 11.3 R-a 实现与确定性边界检查

- `passDeadline`拆为capabilityDeadline / confirmDeadline；首次有效capability接收时，
  在agreement锁内冻结本地capabilityReceivedAt。传入的ReceivedAt仍只供原诊断使用，
  不能为确认窗续期或把迟到能力伪装成及时。相同重复不重新计时。
- 已及时接收能力但waiter稍后才获调度时，不因旧能力ctx到期而误报缺失；父取消与本地
  终局仍优先。尚未收到有效能力且越过原2s时仍capability_missing，不进入策略。
- ordinal0的budgetStart固定为passStart；复用既有selectionExecutionContext与
  subtractSelectionTime扣除两段实际耗时。后续ordinal的起点、min(2s,执行预算)、
  首个group原合计窗口、后续plan窗口均不改，不在solver策略内部增添时间规则。
- 同一个红回归在修复后首跑GREEN：能力约1.9008934s、proposal约2.2013432s、
  confirm约2.5020089s，双侧bound、各执行一次relay_only、同一非空joint digest，
  每侧恰一proposal/confirm，执行deadline仍等于passStart+25s，delivery worker=0。
  正向2.51s、能力迟到负向2.10s、缺confirm负向3.90s，三项共PASS9.222s。
- 纯时间计算覆盖8个边界，包括受限剩余额度、已耗尽、短测试窗口、超2s输入及Start前
  已收到能力；重复/自报时间、迟到回填、已接收但waiter迟到、父取消、first plan/group
  与TimeBudget同步扣除分别验证。首跑session0.733s、architecture6.899s，均PASS。
- architecture新增R-a接线断言及9种变异，与原implicit fallback/#94保护合计20种源码
  变异均拒绝，另保留别名构造点逃逸检查。wire golden与#94冻结函数、#116分区原样保留。
- 初步focused race（一次）session45.368s/client2.463s PASS；后续ordinal25s/1s两种
  既有执行额度各race×20 PASS，package2.230s；scoped vet PASS。此前50ms缩小额度
  的独立探索也通过，最终用1s检验小于2s的分支，避免给新测试引入不必要的极短调度窗。
  这些小范围结果不冒充以下完整压力/无压力/整包矩阵验收。

### 11.4 R-a 首次正式压力批次：36 PASS，第37例 RED

实现固定为`c55d42b`，Go1.23.1、GOMAXPROCS=28、CPU helper=56 worker，
每worker每轮65,536次整数运算后Gosched；未并行其他重测试。命令与首跑结果：

```text
WINKYOU_FLAKE_97_CPU_STRESS=1
go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=50 -failfast -timeout=45m -json
```

36例PASS，第37例FAIL后停止，未执行第38–50例；package385.510s，命令墙钟391.549s。
失败单例31.28s，断言仍为原30s等待relay transport；成功单例最长31.15s是包含
建立、数据验证和cleanup的整个测试耗时，不能当作单一connect时延。
37例均有`observer_workers=0`及`cpu_stress workers_remaining=0`。
本批为**RED，未满足压力≥50通过门**；不与无压力或此前§10统计合并、不rerun求绿。

原始JSONL完整保存在仓库外；SHA-256为
`011f4a3bf3e88aa122675c909f70a10eb03d5084db4c15723a8c8eab50fc55b0`。
下面是第37例的**全部状态变化采样行**及两个退出见证，只去掉测试源文件行号；
原始失败诊断中的运行实例、地址、公钥和进程信息不进入公共记录：

```text
relay_timeline side=1 elapsed_ms=0 sessions=0 []
relay_timeline side=2 elapsed_ms=0 sessions=0 []
cpu_stress cores=28 gomaxprocs=28 workers=56 iterations_per_yield=65536
relay_timeline side=2 elapsed_ms=250 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope= path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=358 sessions=1 [state=new strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=601 sessions=1 [state=capability_exchange strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=650 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=915 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=selection_proposal path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=1052 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=2409 sessions=1 [state=failed strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=true retry_ms=2000]
relay_timeline side=1 elapsed_ms=2551 sessions=0 []
relay_timeline side=1 elapsed_ms=2604 sessions=1 [state=new strategy= negotiated=false capability=false envelope=selection_proposal path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=2652 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=selection_confirm path_commit=false connecting=false bound=false retry_pending=true retry_ms=2000]
relay_timeline side=2 elapsed_ms=2701 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=2750 sessions=1 [state=failed strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=2804 sessions=1 [state=failed strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=true retry_ms=2000]
relay_timeline side=2 elapsed_ms=2905 sessions=0 []
relay_timeline side=2 elapsed_ms=3430 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope= path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=4651 sessions=0 []
relay_timeline side=1 elapsed_ms=4952 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=5105 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=selection_proposal path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=6897 sessions=1 [state=probing strategy=relay_only negotiated=true capability=true envelope=selection_proposal path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=7058 sessions=1 [state=failed strategy= negotiated=false capability=true envelope=selection_proposal path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=7104 sessions=1 [state=failed strategy= negotiated=false capability=true envelope=selection_proposal path_commit=false connecting=false bound=false retry_pending=true retry_ms=2000]
relay_timeline side=1 elapsed_ms=8039 sessions=1 [state=executing strategy=relay_only negotiated=true capability=true envelope=selection_proposal path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=8100 sessions=0 []
relay_timeline side=2 elapsed_ms=8702 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=14901 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=probe_script path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=15705 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=16051 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=true retry_ms=2000]
relay_timeline side=2 elapsed_ms=16951 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=false bound=false retry_pending=true retry_ms=2000]
relay_timeline side=1 elapsed_ms=17285 sessions=1 [state=executing strategy=relay_only negotiated=true capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=17655 sessions=1 [state=failed strategy=relay_only negotiated=true capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=18051 sessions=0 []
relay_timeline side=2 elapsed_ms=18250 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope= path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=18651 sessions=0 []
relay_timeline side=2 elapsed_ms=19154 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=20338 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=21601 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=21700 sessions=0 []
relay_timeline side=2 elapsed_ms=21929 sessions=1 [state=new strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=21954 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=22351 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=22504 sessions=0 []
relay_timeline side=1 elapsed_ms=23900 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=23951 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline observer_workers=0
cpu_stress workers_remaining=0
--- FAIL: TestRelayWGGoTwoEnginesExchangeIPv4Packets (31.28s)
```

最终断言：`timed out waiting for relay transport`。双方诊断均无tunnel peer，
没有已提交path，数据计数0。以上证明本helper与observer已join，**不声称未测的全部
OS socket/fd资源都为零**。

证据所能支持的结论：

- 初轮side1在358ms已见capability（此时state=new），650ms selecting，2,409ms
  failed；对端proposal/confirm分别在后续重建观察中于2,604/2,652ms出现。side2
  1,052ms selecting、2,750ms failed。采样不能给出精确的协议接收/发送时间或错误类。
- 后续4,952/5,105ms双方selecting；6,897ms side1已协商relay_only进入probing，
  7,058ms side2 failed，8,039ms side1 executing；观察到了单侧执行而对侧已失败的
  状态组合，不能宣称压力下可用性收敛已经修复。
- 8,702–16,951ms side2经历下一轮capability_exchange/failed；17,655ms side1
  也failed。其后继续按原runner机制重建，直到30s transport断言失败。未修改退避规则。
- 50ms尽力采样只在状态快照变化时输出，快照跨多个锁；它既不保证准确的包投递次序，
  也不记录每次内部deadline/终止类。因此**不能把本例归因为R-a计时错误、消息丢失、
  存储Sync或调度中的某一项**，更不能仅凭这些日志改窗口/持久化/重试语义。
- R-a精确纯内存反例已由§11.2 RED转为§11.3 GREEN，但本次正式压力门仍未闭合。
  后续独立验证只提供其各自范围的证据，不抵销本例；若需超出R-a的语义修复，须另行
  复审裁决。本PR继续Draft，不合并、不关闭#97，不把压力门降为advisory。

### 11.5 无人工压力100通过；独立relay race首跑另有启动RED

同一Go1.23.1/GOMAXPROCS=28，关闭CPU helper，所有批次串行；没有修改生产代码。
仅文档证据提交追加到`49920c8`，被测生产仍为`c55d42b`：

```text
go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=100 -failfast -timeout=60m -json
go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast -timeout=25m -json
```

- 无人工压力：**100/100 PASS**，package725.224s、命令墙钟729.343s；单例最长7.61s，
  observer退出100/100。保持原双向数据、runtime计数及各阶段等待断言。
- 独立relay race：**0 PASS / 第1例FAIL**，剩余19例未执行；package1.274s、命令
  墙钟7.658s，失败单例0.29s。失败发生在第一个engine的Start，尚未进入策略交换：

```text
relay_timeline side=1 elapsed_ms=0 sessions=0 []
relay_timeline side=2 elapsed_ms=0 sessions=0 []
alpha.Start() error = rpc error: code = DeadlineExceeded desc = context deadline exceeded
relay_timeline observer_workers=0
--- FAIL: TestRelayWGGoTwoEnginesExchangeIPv4Packets (0.29s)
```

这是该例全部状态采样与失败/observer见证。日志没有data-race报告，不能将
`-race`命令失败写成“发现数据竞争”；同样没有证据将它与§11.4的选择压力失败合并归因。
夹具原有coordinator timeout=200ms，**本PR不修改它，也不据此断言启动失败根因**。
不增加被跳过的测试、不重跑该批求绿；独立relay race×20门尚未通过。

### 11.6 其余独立验证与首跑CI

仍使用Go1.23.1/GOMAXPROCS=28，CPU helper关闭，逐批首跑且未并行其他重测试：

```text
go test -race ./pkg/session ./pkg/client -count=20 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -failfast -timeout=35m -json
go vet ./...
go test ./internal/architecture -count=20 -failfast -timeout=20m -json
go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -json
```

- session/client整包race×20 PASS：session898.248s、client14.637s；session的120个、
  client的105个顶层测试均恰20轮通过，未报告数据竞争。新的R-a正向及两个负向也各20轮。
  relay只按#116原规则精确隔离，未丢失其独立首跑RED（§11.5），不写成所有race均绿。
- 全仓vet PASS，命令墙钟14.736s。
- architecture×20 PASS，package191.092s、命令墙钟193.470s，105个顶层门禁各20轮；
  含R-a窗口/预算及原implicit fallback、#94构造点和源码变异自检。
- #116全仓分区PASS：88个有测试包通过、11个包无测试文件，0失败；命令墙钟130.782s。
  governor119.696s、session45.301s、architecture14.724s；未增加skip规则。
- `git diff --check`、增量隐私扫描与2个相对文档链接检查PASS。§10与`9de27ec`逐节
  文本核对未变，真实relay夹具/压力helper/wire golden相对该head未变；配置、工作流、
  solver、governor、probeio、v2相对main `b53f8c8`的delta为0。
- 本轮生产代码为`c55d42b`，其后仅追加文档证据；所有本地测试进程已经结束。
  最终证据head的CI尚未触发，推送后在[PR #124](https://github.com/houyuwushang/winkyou/pull/124)
  单列该head首跑状态，不拿§10旧head结果替代，不manual rerun。

§11.4与§11.5的两个RED均保留，不由后续独立结果抵销。两个失败均不能套用本轮列出的
#118/#120终态签名；本地启动RED没有被登记成未经证实的既有CI问题。
R-a的确定性修复不等于#97完整验收，保持Draft、不合并；超出本次R-a的后续处理待独立
复审裁决。未改冻结时限/预算/重试，不触碰#111待决项，没有现场I/O或主机配置操作。

### 11.7 R-a.1：提前接收的确认锚点澄清（实现前单独提交）

按[PR #124复审及R-a.1裁决](https://github.com/houyuwushang/winkyou/pull/124#issuecomment-5631286704)
继续原分支，基于已推送的`90131ce`。旧实现忠实于R-a字面规定，但proposal/confirm的
往返不可能早于本地pass开始；对端capability先到时，以收到时刻起算会削短这个往返窗口。
因此锚点澄清为max(passStart, capabilityReceivedAt)，由同一纯函数供提前/正常接收
两个调用点使用。锚点不晚于passStart+2s仍由capability deadline保证，总界不超过4s；
2s capability、25s RunTimeout、30s测试死线、退避及消息数字均不变。

本节先于代码单独提交。新增纯内存红回归：先启动对端，使其capability在本地Start前
至少300ms实际到达；每程控制投递950ms，proposal/confirm往返1.9s。旧模型应在提前
收到capability的一侧selection_timeout，新模型须双侧executing、同digest且原25s
执行截止点不变。纯时间边界received_before_start改为passStart+2000ms，不变量为
deadline≤max(start, received)+2s且deadline≤start+budget；新增早到仍用旧锚点的变异。

原§10/§11.1–§11.6首次证据保留；复审已将旧relay race启动RED登记为#136，不在本PR
修改200ms夹具。旧head CI的#118/#133登记见复审评论，不rerun求绿。
本轮生产变动后重新开展独立首跑，不能与旧批次合并计数：Go1.23.1、GOMAXPROCS=28、
原56 worker压力≥50（fail-fast且完整时间线）、无压力≥100、relay race×20、
session/client race×20、architecture×20、全仓#116分区与vet。

强制停止条件：压力再失败且时间线显示单向投递>1s，保留完整时间线后停下等维护者
裁决门政策，不自行改压力强度、窗口、退避或预算；relay race首例命中#136
（alpha.Start DeadlineExceeded、<0.5s且无协议消息）则登记该issue并停下。
CI首跑单列，命中#118/#133/#132/#134/#135只登记，不混修或rerun。
保持原Draft，不合并、不关闭#97，不触碰#111、现场I/O或主机配置。

### 11.8 R-a.1红回归（原R-a生产实现，首次结果保留）

设计提交`3a8f3c9`后，仅添加/更新纯内存测试；Go1.23.1、GOMAXPROCS=28。
`TestSelectionEarlyCapabilityDoesNotShortenConfirmWindow`首跑按预期RED：
测试2.22s、package2.922s；side1实际收到capability比其Start早300,926,000ns，
其proposal/confirm分别在本地pass之后951,743,300ns/1,901,327,000ns投递。
side0 bound、执行1次；side1 failed、`selection_timeout`、零执行，完整双侧日志留存。
worker=0、queued=6，无重发；这是窗口削短的协议反例，不是夹具启动或编译失败。
同版`TestSelectionFirstConfirmDeadlineBounds`首跑只有received_before_start子例RED，
其余7个边界PASS。旧1900ms不能满足新2000ms期望；不把这次预期RED混入实现后验收。

### 11.9 R-a.1最小实现与首轮小范围验证

生产只改firstSelectionConfirmDeadline：anchor先取receivedAt，早于passStart则取
passStart；剩余预算与返回deadline都使用anchor。beginSelectionPass与
receiveSelectionCapability两个调用点逐字不变，其他生产逻辑不变。
原20种变异保留，其中4s扩大窗口变异仅随局部变量改名调整匹配文本；新增第21种
“提前收到时不提升锚点到passStart”变异，仍保留alias构造点绕过检查。
纯时间表增补提前接收时的小window及不足2s剩余预算，共10个边界。

Go1.23.1/GOMAXPROCS=28，小范围首跑PASS：session11.304s、architecture3.800s。
新红回归转GREEN：capability提前300,061,300ns，双侧bound、各执行一次、同digest，
执行deadline仍为各自passStart+25s，worker=0/queued=6；21种源码变异均被拒，
10个纯时间边界全通过。原1.9s+0.6s正向、迟到/缺确认负向及预算/later ordinal用例
同批通过。另对新回归及纯时间边界做单轮race smoke通过，无数据竞争报告。

以上只是实现检查，不充当压力/无压力/整包race×20验收；后续采用全新独立首跑，
每步失败先完整读取证据再判定停止条件，不自动启动下一批或重跑求绿。

### 11.10 R-a.1全新压力首跑RED与停止（不推进后续批次）

被测head为`328ac633819df4f439723cee60ebbabb0cbb103e`；Go1.23.1/windows、
GOMAXPROCS=28、原56 worker/每轮65,536次运算后Gosched，未并行其他重测试：

```text
WINKYOU_FLAKE_97_CPU_STRESS=1
go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=50 -failfast -timeout=45m -json
```

**40例PASS，第41例FAIL，余9例未执行，压力门未通过。** package378.256s，命令墙钟
382.396s；失败单例31.30s，仍是原30s等待relay transport的断言。41例observer与
CPU worker均join；不将这些见证扩大为未测的全部OS资源零残留。原始JSONL完整留在
仓库外，SHA-256为`e947d3614bc8ceed0dbb2b21edeae877f1ea0ce8ef518b49305253d66afda7a0`，不公开实例身份/地址/密钥字段。

第41例全部状态变化采样与退出见证（只去掉测试源文件行号）：

```text
relay_timeline side=1 elapsed_ms=0 sessions=0 []
relay_timeline side=2 elapsed_ms=0 sessions=0 []
cpu_stress cores=28 gomaxprocs=28 workers=56 iterations_per_yield=65536
relay_timeline side=2 elapsed_ms=158 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope= path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=350 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=401 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=450 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=selection_proposal path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=551 sessions=1 [state=probing strategy=relay_only negotiated=true capability=true envelope=selection_confirm path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=551 sessions=1 [state=planning strategy=relay_only negotiated=true capability=true envelope=selection_confirm path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=600 sessions=1 [state=probing strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=600 sessions=1 [state=executing strategy=relay_only negotiated=true capability=true envelope=probe_script path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=850 sessions=1 [state=planning strategy=relay_only negotiated=true capability=true envelope=probe_result path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=904 sessions=1 [state=executing strategy=relay_only negotiated=true capability=true envelope=probe_result path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=1001 sessions=1 [state=executing strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=1201 sessions=1 [state=executing strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=8670 sessions=1 [state=binding strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=8751 sessions=1 [state=binding strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=8850 sessions=1 [state=bound strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=false bound=true retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=9551 sessions=0 []
relay_timeline side=1 elapsed_ms=11042 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=observation path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=11042 sessions=1 [state=bound strategy=relay_only negotiated=true capability=true envelope=observation path_commit=false connecting=false bound=true retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=11051 sessions=1 [state=bound strategy=relay_only negotiated=true capability=true envelope=path_commit path_commit=true connecting=false bound=true retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=11101 sessions=1 [state=bound strategy=relay_only negotiated=true capability=true envelope=observation path_commit=true connecting=true bound=false retry_pending=true retry_ms=2000]
relay_timeline side=2 elapsed_ms=11254 sessions=1 [state=bound strategy=relay_only negotiated=true capability=true envelope=observation path_commit=true connecting=false bound=true retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=11300 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope=path_commit path_commit=true connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=12300 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=path_commit path_commit=true connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=12500 sessions=1 [state=failed strategy= negotiated=false capability=false envelope=path_commit path_commit=true connecting=false bound=false retry_pending=true retry_ms=2000]
relay_timeline side=1 elapsed_ms=12550 sessions=0 []
relay_timeline side=1 elapsed_ms=12960 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope= path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=13202 sessions=1 [state=bound strategy=relay_only negotiated=true capability=true envelope=capability path_commit=true connecting=false bound=true retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=14750 sessions=1 [state=failed strategy= negotiated=false capability=false envelope= path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=26454 sessions=0 []
relay_timeline side=2 elapsed_ms=26606 sessions=0 []
relay_timeline side=1 elapsed_ms=26749 sessions=1 [state=capability_exchange strategy= negotiated=false capability=false envelope= path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=27000 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=27254 sessions=1 [state=selecting strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=2 elapsed_ms=28403 sessions=1 [state=planning strategy=relay_only negotiated=true capability=true envelope=selection_proposal path_commit=false connecting=true bound=false retry_pending=false retry_ms=0]
relay_timeline side=1 elapsed_ms=29250 sessions=1 [state=failed strategy= negotiated=false capability=true envelope=capability path_commit=false connecting=false bound=false retry_pending=false retry_ms=0]
relay_timeline observer_workers=0
cpu_stress workers_remaining=0
--- FAIL: TestRelayWGGoTwoEnginesExchangeIPv4Packets (31.30s)
```

最终断言为`timed out waiting for relay transport`。本例没有落在#136的Start前
失败签名：已有完整选择/执行与后续重建，不能登记成200ms夹具冷启动问题。

分阶段证据与停止口径：

- 初轮551ms双方已协商relay_only，600/904ms均已到executing；side1在8,850ms
  被观察为bound，随后9,551ms sessions=0。side2在11,042ms被观察为bound。
  因此不能把本例说成“R-a.1仍未允许双方完成首轮选择”，也不能说整个链路验收成功。
- side1在11,042ms重建后又失败；26,454/26,606ms双方sessions=0，随后进入末轮。
  这些重建由既有机制产生，本次没有添加或修改重试。
- 末轮side2于27,000ms selecting，side1于27,254ms selecting；side2在28,403ms
  已协商relay_only进入planning，而side1到29,250ms仍仅显示最后收到capability，
  并进入failed。按复审使用的“跨端selecting到对端仍未闭合确认”的时间线口径，
  观察间隔为**29,250−27,000=2,250ms（>1s）**，触发本轮保守停止线。
- 上述是50ms尽力采样的状态/最新envelope快照，**不是同一帧send→receive的精确
  单向计时**；它不能排除消息处理或调度等待、被覆盖的中间快照，也不能证明具体丢失
  或迟到的是哪一帧。因此不把2,250ms写成已测得的纯网络传输时延，不据此修改窗口、
  退避、消息可靠性或既有绑定/重建策略。若维护者要求更精确的投递归因，应另行授权
  测试侧观察方案，不能把缺少该见证当作继续验收或放宽门的依据。

按§11.7与本轮提示词**停下**：仅归档本例，未启动无压力100、独立relay race×20、
session/client整包race×20、architecture×20、全仓分区或vet；不引用§11.5/§11.6
的旧生产head PASS充当本轮结果。小范围GREEN与单轮race smoke见§11.9，范围不混淆。
没有rerun；本轮提交尚未推送，未触发新head CI，也未推进PR描述的验收更新。
保持原Draft、不合并；等待维护者裁决压力门政策，或另行授权下一步的观察/设计。

### 11.11 维护者授权的测试侧定位：同步状态落盘阻塞控制路径

2026-09-11，维护者明确选择保留验收门及产品预算，并授权继续测试侧定位。
本节不是放宽裁决，也不是新的验收PASS。基于本地`a8ae9f5`，本轮生产、配置、
工作流delta均为0；不提交、不推送、不合并，不推进其余验收或现场。
§11.10首跑原件及其SHA-256重新核对一致；历史记录不覆盖。

#### 11.11.1 方法与范围

- 保留原relay测试、56 worker、GOMAXPROCS=28、Go1.23.1、200ms coordinator
  timeout、2s选择子窗口、25s执行预算、30s transport等待及退避数值。
- 私有Go overlay仅替换`_test.go`：在既有test coordinator增加gRPC server
  interceptor；在engine启动前安装测试logger和已有peer-change回调；双方Start
  完成后用转发型`CoordinatorClient`包装器记录SendSignal，并追加OnSignal/
  OnPeerUpdate观察回调。不替换任何生产文件、不新增生产hook、不改报文内容。
- 同一报文以实际payload的内部哈希关联，只输出本次样本的数字frame编号、
  side、类型和本地单调相对时间；不输出payload/epoch/密钥/实例标识。
  追加的OnSignal在产品handler之后，因此其时间是**产品信令回调返回**，
  不是网卡收包或`receiveSelectionControl`精确接收时间。启动早期尚未安装
  的客户端观察点不可追认；server观察点从开始即存在。
- 观察事件先存内存，原测试清理后输出；容量16,384，溢出则证据不完整并失败。
  第二个独立诊断增加`runtime/trace`，不注入丢包/延迟、不改变时钟。
  原始测试失败输出和trace均私存仓库外，不作为CI artifact公开。

#### 11.11.2 新样本实际结果

| 诊断 | 结果 | 见证 |
|---|---|---|
| 消息/日志观察，原压力profile，最多50、fail-fast | 第1例FAIL，30.54s；余49未执行 | 243 events，overflow=0；observer及56 workers join |
| 独立单例压力+runtime trace | FAIL，34.34s | 126 events，overflow=0；observer及56 workers join；trace正常关闭 |
| 三个独立因果测试，无网络/无压力 | PASS，package0.290s | 写锁阻塞、offline清理对照、terminal对象替换 |
| 同三个因果测试`-race -count=20` | PASS，package2.300s | 3个顶层测试各20次；两个健康性子例各20次；无race报告 |
| `go vet ./pkg/client` | PASS | 本轮诊断范围，不冒充全仓vet |
| `go test ./internal/architecture -run '^TestSelectionConvergence' -count=1` | PASS，2.321s | 既有选择边界及变异；非architecture×20验收 |

两个动态诊断都没有重现历史第41例的“首轮双边选择成功后bound→消失”完整序列；
它们在更早阶段已失败。观察器和trace有运行成本，**不得据此估计现场失败率、
声称原50次压力更差，或取代原首跑**。诊断失败按原30s断言收场；34.34s含
调度延迟及测试清理，不表示把产品等待改成34s。

独立trace样本中同一条capability（frame 3）：

```text
client_send_begin/end        707.914ms
server_receive/send_end      729.774ms
engine_signal_callback_end 10760.488ms
server_send_end -> callback_end = 10030.714ms
```

后续proposal（frame 4）在749.320ms完成server send，11215.378ms才观察到
客户端产品回调返回，间隔10466.058ms。这是同帧、同进程单调时钟下的**传输与
产品回调合计时间**，仍不得标成纯网络单向时延。

#### 11.11.3 已证实的阻塞链

trace记录并关联到了具体goroutine自身的栈，而非把唤醒者或GC goroutine的栈
当成阻塞者。Go trace跨generation的同状态重述不结束等待：初版辅助分析按
重述切片，所得4.179s等只是片段；复核后合并连续同状态得到下表，原文件均保留。

| 实际栈/状态 | 连续区间 | 时长 |
|---|---|---:|
| `receiveSignals → dispatchSignal → handleSignal → persistState → WriteRuntimeState → atomicWriteRuntimeFile → replaceRuntimeStateFile → MoveFileEx`，Syscall | trace原点后747.716–10754.801ms | 10007.085ms |
| `startStateLoop → persistState → WriteRuntimeState → ... → MoveFileEx`，Syscall | 23734.976–33764.458ms | 10029.482ms |
| `heartbeatLoop → sendHeartbeat → dispatchPeer → handlePeerUpdate → upsertPeer → persistState → WriteRuntimeState → RWMutex.Lock`，Waiting | 22671.125–33764.949ms | 11093.824ms |
| `Session.run → fail → OnError → handlePeerSessionError → persistState → WriteRuntimeState → RWMutex.Lock`，Waiting | 2711.974–15197.016ms | 12485.042ms |

trace与观察器各有自己的起始点，不能混用两种原点相减；各自的duration不受此影响。
Syscall见证定位到`MoveFileEx`调用路径，不足以区分文件系统、过滤驱动、存储设备
或OS调度等更下层原因，本轮不作这类归因。

源码对应关系：

1. [`WriteRuntimeState`](../../pkg/client/runtime.go)持包级`runtimeStateIOMu`
   完成整个原子写入，包括Sync和replace。即使两个engine的状态文件不同，仍共用
   这一把锁。Windows replace使用`MOVEFILE_WRITE_THROUGH`；外层2s重试截止仅在
   **单次系统调用返回后**检查，不能截断一个尚未返回的10s系统调用。
2. [`handleSignal`](../../pkg/client/peer_manager.go)在解码/启动solver处理前同步
   `persistState`；[`dispatchSignal`](../../pkg/coordinator/client/grpc.go)串行调用
   handler。因此一个状态文件写入可同时拖住当前capability及后续已发出的proposal。
3. heartbeat成功后在同一goroutine里同步`GetPeer → dispatchPeer → handlePeerUpdate`，
   后者也同步持久化。状态锁等待期间，heartbeat loop不能发送下一次心跳。
   选择状态/失败hook同样同步落盘，连错误通知及`schedulePeerRetry`都可能被拖住。
4. 实际trace样本side 2最后一次早期成功heartbeat为2631.220ms，下一次到
   15251.193ms才成功，间隔12619.973ms，超过原fixture的5s lease。
   在12534.898ms，GetPeer已返回`online=false`；12589.853ms客户端观察到
   disconnected/stale。offline信息确实进入产品回调，不是推测丢失心跳。
5. `handlePeerUpdate`对没有WG握手/in-band健康证据的peer执行`cleanupPeer`。
   单纯bound不足以保留会话。独立fake对照中，bound无握手→会话移除且RemovePeer=1；
   有握手及计数→保留且RemovePeer=0。这证明历史bound也存在可走的清理路径，
   **但未唯一证明历史第41例实际走了这条路径**。
6. 移除后的信令/peer update可再次`ensurePeerSession`。其terminal分支没有等待
   node级退避，只替换对象；独立构造级测试确认`retryPending=true`的terminal对象
   可立即被新对象取代，retryDelay归零。该测试用nil runner表征Closed，不声称
   重现完整Failed执行。新旧epoch控制帧冲突的`selection_conflict`也在首个动态
   诊断中出现；这不构成放宽epoch验证的理由。

因此，本轮已定位一个**可复现的产品控制路径与展示用状态落盘同步耦合**问题：
普通状态写入变慢→信令/心跳/状态hook排队→选择截止与coordinator lease先到期→
清理/重建→旧新会话冲突。两个engine同进程共锁放大了本夹具的影响；不把这种
跨engine共锁特性推广为两台设备共享一把锁，但每个实际进程仍有同步回调依赖。

#### 11.11.4 未闭合项与下一步边界

- 历史§11.10第41例无上述trace/逐帧见证，原2250ms仍只属跨端快照间隔；
  不能把新样本替换为旧样本的唯一根因。S3不对称确认及重建语义也未因此解决。
- 未查明Windows该系统调用为何约10s；未检查或修改主机服务、防护软件、磁盘配置。
- 建议另行设计/评审：将**普通展示用runtime快照**与信令、心跳、选路回调解耦，
  采用有界合并写入/明确关闭排水，并评估按实例隔离序列化。不能禁用持久化换取PASS。
  governor安全ledger、durable burn/FINISH不属于展示快照，必须保留原安全同步契约。
- 现有2s/25s/30s、5s测试lease、重试政策和压力门均不改变；本PR生产修复范围
  未扩展。未跑其余正式验收、未推送、未产生新CI，不把诊断因果测试的PASS算作
  产品已修好。

私有原始证据摘要（全部SHA-256）：

```text
pressure-observed-first.jsonl       1df6e2e2acbc15711d208b216b7de000ce51def3d86c3edd36f6049933c58e83
pressure-trace-first.jsonl          a4294144ef0b909bc7da21516d294676b5f610c62811ca552db9ea51aab61198
pressure-trace-first.out            139e345e30500d48359a1446fe4da0103c2a6b77f203ab989c65f93f15c4a8e0
trace-intervals-status-joined.jsonl  25946e5b2f593004dccc60c8c4ac598102ae3402fca082af05eaa17e38b3c7d5
causal-tests-first.jsonl            a9bef8bbb19b0fe81a3cdf4f67baf3fe8f365e026aa83b90b787c30430dfdfb7
causal-tests-race20-first.jsonl      c3f5c5b028116df4d1c51bdc4ac17cbb0b40bb7a5c2d03d82fa0fee30d2b5d49
```

### 11.12 状态快照解耦实现授权与边界（代码前记录）

2026-09-11，维护者在阅读§11.11结论后明确授权按该方向修复。本节扩展的仅是
普通runtime展示快照与控制回调的耦合；不扩展S3协议、预算、重试、现场权限。
保持原Draft分支，独立复审前不合并；实现细节及新证据待复审，不自称已获专家批准。

1. 每个legacy engine最多一个后台snapshot worker，最多一个合并的待处理通知。
   `persistState`只标记待写，不采集快照、不编解码、不等待文件I/O，不为每个事件
   创建goroutine。worker取最新内存快照并复用原原子写入；既有5s周期刷新保留。
   不新增失败重试定时器；只有后续事件/原周期可以请求下一份快照。
2. 文件读、写、删除、instance条件删除仍对同一状态文件互斥；将包级全文件I/O锁
   改为按绝对Clean路径（Windows大小写归一）引用计数管理的锁。条目无引用即释放；
   不持全局注册表锁做I/O。词法归一不是符号链接/junction等所有物理别名的身份认证，
   不能替代CLI既有跨进程owner锁。`WriteRuntimeState`等同步API与原子替换保证保留。
3. Stop/启动失败先关闭通知入口，丢弃尚未执行的展示快照；已开始写入必须返回后，
   由同一worker删除状态文件，再发布done。删除不能抢在最后一次写入前，以免文件复活。
   网络资源按既有流程关闭；展示worker不拥有网络能力。成功Stop必须有writer join
   和删除见证，不能以“发出取消请求”冒充已排空。
4. 单次展示writer排水等待上限为2s，**不是连接/probe/ledger预算**。不可中断的OS
   文件调用超时仍在途时，Stop返回稳定`runtime_snapshot_drain_pending`，保留该writer
   引用并阻止同一engine重新Start，未完成时再次Stop仍只等待原worker，绝不另起worker
   或提前删除。OS调用返回后原worker继续清理。此分支承认仍有最多一个文件worker，
   不声称goroutine零残留、不触发安全trip、不把文件I/O等待变成新的联网许可。
5. 失败日志保留原错误可观测性；异步快照是best-effort展示，不是会话状态的权威输入。
   此改动不删除展示文件功能，不改其JSON schema，也不放宽同文件一致性/权限。
   governor ledger、burn/FINISH、session/probe lease及其同步/排水契约完全不动。
6. 回归先红后绿：持有状态文件锁时信令、heartbeat/peer回调与session状态hook仍可
   返回；不同文件不互堵；同文件继续互斥；事件风暴只保留一个pending；最终快照新鲜；
   write/remove错误可见；close前后通知竞态、最后写入先于删除、超时不重启不复活；
   源码门禁及变异拒绝同步落盘回流、无界goroutine/队列、忽略排水和全文件共锁。
7. 原压力及后续验收仍使用原fixture、Go1.23.1和原数字。新生产head需要新首跑，
   不覆盖§11.10/§11.11 RED；若再次出现此前停止签名，保留证据并停下，不改数字求绿。
   #136及其他隔离签名不混修，实际完整通过前不推送验收结论。

### 11.13 实现期回归与首轮竞态证据（不是完整验收）

1. 先提交§11.12，再提交三条阻塞回归。旧同步实现下，持有runtime文件I/O锁，
   signal、heartbeat peer update、selection state三个callback都超过固定1s测试
   防挂死guard：**3/3 RED**，case共3.02s、package3.514s。此guard不是协议窗口。
   原日志`control-callback-red-first.jsonl` SHA-256：
   `c591f9543527d62df3ff70295ec88bff01226f3fa512d3c1338e609b213374d8`。
2. 引入单worker、单pending通知、按文件锁后，以上三条GREEN；锁注入从旧全局锁
   机械替换为同一文件的锁，回调必须在持锁期间返回这一oracle不变。§11.11的旧
   “同步回调确实阻塞”诊断源文件与日志另行保留为历史材料，不纳入新的GREEN oracle。
   首轮普通focused测试14项全部PASS（package2.812s），涵盖原状态文件启停与atomic
   round-trip、独立路径不互堵、4,097通知合并为2次write、一个worker、关闭丢弃pending、
   remove错误、2s pending排水阻止restart、启动失败与write错误可观测。
3. 首次开发期focused `-race -count=20 -failfast` **RED，不覆盖**：11轮14项均PASS，
   第12轮`TestEngineStartPersistsRuntimeStateAndStopRemovesIt`出现race，package26.867s。
   新后台`engine.snapshot → syncTunnelPeerStateLocked`读取`tun`，与`Start`原无锁
   `e.tun = tun`发布并发。不是旧隔离flake，不归因于协调器/预算；修复为持同一`e.mu`
   发布`tun`，在正式新首跑前补测。原日志` snapshot-focused-race20-first.jsonl`
   （文件名无前置空格）SHA-256：
   `e300085dbba06257e06444bd75333ca2d416310ff9558ea1575308a2ad3e7e41`。
4. Stop的短生命周期所有权以`TryLock`取得：并发或status回调重入Stop立即返回
   `runtime_snapshot_drain_pending`，不排队、不自锁。当前Stop返回pending后，再次调用
   仍等待同一writer；原worker删除完成后才可解除stopping。删除本身失败则保留错误与
   writer引用，禁止restart，不自动重试删除。空statePath不创建展示worker/文件。
5. runtime展示写入原JSON schema、Sync/原子替换、文件权限、5s tick均未变；仅启动时
   tunnel发布补锁，不改连接/选择/探测数字。新增源码门禁覆盖9个小型并发原语、
   legacy engine同步I/O入口、单constructor、Start/Stop顺序及22条违规变异；原
   SelectionConvergence门禁与21条变异另行保留。完整新压力/全仓/CI结果仍待记录。
