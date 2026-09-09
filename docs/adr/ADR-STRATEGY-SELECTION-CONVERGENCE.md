# ADR：legacy session 策略选择的确定性收敛

Status: **维护者接受 S3（含 S1 前置），授权实施；实现 PR 仍为 Draft，待独立复审**（2026-09-09）。
基线 `main = 214ff2d`。Refs #97；不关闭 issue。
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
- 第一轮确认消耗原 capability 2s 窗口，不能在 2s 后悄悄再开一个 2s。
  后续策略确认拟从该 candidate 既有 RunTimeout 扣除，并受同样 2s 子上限限制；
  不增加 25s 数字或候选数量。确认/执行共享绝对 deadline 的起算调整须显式评审。
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

## 7. 验收计划（均尚未执行）

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

首轮绝对 deadline 在 Start 首次发送 capability **之前**建立：发送、能力接收、proposal、
confirm 共用原 capability 2s（测试配置只能缩短）。没有额外2s确认窗口。
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
