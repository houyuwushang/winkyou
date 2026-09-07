# ADR 提案：C1c 前的 session inactivity / liveness 重裁决

- 状态：**Accepted（2026-09-06）：§11 六项裁决由维护者委托独立复审人按复审推荐代填（复审记录见
  [PR #105 评论](https://github.com/houyuwushang/winkyou/pull/105#issuecomment-5554766996)）；
  文本接受不等于实现授权——liveness 实现与 C1c 仍须维护者另行下达，不授权现场 I/O。**
- 基线：`main = f2df7456a553ee731fa8801114985413ebb49540`，PR #104 已独立复审并合入。
- 跟踪：[#98](https://github.com/houyuwushang/winkyou/issues/98)。
- 上位约束：[Gate C1 ADR](./ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md) §16.8、§16.10、§18、§19，
  [取消排水契约](../CANCELLATION-DRAIN-CONTRACT.md)、
  [跨重启契约](../PAIRING-RESTART-SAFETY-CONTRACT.md)。

本文所有新增参数、线格式、接口要求和验收条目已按 §11 裁决**接受为完整方案**（2026-09-06）。
文本接受关闭的只是 Gate C1 §16.8 的"重裁决"前置门；liveness 实现须由维护者另行授权并独立复审，
C1c 与现场 I/O 仍分别冻结。现有 C1b 的常量、packet trace、golden、parser、默认行为及历史失败
证据保持原样，直到获授权的实现 PR 按 §9 取证后才改变。

### 已确认的产品取舍（不等于接受本提案）

维护者于 2026-09-06 明确：数据面自主实现不是当前优先项，**暂时保留 WireGuard**，先推进
个人设备互联与困难 NAT 路径的稳定业务承载。本轮不自研替代数据面、不维护双实现、不改
WireGuard 密码协议或依赖版本；也不将 WireGuard 定为永久不可替换依赖。

WinkYou 负责定义并验证会话存活、资源约束、停止与 transport 交接；是否采用本文的双端挑战、
具体时间/额度/线格式，仍由 §11 单独裁决。换网迁移和受控恢复属于后续设计，不因这项产品
取舍而被视为已实现或已授权。日后替换数据面须以必要功能受阻、实测性能或适配成本为依据，
另立协议与独立评审范围。

## 1. 要解决的问题与不解决的问题

用户是同一操作者的两台自有设备。已经完成一次困难 NAT 求解、WireGuard handoff 和 post-OOB
echo 后，用户暂时不操作，session 不应被当成失联；对端断电、链路黑洞或控制 worker 失效时，
本机又必须停止发送、释放唯一 transport，不能重新打洞或跨重启恢复。

成功标准不是“延长 15 秒”，而是同时证明：

- **业务空闲不等于失联**：没有 inner 业务包时，健康 session 仍保持到显式停止或绝对上限。
- **入站包不等于双向可用**：持续收到垃圾、重放、单向业务或空 keepalive，不能无限续租。
- **失联有界**：双方各自持有不可被远端改写的截止时间；发送强制点也检查它。
- **不恢复**：失联只是本 session 的终局，不生成 credential、不增加 attempt、不换 endpoint。

本提案不解决笔记本移动后的换地址、自动重连、共享出口、跨用户协作或长期 daemon。与 FRP/
SSH relay 不同，liveness 流量只走已经交接的加密 UDP 数据面，不依赖或复活 SSH/OOB。

## 2. 当前事实与证据强度

以下是基线实现事实，不是本提案已经实现的证据：

| 位置 | 核实结果 | 对裁决的影响 |
| --- | --- | --- |
| `internal/v2/gatecorchestrator/session.go:foregroundSession`、`types.go` | responder 用 5s ticker 累计三次无 inner 数据；收到 inner 包清零。initiator 只等待本地取消或 absolute ceiling。 | 计数不是“最后一包后精确 15s”；两端不对称。 |
| `gatecorchestrator/trusted.go:bindingPeer` | `Keepalive: 0`。 | 没有已配置的 persistent keepalive 可支撑“三个 keepalive 周期”。 |
| `pkg/tunnel/tunnel_wggo.go:readTransportLoop` | `TransportRxPackets` 在交给 WireGuard 解密前增加。 | 原始 transport 计数不能作为认证活动证明。 |
| 同文件 `refreshPeerStatsLocked`、`pkg/tunnel/tunnel.go` | 目前有聚合 `RxBytes`、握手时间和事件；没有带错误、epoch 与认证接收时间的专用 liveness 接口。 | 不把旧 snapshot 或丢失的 event 当成一次新活动。 |
| `pkg/config/validator.go:validateGateC`、`orchestrator.go` | trusted `session_ceiling` 为 5s..24h；session deadline 在 `FinishAndDetach` 前起算，不因 post-OOB 阶段重启。 | 保留该绝对上限；liveness 只能更早关闭。 |

仓库固定 `wireguard-go f333402bd9cb`。本次比对本地模块源码与官方同 commit：

- [`receive.go`](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cb/device/receive.go)：transport
  在解密及 replay 检查后更新认证接收统计；空 keepalive 不写入 TUN。聚合 `rx_bytes` 还包含
  已接受的握手，不能直接解释成一次业务应答或一次新 RTT 证明。
- [`timers.go`](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cb/device/timers.go)：persistent
  timer 在认证报文**发送和接收**时都会重置；空 keepalive 不触发 `timersDataReceived` 的回包逻辑。
  因此“双方都设置同一 keepalive interval”不保证双方独立周期发包，更不保证每包都有应答。
- [官方 quick start](https://www.wireguard.com/quickstart/#nat-and-firewall-traversal-persistence) 将
  persistent keepalive 定位为维持 NAT/firewall 映射，给出常用 25s 建议；这不是任意 NAT 的保证。
- [官方协议说明](https://www.wireguard.com/protocol/) 说明内建 rekey、keepalive、重传计时器。
  不能把“没有重新调用 solver”写成“WireGuard 内部不会再发包”。

从 timer 代码可推导一个待测试反例：空闲时一侧先发 empty keepalive，另一侧收到后将自己的
persistent timer 后移，且不必回复 empty keepalive。直接用双侧 RX 超时可能误杀健康路径。
这是**源码推导**，本 docs-only PR 没有运行该网络反例；§9 要求以后用真 WireGuard 验证。

## 3. 选项与推荐

三个候选方向并不完全互斥；“可信活动来源”“本地时间政策”“双端检测”必须一起考虑。

| 方案 | 优点 | 缺口 / 代价 | 提案意见 |
| --- | --- | --- | --- |
| A：只放大 inner inactivity，允许本地有界配置 | 改动少，可降低短时误退出 | 仍把业务空闲当成失联；单改 responder 窗口不能给 initiator 提供对等检测；单独使用不满足本提案的双向证明。 | 不推荐单独使用。 |
| B：认证 outer RX + persistent keepalive + 双端超时 | 不需要新的 inner 消息 | 需要可靠的认证活动接口；统计不是双向证明；双侧 timer 相互重置存在上述反例。 | 保留研究输入，不能仅靠调 25s 宣称闭合。 |
| C：双方独立、低频、加密隧道内 PING/PONG；有限本地失联窗口 | 不依赖业务流量或 WG 私有 hook；当前随机挑战得到双向证明；两端同一终止规则 | 新增小型 post-FINISH 控制协议、分流和独立计费，须评审其完整契约。 | **推荐，未接受。** |

C 不是重复使用一次性的 post-OOB echo，也不是复制 legacy ping daemon。它保持 WireGuard
`PersistentKeepalive=0`，以定长数据消息验证同一 fixed-target path；outer/业务计数只作诊断，
不延长 liveness 截止时间。不得在 C 失败后自动退回 A/B。

## 4. 推荐方案的范围、参数与激活

### 4.1 仅 trusted local policy

拟在 Gate C peer 的 trusted config 增加 `session_liveness`，精确成员为：
`mode="challenge_v1"`、`missed_rounds=2|3`（默认 3）。这是**新增配置提案，不是现在可用配置**。

- 编译期 `K=20s`（本端请求间隔）、`R=5s`（单次答复窗）、`Mmax=3`、drain=2s。
- 本地 `M` 只能取 2 或 3；失联界 `L=M*K+R`，分别为 45s / 65s。配置只降低容错窗口，不提高
  发包速率；不开放任意 interval、0/无限、热重载、remote override 或环境变量。
- `session_ceiling` 的 5s..24h 验证和原起算点不变，剩余时间小于 `L` 时 absolute deadline 优先。
  短 session 可以在第一个心跳前正常达到绝对上限；不自动延寿来完成心跳。
- C1c exact build/私有授权实例必须明确选择该 policy；普通构建及缺失 policy 的旧 C1b 路径
  不静默改变行为。C1c 缺字段、未知 mode/成员、非整数或超界 M 在 SSH/UDP 前拒绝。
- 两端使用同一经审查构建；M 可分别更保守。policy 不来自 artifact、OOB 或 peer report，
  不通过网络协商，不改变四套 artifact/parser 或 Noise prologue；跨版本兼容不在此门。
- **policy 生效即整体替换 Gate C1 §16.8 的 inner-inactivity 规则（复审必补项）。** C1b 的
  responder 以 5s×3 inner 数据报 ticker 判定失联，而 §7.1 的分流 adapter 会在 foreground
  reader 之前截走 WYCL PING/PONG；若两套规则并行，健康但业务空闲的 session 仍会在 15 秒内以
  `inactivity_ceiling` 退出，直接否定 §1 第一条。因此 `session_liveness` 存在时：responder
  不再运行 inner-inactivity ticker，`inactivity_ceiling` 终局在该路径不再产生；两端对称地只以
  本节许可到期、authenticated CLOSE、absolute ceiling 与 §8 的稳定错误结束。缺 policy 的旧
  C1b 路径保持 §16.8 原行为，不受影响。

20s 是给常用 25s 映射保持建议留余量的**待验证工程值**，不是 NAT 分类结论。短于该间隔的
映射寿命、超出 5s 的 RTT 或连续丢包可以导致保守终局；不能通过在线缩短 K/扩大 M 补救。
每 20 秒的双向 PING/PONG 客观上也刷新 fixed-target 路径上的 NAT 映射，且低于
[#106](https://github.com/houyuwushang/winkyou/issues/106) / [PR #107](https://github.com/houyuwushang/winkyou/pull/107)
在隔离 runner 只读实测到的 30s 普通 UDP conntrack 默认值；这只是与该实测的对照，不构成
NAT 分类或寿命下界结论。本节 liveness 只在 durable FINISH 之后运行，不能用于 VERIFY 之前的
候选路径续命——建立阶段的映射寿命问题由
[Hard16 映射寿命 ADR](./ADR-N3C-HARD16-MAPPING-LIFETIME.md) 单独裁决。

### 4.2 绝不能提前激活

```text
原 Gate B + VERIFY + capped WG challenge + R1 + durable FINISH
  -> attempt detach -> OOB drain -> 原一次性 post-OOB echo 成功
  -> 本地 liveness arm -> data_plane_ready -> periodic proof 或 terminal
```

建立阶段仍是 3/3 shared readiness/WireGuard/R1 datagram、3s challenge、原 20s/45s attempt 与
2s drain、8 frame/8256 byte；新增 liveness 在此之前 **0 包**，不能占用或兑换 establishment
headroom。同一 transport、同一 peer/attempt/generation/path/consumer/owner 始终不变。

## 5. 双端计时与状态机（推荐冻结）

双方各自运行完全相同的请求器，收到对方请求时各自答复；不用共享时钟或角色 leader。

1. 本地 post-OOB echo 成功时取得单调时钟 `t0`，首次许可至 `min(absolute, t0+L)`。随后每个
   `t0+n*K` 槽最多发一次新的 PING（n 从 1 开始），不得靠收包重排发送槽。
2. PING 取得一个全新 128-bit `crypto/rand` nonce 与递增 sequence；只保留 **一个**本端 pending
   请求。发送时间 `s` 在控制包被有界出站路径接纳时记录，应答必须在本地处理时满足
   `now < s+R`；入队时间不等于已验证时间。PING/PONG 的本地出站期限均至多 1s，且不得晚于
   原 session/许可期限；发送失败、超时或排队过期不补发。同一次 PING 的 nonce 不因失败重用。
3. 只有当前 peer/attempt/context/role、sequence、nonce 全匹配的 PONG，才可一次性续许可到
   `min(absolute, s+L)`。使用 **请求发送时刻**，不使用答复收到时刻，不能靠延迟回复延寿。
4. PING、业务包、empty keepalive、握手、raw RX/TX、上次握手成功或本地写成功都不续许可。
   对方 PING 只允许一个对应 PONG，不证明本端 PING 已到达对方。
5. R 到期销毁 pending；后续槽使用新 nonce/sequence。没有同一请求重传、ACK 的 ACK、离线
   队列或失败补发。这是已建立 session 的有限周期协议，不是新的 NAT attempt。
6. `now >= lease_until`、absolute 到期或 session 撤销先于任何新 I/O。到期同刻到达的 PONG 不复活
   session。事件队列积压也不能越过该判断；旧的 PONG 不在下一轮匹配。
7. 调度延迟不追赶多个 missed slots；不足答复窗或已有 pending 时不制造第二请求。若本地
   时钟/挂起证据不能维持该界，关闭 session，不补发、不重建。

默认三轮全失时，首次发送槽为 20/40/60s，许可在 65s 到期；M=2 时在 45s 到期。
最后一次有效 PONG 所绑定的请求发生于 `s`，则双方各自从自己的 `s` 起至多 L 停止新发送，
再至多 2s 排水。**不是等收到最后一个普通报文后再加 L。**

由于两端都要求自己的 nonce 被返回，单向黑洞不会被另一方向的业务流量无限续命。对端崩溃
后可能有在途 PONG，但它只能续到其旧请求的 `s+L`；不承诺两端同时观察到相同 terminal。
正常调度、时钟契约满足时，故障注入后的默认新发送截止上界 65s、排水上界 67s；这不是已经
实测的 SLA，必须通过 §9 的进程外见证。

### 5.1 时钟与挂起

时间判定不信任 peer timestamp。实现须使用可注入本地时钟，并在写强制点同时检查原绝对
期限与 elapsed 许可。不能假设所有平台的 Go monotonic clock 都包含系统睡眠时间。

提案为保守检测：arm 时固定本地 `(mono0, UTC0)`；每次判定用
`elapsed=max(monoNow-mono0, UTCNow-UTC0)`。所有槽、答复窗及续许可统一按此 elapsed 计算；
原 absolute deadline 仍保留，并以 arm 时的剩余时间再约束 elapsed，不能重新起算绝对寿命。
以**固定起点**计算的两种 elapsed 差值绝对值超过 2s、单调时钟相对上次读数倒退或任一
时钟溢出，在下一次 I/O 前以 `session_liveness_clock_invalid` 终局。不重置起点来吃掉多次短
挂起，不校准/延长既有许可；小幅前跳最多提前退出，不用较慢时钟延寿。

**裁决（2026-09-06）：UTC 相对上次读数倒退本身不终局，只记入 witness。** 理由：`max()` 已
保证任何回拨都不能延长许可（回拨只会让 UTC 项变小、由单调项兜底），因此 NTP step 或手动
校时的小幅回拨没有安全后果，将其判为终局只损失可用性。单调时钟倒退、任一溢出与 >2s
发散仍按上文终局；回拨若同时造成 >2s 发散，仍由发散规则终局。

支持平台必须用系统 suspend/resume 证据验证，不能只用缩短 ticker 的单测替代。本地校时也
可能保守终止，这是待接受的可用性代价。机器完全不被调度期间无法保证清理在物理 2s 内
执行；恢复后第一项动作必须是过期检查，不能先 flush backlog。

## 6. 独立 inner 线格式提案

新协议仅在已经认证、解密且通过 WireGuard peer/AllowedIPs 检查的 **inner 入站路径**解析。
不新建 UDP listener。暂定内部标识 `winkyou-gate-c-session-liveness/1`，不是新的 OOB profile。
使用虚拟 UDP 端口 32113（不同于旧 WYCE 的 32112），src/dst 都是本地已绑定的 exact virtual
identity。不是 public target，也不注册第二个 probeio target。

| UDP payload offset | 长度 | 含义 |
| --- | ---: | --- |
| 0..3 | 4 | ASCII `WYCL` |
| 4 | 1 | version=1 |
| 5 | 1 | kind：PING=1 / PONG=2 |
| 6 | 1 | sender：initiator=1 / responder=2 |
| 7 | 1 | reserved=0 |
| 8..23 | 16 | SHA-256(concat(UTF8(`winkyou-gate-c-liveness-attempt/1`), 0x00, UTF8(attempt ID))) 的前 16 bytes |
| 24..39 | 16 | 原 context digest 的前 16 bytes（generation=1 已绑定其中） |
| 40..47 | 8 | 非零 sequence，big-endian，每个 sender 从 1 单调递增 |
| 48..63 | 16 | 随机 challenge nonce；PONG 原样回显对应 PING 的 sequence/nonce |

上表串接符表示 byte concatenation。payload 恰好 64 bytes；IPv4 无 options 的 inner IP packet
为 20+8+64=92 bytes，UDP length=72。WireGuard 填充到 96 bytes，加 32 bytes transport
overhead 后为 128-byte UDP payload。现阶段只承接 C1b 的 IPv4 virtual identity；不能把
“64-byte payload”写成“64-byte完整包”，也不更改旧 WYCE parser。

IP/UDP 长度、checksum、无 fragment/options、virtual identity、magic/version/type/role/reserved、
digest 和 exact length 都严格校验。IPv4 UDP checksum 必须生成并验证；不接收零 checksum。
只有 PING 生成本端递增 sequence；PONG 回显对方 PING 的 sequence，不消耗或推进本端请求
sequence。PONG 的 role 是实际答复方，不复制 PING sender。128-bit nonce 不等于新密钥：加密仍完全由
现有 WireGuard 提供，不新增密码库、Noise 消息或加密算法。

- 对端 PING sequence 只保存最高已消费值；通过格式/绑定校验后先标记已消费，再进行答复
  admission。即使队列/额度不足而丢弃，也不因重放再次答复；允许因丢包跳号。只允许
  `1..Npeer_limit`，其中 `Npeer_limit` 使用本地冻结的 N+1，不采用对端自报寿命。
  sequence 溢出或 nonce 生成失败关闭 session，不重置计数。
- 无 pending 的 PONG、重复/超时 PONG 只丢弃并计数；新 PING/PONG 不复用 WYCE 的 nonce。
- 经过认证却属于本控制端口的错 binding/role/type/格式按稳定 protocol error 终局；普通业务
  流量不进入该 parser，不能因为“不像 WYCL”被吞掉。
- 旧 WYCE、WYCR、WYCF、WYHB 在此 parser 拒绝；旧 parser 不增加接受 WYCL 的分支。新 frame
  不进 SSH/OOB，不改变任何已冻结建立序列。既有 WYCE echo 不生成/校验 UDP checksum，保持原样
  不回溯修改；本节 checksum 要求只约束 WYCL。

## 7. 所有权、计费与停止发送的强制点

### 7.1 消费位置

orchestrator 拥有 liveness 状态与 policy；`pkg/tunnel` 仍不认识 solver、artifact、NAT 或重试。
使用 session-owned 的 inner 分流 adapter：只截获 exact virtual control tuple 的解密入站包，
普通包继续交给原 TUN/interface **恰好一次**。不能与应用竞争读取 `ReceivePacket`，不能把
业务包消费掉后只给计数。发出的控制包走现有 inner 注入与同一 lease-owned transport。

**接口冻结（2026-09-06）：** 实现该 adapter 需要 `pkg/tunnel` 提供一个通用的 inner-tap 接口，
位于 wireguard-go 解密/AllowedIPs 检查之后、TUN 写入之前；它只按调用方给定的 exact
`(src, dst, proto, sport, dport)` 匹配并把匹配包交给注册方、其余包原路交付恰好一次，不认识
solver、artifact、NAT、attempt 或 policy，不做重试、缓冲或再注入。该接口的存在、单注册方、
恰好一次与零认知不变量在此冻结；其命名与签名由实现 PR 固定并进入 architecture gate。

新增队列最多 2 个待出站、2 个入站控制包；每个 inner 包至多 92 bytes；满队列不派生 goroutine
或等待队列，只丢弃该控制事件并单列 witness。新增协议 worker 至多 2 个、显式 timer 至多
2 个、pending challenge=1、peer sequence high-water=1，均在 session close 时停止并 join。
原 WireGuard/transport 自带 worker/timer 不冒充新增计数为零，另以既有基线和总残留见证核对。

### 7.2 分开的账本

令 `T` 为原 trusted `session_ceiling`，`N=ceil(T/20s)`，以 duration 的整数单位作 checked
ceiling（不先向下截断成秒），在 **任何 SSH/socket 前**冻结本地上限，不接受远端数字：

| 维度 | 每端提议上限 / 计数位置 |
| --- | --- |
| 新 socket / target / five-tuple / child / OOB frame / attempt | 全部 0 |
| liveness PING | N 个，每 20s 槽最多一次；inner 注入前消费 |
| liveness PONG | N+1 个；每个新对端 PING 最多一个，+1 只覆盖边界偏移，不可换成 PING |
| liveness 合计 | 2N+1 个，任意 rolling 20s ≤4 个；无延后发送队列 |
| 单个 liveness 包 | inner 92 bytes；对应 WG UDP payload 128 bytes |
| WireGuard 自动控制 lane | type 1/2/3 与 type 4 的 32-byte empty keepalive；rolling 1s ≤4、session 总数 ≤4*ceil(T/1s) |
| 控制 lane 单包 | ≤148-byte UDP payload；先分类校验长度、再扣额度、再底层 I/O |
| 正常用户数据 | 不计入 probe 5/64/512 PPS 或 liveness 额度；所有写仍受同一 session 截止与唯一目标约束 |

例：T=600s 时 N=30，liveness 总上限 61；T=24h 时总上限 8641。正常稳定情况下每端每轮
一个 PING、一个 PONG，即约 0.1 packet/s 的 liveness 数据包；该值不包含 WG rekey/自动控制，
不能据此声称全部 OS 包数也是 0.1 PPS。实际 IP/UDP overhead 与 OS packet 数另做 witness。
额度计数记录已接纳的发射意图；接纳后排队过期、写失败或 WireGuard 丢弃均不退还。实际
发射另由 transport/OS 见证，不把 accepted 计数声称为成功发射数。

加密后不能凭包长把 liveness 与用户数据区分：liveness 额度在可信 inner 注入点执行；WG
自动控制 lane 在 `WireGuardSessionGate` 的出站点按公开 message type/严格长度执行。不能将
某个 128-byte 用户包冒充 liveness，也不能按应用消息数量推导 TCP/OS 包数。

未经认证/重放/过速的入站 PING 在答复 admission 前丢弃，不让对端直接触发本机持久 trip。
PING/PONG 达到合法 admission 上限时只拒绝该控制事件；PONG 总额度不足同样不答复，不能
借用 PING 额度。硬违规指已拒绝后仍尝试绕过 admission 发射，而不是把正常限流本身判成违规。
本地代码绕过 admission、突破已冻结上限或 writer/drain 硬违规，才按现有 governor 所有权路径
持久 trip。WG 自动控制额度耗尽必须在下一次 write 前关闭并持久 trip；不能清零后续发。
该控制 lane 是新上限提案，必须有真实 rekey/丢包测量证明未误伤正常路径，不能自行扩额。
WG 控制上限并不承诺抵抗合法 peer 主动诱发控制流量的拒绝服务；当前仍是同一操作者的
自有设备信任范围。两类计费政策不同，须在复审时明确接受，不能对外声称任意远端均无法 trip。

### 7.3 许可不是仅有一个 timer

续许可只由消费了当前 PONG 的本地 controller 持有；普通 packet consumer 不能提供时间值。
`WireGuardSessionGate` 对 **每个 active write**（含 WG timer 产生的包）检查该许可、原 absolute
deadline、关闭状态及绑定；timer/watchdog 同时主动取消与关闭 transport。两者缺一不可。

pending callback、调度暂停、`context.Background()`、晚到 PONG 不能越过写强制点。停止之后
不接受新 write；停止前已接纳的在途调用由原 2s drain 关闭/join，排水后 OS counter 不再变化。
不把“逻辑 revocation”当作已证明 OS 零残留，宿主不可调度的限制同 §5.1。

durable FINISH 仍只记录一次且先于 attempt release；post-FINISH liveness 超时不得改写 FINISH、
退款或新建 admission。session end 是本地脱敏结果，不把 journal 变成待执行任务。

post-FINISH 的持久 trip 必须由仍持机器锁的同一 orchestrator governor owner 落盘，沿用
`sessionDrainFailure` 的 owner 路径；**不能调用已释放 AttemptLease 的 Trip**，也不创建第二
governor。只给 session 写强制点一个绑定不可变 session 身份、不可自选原因/目标的窄违规回报
能力；session 关闭后该回报能力失效。owner 不可用则拒绝继续发送并报告不可确认状态，不能
伪报持久化成功。cap、取消和 owner 失效均需证明 session 自身被关闭，而不只排空旧 attempt。

## 8. 结果、取消与兼容

- 原 authenticated CLOSE 与 absolute ceiling 保留；本地 Ctrl-C 按原路径至多尝试一次
  best-effort CLOSE，但仅在 session 许可尚有效且撤销前。它属于原 teardown 账，不加 ACK/
  重传，不保证一定送出；session 已撤销/过期后的 drain 不具有补发 CLOSE 的权限。
- 失联为 `session_liveness_timeout`；认证控制格式错误为 `session_liveness_protocol_invalid`；
  本地时钟契约失败为 `session_liveness_clock_invalid`；local cap 违规为
  `session_liveness_budget_exceeded`；缺失分流/许可能力为 `session_liveness_unavailable`。
- 新能力缺失应在 preflight 零 I/O 拒绝；运行中失去能力则立即关 session。普通失联、peer
  protocol error、clock failure 干净排水不 trip；local cap/无法排水沿用持久 trip 规则。
- 运行期错误固定 `retryable=false`、`credential_burned=true`、`finish_recorded=true`，stage
  为已有 terminal；preflight 则 burn/finish=false。曾经 `data_plane_ready` 不等于 session
  现在健康，不能把 loss 记为“整个窗口成功”。drain 失败以现有 `session_drain_failed` 优先报告。
- progress 不新增周期通知，不重排旧序列。witness 只加 ping/pong/timeout/drop/control 计数、
  elapsed、绑定核验布尔值和 drained；nonce、sequence 原值、ID/digest、key、endpoint、路径、
  hostname/账号和底层错误都不公开。
- 首个 C1c 配对的两端 policy/exact build/参数须写入私有授权记录，由两人核对，不给旧 peer
  fallback。根权限风险接受与三项硬化登记、Windows real ssh.exe 未取证限制均原样保留。
  混用旧 peer 的负面测试只证明新版一端有界拒绝/结束，不推定旧实现获得了新失联规则；
  exact build 双端事前核对是窗口前置，不用旧 artifact 的通过伪称已经协商了新 policy。

## 9. 实现前冻结、实现后必过的验收矩阵

本表**全部待实现/待实测**；docs CI 全绿不能勾选它。

| 类别 | 必过用例与断言 |
| --- | --- |
| 计时纯函数 | M=2/3、K/R/L 算术、0/负值/溢出拒绝；相等边界拒绝；PONG 以请求发送时刻续许可；排队不提前算认证；missed slots 不补发；迟到事件不复活；多次短挂起累计不能延寿。 |
| 线格式 golden | 64-byte payload、92-byte inner、128-byte WG payload；双 role PING/PONG、字节序、digest/nonce/seq；IPv4/UDP checksum；旧/新 parser 互拒。 |
| 正常空闲 | 真 WireGuard 下无业务至少 180s，双侧 proof 持续且不会在 15s 退出；再验证超过一次 rekey 的长窗口与原 post-OOB echo。 |
| 单向业务与 keepalive | 任一方向持续业务、只有 empty keepalive、只有握手、垃圾 RX 均不能替代 matching PONG；加入 §2 persistent-timer 反例，不能把 raw stats 当作通过。 |
| 丢包与黑洞 | 默认 M=3 时连续两轮丢失后第三轮及时成功、三轮失效终局；双向/两种单向黑洞均从最后 proof-send 起 ≤65s 停新发、≤67s 排水；M=2 时一轮丢失容错、两轮终局，对应 45/47s。 |
| 负面认证矩阵 | nonce/role/attempt/context/虚拟地址错误、错版本、oversize、fragment、checksum、重复/乱序/迟到/跨 session 重放；无越界答复、无续许可。 |
| 分流与 backpressure | 业务双向完整交付、不被控制 reader 偷走；队列满有界丢弃；控制包不进入 OS listener；持续业务不饿死 close/watchdog。 |
| 强制点 mutation | 伪造 raw RX 续租、Tx 续租、receiver 自报 deadline、忽略 liveness 的 WG timer write、第二 socket/target、提前启用、绕过 inner/自动控制计费均失败；owner 的持久 trip 可重开核验，过期 attempt/session 回报能力无效。 |
| FINISH/权限回归 | 3/3、R1、8 帧、原 plan/cost/golden 不变；FINISH 前 liveness=0；不复活 OOB/旧 probe handle；相同 artifact 重启零 emission。 |
| 故障/排水 | peer/process/consumer kill、controller 卡住、写错误、late PONG 与 cancel 竞争、suspend/resume/时间跳变；owned socket/process/timer/worker/lock/接口路由残留为零。 |
| 重复与平台 | fake clock 状态矩阵 race×20；三 planner profile 真 WG memory/loopback 回归；100 fresh 生命周期；required Linux netns 与之后另行授权的 disposable router 进程外见证。 |

长窗口的计数必须拆成 establishment、R1、post-OOB echo、liveness、WG 自动控制、用户数据和
teardown；同一 OS datagram 不重复计费。Windows 的 expected `Killed=true` 不是失败判据，
也不是其新 liveness/Wintun 已经通过的证据。首次实测若超出提案上限，停下复审，不改断言求绿。

## 10. 交付分层与不授权清单

1. 本 PR：只有文档与源码/官方资料核对，维护 Draft；不会产生新网络能力。
2. 维护者与独立专家裁决 §11，接受并合入文本后，才能另行授权实现；建议先闭合 memory/
   loopback/required netns 的 liveness 证明，再进入 C1c field capability 的 exact build 评审。
3. C1c disposable-router 的构建、环境、权限和运行仍逐项另行签发；通过以后才能签发 C2。

不增加 SSH child、OOB frame、listener、socket、target、governor authority、retry/fallback、
daemon、scheduler、自动恢复、默认 `wink up` 或 stdio v1/v2 接线。不改 root 裁决、不签名任何
现场实例、不配置宿主网络。接入实现若需要额外权限或不能满足上述资源/时钟/分流契约，必须
回到 ADR，不把本提案当作“为实现方便可以变通”。

## 11. 裁决栏（2026-09-06 填写）

维护者（houyuwushang）委托独立复审人按其复审推荐代填以下裁决；复审记录为
[PR #105 评论](https://github.com/houyuwushang/winkyou/pull/105#issuecomment-5554766996)。
代填不改变角色边界：实现授权与 C1c 开工仍须维护者另行下达。

| 决策 | 维护者选择 / 独立复审记录 |
| --- | --- |
| 是否接受 C 的双端随机挑战，而不是 outer-only 续租 | **接受。** A 把业务空闲当失联且两端不对称；B 受 WireGuard persistent timer 收发互重置反例约束、raw 统计非双向证明。C 失败后不得回退 A/B。 |
| 是否接受 K=20s、R=5s、M=2/3、L=45/65s，保留原 absolute ceiling | **接受为待验证工程值。** §9 "真 WireGuard 下无业务 ≥180s 双侧 proof 持续"与黑洞 ≤65s/≤67s 见证为必过；实测超界则回到本 ADR 修订，不在实现中调参求绿。 |
| 是否接受 WYCL 定长格式、虚拟端口与单次 nonce/sequence 规则 | **接受。** 64-byte payload / 92-byte inner / 128-byte WG payload 核算无误；端口 32113 与 WYCE 32112 分离；旧 parser 不增加分支。 |
| 是否接受新增 post-FINISH 两类控制账与写强制点；WG 控制 lane 上限是否足够 | **接受两类控制账与写强制点。** WG 控制 lane 的 rolling 1s ≤4 / 单包 ≤148 bytes 作为**提案上限**接受，须以真实 rekey 与丢包实测证明不误伤正常路径后才算冻结；实测不足即回 ADR，不得自行扩额。 |
| 是否接受时钟/挂起 fail-closed、双侧失联终局与新的稳定错误 | **接受**,并按 §5.1 裁决修正一处：单调时钟倒退、任一溢出、固定起点 elapsed 发散 >2s 终局;UTC 相对上次读数倒退本身只记 witness 不终局。五个新稳定错误类接受。 |
| 是否接受不改旧默认/无协商，以及先隔离证明再授权 C1c 的执行顺序 | **接受。** policy 缺失的 C1b 路径原样;policy 生效时整体替换 §16.8 inner-inactivity 规则（§4.1 必补项）;先 memory/loopback/required netns 证明，再 C1c exact build 评审。 |

表格已闭合、Status 为 Accepted，因此 Gate C1 §16.8 的"C1c 前 inactivity 重裁决"前置门**在文本层面关闭**；
但 §9 验收矛阵全部待实现/待实测，liveness 实现、C1c 与任何现场窗口仍各需维护者另行授权与独立复审。
