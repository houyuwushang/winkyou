# WinkYou v2：直连优先的产品与架构重启计划

- 状态：**Accepted**（2026-08-13,见 [`../PHASE0-EXIT-RECORD.md`](../PHASE0-EXIT-RECORD.md)）
- 日期：2026-08-11
- 目标读者：维护者、早期测试者、未来的本地 API 集成者
- 修订状态：第三轮架构复审意见已纳入正文
- 决策状态：PR #11 已合入、Issue #12 已修复,Phase 0 出口门槛全部满足,本文自 Phase 0 出口记录合入起为 Accepted。接受范围与不授权事项见 §20 与出口记录 §4

审查记录：

- [`WINKYOU-V2-PLAN-REVIEW-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-2026-08-11.md)
- [`WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md)
- [`WINKYOU-V2-PLAN-REVIEW-FOLLOWUP-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-FOLLOWUP-2026-08-11.md)
- [`WINKYOU-V2-PLAN-REVIEW-ROUND3-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-ROUND3-2026-08-11.md)

> 本文是已接受的产品与技术计划，但不是现场测试授权。
> 在新的正式 ADR 接管之前，
> [`CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) 仍是当前实现的权威基线。
> 本文不会解除
> [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](../INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)
> 之后对自动生日打洞、自举恢复和真实网络试验的暂停。

## 1. 执行摘要

WinkYou 不应把自己重新做成另一个 frp，也不应一开始就试图交付一个功能齐全的中心化 VPN 平台。它更有机会形成差异化的位置是：

> **一个可解释、可通过版本化本地 API 复用、资源有机器级硬上限的 P2P 连接求解器，以及建立在它之上的直连优先个人网络。**

本计划建议：

1. 保留现有求解抽象、路径评分、有效策略算法、`transport.PacketTransport`、WireGuard 数据面及行为测试；渐进替换与 rendezvous 深度耦合的 session 编排和分裂运行时。
2. 先按参考 10–12 周完成 Phase 1a 工程构建，再进入至少 4 周 Phase 1b 外部证据期；内部顺序是 governor/probeio、`wink diagnose`、NAT 验证矩阵，最后才稳定版本化进程外 API，不立即全面重写 v2。
3. 默认 `direct: required`、`relay: disabled`。Relay 只作为用户明确选择的控制通道或降级数据路径，绝不伪装成直连。
4. 将“无 coordinator”定义为“没有必须依赖的项目中心服务和单点故障”，而不是违反网络事实地承诺“零基础设施冷启动”。
5. 保留生日悖论求解能力，但 v2 alpha 只能人工启用、只允许隔离环境、受机器级统一资源预算和持久化熔断器约束；自动恢复继续保持 NO-GO。
6. 用外部使用证据决定是否继续完整 v2：真实留存、跨网络直连结果和首个外部 API 集成，比 Star 数更早、更可信。
7. 所有生产节点和高风险主动探索共享一个 OS 级 canonical machine-safety namespace 和预算权威；唯一例外是用户逐次显式确认、能力被编译期 allowlist 限死的 standalone 诊断/单次测试，它必须显示为 `user_acknowledged`。v2 alpha 不迁移会在 governor 之外自行创建探测 socket 的 Pion ICE、quic-go 等第三方路径。

## 2. 为什么需要重启，而不是继续叠加功能

WinkYou 最初解决的是一个非常真实的个人问题：让自己的设备在任何网络下仍有机会互联，同时兼顾虚拟局域网和内网服务访问。生日悖论式打洞证明了项目拥有一项有辨识度的能力——在普通方法失败时，它仍可能快速找到可用的 UDP 五元组。

但此前的事故也证明，单次连接成功不等于可长期运行的系统。当前风险不是求解算法本身“太强”，而是以下职责缺少统一边界：

- 链路健康检测可以触发新的恢复动作，但没有机器级 single-flight、全局预算和独立停止开关；
- 节点宕机后，多个恢复循环可能把同一个故障放大成持续发包；
- 当前存在 coordinator/WireGuard 与 autonomous userspace 两个顶层生命周期家族，其内部又至少有 session strategy、mesh shortcut、cached self-bootstrap/puncher 三条主动探测触发/执行路径；
- 身份、成员资格、发现、信令、路径选择和数据面之间的信任关系还不够明确；
- “能够打通”尚未变成“能解释、能限制、能安全失败、能让别人采用”的产品。

因此 v2 的目的不是抛弃有效的求解思想，也不是把现有编排原样搬家，而是保留可证明的抽象、算法和测试，把它们放进一个无法绕过资源边界、可以渐进替换的系统中。

## 3. 产品定义

### 3.1 第一目标用户

v2 alpha 优先服务：

- 个人、开发者和 homelab 用户；
- 2–20 台相互信任、但可能分散在不同网络中的设备；
- Windows 和 Linux 用户；
- 希望优先直连，并愿意理解网络限制和失败原因的人。

首个发布级支持矩阵：

| 维度 | v2 alpha 范围 |
| --- | --- |
| 操作系统 | Windows、Linux 发布级；macOS 仅保证可编译 |
| 网络模型 | 路由式 L3 overlay，不模拟二层以太网 |
| 使用方式 | 首个 alpha 先交付 L3 互联；具名 TCP/UDP 服务进入独立 Phase 3b |
| 地址 | 确定性 IPv6 ULA 优先，兼容 IPv4，并检测本地路由冲突 |
| 操作入口 | CLI + 声明式配置；暂不建设 GUI |
| 规模 | 2–20 个可信设备；不承诺企业级大规模控制面 |

### 3.2 产品承诺

WinkYou 应能清楚回答三个问题：

1. **能不能直连？**——给出观测证据、尝试过的策略和准确的停止原因。
2. **用了多少代价？**——展示套接字、包、五元组、时间和外部依赖。
3. **失败后会不会失控？**——所有主动探测都受硬预算、退避、single-flight、熔断和持久化停止状态保护。

### 3.3 明确不做什么

v2 alpha 不追求：

- frp 的通用反向代理功能对等；
- Tailscale/ZeroTier 类完整 SaaS 控制台；
- “任何 NAT 都保证直连”的不真实承诺；
- 默认使用 WinkYou 自有公共 coordinator、目录或 Relay；
- 自动把机器上的所有虚拟网卡、端口或第三方网络公布给其他节点；
- 未经授权的真实家庭、办公或公网生日打洞测试；
- 为了 Star 数堆叠大量尚未验证的功能。

## 4. 不可回避的网络事实

“无中心协调”可以做到，“完全无已知信息的冷启动”做不到。

若两个节点同时满足以下条件：

- 不在同一局域网；
- 没有可直接到达的 IPv6；
- 彼此不知道任何当前地址；
- 没有预共享的离线邀请信息；
- 不使用目录、DHT、已有网络路径或第三方信令；

那么它们没有渠道交换打洞所需的候选地址和同步信息。任何声称在这些条件下仍能发现彼此的方案，实际上都隐藏了某种公共服务、广播域或先验地址。

因此 WinkYou 的目标应是：

> **不依赖某一个强制中心服务；允许用户组合多种可替换的发现和信令来源，并在形成原生直连后退出外部依赖。**

同样，若双方都是端口分配近似随机的 endpoint-dependent NAT，或者任一网络彻底阻断 UDP，算法不能保证建立 UDP 直连。正确行为是有界尝试后停止并解释，而不是无限增加探测量。

## 5. 总体架构

```text
                           +----------------------+
                           | CLI / config / status|
                           +----------+-----------+
                                      |
 +----------------+        +----------v-----------+       +------------------+
 | Node identity  +--------> Unified Node Runtime <-------+ Membership / ACL |
 | WG key binding |        +----+------------+----+       | revoke / invites |
 +----------------+             |            |            +------------------+
                                |            |
                   +------------v--+      +--v----------------+
                   | Discovery and |      | Recovery controller|
                   | signaling     |      | single-flight      |
                   +-------+-------+      | backoff / breaker  |
                           |              +----------+----------+
                           v                         |
                   +-------+-------------------------v--+
                   | Connectivity Solver               |
                   | observations -> plans -> results  |
                   +----------------+------------------+
                                    |
                    every active exploration obtains
                   a lease from one machine authority
                                    |
                   +----------------v------------------+
                   | transport.PacketTransport         |
                   | selected direct or explicit relay |
                   +----------------+------------------+
                                    |
                   +----------------v------------------+
                   | WireGuard packet data plane       |
                   +-----------------------------------+
```

核心约束：

- v2 只有一个 `Node Runtime` 管理节点、对等端、恢复代次和停止状态；迁移计划明确处理当前两个顶层生命周期家族和三条主动探测入口。
- 求解器只负责把观测转换为有成本声明的计划和结果，不拥有无限重试权。
- 所有生产节点和高风险主动探索的 socket、目标登记、发送和回复都必须经过 OS 级 canonical machine-safety namespace 中的唯一 `ResourceGovernor`；多进程、多个 Mesh 或多个可配置数据目录不能各自拥有一份“节点级”预算。第 8.6 节的显式 `user_acknowledged` 只是一条隔离、低风险、不可升级的 standalone 入口，不是 Node Runtime 的第二种 governor。
- v2 alpha 不启用无法接入该强制点的第三方主动探测库；未来任何自行创建 socket 的传递依赖都必须有显式治理声明和 CI 依赖闭包检查。
- WireGuard 继续保护用户数据；发现通道或 Relay 不因能传递消息而获得成员权限。
- 控制图保持稀疏，数据直连按需建立；节点增加不应导致 N² 级重型恢复任务常驻。

## 6. 身份、成员关系与信任

### 6.1 节点身份与 WireGuard 绑定

- 每个节点生成稳定的 Ed25519 身份密钥；`NodeID` 从公钥确定性派生。
- WireGuard 密钥是独立、可轮换的数据面密钥。
- 节点身份为当前 WireGuard 公钥签署有期限的绑定记录；WG binding 作为独立控制记录传播，不写进 root roster，避免每次 WG 轮换都要求离线 root 重签。
- Mesh 创建时生成离线 root key。root key 默认不驻留在长期在线进程中，也不充当普通节点身份。

### 6.2 Alpha 单写者签名名册

v2 alpha 不实现委托邀请链、下放 revoke 权或多写者分区合并。成员不共享全局 mesh secret，成员资格由唯一 root 签署的完整 roster 决定。

roster 至少包含：

- `mesh_id`、root key ID、单调 `version` 和 `issued_at`；
- 成员 NodeID 与身份公钥；
- `control_transit`、`data_transit` 等独立能力位；
- roster 内容摘要和 root 签名。

只有离线 root 管理工具可以生成更高版本。alpha 不授予成员 `invite` 或 `revoke` 写权限。能力分离仍然成立，但授予动作收敛到一个 writer。

### 6.3 加入与信任锚交付

加入流程必须先有目标身份，不能使用“谁持有谁能加入”的通用 bearer invitation：

1. 操作员从现有 root 管理工具读取 MeshID，通过本地输入、文件或扫码交给新设备；MeshID 只是加入目标选择器，不是信任锚；
2. 新设备本地生成身份密钥，导出包含 MeshID、NodeID、公钥、nonce 和能力请求的 join request；
3. 操作员通过受控带外通道把 join request 交给 root 管理工具；
4. root 工具显示 MeshID、目标指纹和权限变化，操作员确认后签发 roster `N+1`；
5. 返回 bundle 包含 root 公钥、完整签名 roster、目标身份和必要 bootstrap anchors；
6. 新设备导入 bundle 前必须建立 root 信任锚：要么使用操作员控制的 U 盘、二维码或局域网直传，要么在任意传输后由两端人工比对 root key 指纹；
7. 新旧节点随后通过已认证连接传播同一份 roster。

对 2–20 台自有设备，每次加入需要一次 root 管理动作和首次指纹确认，是 alpha 有意接受的安全/复杂度交换。

Phase 2 的加入流程 mini-ADR 必须固定 MeshID 的手工输入、文件和二维码 UX，明确展示 MeshID 与 root key 指纹的不同安全含义，不能让“扫到了某个 MeshID”被误解为已经验证 root 身份。

### 6.4 Freshness、撤销与反回滚

- root 管理工具是唯一 writer；它为新设备签发时使用的 roster 就是签发时刻的最新版。
- 节点持久化已接受的最高 `(version, digest)`，拒绝更低版本。
- 收到两个 root 签名均有效、版本相同但内容不同的 roster 时必须拒绝并产生最高级别告警；这意味着 root 泄露或签发工具故障。
- 每条已认证 peer 连接建立时交换 `(version, digest)`，低版本节点向高版本节点拉取并验证完整 roster。
- `wink status` 展示 roster 年龄；超过可配置阈值只告警、不硬过期，避免离线 root 造成全网同时失效。
- 撤销由 root 签发删除目标身份的 roster `N+1`；撤销传播窗口等于其他节点再次连通并完成反熵的时间，alpha 文档必须明确披露。
- 被撤销节点不能用旧 roster、旧路径缓存或旧 WG binding 降级已经见过新版本的节点。

root 丢失、备份和轮换必须在 Phase 2 mini-ADR 中闭合；不得为了简化轮换而把 delegated PKI 偷渡回 alpha。

### 6.5 能力分离

成员资格不自动授予中转权限。`control_transit` 与 `data_transit` 分别由 roster 能力位控制。具名服务在 Phase 3b 使用独立服务 ACL，默认拒绝；发现服务不等于获得访问权。

## 7. 可插拔发现与信令

发现负责“在哪里可能找到对方”，信令负责“交换经过认证的求解消息”。二者都通过接口接入，不能硬编码到某个 coordinator。

建议按以下来源组合：

| 来源 | 适用场景 | 默认策略 |
| --- | --- | --- |
| 手工/静态地址 | 固定服务器、调试、最小自托管 | 支持 |
| 加入 bundle 或二维码中的 anchor | 首次加入、家庭成员交接 | 支持 |
| LAN discovery | 同一广播域中的首次配对 | 支持，可关闭 |
| 全局 IPv6 候选 | 双方具有可达 IPv6 | 支持 |
| 已有路径适配器 | Tailscale、frp、皎月连、其他 VPN/P2P/端口映射 | 显式配置 |
| 用户自有公共节点 | 自托管 anchor/信令 | 支持 |
| 公共 DHT | 更宽松的去中心发现 | 仅保留接口，alpha 不启用 |

已有路径适配器采用通用模型，而不是绑定供应商 API：

- 用户明确指定本地接口、对端地址或命令提供的 endpoint；
- 默认只携带经过签名的发现/信令流量；
- 不自动枚举并发布所有虚拟接口；
- 当原生直连验证通过后，控制器可退出该外部路径；
- 路径评分明确记录第三方依赖，并降低其优先级。

公共 STUN 可默认启用，因为它只提供地址观测而不承担成员授权，但必须：

- 首次配置和文档中明确披露会向所选 STUN 服务暴露源 IP 和时间信息；
- 允许完全关闭或替换为用户自托管 STUN；
- 使用多个观测源时保留原始样本，不把一次结果永久标记为 NAT 类型。

公共 DHT 在 alpha 中不启用，因为它引入可枚举性、元数据泄露、投毒、Sybil 和滥用响应等额外问题。接口可以先稳定，公开实现必须单独 ADR 和威胁模型。

## 8. 连接求解器

### 8.1 独立交付边界

连接求解器应能脱离完整虚拟网络使用：

- `wink solver serve --stdio`：提供版本化、跨语言、进程外的本地求解 API；
- `wink diagnose`：只观测 NAT/端口行为并生成可脱敏报告；
- `wink connect-test`：两节点执行一次受限的直连验证；
- WinkYou Node Runtime：把求解结果绑定为 WireGuard 数据路径。

Go 包边界仍用于内部解耦，但 v2 alpha 不承诺稳定的外部 import API。这样即使尚未完成整套 overlay，用户和 Python/Node/Rust 等集成方也能获得即时价值。

### 8.2 策略顺序

默认从低风险、低成本、高确定性的候选开始：

1. 同局域网候选；
2. 可验证的全局 IPv6；
3. 手工/静态 endpoint；
4. PCP、NAT-PMP、UPnP 显式端口映射；
5. 多 STUN 观测与基于 governor-owned socket 的有界连通性检查；
6. 可预测端口分配的有界求解；
7. 人工触发、受硬预算限制的生日悖论求解。

Relay 不属于“直连策略排序”的最后一项。它是单独的用户策略，必须显式选择。

### 8.3 NAT 观测不是永久标签

`wink diagnose` 应记录：

- 观测时间窗口和网络接口；
- 每个 STUN 目标得到的映射；
- endpoint-independent / endpoint-dependent 行为证据；
- 端口增量、抖动和样本置信度；
- 公网 IP、网关或接口变化；
- UDP 被阻断、响应不一致或样本不足。

报告只能陈述“在该时间窗口观察到的行为”，不能把 NAT 类型永久写入节点身份。

### 8.4 协调尝试协议

需要双方同步的策略使用经过认证的 attempt epoch，并为每个参与者对选出唯一 owner：

```text
DISCOVER -> PLAN -> PREPARE -> READY -> FIRE -> VERIFY -> COMMIT
                                     \-> FAIL -> COOLDOWN
```

- `attempt_id`、双方参与者标识、角色、网络观测代次和过期时间都进入认证上下文；Phase 2 正式成员使用稳定 NodeID，Phase 1a 测试使用只在本次测试有效的临时标识；
- owner 才能启动该节点对的重型求解；
- 旧 epoch 的消息、延迟包和重复 READY 不得创建新发送器；
- 只有经过双向验证的路径才能 COMMIT；
- 新路径提交前保留仍健康的旧路径，不因一次瞬时本地错误拆除健康链路。

#### Phase 1a 测试专用认证上下文

Phase 1a 的 `wink connect-test` 不等待 Phase 2 的 Ed25519 身份、roster 和通用 `SignalingChannel`，但也不允许明文或匿名协调。它使用独立的 `TestPairingChannel`，只证明双方持有本次测试的一次性凭据，不声称证明 Mesh 成员身份：

- 双方为每次测试各自生成一次性临时密钥对和临时参与者标识；发起方生成至少 128 bit 随机、短期有效、单次使用的 pairing token，并由操作员通过二维码、文件或其他受控带外通道交给另一端；
- 会话密钥必须由经过审查的 PSK 认证密钥交换导出，并绑定协议版本、双方临时公钥、角色、`attempt_id`、网络观测代次、过期时间和完整 transcript；禁止自行拼接 hash/MAC 发明握手协议；
- 如果未来提供短位数手工输入码，必须采用经过审查的 PAKE、尝试限速和锁定策略，不能把低熵短码直接当作 PSK；
- `TestPairingChannel` 只承载有大小、消息种类、速率和期限上限的 PREPARE/READY/FIRE/VERIFY 控制消息；其承载只能是操作员明确提供的静态信令端点、已有 control underlay，或实现 mini-spec 明确允许的有界带外交换，不默认依赖 WinkYou 公共 coordinator；
- pairing token 在一次 attempt 或最多 10 分钟后失效，成功、失败和取消都必须销毁会话材料；重放、错 token、跨会话消息、角色反射和过期消息必须 fail-closed；
- API、状态和报告统一标记 `auth_scope: test_only`。该上下文不能签发 roster、创建稳定 NodeID、绑定长期 WireGuard key、加入 Mesh、授权 transit/service、触发恢复控制器或升级为生产会话；
- Phase 2 的正式成员路径必须改用 roster 身份和通用 `SignalingChannel`。生产 Node Runtime 永久拒绝 `test_only`；测试适配器不得被扩展成第二套成员身份。Phase 2 后是否保留纯独立诊断入口，由外部证据和单独决议决定。

Phase 1a 开工时先形成这一握手和 `TestPairingChannel` 的小型协议说明；在该说明通过安全审查前，`connect-test` 只能使用模拟传输。

### 8.5 角色化生日求解

生日悖论策略不应实现为“每个 socket × 每轮新目标”的无限笛卡尔积。

对于“一侧较难、一侧较易”的场景：

- hard side 在一个 attempt 内打开有限数量的映射 socket；
- easier side 只对事先生成并冻结的有限目标集合探测；
- 两侧通过 PREPARE/READY/FIRE 对齐短时间窗口；
- 某个 socket 命中后，只提升该 socket 对应路径，不复制整个发送集合。

对于双方端口分配可预测的 endpoint-dependent NAT，只允许有界的同步预测。若双方分配近似随机，或 UDP 被阻断，策略必须停止并报告 `unsupported_random_double_hard_nat` 或 `udp_blocked`，不能自动升级暴力规模。

### 8.6 资源契约

每个 `Strategy` 的计划必须在执行前声明最坏成本：

- socket 数；
- 目标 endpoint 数；
- 每秒包数和总包数；
- 新五元组数；
- 最大持续时间；
- 是否属于 heavyweight attempt。

配置可以降低预算，不能突破当前发布版本在代码中规定的硬上限。仅在策略接口上传入一个 `AttemptLease` 不足以形成强制边界，v2 还必须满足以下约束。

#### 机器级唯一预算权威

“节点级预算”在安全上是官方 WinkYou 安装实例的机器级语义，不是单进程变量：

- 安装程序/运行时按操作系统规则确定一个 canonical machine-safety namespace；它独立于用户可配置的 Mesh/data state directory，stdio/API 请求不能改写；
- governor 在该 namespace 取得 OS 级全局互斥量或独占 `governor.lock`；同一机器上的多个官方 WinkYou 数据目录仍竞争同一把锁；
- 持锁进程是该机器唯一可以创建 `AttemptLease` 的官方 WinkYou 预算权威；
- Phase 1a 的最小实现不包含进程间代理：后续 `wink solver serve --stdio`、`wink diagnose`、Node Runtime 或其他主动命令若发现已有 owner，必须在主动联网前失败，显示 owner PID、进程启动标识和构建版本，并给出复用/关闭现有进程的建议；不能静默创建第二个 governor；
- 锁元数据记录 owner PID、进程启动标识和构建版本用于诊断，但是否持锁以 OS lock 为准，不能仅信任 PID 文件；
- safety trip 与硬预算诊断状态使用同一 canonical safety namespace，进程重启、换 CLI 入口或换 Mesh 数据目录不能绕过；
- 多进程压力测试必须证明启动 N 个 stdio/diagnose 进程不会把预算放大为 N 倍。

进程间代理是未来共享 daemon 的可选增强，必须与 Windows Named Pipe/Unix domain socket 的 ACL、peer credential、协议版本和本地拒绝服务威胁一起评估，不属于 Phase 1a 退出门槛。

该锁防止官方 WinkYou 二进制因误配置或多进程集成而放大资源，不声称阻止一个已经能运行任意网络程序的恶意本地用户；对该威胁需要 OS 防火墙、账户隔离或 egress policy。

#### 非特权安装与显式知情降级

官方发布必须同时给出可工作的安装路径和可解释的免安装路径：

- 官方安装包负责按 OS 规则预建 canonical machine-safety namespace、最小权限 ACL 和卸载策略；tarball/portable 用户可先运行 `wink setup-machine-scope`，该命令只创建并验证安全 namespace，清楚说明是否需要一次提权，不启动节点或发包；
- 默认 `governor_scope=machine`。若 machine scope 不存在、ACL 不可信、容器边界不能代表宿主机，或当前用户无权打开它，命令不得静默创建每用户/每目录 governor；
- 未明确降级时，`wink diagnose` 仍可完成接口、路由、配置和锁状态等纯被动检查，但必须把 STUN 与其他主动步骤标记为 `active_probe_blocked`，输出一条可复制的 `setup-machine-scope` 修复指令；其他主动命令在发包前 fail-closed；
- 对非特权 portable/受限企业测试者，只有本地进程启动参数 `--governor-scope=user-acknowledged` 可以显式开启降级；不得由导入配置、环境变量、JSON-RPC 请求或远端消息替用户确认，也不得把选择静默持久化为后续默认值；
- `user_acknowledged` 仍须取得 canonical per-user lock，并使用一套独立、只能更低的编译期硬上限；它只允许 same-socket STUN `diagnose` 和一次性配对的单个 `connect-test`，禁止 Node Runtime、自动恢复、端口映射、预测策略、birthday、后台常驻和并行 heavyweight attempt；
- CLI 启动时打印醒目警告；`handshake`、`status`、本地日志、脱敏报告和双方 `connect-test` transcript 都必须标记 `governor_scope: user_acknowledged` 及实际边界。任一端降级时，报告不得宣称已验证机器级安全；
- 容器内 scope 必须标记为 `container` 或 `user_acknowledged`，不能把单容器互斥描述成宿主机全局互斥；多容器支持需要共享可信 namespace 或独立的宿主 egress 约束。

这条降级只解决第一次诊断和单次连接实验的可用性，不降低完整 WinkYou 节点的安全基线。Phase 3a Node Runtime 及 Phase 5 生日实验始终要求 `governor_scope=machine`。Phase 1a 的实现 mini-ADR 必须在任何主动降级模式发布前固定其较低数值上限、OS ACL、符号链接/抢占防护和卸载行为。

预算按层级租用：

```text
MachineGovernor -> PeerLease -> AttemptLease -> ProbeSocket
RestrictedUserGovernor -> PeerLease -> AttemptLease -> ProbeSocket
```

任一层额度不足都会拒绝更深层租约。配置只能降低当前 scope 的发布硬上限。`RestrictedUserGovernor` 是不同的能力类型，只能签发 `diagnose`/单次 `connect-test` allowlist 内的租约，不能被当作 `MachineGovernor` 传给 Node Runtime、恢复控制器或 heavyweight 策略。

#### 探测 I/O 强制点

v2 将暂定名为 `internal/probeio` 的能力边界作为主动 UDP 探索的唯一生产入口：

- `AttemptLease.OpenProbeSocket` 创建 socket 并扣减 socket 额度；
- `RegisterTarget` 登记 endpoint，在此扣减 target/新五元组额度；
- `SendProbe` 必须拒绝未登记 endpoint，并在每次发送时扣减 PPS 与总包额度；
- 入站 HELLO/ACK 的读取可以通过受控 `ProbeSocket` 完成，但任何回复仍须走 lease 发送路径并计入 PPS/总包额度；回复到已登记五元组不重复扣 target 额度；
- `Promote` 原子验证 attempt epoch、peer 和远端地址，取消兄弟 worker、关闭其他 probe socket、清除遗留 deadline，并把唯一成功 socket 移交为 `PacketTransport`；
- `Promote` 或 `Close` 后旧句柄立即毒化，读取、回复和发送都返回 `ErrLeaseClosed` 类错误；
- 策略、恢复控制器、诊断命令和本地 API 都不得获得用于主动探索的原始 `*net.UDPConn`。

已提交 `PacketTransport` 的正常 WireGuard 数据包不消耗探测 PPS/target 预算，但仍受路径数、生命周期和恢复策略约束。

#### 第三方 socket 库治理

静态检查直接调用 `net.ListenUDP` 仍抓不到在依赖内部自行开 socket 的库。当前 v1 的 `legacyice -> pkg/nat -> pion/ice` 就是已知实例，quic-go 也自行管理 UDP socket。

因此 v2 alpha 明确选择：

- 不把 Pion ICE、quic-go 或其他无法接入 `probeio` 的主动探测路径迁入 v2 alpha；
- `legacyice` 作为 v1 compatibility/legacy 行为保留，不成为 v2 探测实现；
- v2 的 STUN 观测和初始有界检查使用 governor-owned socket；
- 未来若要重新使用第三方网络库，必须先提交独立治理声明，说明它是接收 governor-owned `PacketConn`、使用可验证的粗粒度最坏成本租约，还是仅用于已提交数据路径；
- 若采用粗粒度租约，必须预扣最坏 socket、并发检查、STUN 目标、packet 和持续时间，并用进程内计数及进程外 socket/conntrack 观测证明没有越界；无法证明则继续排除；
- CI 检查生产依赖的传递闭包；任何能够自行创建 UDP socket 的新增第三方库必须进入白名单，并记录 owner、用途、治理方式和验收测试。

Phase 1a 的依赖图必须证明：所有主动探测 socket 都由 `probeio` 所有，或者存在经过明确审查的第三方治理声明；不能出现“策略代码没直接调用 UDP，所以视为安全”的推论。

#### 非 UDP 主动网络行为

TCP dial 和 DNS discovery 不进入 `probeio`，但不能完全无预算：

- TCP 建连使用粗粒度 lease，限制并发、目标数、速率和超时；
- DNS 查询由 discovery provider 限制并发、QPS、缓存和重试；
- QUIC 建连在未来即使只承载数据，也必须先声明 socket/握手成本与治理方式；
- 这些边界和“不进入 probeio 的原因”写入接口文档与验证矩阵。

## 9. 生日策略的 alpha 安全边界

v2 alpha 中：

- 默认 `birthday: disabled`；
- 只接受 `disabled` 或 `manual`；
- `automatic` 配置直接校验失败；
- `manual` 仍只允许隔离实验网络，不授权家庭、办公或公网试验；
- cached self-bootstrap 和 autonomous birthday recovery 继续为 NO-GO。

第一版隔离实验硬上限：

| 资源 | 计量范围 | 上限 |
| --- | --- | ---: |
| 映射 sockets | attempt | 8 |
| 预生成目标 | attempt | 8 |
| round 时长 | attempt | 1 秒 |
| attempt 总时长 | attempt | 5 秒 |
| 单次 burst | endpoint/send | 1 包 |
| heavyweight 并发 | machine | 1 |
| 发送速率 | machine | 64 packets/s |
| 总发送包 | attempt | 512 |
| 新五元组 | attempt | 512 |
| 同一节点对冷却 | peer pair | 至少 5 分钟 |

以下任一事件必须原子停止本 attempt 的全部发送器，并触发机器级持久化 safety trip：

- Windows `WSAENOBUFS` 或等价资源耗尽；
- 连续写失败达到低阈值；
- 任一声明预算或硬上限被突破；
- worker 无法在取消期限内退出；
- 观测代次变化后旧发送器仍试图发送。

`wink safety trip` 必须写入独立于恢复状态机的持久化标记。进程重启不能自动清除；只能由操作员查看原因后执行显式 reset。任何策略、恢复循环或 peer 事件都不能绕过该标记。

未来若要讨论自动生日恢复，至少需要新的 ADR，并同时满足：

- 隔离网络；
- 硬资源上限；
- 退避与抖动；
- 节点对和机器级 single-flight；
- circuit breaker；
- 独立 kill switch；
- 故障注入；
- 24 小时持续测试；
- 进程外 conntrack/网络观测；
- 第二位审查者；
- 对一个明确命名环境的单独批准。

满足这些条件仍不等于获得公网发布许可。

## 10. 长期链路、故障与恢复控制器

此前的核心教训是：健康检测不能直接拥有“不断求解”的权力。统一恢复控制器按节点对维护状态：

```text
STABLE -> SUSPECT -> DEGRADED -> RECOVERY_PENDING -> RECOVERY_RUNNING
   ^          |          |                |                  |
   +----------+----------+----------------+---- COMMIT -------+
                                             \-> COOLDOWN
                                             \-> CIRCUIT_OPEN
```

规则：

- 单个 keepalive 丢失只进入 `SUSPECT`，经过抖动窗口和多信号确认后才能降级；
- 每个节点对同一时刻至多有一个恢复任务，节点全局至多有一个 heavyweight attempt；
- peer 宕机、路由变化、接口变化等事件只提交幂等意图，不直接创建 goroutine；
- 重复事件合并，恢复使用指数退避和随机抖动；
- 网络观测变化会推进 generation，并取消旧 generation 的全部任务；
- 健康的现有路径在新路径 VERIFY/COMMIT 前保持工作；
- 达到失败、时间或资源阈值后打开 circuit，等待冷却或人工动作；
- safety trip 的优先级高于任何恢复状态；
- 状态命令必须展示当前路径是 direct、external-control、relayed/degraded 还是 unavailable。

控制拓扑采用“稀疏控制图 + 按需数据直连”：节点只需通过少量可信邻居传播小型签名控制记录，实际通信的节点对才建立和维护数据路径。20 节点测试必须证明没有 N² 个重型恢复循环。

## 11. 直连与 Relay 策略

默认值：

```yaml
connectivity:
  direct: required
  relay: disabled
```

语义：

| 配置 | 行为 |
| --- | --- |
| `direct: required` | 只有验证过的端到端直连才可承载用户数据；失败时明确不可用 |
| `direct: preferred` | 优先并持续尝试直连，但允许用户选择临时降级路径 |
| `relay: disabled` | 不使用 WinkYou 数据 Relay；默认值 |
| `relay: control_only` | Relay/anchor 只能交换认证信令，不能承载用户包 |
| `relay: fallback` | 可立即建立标记为 relayed/degraded 的数据路径，同时后台以受限频率继续求解直连 |

配置约束：

- `relay: fallback` 只允许与 `direct: preferred` 组合；
- `direct: required` 与数据 Relay 组合时配置校验失败，避免 UI/状态语义含糊；
- 第三方已有路径可在 `relay: disabled` 时作为显式的 control/bootstrap provider，因为它不自动成为 WinkYou 用户数据路径；
- 任何 Relay 路径都必须显示 Relay 节点、信任边界和流量计数，不能以“connected”掩盖其降级性质；
- control transit 与 data transit 使用不同授权能力。

这既保留“直连是产品核心”的立场，也允许其他用户在明确知情的情况下选择可用性优先。`direct: required` / `relay: disabled` 是 v2 的待验证产品假设，不是代码事实；Phase 1b 必须记录因 direct-required 无法完成首次连接的比例及其对两周留存的影响。若证据反对当前默认值，必须通过显式产品决议重开。

## 12. L3 网络与具名服务

### 12.1 L3 overlay

- 每个 Mesh 获得确定性生成的 IPv6 ULA 前缀；节点地址从 MeshID/NodeID 派生并检测冲突；
- IPv4 地址段由配置或迁移工具生成，启动前检查宿主路由、VPN 和局域网重叠；
- 冲突默认阻止安装路由并给出修复建议，不静默覆盖系统路由；
- 不广播 ARP、DHCP 或任意二层帧。

### 12.2 具名 TCP/UDP 服务

具名服务属于 Phase 3b，不阻塞 Phase 3a 的首个 L3 alpha。Phase 3a 用户先通过虚拟 IP + 端口访问，并由文档明确宿主防火墙责任；是否把 Phase 3b 纳入同一 alpha，由 Phase 3a 的真实使用证据决定。

服务记录至少包含：

- 服务名、协议、端口/本地目标；
- 发布节点身份和签名；
- 允许访问的节点/角色；
- 有效期和版本；
- 是否只允许 direct path。

服务访问默认拒绝。控制面发现到服务不等于获得访问权，ACL 必须在发布端执行。

## 13. 内部模块与版本化本地 API

v2 alpha 采用 GitHub 发布二进制优先。Go 包边界首先是内部工程约束，不承诺外部稳定 import API，当前根模块名也不阻塞 Phase 1。

建议的内部 domain 边界：

```text
connectivity   canonical observations, plans, result, failure report
transport      PacketTransport
discovery      provider and signaling interfaces
probeio        governed active-network capability
```

具体 STUN、端口映射、预测和生日策略位于 `internal/`。`connectivity` domain 不能依赖 `rendezvous/proto`。版本化 wire DTO 与 domain model 可以不同，但只能通过显式 adapter 转换，并必须有 round-trip、未知字段、版本兼容和 golden tests；不得继续维护多份没有边界的准 domain model。

内部接口方向：

```go
type Strategy interface {
    Name() string
    Plan(Context, Observations) ([]Plan, error)
    Execute(Context, Plan, AttemptChannel, AttemptLease) (Result, error)
}

type AttemptChannel interface {
    Send(ctx context.Context, peer ParticipantID, msg AuthenticatedAttemptMessage) error
    Receive(ctx context.Context) (AuthenticatedAttemptMessage, error)
}
```

关键约束：

- `Strategy` 不直接依赖 coordinator 或 wire DTO；
- `AttemptChannel` 是最小 attempt 消息契约，不等同于成员身份系统；Phase 1a 的 `TestPairingChannel` 和 Phase 2 的正式 `SignalingChannel` adapter 分别实现它，策略不能据此授予成员或 transit 权限；
- `Plan` 在执行前声明最坏成本；
- 没有当前允许 scope 中唯一 governor 签发的 `AttemptLease` 就不能主动联网；生产节点、高风险策略和恢复控制器只接受 `MachineGovernor`，`RestrictedUserGovernor` 只接受第 8.6 节的低风险方法；
- 信令认证与承载通道分离；
- 求解结果通过 `PacketTransport` 交给数据面；
- 现有 `pkg/session` 在 contract tests 保护下渐进抽取/替换，不做大爆炸删除。

### 13.1 外部协议

Phase 1 使用 `wink solver serve --stdio` 提供 JSON-RPC 2.0。framing 在 v1 schema 中固定为 LSP 风格的 `Content-Length` 头，不使用动态 Go plugin，也不默认监听 localhost/LAN。

初始方法集：

```text
handshake
diagnose
connect_test
cancel
status
export_redacted_report
```

长操作通过绑定原请求 ID 的 server-to-client progress notification 报告阶段、剩余预算和可取消状态，不能等待未来版本再补通知语义。

`handshake` 至少返回：

- schema/framing 版本；
- WinkYou 构建版本；
- 当前硬上限表和可用剩余额度；
- governor owner、lock 状态、实际 `governor_scope` 与该 scope 的功能/预算限制；
- 可用的 `auth_scope`，并区分 `test_only` 与 Phase 2 正式成员身份；
- safety trip 状态；
- 支持的方法和 notification 能力。

协议固定负面清单：

- 不传递 raw socket、文件描述符或 `PacketConn`；
- 不提供任意 `open_socket`、`send_packet`、批量目标或端口扫描方法；
- 不提供提高发布硬上限的方法；
- `connect_test` 必须绑定有期限、经过认证的 peer/attempt 上下文；Phase 1a 只接受 `auth_scope=test_only`，Phase 2 正式成员路径只接受 roster 身份，二者不能互相升级；
- stdio 进程默认必须先取得 machine governor lock，不能每个进程创建独立预算；已有 owner 时 Phase 1a 在主动联网前失败并报告 owner，不隐含 IPC 代理；
- 只有进程启动者显式传入 `--governor-scope=user-acknowledged` 时，stdio 才可进入第 8.6 节的低风险方法 allowlist；JSON-RPC 客户端不能在握手后改变 scope。

协议还必须限制请求大小、并发、速率和 deadline，支持取消传播和默认脱敏。若未来需要共享 daemon，另行评估 Windows Named Pipe 与 Unix domain socket，使用 OS ACL、peer credentials/能力令牌，默认仍不监听 LAN。

## 14. 配置与 v1 迁移

建议的 v2 配置轮廓：

```yaml
version: 2

connectivity:
  direct: required       # required | preferred
  relay: disabled        # disabled | control_only | fallback
  birthday: disabled     # disabled | manual; automatic rejected in alpha

discovery:
  lan: true
  public_stun: true
  static: []
  bundle_anchors: []
  existing_paths: []
  dht: false             # not implemented in alpha

transit:
  control: false
  data: false
```

v2 是明确的协议和配置断代：

- v1 与 v2 节点不互操作；
- 不构建隐藏的双协议兼容层；
- `wink config migrate-v1` 只读取旧配置并生成一个待审查的新文件；
- 迁移命令绝不启动节点或写入系统路由；
- 网络接口、日志级别等安全字段可以映射；
- 全局共享 secret、旧 recovery 权限和 coordinator authority 不能自动迁移，必须拒绝并解释；
- 身份和成员关系由新的 join request、root-signed roster 和信任锚确认流程建立。

## 15. 分发本身是产品的一部分

技术方向有潜力，但“做出一个更强的打洞算法”不会自动产生用户。GitHub 发布二进制是主要分发方式，价值漏斗为：

```text
wink diagnose
    -> 可分享的脱敏 NAT/直连可行性报告
    -> 两节点 connect-test
    -> 完整 L3 网络
    -> 其他项目通过版本化 stdio API 集成
    -> 经需求验证后启用具名服务
```

每一级都必须独立提供价值：

1. 用户无需先部署完整网络，就能知道当前 NAT/UDP/IPv6 条件。
2. 报告默认保存在本地，用户可检查脱敏内容后主动导出。
3. 两节点测试给出可复现的成功或失败证据，而不是只显示“连接超时”。
4. 满足持续互联需求的用户再进入 L3 WinkYou。
5. 只需要求解能力的开发者通过跨语言本地 API 接入，不依赖 Go import。

非特权用户第一次运行时，即使 machine scope 尚未建立，也必须先得到有用的被动诊断、明确的阻断原因和一条可执行的安装修复路径；选择 `user_acknowledged` 的测试者则必须在结果中持续看到降级边界，不能用一次确认换取永久静默退化。

默认不启用遥测。早期数据来自用户明确提交的脱敏报告和自愿测试记录，至少公开：

- NAT 行为矩阵；
- 不同场景的直连成功率；
- 建连 p50/p95；
- socket、packet、five-tuple 消耗；
- 每类失败原因和停止原因；
- 是否借助第三方控制路径；
- machine scope 建立失败率、`active_probe_blocked` 比例和显式 `user_acknowledged` 使用比例；
- 因 `direct: required` 无法完成首次连接的比例。

项目早期不以“能否达到 100k Star”作为工程决策标准。更合理的里程碑是：

- 找到首批 10 位外部测试者；
- 至少 5 个独立外部部署在两周后仍使用；
- 获得第一个外部项目的 stdio API 集成；
- 达到 100 个有实际连接活动的节点；
- v2 alpha 在 3 个独立部署、10 个跨网络节点对上连续运行 14 天。

若经过定向招募和支持后，两周留存的独立外部部署仍少于 5 个，应先复盘定位、安装成本、direct 默认值和报告价值，不继续盲目扩大 v2 功能面。

## 16. 分阶段实施计划

时间仅是单维护者条件下的参考节奏；每阶段由证据门槛推进，不因日历自动进入下一阶段。

### Phase 0：立即安全门禁与决策基线（1–2 周）

交付：

- RFC 复审可以继续，但在 PR #11 合入前保持 Draft；
- 独立审查并合入 PR #11 的 fail-closed 产品门禁；
- 将 PR #11 在 `pkg/config`、`pkg/meshruntime` 的拒绝逻辑测试设为永久回归门禁，删除或放宽必须有独立 ADR；
- PR #11 合入前不从 `main` 打 tag 或 release；
- 解决 Issue #12 的 coordinator TLS、节点认证、授权和撤销，或者明确无这些能力的 remote coordinator 不属于公开支持路径；
- 保持当前 baseline 权威，直到正式 ADR 合入；
- 固化 incident NO-GO、发布硬预算、machine lock、kill-switch 和回滚责任；
- 完成仓库卫生审计和 release artifact allowlist，不无审查删除历史证据。

Phase 0 是安全决策 timebox，不得静默膨胀成 coordinator 全面重写。如果 Issue #12 的 TLS、认证、授权和撤销无法在该阶段以可审查质量闭合，就采用已经写明的逃生门：明确排除 remote coordinator 的公开支持路径，并把修复移入独立后续计划；不能为了守住 1–2 周而放宽安全门禁。

退出门槛：PR #11 已合入且永久测试通过；Issue #12 已修复或相关远程路径被明确排除；架构决策、威胁边界、禁止事项和回滚责任均有记录。达到这些条件后，本文才可以从 Draft 标记为 Accepted。

### Phase 1a：求解器构建期（参考 10–12 周）

Phase 1a 范围已包含安全内核、入口产品、验证设施和外部协议，参考时长因此从首稿的 6–8 周调整为 10–12 周；工期不能成为放宽退出门槛的理由。内部关键路径固定为：

1. 最小 domain contract、machine/user scope、governor/lease 与 `probeio` 强制点；
2. `wink diagnose`、被动降级 UX、脱敏报告和较低风险的 STUN 路径；
3. 可重复 NAT 矩阵、故障注入、依赖闭包和进程外资源证明；
4. 测试专用 pairing、`wink connect-test`，最后在前三项稳定后固化 stdio API/framing 与跨语言示例。

交付：

- canonical connectivity domain model，并切断 `solver -> rendezvous/proto` 依赖；在 contract tests 保护下抽取/替换旧 session 编排，不做大爆炸重写；
- canonical machine-safety namespace、OS 全局单实例锁、三层 lease、持久化 safety trip、`setup-machine-scope` 和显式 `user_acknowledged` 低风险模式；
- `probeio` 的 socket/target/send/reply/poison/Promote 强制契约；
- 生产传递依赖治理清单；v2 alpha 主动探测不迁移 Pion ICE、quic-go 等自开 socket 路径；
- TCP dial 粗粒度租约和 discovery DNS 限速；
- `wink diagnose`、被动诊断、脱敏报告和较低风险 STUN 观测；
- 可重复 NAT 模拟矩阵、故障注入和进程外资源观测；
- 经过安全审查的一次性 pairing mini-spec、`TestPairingChannel` 和 `wink connect-test`；
- 最后固化 JSON-RPC 2.0 over stdio、固定 `Content-Length` framing、handshake、progress notifications 和最小跨语言示例。

退出门槛：

- 受支持的确定性场景在模拟中连续 100 次通过；
- 任意输入和故障注入都不突破 machine/peer/attempt 硬上限；
- 启动多个 Node Runtime、stdio 或 diagnose 进程不会把预算乘以进程数；
- 第二个进程在任何发包前 fail-closed，并输出真实 owner 诊断；Phase 1a 不以未实现的 IPC 代理作为退出依赖；
- Linux 非 root tarball、受限 Windows 和容器场景都覆盖三种结果：可信 machine scope、只产生被动结果的 `active_probe_blocked`、显式 `user_acknowledged`；后者的功能 allowlist、较低硬上限和所有可观测标记不可绕过；
- CI 证明所有能自行创建 UDP socket 的生产第三方依赖都有治理声明；
- 未注册 endpoint 发送、Promote 后旧句柄、取消后残留 worker 均被确定性拒绝；
- `WSAENOBUFS`、连续写失败和预算突破会停止发送并持久化 trip；
- pairing 的错 token、重放、过期、跨会话、角色反射和升级到 Mesh/Node Runtime 全部被确定性拒绝；
- 至少一个 Python、Node 或 Rust 的最小 stdio API 示例可运行。

### Phase 1b：外部证据期（至少 4 周）

招募可在 Phase 1a 后半段开始，但证据窗口独立计算。门槛：

- 至少 10 位外部测试者实际运行 diagnose 或 connect-test；
- 至少 5 个独立部署在两周后仍使用；
- 至少一个外部 stdio API 集成或经过验证的集成意向；
- 收集直连成功率、失败分类、p50/p95、资源消耗和 direct-required 首连失败比例；
- 未出现无界网络资源行为。

完整 v2 的继续决策发生在 Phase 1b 后。未达门槛不否定 Phase 1a 技术成果，但必须先复盘定位和分发，不能通过降低证据门槛自动进入 Phase 2/3。

### Phase 2：身份、成员与发现（4–6 周）

交付：

- Ed25519 身份和独立 WG key binding；
- 离线 root、单写者签名 roster、join request 和 trust-anchor 指纹确认；
- roster 反回滚、同版本冲突告警、年龄展示和连接时反熵；
- root 备份/轮换 mini-ADR；
- 静态、bundle anchor、LAN、IPv6、已有路径 provider；
- 通用 `SignalingChannel` 及到最小 `AttemptChannel` 的 adapter；正式成员 `connect_test` 替换 Phase 1a 的 `test_only` 上下文，Node Runtime 保持拒绝测试身份；
- replay、撤销传播、provider 去重和信任锚替换攻击测试。

退出门槛：无项目中心 coordinator 的创建、目标身份加入、重启、撤销和 roster 反熵流程在隔离环境可重复通过。

### Phase 3a：统一运行时、恢复控制器与 L3（6–8 周）

交付：

- 单一 Node Runtime；
- L3 overlay、地址和宿主路由冲突处理；
- STABLE→SUSPECT→DEGRADED→RECOVERY_PENDING→RECOVERY_RUNNING→COOLDOWN/CIRCUIT_OPEN 恢复控制器；
- 稀疏控制图与按需数据直连；
- `direct`/`relay` 策略和不含糊的状态输出；
- v2 配置及只生成文件的迁移工具。

Phase 3a 恢复控制器只能自动调度已经通过硬资源证明的低风险策略；birthday 继续 disabled/manual-only，不能因恢复控制器存在而进入自动路径。

退出门槛：Windows/Linux E2E 覆盖 L3、重启、路由冲突和 Relay 禁用不变量；20 节点 24 小时 fake-clock 全不可达测试证明没有 N² heavyweight attempt，所有 generation worker、退避和 circuit 行为可解释。

### Phase 3b：具名 TCP/UDP 服务（证据驱动、独立增量）

仅在 Phase 3a 用户反馈证明需要后进入：

- 签名服务记录、按名解析和发布端 ACL；
- 默认拒绝和 direct-only 服务约束；
- 服务权限与 roster transit 能力分离；
- 独立的 Windows/Linux TCP/UDP E2E 门槛。

Phase 3b 不阻塞首个 L3 alpha，是否属于同一 alpha 由 Phase 3a 证据决定。

### Phase 4：扩展直连策略组合（4–6 周）

依次实现并验证：

- 全局 IPv6；
- PCP/NAT-PMP/UPnP；
- 基于 governor-owned socket 的多 STUN 和有界连通性检查；
- 可预测端口分配求解。

若未来需要完整 ICE 或 QUIC，必须先通过第三方 socket 治理 ADR。能注入 governor-owned `PacketConn` 优先；只能粗粒度预扣的库必须声明最坏成本并接受进程内计数与进程外观测；无法证明上限则不启用。

### Phase 5：人工生日求解（无固定日期）

仅在统一 machine governor、持久化 trip、单实例锁、取消证明和隔离观测全部通过后开始。第一版严格使用第 9 节硬上限，不进入自动恢复。

退出门槛：隔离 Windows/Linux 环境完成资源耗尽、取消、时钟漂移、延迟包、多进程竞争和进程外 conntrack 验证，并由第二位审查者确认。

### Phase 6：外部 v2 alpha 与迁移

交付：

- 签名构建、最小安装文档和可复现诊断；
- 3 个独立部署、10 个跨网络节点对；
- 14 天运行报告；
- v1 到 v2 的安全配置生成与拒绝清单；
- 明确的 alpha 限制和无直连场景。

未通过这些门槛前，不做 production-ready、always-connect 或任意 NAT 保证。

## 17. 验证矩阵

### 17.1 单元、属性与架构测试

- MeshID 选择器与 root key 信任锚在 join UX 中分开展示，扫码/文件替换不能绕过 root 指纹确认；
- root roster 签名、join request 目标绑定、信任锚指纹确认和整体替换攻击；
- roster 版本回滚、同版本不同摘要最高级告警、连接时反熵和撤销传播；
- WireGuard key rotation 不要求 root 重签 roster；
- ULA/IPv4 地址和宿主路由冲突；
- 多 provider 去重、过期和 DNS 限速；
- `relay: disabled` 时任何数据 Relay 都不可创建；
- machine/peer/attempt 任一输入下都不超过 `AttemptLease` 与发布硬上限；
- `RegisterTarget` 扣新五元组，向未注册 endpoint 发送被拒绝；
- 入站回复包计入 PPS/总包预算；
- `Promote`/`Close` 后旧 ProbeSocket 句柄被毒化；
- 成功 socket 只移交一次，遗留 deadline 清除，兄弟 worker 全部退出；
- 多进程、多个 Mesh 和不同数据目录竞争时仍只有一个官方 WinkYou 预算权威；
- machine namespace ACL/owner 校验、portable 缺失路径、per-user lock 和 `user_acknowledged` 功能 allowlist；
- `test_only` pairing 的错 token、重放、过期、跨会话、角色反射、取消后清零及 Mesh/Node Runtime 权限升级拒绝；
- JSON-RPC framing、handshake、scope/auth_scope 标记、progress notification、取消和版本拒绝；
- wire DTO/domain adapter round-trip、未知字段和 golden tests；
- 依赖闭包中所有自开 UDP socket 的第三方库都有治理声明；
- PR #11 的 fail-closed 配置与 runtime 用例是永久回归门禁。

### 17.2 可控 NAT 模拟

至少覆盖：

- LAN；
- 双方全局 IPv6；
- EIM × EIM；
- EIM × EDM；
- 可预测 EDM × EDM；
- 随机 EDM × EDM，预期有界失败；
- CGNAT；
- UDP 完全阻断；
- NAT 行为、接口或公网 IP 在 attempt 中变化。

所有声明支持的确定性场景必须连续 100 次通过；不支持场景必须在预算内稳定失败并输出同类原因。

### 17.3 恢复与规模（Phase 3a 退出门槛）

- 20 节点、24 小时 fake-clock 全部不可达；
- 证明不存在 N² heavyweight attempt；
- 每机器、节点对和 attempt 的并发、packet、socket、target、five-tuple 上限保持不变；
- keepalive 抖动不会形成恢复风暴；
- 旧 generation worker 不会在网络变化后复活；
- 恢复控制器不能自动启用 birthday 或其他未通过资源证明的策略。

### 17.4 故障注入

- `WSAENOBUFS`/等价资源错误；
- 连续和间歇写失败；
- context cancel 与退出超时；
- 时钟跳变；
- 签名重放和延迟控制消息；
- machine lock 竞争、持锁进程崩溃和陈旧诊断元数据；
- machine namespace 权限错误、符号链接/路径抢占、不同用户、不同数据目录和容器边界误报；
- pairing token 泄露、低熵输入、错误角色、transcript 篡改和测试身份升级；
- 路由安装冲突；
- Relay/第三方控制路径中断；
- 进程重启或切换 CLI 后 safety trip 仍生效。

### 17.5 隔离系统测试

- Windows 与 Linux 进程指标；
- 进程外 socket/conntrack/出口包观测；
- 同时启动多个 stdio、diagnose 和 Node Runtime，确认硬预算不放大；
- Linux 非 root tarball 和受限 Windows 首次运行仍返回被动诊断与准确修复命令；显式 `user_acknowledged` 的报告、握手和对端 transcript 都显示降级，且不能启动 Node Runtime；
- 无项目中心 coordinator 的创建、加入、撤销和重启；
- L3 TCP、UDP、ICMP；
- Phase 3b 独立测试具名 TCP/UDP 服务与 ACL；
- 先用 Tailscale/frp 等作为控制 underlay，再移除它，已提交直连继续工作；
- 默认配置下 Relay 不可用且不会被静默启用。

## 18. 主要风险与取舍

| 风险 | 处理方式 |
| --- | --- |
| “无 coordinator”被误解为无任何 bootstrap | 文档和状态明确展示每个发现/信令来源 |
| 直连默认值伤害首连与留存 | 不做绝对保证，Phase 1b 量化 direct-required 首连失败并允许重开默认值 |
| 生日算法再次形成资源风暴 | machine governor、硬上限、single-flight、持久化 trip、默认禁用 |
| 第三方库绕过 probeio 自行开 socket | v2 alpha 排除 Pion ICE/quic-go 主动探测，传递依赖白名单与治理 ADR |
| 多进程或多数据目录把节点预算放大 N 倍 | canonical machine-safety OS 锁；Phase 1a 后续进程在联网前失败并提示 owner，IPC 代理只在未来共享 daemon 中评估 |
| 非特权用户因 machine scope 缺失无法进入价值漏斗 | 安装器/`setup-machine-scope` 建立可信 namespace；默认保留被动诊断，仅以显式、可观测、低风险 `user_acknowledged` 支持单次测试 |
| Phase 1a 临时 pairing 长成第二套身份 | 独立 `auth_scope=test_only`、临时 ID/密钥、能力负面清单、Phase 2 正式路径替换及升级拒绝测试 |
| 身份系统过度复杂 | alpha 使用单写者 root-signed roster，不实现委托 invite/revoke |
| bundle 被整体替换 | 受控带外通道或双端 root 指纹确认 |
| 离线 root 阻碍例行 WG 轮换 | WG binding 由节点身份自签，不进入 roster |
| 同时做 overlay 和服务授权扩大范围 | Phase 3a 先 L3，具名服务/ACL 独立进入 Phase 3b |
| 外部路径变成隐性永久依赖 | 显式 provider、依赖降权、直连成功后退出、状态可见 |
| 默认公共 STUN 引发隐私疑虑 | 明示、可关闭、可自托管、遥测默认关闭 |
| 完整 v2 投入后无人使用 | Phase 1b 外部留存门槛先于完整 mesh 重建 |
| 追逐 frp 功能与 Star 数导致失焦 | 求解器和直连个人网络是核心；frp/Tailscale 是可组合 underlay/集成对象 |

## 19. 维护者审查清单

请在接受本文前逐项确认或提出修改：

- [ ] 是否接受“版本化本地求解 API + 直连优先个人网络”的定位？
- [ ] 是否接受首要用户为 2–20 台可信设备的个人/homelab？
- [ ] 是否接受 Windows/Linux 发布级、macOS 暂时仅编译？
- [ ] 是否接受 Phase 3a 先交付 L3，具名服务推迟至独立 Phase 3b？
- [ ] 是否接受 `direct: required`、`relay: disabled` 是 Phase 1b 必须验证的默认值假设？
- [ ] 是否接受 `relay: fallback` 必须配合 `direct: preferred`，并始终标记 degraded？
- [ ] 是否接受“无强制中心服务，但冷启动需要至少一种发现来源”的表述？
- [ ] 是否接受公共 STUN 默认开启但明示、可关闭、可自托管？
- [ ] 是否接受 DHT 仅留接口，alpha 不启用？
- [ ] 是否接受 Ed25519 节点身份、独立 WG binding、离线 root 和单写者 roster？
- [ ] 是否接受 bundle 通过受控带外通道或 root 指纹人工确认建立信任锚？
- [ ] 是否接受 control/data transit 分权，invite/revoke 不在 alpha 下放？
- [ ] 是否接受 canonical machine-safety namespace 只有一个 governor 权威，多进程、多 Mesh 和不同数据目录都不能各自分配预算？
- [ ] 是否接受 machine scope 缺失时默认只做被动诊断，并仅通过每次显式确认的 `user_acknowledged` 低风险模式开放 STUN/单次 connect-test；Node Runtime 与 birthday 永不接受该降级？
- [ ] 是否接受 Phase 1a 不实现隐含 IPC 代理，第二个主动进程在发包前失败并显示 owner，代理随未来共享 daemon 单独审查？
- [ ] 是否接受 v2 alpha 主动探测不迁移 Pion ICE、quic-go 等自开 socket 第三方路径？
- [ ] 是否接受 Phase 1a 使用不可升级的 `auth_scope=test_only` 一次性 pairing，Phase 2 正式成员路径以 roster 身份替换它？
- [ ] 是否接受单一 Node Runtime、恢复控制器和稀疏控制图均属于 Phase 3a？
- [ ] 是否接受随机 double-hard NAT 的有界失败？
- [ ] 是否接受生日策略 alpha 默认禁用、只允许人工隔离实验及第 9 节硬上限？
- [ ] 是否继续维持 cached self-bootstrap/autonomous birthday recovery 的 NO-GO？
- [ ] 是否接受 v1/v2 不互操作，迁移工具只生成安全字段配置？
- [ ] 是否接受 Phase 1a 构建与 Phase 1b 证据分开，证据不过门槛就暂停完整 v2？
- [ ] 是否接受遥测默认关闭、由用户主动提交脱敏报告？
- [ ] 是否接受以真实留存、API 集成和跨网络稳定性为近期目标，而非 100k Star？

## 20. 接受本文意味着什么

本文只有在 PR #11 合入、其 fail-closed 测试成为永久门禁后才能从 Draft 标记为 Accepted。只要旧 remote coordinator 仍在公开范围，Issue #12 也必须修复；否则必须明确将该路径排除。

接受本文只代表：

1. 可以据此编写正式 ADR、issue 拆分和 Phase 0/1a 实施计划；
2. 可以开发本地、模拟器内的 domain model、machine governor、probeio、stdio API 和安全基础设施；
3. 旧 baseline 何时被取代，必须由后续明确提交决定。

接受本文**不代表**：

- 批准自动生日恢复；
- 批准在真实家庭、办公或公网环境进行探测；
- 批准启用当前任何被暂停的 scheduled task；
- 批准部署公共 coordinator、DHT、Relay 或收集遥测；
- 批准发布 production-ready 声明。

这些动作都必须在相应阶段通过独立审查和明确授权。
