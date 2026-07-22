# 生日悖论直连改造设计（Birthday-Paradox Direct Punch）

> **暂停告警（2026-07-22）：** 产品化 cached self-bootstrap 在失联重试中造成 UDP 五元组/出口会话风暴。该方向短期暂停，当前实现为 **NO-GO**，不得在办公网、生产网或未经外部限流的公网启用。早期真机直连成功只证明算法可行，不代表长期自治恢复具备资源安全性。事故计算与恢复门禁见 [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)。
>
> 状态：M6 真机公网直连和 M7 无 Wintun 用户态 SSH bridge 已完成（2026-07-16），M8 记录了随后约 11 小时的无重连会话及单 stream 收尾缺陷。之后 `birthday_punch` 获胜 socket 已接入自治图运行时并完成三节点现场 edge rotation；recovery card/cached self-bootstrap 随后取得 r12 公网进程重入结果。Slice 4.5 已把运行时抽到 `pkg/meshruntime`，并在 2026-07-19 完成 C -> B -> A 三节点产品 `wink up` 滚动现场部署：三者均 zero seed、无基础设施 coordinator，并各有两条一跳 `protected_direct` packet edge。透明系统 L3、OS 自启动/重启、同时冷启动和公网 IP 变化仍是后续工作。
> 背景证据：`.live-run/` 抓包 + `implementation_plan.md` 2026-06-06 条目 + 三方审阅结论。

## 1. 为什么现在打不通（一句话）

现有 `legacyice/public_direct` 在**对称×对称 NAT**（EDM×EDM，最难档）下，四个决定成败的维度全部做反：

| 维度 | 现状 | 正解 |
|---|---|---|
| 源 socket 数 | **1 个**固定 UDP mux | 每端 **256~512 个**源 socket（生日悖论） |
| 端口预测锚点 | 锚"对端打 STUN 的映射端口"±512 | 学 NAT 端口分配规律，预测"对端打**我**时"的端口 |
| 打洞时序 | **~7ms** 一次性 burst | 信令**同步触发** + 持续数秒双向对撞 |
| NAT 分类 | 单 STUN → `nat_type=unknown` | 多 STUN 分类，据类型选策略 |

现场实测：inner 端发出 500+ 包全部出向、对端 tcpdump **零入站**（`.live-run/inner-live-wide-collect.txt`）。根因是 inner 用单 socket 打对端 2050 个端口，自己的对称 NAT 给每个目标分配不同公网源端口，对端无法匹配任何映射，全部当未授权入站丢弃。

生日悖论数字（danderson 实测）：一端对称开 256 socket、另一端猜 256 次 → 命中 **64%**；而 `m=1、n=2050` 的现状双对称命中率 **≈0%**。不是发得不够，是撒错了维度。

## 2. 目标与非目标

**目标**
- 双方对称 NAT 时，用「多源 socket + 端口预测 + 同步触发」建立可用 UDP 直连；获胜 socket 可交给现有 WireGuard 路径，也可交给不依赖 Wintun 的用户态数据面。
- 作为**新 strategy** 与现有 `public_direct`/`relay_only`/`signal_relay` **并存**，不推倒 pion 那条路径。legacy client/session portfolio 只有显式把 `birthday_punch` 放入 `connectivity.strategy_order` 才会启用；当前 `autonomous_mesh` edge solver 则直接使用它。

**非目标**
- 不追求 100% 成功——双对称纯直连是物理上的概率事件，**relay 永远是兜底**。
- M1–M6 不改 solver/session 对外接口；M7 先提供固定目标 TCP 转发，不在本轮实现透明三层 VPN、全局路由或 UDP proxy。

## 3. 核心模型

1. **多源 socket**：每端开 N 个 `net.ListenUDP(":0")`，在自己 NAT 上打出 N 个并存的"洞"。N 默认 256，双对称可 512。
2. **端口预测**：先测本端 NAT 的端口分配规律——
   - 现场证据：inner `49053→23984/85/86/87`、local `53381→53379..82`，两端都是**顺序分配（delta≈+1）**，可精确预测，不必纯随机撒。
   - 预测"对端打我时"会落在哪批端口，双方通过信令互告，把撒网范围从 65535 缩到几百。
3. **同步触发**：coordinator 信令交换端点/模式后，约定 `T0` 双方**同时**开打并**持续数秒**，让两端出向包在各自 NAT 开孔的时间窗重叠（对称 NAT 打洞的硬要求）。
4. **命中即锁定**：任一源 socket 收到对端 punch 回包 → 锁定 `(localConn, remoteAddr)` → 小握手确认双向可达 → 移交数据面。

## 4. 架构与接入点

```
port_predict (M1) ──┐
                    ├─► puncher (M2) ──► connected-conn (M3) ──► iceadapter.New(conn) ──► PacketTransport ──► tunnel/WG
signal+sync (M4) ───┘                                             （现有，不改）
        └──────────────► birthdaypunch strategy (M5) ──► solver portfolio（现有）
                                    └─► portforward (M7) ──► QUIC/mTLS streams ──► fixed TCP target（无 Wintun）
```

- **数据面移交是可插入的**：puncher 保留获胜的原始 `*net.UDPConn`。现有 `iceadapter.New(conn, pathID)` 可把它变成 `PacketTransport`；M7 则把同一 socket 直接交给 `pkg/dataplane/portforward`，用 QUIC 可靠流承载 TCP 转发。后者完全不初始化 WireGuard、Wintun 或 `wink0`。
- **strategy 封装**：实现 `solver.Strategy` 并注册进现有 portfolio。legacy `auto` 当前仍严格遵循显式 `connectivity.strategy_order`，没有按 NAT 类型自动把它排到 `public_direct` 前；`autonomous_mesh` 当前独立固定选择 `birthday_punch`，尚未接入完整 strategy portfolio。

## 5. 里程碑

| # | 里程碑 | 交付 | 状态 |
|---|---|---|---|
| M1 | NAT 端口分配规律探测器 | `pkg/nat/port_predict.go` + 单测 + `wink debug port-alloc` | ✅ 完成；已合并多 STUN mapping 检测并跨目的地采样 |
| M2 | 多 socket puncher 核心 | `pkg/nat/puncher/` + 单测（race 绿） | ✅ 完成，含端点学习/grace/固定端口/动态撒网 |
| M3 | connected-UDP 适配器 | `ConnectedConn`（`puncher/connected.go`）→ iceadapter | ✅ 完成 |
| M4 | 信令端点交换 + 同步触发 | `birthdaypunch/messages.go`,`sync.go` | ✅ 完成 |
| M5 | `birthday_punch` strategy | `pkg/solver/strategy/birthdaypunch/` + `client/strategy_factory.go` 注册 | ✅ 完成，全量测试绿 |
| M6 | 真机联调 + 调参 | `cmd/punchtest/` 工具 + 联调 | ✅ 完成：EDM×EDM 连续三轮公网直连，双端 5/5，物理口抓包确认 |
| M7 | 无 Wintun 用户态数据面 | `pkg/dataplane/portforward/` + `punchtest bridge` | ✅ 完成：公网命中 socket 上建立 QUIC/mTLS，固定目标 SSH 成功；关闭两端 overlay 后新建 SSH 仍成功 |
| M8 | 长时稳定性与产品形态决策 | 无重连 soak + stream 收尾诊断 + 方案评审 | 🔄 进行中：626 次新建 SSH 完整成功，已知连续可用约 10 小时 58 分；随后出现单 stream 收尾卡住，原 QUIC 会话及已认证交互 SSH 仍存活 |
| M9 | 自治 mesh edge 与 peer transit | `cmd/meshnode` + `pkg/mesh` + shortcut manager | ✅ 三节点公网 edge rotation、peer 协调与用户态 routed SSH 已现场验证；仍非透明 L3 |
| M10 | cached self-bootstrap | `pkg/recoverycard` + `pkg/bootstrap/selfhosted` | 🧪 post-r9 源码候选；本地 peer runtime 替换和两代三 runtime 全 direct triangle 测试均通过 5 次重复与 race，公网 NAT/机器重启仍待验收 |

## 6. 验证判据（M6 终态）

- ✅ inner `enp69s0` 抓到来自 `192.0.2.10` 的公网入站 UDP；R3 为 26 包、0 kernel drop。
- ✅ 两端 `punchtest` 都打印 `HIT`，应用层 ping/echo 连续三轮 5/5，RTT 35–37ms。
- ✅ `m6-overlayoff-20260716-r4` 在两端 Tailscale/natpierce 都关闭时仍双端 HIT + 5/5，公网物理路由和持续状态监控均已留证。
- ✅ `no-wintun-20260716-r1` 把命中 socket 升级为 QUIC/mTLS bridge；本机 `Tailscale=Stopped`、`natpierce_count=0`，远端 `tailscale=inactive`、`natpierce_count=0` 时，通过 `127.0.0.1:22022` 新建 SSH 仍成功。
- 🔄 同一 v2 QUIC 会话正在做无重连长测；业务完成态已连续验证到约 10 小时 58 分，进程/会话存活超过 11 小时，但已经发现“新 stream 认证成功后短命令不退出”的收尾问题。
- ✅ 独立 `punchtest bridge` 仍可复现实验；`pkg/meshruntime` 已把同类获胜 socket 接成图中的 direct `PacketNeighbor`，`cmd/meshnode` 保留薄兼容入口，Slice 4.5 还把该运行时接入显式 opt-in 的 `wink up` 生命周期。该产品 adapter 已完成 C -> B -> A 三节点现场部署；透明系统 L3 尚未接入。

## 7. 图论视角与 punch method portfolio

原则（项目最初的设计直觉）：把网络看成**通信图**——两节点若在图上连通（能各自与某些中间节点通信），就存在一条可雕刻的直连路径。做法是发特制包去**学习并影响路径上路由/NAT 节点的状态**，把"可达"变成"直连"。

据此 puncher 不是单一算法，而是**可插入的 punch method portfolio**，按两端在图中的位置和 NAT 行为组合选择：

| method | 机理 | 适用 | 物理边界 |
|---|---|---|---|
| 端点学习 endpoint-learning | 路径观测点（STUN/coordinator/对端回包）告知节点经 NAT 后的真实出口 | 所有场景的信息基础 | 无 |
| 端口预测 predictive | 顺序/保持型 NAT 端口可推算（inner 真机 delta+1、conf 1.0） | 可预测 NAT | 随机型失效 |
| 生日悖论 birthday | 多源 socket + 撒网，概率对撞 | 对称/混合 NAT | 需两端同时配合 |
| TTL-scoped punch | TTL 受限包只在指定跳（本端出口 NAT）建映射，不惊动对端过滤 | 精确时序控制 | 需 TTL 可控 |
| ICMP-assisted (pwnat) | 伪造 ICMP 让对端 NAT 借道已有映射 | 无信令/严格过滤 | ICMP 限速/过滤 |
| spoofed-source | 用对端 NAT 已放行的源地址发包 | 已知对端通信对象 | BCP38 出口过滤挡死 |
| 普通 peer transit | 已建立图上的用户节点转发 | 直连尚未建立或物理不可行时 | 非物理直连；不是专用基础设施 relay |

落地次序：**核心三法（端点学习+预测+生日悖论）先做**（M2，真机已验证可行）；伪装包类（TTL/ICMP/spoofed）作为受控插件逐步评估；直连尚未成功时由已经存在的普通 mesh graph 提供 peer transit，而不是新增专用基础设施 user-data relay。架构上 `Puncher` 是接口，每种 method 一个实现，策略层按“图中位置 + NAT 类型”选组合。真机数据已证明这套对**可预测×混合**类非对称拓扑高度可行，但不保证所有 NAT 对都能建立物理直连。

## 8. 实现现状与真机验证（2026-07-16 联调）

详细的真机操作实录、每轮尝试与复现步骤见 [`docs/BIRTHDAY-PUNCH-FIELD-LOG.md`](./BIRTHDAY-PUNCH-FIELD-LOG.md)。

### 8.1 代码现状（M1–M7 与后续 graph 接入）

- **M1** `pkg/nat/port_predict.go`：`ProbePortAllocationWithMapping` 同时做“同 socket、多 STUN”mapping 检测与“新 socket、轮换 STUN”端口分配采样；保留单 STUN `ProbePortAllocation` 兼容入口；`wink debug port-alloc` 默认使用配置中的全部 STUN。
- **M2** `pkg/nat/puncher/`：`puncher.go`（核心）、`packet.go`（punch 包）、`target.go`（predictive/birthday 目标）、`connected.go`（M3 的 `ConnectedConn`）。
- **M4** `pkg/solver/strategy/birthdaypunch/`：`messages.go`（punch_endpoint/punch_start）、`sync.go`（planPunch 决策 + 同步时刻）。
- **M5** 同目录 `strategy.go`（Execute 编排）+ `pkg/client/strategy_factory.go` 注册（config `strategy_order: [birthday_punch, ...]` 启用）。
- **验证工具** `cmd/punchtest/`：独立于 wink 的 CLI，子命令 `probe` / `mapping` / `punch` / `bridge`；`bridge` 在获胜 UDP socket 上运行用户态 QUIC 可靠流和固定目标 TCP 转发，不需要 Wintun/管理员。
- **M9** `cmd/meshnode`：shortcut manager 将 `birthday_punch` 获胜 socket 交给 `iceadapter`，安装成可参与 link-state routing 的 direct `PacketNeighbor`；普通 peer 可承载协调消息和正常 graph transit。
- **M10** `pkg/recoverycard` + `pkg/bootstrap/selfhosted`：post-r9 源码候选持久化成功端点，在没有 neighbor/route 时让双端按 pair window 直接 punch；第一条边恢复后由 r9 maintained-edge controller 补齐其余 direct edge。详细边界见 [`SELF-BOOTSTRAP-RECOVERY.md`](./SELF-BOOTSTRAP-RECOVERY.md)。

### 8.1.1 显式绑定打洞 underlay

产品配置可选字段 `nat.punch_interface` 用接口名固定 `birthday_punch` 和 cached self-bootstrap 使用的 underlay：

```yaml
nat:
  punch_interface: Ethernet  # 必须替换为本机精确名称；Linux 常见为 eth0
  stun_servers:
    - stun:stun.cloudflare.com:3478
    - stun:stun.l.google.com:19302
```

启用后，运行时先把接口名解析为精确的 interface index 和可用单播 IPv4；接口不存在、已 down 或没有可用 IPv4 时启动/本轮求解直接失败，不回退到系统默认路由。所有同 socket mapping probe、fresh-socket port-allocation probe 和 punch socket 都绑定该源 IP；Windows 还在 bind 前设置 `IP_UNICAST_IF`，Linux 使用 `SO_BINDTODEVICE`（权限不足会显式失败）。未配置时保持原来的系统路由选择行为，且 `local_bind_ip` / `local_bind_interface` 证据留空，不能把 wildcard socket 地址误当成实际出口。显式配置时，`birthday_punch` 的 `PathSummary.Details` 与 self-bootstrap status/event 日志使用同名证据 `local_bind_ip`、`local_bind_interface`；self-bootstrap 另记录获胜 socket 的 `local_bind_addr`。

`wink debug port-alloc` 和 `wink doctor` 的 STUN mapping 检查也读取同一字段并使用 bound probe；前者的 JSON/文本结果、后者的 STUN check message 会明确输出 `local_bind_interface` 和 `local_bind_ip`。因此可在不启动 normal runtime 的情况下先做只读 underlay STUN 探测；配置文件无法加载或显式接口无法解析时不会静默退回默认路由。

这个开关只保证“操作员指定的 underlay 被执行且可观测”，不能单独证明该接口就是物理 WAN，也不能证明路径中不存在上游 VPN/overlay。现场验收仍必须冻结预期接口/IP，并结合路由、接口类型和对端抓包判定。

cached self-bootstrap 对 preserving/sequential 端口模型先进行一次低成本窄预测；如果该候选组发生一次由 punch deadline 确认的失败，后续窗口会保留预测目标并升级为 `cached_predictive_birthday_fallback`。这是必要的退化闭环：一次大规模打洞本身就可能消耗大量顺序 NAT 映射，若永远围绕旧 anchor 搜固定 span，下一轮只会落后得更多。升级仍发生在同一个 pair session、互补 selector/receiver 角色和单个 `Punch` 内，不会引入第二条并行 owner 路径。

### 8.2 puncher 在真机迭代中补齐的 4 个关键机制

1. **端点学习闭环**（`peerSet`）：任一 socket 收到对端 probe → 记住其真实源地址 → 所有 sender 下一轮直接回打它。**一端打准，双方即锁定**，不依赖两端都预测准。这是 §7 图论"用收到的包反推对端位置"的落地。
2. **命中 grace**（`gracePeriod`）：本端命中后继续 punch/ack 一个窗口，让对端也完成握手，避免"一端命中、另一端卡死"。获胜 socket 的 reader 在报告首个 ACK 后仍会留到 grace 结束；交给数据面前会清除轮询遗留的短 read deadline，避免首包立即 timeout。
3. **固定本地端口**（`Config.LocalPort`）：port-preserving/cone 端用它，使公网源端口固定 = symmetric 对端打过的目标，穿过对端 filtering。
4. **低速动态撒网**（`Config.BirthdayN/Lo/Hi`）：random 端每轮每 socket 只撒少量**新**随机端口，靠时间累积覆盖端口空间，**避免一次性海量包压垮网络/控制通道**。

### 8.3 真机诊断结论（含一处重要修正）

拓扑：`inner`（Linux，公网 `198.51.100.20`）↔ `本机`（Windows，公网 `192.0.2.10`），两端各在运营商 NAT 后。

**2026-07-16 M6 成功轮次开始前，两端都是 symmetric + random（EDM×EDM 最难档）**。16-sample 多 STUN 探测中，inner 与本机同 socket 到 Cloudflare/Google/MiWiFi 都得到不同映射，跨目标分配序列均判为 `random`，所以三轮都采用双向 birthday，而不是沿用早期 inner sequential 的旧结论。

上面是此前 M6 轮次的现场结论，不应硬编码成机器属性。新探测器落地后，本机同一天连续两轮又观测到时变行为：一轮 6-sample 在相同 Google/Cloudflare 目的 IP 下出现 `45685 / 52247 / 15048 / ...`，判为 `random`；紧接一轮 12-sample 全部 `mapped_port == local_port`，判为 `preserving`。两轮同-socket mapping 都只得到一致映射，因此保守显示 `mapping_type=unknown`。这说明端口冲突/网关状态也会改变短期样本，真机联调必须在每轮前重测并保留原始 samples，不能把一次分类当永久事实。

> **✅ M1 单 STUN 盲点已修（2026-07-16）**：`port-alloc` 与 `birthday_punch` 现在会使用全部配置 STUN。探测先用同一个 socket 打多个目标判断 mapping behavior（EIM/EDM），再让新 socket 轮换不同 STUN 采样端口分配序列，显著降低只观察单一目的地造成的误判；输出也记录实际 STUN 目的地址。仅配置一个可用 STUN 或多目标映射一致时，`mapping_type` 保持 `unknown`。分类仍是当前时间窗口的观测值，不是 NAT 的永久标签。

### 8.4 M6 真机结果：控制通道卡点已解除

此前 SSH 前台持有 responder，连接 reset 会连带杀掉打洞进程。改为 `setsid`、stdin/stdout/stderr 全脱离并落盘后，连续三轮均成功：

| run | 参数（双方） | 结果 |
|---|---|---|
| `m6-codex-20260716-r1` | 128 sockets × 64 fresh targets/round，250ms，burst 1 | 双端 HIT + 5/5 |
| `m6-codex-20260716-r2` | 128 × 48，300ms，burst 1 | 双端 HIT + 5/5，RTT 36–37ms |
| `m6-codex-20260716-r3` | 128 × 48，300ms，burst 1，45s 窗口 | 双端 HIT + 5/5；inner 物理口抓到 26 包、0 drop |

R3 首包为 `192.0.2.10:19786 -> 172.20.0.11:16048`，与 responder 的 `peer=192.0.2.10:19786`、本地获胜端口 `16048` 完全对应。现场产物归档在 `.live-run/runs/m6-codex-20260716-r{1,2,3}/`（Git 忽略）。较低负载 `128×48×300ms` 已连续两轮成功，并已回灌正式 strategy。

### 8.5 M7 无 Wintun 数据面

- `pkg/dataplane/portforward` 接管 puncher 的获胜 `*net.UDPConn`，使用 `quic-go v0.54.1`（兼容项目 `go 1.23`）承载双向可靠流。
- 共享的 32 字节随机 secret 通过 HMAC 分别派生 client/server Ed25519 身份；QUIC 使用 TLS 1.3、双方固定公钥校验和角色区分，不信任系统 CA，也不是裸 `InsecureSkipVerify`。
- responder 只拨配置中的固定 TCP target；initiator 默认只监听 `127.0.0.1`。每个本地 TCP 连接映射为一条 QUIC 双向 stream。
- 真机 v2 命中约 37 秒：本机获胜 socket `0.0.0.0:53746 -> 198.51.100.20:11459`，远端 `0.0.0.0:35239 -> 192.0.2.10:2131`；随后 `ssh -p 22022 node-c-user@127.0.0.1` 成功。
- 全部 overlay 关闭的证明来自同一轮 v1：本机公网路由为物理以太网 ifIndex 9 / `10.0.0.1`，远端回程为 `enp69s0` / `172.20.0.1`；关闭后另开 SSH stream 返回 `BOTH_OVERLAYS_OFF_BRIDGE_OK`。

### 8.6 M8 长时运行快照（2026-07-17）

- v2 原始会话于 `2026-07-16 22:13:51 +08:00` 建立；测试期间不自动重启 bridge、不重新打洞，QUIC `KeepAlivePeriod=10s`、`MaxIdleTimeout=5m`。
- 后台探针每分钟通过 `127.0.0.1:22022` 新建一次 SSH/QUIC stream。到 `2026-07-17 09:12:09 +08:00` 共 `626/626` 次完整成功，距原会话建立约 10 小时 58 分。
- `09:13:12` 的下一条 stream 已完成 OPEN、远端 target connect/accept 和 SSH 用户认证，但短命令没有正常退出；`09:17` 后另开的交互 SSH 也成功获得远端 PTY。到 `09:22` 原 bridge 双端进程和 QUIC 会话仍在。因此当前证据是“会话仍可承载已认证 stream，但出现单 stream 收尾卡住”，不是整条链路已死亡，也不能继续把探针计为全绿。
- 旧监控器没有独立于 SSH 客户端的 wall-clock deadline，导致这次卡住后停止追加日志。下一轮监控必须同时记录 `open/target/auth/command-exit` 分层状态，并在单探针超时后继续后续探测，避免一个客户端挂住遮蔽整条会话状态。
- 长测期间 Tailscale 已恢复作为运维救援通道；它不改变已建立 bridge 的公网 peer endpoint。两端 overlay 全关闭的独立性证据来自 §8.5 的现场轮次，不应误写成整夜都关闭了 overlay。

### 8.7 后续方案与已冻结边界

这里先区分三个概念，不把它们混成一个“下一步”：

- **连接耐久**：保持同一 punch + QUIC 会话，在不重打洞的情况下测首次业务失败时间；自动重连必须关闭，否则会掩盖原会话寿命。
- **实验性 graph runtime**：`cmd/meshnode` 已能让 solver 创建 direct edge、peer transit 和用户态 TCP service，不再只有人工 `punchtest bridge`；正常的长期产品入口现在是显式启用 `autonomous_mesh` 的 `wink up`，`cmd/meshnode` 保留为兼容/实验入口。
- **重连生命周期**：r9 在还有 alternate route 时由普通 peer 协调修边；post-r9 在完全无 route 时可用双方 recovery card 恢复第一条边。本地源码测试已覆盖一个全新 peer runtime 从 card 回来，以及全部三 runtime 重建后“self-bootstrap 成树、普通第三节点补齐最后直边”；不能把它写成公网 NAT 或机器重启已通过。
- **主引擎 backend**：显式 `autonomous_mesh.enabled: true` 现在会让正常的 `wink up` 采用上述 graph、恢复与 selected-port 服务生命周期，并通过统一 runtime state 支持 `status`、`peers` 和 authenticated graceful `down`。Slice 4.5 的全量测试、目标 race、全量 vet、隔离本机 CLI 生命周期和 C -> B -> A 三节点现场 rollout 均已通过；A 的四个 SSH facade 都返回了完整命令输出。后续 120 秒 monitor 中 44 个 SSH 承载探针均 exit `0`，虽然 Win32-OpenSSH 仍打印 pending-I/O close warning；该 warning 不等于 WinkYou stream 失败，历史 M8 第 627 条真实挂起仍需独立回归。这仍不等于透明 L3 已实现。

用户态服务入口仍需决定固定目标端口、多目标/ACL、SOCKS5/HTTP CONNECT，还是更接近虚拟局域网语义的用户态 IP 栈；不同选择会改变配置、权限、安全边界和 `wink up` 接口。在该决策完成前，不把 `netif.backend: proxy` 当作既定路线。

首次产品迁移和真实 executable 滚动部署已完成；近期恢复工作转向 OS 自启动、机器重启、三节点同时冷启动和公网 NAT/IP 变化 fault matrix。若所有已知公网 IP 同时变化且没有 LAN/IPv6/静态映射/仍可达 peer/外部目录，recovery card 没有可发送的目的地址；这仍需发现源，而不是专用数据 relay。透明三层组网仍需要系统网络接入层，不能把 graph routing 或固定端口转发冒充完整 VPN。完整现场记录见 [`SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md`](./SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md)。

## 9. 参考

- danderson/nat-birthday-paradox（256 socket→64%、双对称需两端 256×256）
- RFC 5780 NAT Behavior Discovery；RFC 4787 术语
- Ford/Srisuresh/Kegel《P2P Communication Across NATs》(simultaneous open)
- Tailscale disco + DERP（先中继保活、后台升级直连）
