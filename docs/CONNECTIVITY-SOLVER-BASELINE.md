# Connectivity Solver Baseline v2（WinkYou 架构基线草案）

> 状态：Draft / Proposed
> 
> 目的：取代“传统 ICE/TURN P2P VPN”作为项目的主叙事与主架构约束。
> 
> 注意：本文件**不覆盖**旧的 `docs/EXECUTION-BASELINE.md` 历史价值。旧 baseline 应冻结为 legacy 基线，并通过 git tag 固定；本文件是后续重构与实现的**新规范入口**。

---

## 1. 项目重新定义

WinkYou 不再被定义为“一个固定 ICE/TURN 流程驱动的 P2P VPN”。

新的定义是：

> **WinkYou = 连接求解引擎（Connectivity Solver） + 安全数据面（WireGuard Data Plane）**

系统的职责不再是：

- gather candidates
- offer / answer
- connect
- attach tunnel

而是：

- 会合（rendezvous）
- 交换能力（capability exchange）
- 获取观测（observation）
- 合成脚本（probe / path synthesis）
- 选择路径（path selection）
- 绑定安全数据面（bind secure data plane）
- 在退化时重新求解（re-solve on degrade）

P2P 只是系统可能求得的结果之一；relay 是保底路径，不是产品失败态。

---

## 2. 旧架构中保留与降级的部分

### 2.1 必须保留

- `pkg/tunnel`：以 `wireguard-go` 为核心的安全数据面
- `pkg/netif`：TUN / Wintun / 平台网络接口层
- `pkg/coordinator`：现有基础会合与消息传递骨架（后续语义演进为 rendezvous plane）
- `pkg/relay`：自有中继能力
- 当前每个 peer 可以绑定独立 transport 的方向

### 2.2 必须降级为兼容层 / strategy 的部分

- `pkg/nat` 作为“系统总入口”的地位
- `NATTraversal -> ICEAgent -> Connect()` 作为唯一求解抽象
- `ICE_OFFER / ICE_ANSWER / ICE_CANDIDATE` 作为唯一控制语言
- NAT type 作为决策核心的地位

### 2.3 禁止继续扩大的旧耦合

- 不再向旧 `peer_session` 里追加更多 retry / fallback / branch
- 不再把 tunnel 与 “ICE transport” 直接耦合
- 不再把 raw `net.Conn` 直接当作 WireGuard 的通用 transport 抽象

---

## 3. 新架构的五层边界

### 3.1 Rendezvous Plane

职责：

- 节点注册
- 身份认证
- 发现对端
- 创建 / 关闭 session
- 交换 capability / observation / script / result / path commit
- 协调 fallback / suspend / resume

约束：

- 它不再只是 ICE 信令转发器
- 它是会合与实验交换总线
- 它不负责决定最终路径

### 3.2 Observation Plane

职责：

- 获取中间网络行为样本
- 记录映射、过滤、超时、可达性差异
- 记录不同协议 / 端口 / 目标下的行为差异

原则：

- 失败也是观测
- NAT type 只是 hint，不是最终答案
- 观测结果必须可积累、可复用

### 3.3 Solver Plane

职责：

- 基于 capability、observation、历史 profile、预算约束，合成可执行脚本或候选路径
- 执行多轮求解，而不是单次 connect
- 对结果进行评分、排序、复用和重试决策

原则：

- 不追求一次命中
- 每一轮尽量最大化信息增益
- relay 是预算下的保底 path，不是架构中心

### 3.4 Transport Plane

职责：

- 提供统一的包级传输抽象
- 把底层 UDP / QUIC datagram / TURN / framed TCP / TLS / WebSocket 等都统一适配为 packet semantics

硬约束：

- WireGuard 只消费“包”，不消费“原始 stream”
- raw TCP/TLS/WS 不能直接塞进当前 tunnel bind
- 所有 stream transport 必须先 framing 成 datagram / packet transport

### 3.5 Tunnel Plane

职责：

- 只消费统一的 `PacketTransport`
- 不参与 NAT 判断
- 不参与 path 求解
- 不关心底层是 UDP、TURN、QUIC 还是 framed stream

---

## 4. 核心抽象（第一轮必须冻结）

### 4.1 PacketTransport

第一轮必须引入：

```go
package transport

import (
    "context"
    "net"
    "time"
)

type PacketMeta struct {
    ReceivedAt time.Time
    PathID     string
}

type PacketTransport interface {
    ReadPacket(ctx context.Context, dst []byte) (n int, meta PacketMeta, err error)
    WritePacket(ctx context.Context, pkt []byte) error
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    Close() error
}
```

说明：

- 第一轮 `PacketMeta` 可以很薄，但接口形状先冻结
- tunnel 只能依赖这个抽象
- 未来所有 transport adapter 都必须向这里收敛

### 4.2 Strategy

旧 ICE 不再是架构本体，而是一种 strategy。

建议统一成如下形状：

```go
package solver

import "context"

type Strategy interface {
    Name() string
    Plan(ctx context.Context, in SolveInput) ([]Plan, error)
    Execute(ctx context.Context, sess SessionIO, plan Plan) (Result, error)
}
```

说明：

- 允许未来出现 `legacy_ice_udp`、`udp_probe`、`tcp_simopen`、`quic_443`、`relay` 等不同 strategy
- 第一轮不要求全部实现，但第二种 strategy 的“容纳能力”必须在架构上成立

### 4.3 Binder

Binder 是独立角色，不应混在 peer session 里。

```go
package session

import (
    "context"
    "github.com/houyuwushang/winkyou/pkg/transport"
)

type Binder interface {
    Bind(ctx context.Context, peerID string, pt transport.PacketTransport) error
    Unbind(ctx context.Context, peerID string) error
}
```

说明：

- Binder 只负责把选中的 path 绑定到 tunnel
- Solver 不直接碰 tunnel
- Session 不直接实现 tunnel 绑定细节

### 4.4 Session Envelope

第一轮引入新的 session v2 消息骨架，即便 payload 还是 stub。

```text
SessionEnvelope {
  session_id
  from_node
  to_node
  msg_type
  seq
  ack
  payload
}
```

最低应包含的消息类型：

- Capability
- Observation
- ProbeScript
- ProbeResult
- PathCommit

第一轮不要求 payload 丰满，但要求控制面具备表达力。

---

## 5. 第一轮目录重组原则

### 5.1 新增目录（第一轮）

```text
pkg/
  transport/
    transport.go
    iceadapter/

  session/
    session.go
    state_machine.go
    binder.go
    types.go

  solver/
    types.go
    strategy/
      legacyice/

  rendezvous/
    proto/
    client/
    session/
```

### 5.2 旧目录的第一轮处理方式

- `pkg/client`：保留外部入口，但内部逐步退化为 orchestration / glue
- `pkg/nat`：不再是总入口；第一轮通过 adapter 迁移到 `pkg/solver/strategy/legacyice`
- `pkg/coordinator`：第一轮不大搬迁，只新增 rendezvous v2 骨架，后续逐步迁移语义
- `pkg/tunnel`：改为消费 `transport.PacketTransport`

### 5.3 第一轮禁止做的大迁移

- 不要一口气把所有旧目录 rename 掉
- 不要在 Phase 1 就大规模移动 coordinator / client 的文件位置
- 先通过 adapter 过渡，跑通 vertical slice，再考虑物理迁移

---

## 6. 第一轮最小可运行 vertical slice

第一轮只做下面四件事：

1. 引入 `PacketTransport`
2. 让 tunnel 从 `net.Conn` 改为依赖 `PacketTransport`
3. 把现有 ICE/UDP 路径包成 `pkg/solver/strategy/legacyice`
4. 新增 `session/rendezvous v2` 的消息骨架，让 `peer_session` 退化成 glue 层

第一轮不做：

- 不实现全功能多策略 solver
- 不实现完整 probe sentinel 网络
- 不实现 TCP / QUIC / TLS443 全打通
- 不优化 CLI 体验
- 不做 userspace / proxy / no-admin 收口

---

## 7. 运行时状态机（新）

建议替代旧固定 connect 流程：

```text
DISCOVER
  -> RENDEZVOUS
  -> CAPABILITY_EXCHANGE
  -> OBSERVE_LOCAL
  -> EXCHANGE_OBSERVATIONS
  -> SYNTHESIZE_SCRIPT
  -> EXECUTE_SCRIPT_ROUND
  -> SCORE_PATHS
  -> PATH_COMMIT
  -> BIND_TRANSPORT
  -> MAINTAIN
  -> LEARN
  -> (on degrade) RE-SOLVE or FALLBACK
```

第一轮允许简化：

- `OBSERVE_LOCAL` 可以暂时由 legacy ICE gather 替代
- `SYNTHESIZE_SCRIPT` 可以先退化成固定 legacyice plan
- `PATH_COMMIT` 可以先提交单一路径

但状态机边界必须先立住。

---

## 8. 与旧 baseline 的关系

旧 `docs/EXECUTION-BASELINE.md` 不应直接删除。

正确处理：

1. 先给当前 HEAD 打 tag：`legacy-ice-turn-baseline-2026-04-15`
2. 在旧 baseline 顶部增加说明：
   - 这是 legacy ICE/TURN 方案基线
   - 新架构基线见 `docs/CONNECTIVITY-SOLVER-BASELINE.md`
3. README 后续再逐步切换为指向新 baseline

这样做可以保留历史与回滚能力，也能让本轮重构有明确边界。

---

## 9. 第一轮验收标准

### 9.1 架构验收

- tunnel 已不再公开依赖 `net.Conn`
- 至少存在一个 `PacketTransport` 实现（ICE adapter）
- 旧 ICE 不再是系统总入口，而是 strategy
- session 层已经能表达 `Capability / Observation / ProbeScript / ProbeResult / PathCommit`
- `peer_session` 不再继续承担“求解器 + binder + 信令黑箱”三合一职责

### 9.2 兼容验收

- 现有 UDP / ICE / WireGuard 路径仍能工作
- 现有直连测试不应明显退化
- 现有 relay 路径暂可维持兼容，但不再是唯一架构轴心

### 9.3 未来扩展验收

- 新架构下能自然容纳第二种 strategy
- 能自然容纳 framed stream transport，而不必再改 tunnel 抽象

---

## 10. 三条纪律

1. 不要再把“连通性求解”写成一次 `Connect()`。
2. 不要把 NAT type 当作主要决策输入。
3. 不要把 raw TCP `net.Conn` 直接塞进当前 WireGuard bind；所有 stream transport 必须先 framing 成 packet transport。

---

## 11. 这一版基线的使用方式

- 本文件先作为**规范文档**，不是实现 PR
- 代码模型的下一轮工作只围绕 **Phase 1 vertical slice**
- 任何 PR 如果违反本文件边界，应视为偏航，而不是“实现细节不同”

