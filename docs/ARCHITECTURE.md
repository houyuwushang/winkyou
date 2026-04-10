# WinkYou 项目架构文档

> 本文档面向所有开发人员，描述项目整体架构、模块划分、任务依赖关系以及各模块与项目目标的耦合方式。
>
> 当前 MVP 执行以 [EXECUTION-BASELINE.md](EXECUTION-BASELINE.md) 为准。
> 当本文档与执行基线冲突时，以执行基线为准。
>
> 术语说明：当前文档中的“中继”在 MVP 语境下默认指 `TASK-07` 的 `TURN server relay`；“节点 A 作为 B 到 C 的受信中继”属于 `post-MVP` 扩展，单独见 [PEER-RELAY-DESIGN.md](PEER-RELAY-DESIGN.md)。

## 一、项目目标

WinkYou 是一个 **P2P 内网穿透虚拟局域网** 项目，核心目标是：

| 目标 | 描述 | 优先级 |
|------|------|--------|
| G1 | 任意两台设备能够建立加密的P2P连接 | P0 |
| G2 | 跨NAT环境自动穿透，无需手动配置 | P0 |
| G3 | 穿透失败时自动回退到中继，保证100%连通 | P0 |
| G4 | 虚拟局域网体验，设备间像在同一网络 | P0 |
| G5 | 跨平台支持（Windows/Linux/macOS） | P0 |
| G6 | 无管理员权限也能使用（降级模式） | P1 |
| G7 | 易于部署和使用 | P1 |

---

## 二、系统架构总览

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           WinkYou 系统架构                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│                         ┌─────────────────┐                              │
│                         │   协调服务器     │                              │
│                         │  (Coordinator)  │                              │
│                         │   [TASK-05]     │                              │
│                         └────────┬────────┘                              │
│                                  │                                       │
│              ┌───────────────────┼───────────────────┐                   │
│              │ 控制平面(gRPC)     │                   │                   │
│              │ - 节点注册         │                   │                   │
│              │ - 密钥交换         │                   │                   │
│              │ - 信令传递         │                   │                   │
│              │                   │                   │                   │
│      ┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐          │
│      │   WinkNode    │   │   WinkNode    │   │   WinkNode    │          │
│      │  [TASK-06]    │   │  [TASK-06]    │   │  [TASK-06]    │          │
│      └───────┬───────┘   └───────┬───────┘   └───────┬───────┘          │
│              │                   │                   │                   │
│   ┌──────────┴──────────┬────────┴────────┬──────────┴──────────┐       │
│   │                     │                 │                     │       │
│   ▼                     ▼                 ▼                     ▼       │
│ ┌─────────┐      ┌─────────────┐   ┌─────────────┐      ┌─────────┐    │
│ │ NAT穿透  │      │  WireGuard  │   │  中继服务   │      │ 网络接口 │    │
│ │[TASK-04]│      │   隧道层    │   │  [TASK-07] │      │ [TASK-02]│    │
│ │         │      │  [TASK-03]  │   │            │      │          │    │
│ │ STUN    │      │             │   │   TURN     │      │ TUN/TAP  │    │
│ │ ICE     │      │  加密传输    │   │   Relay    │      │ Netstack │    │
│ └─────────┘      └─────────────┘   └─────────────┘      └─────────┘    │
│                                                                          │
│ ┌────────────────────────────────────────────────────────────────────┐  │
│ │                        基础设施层 [TASK-01]                         │  │
│ │                   配置管理 | 日志系统 | CLI框架                      │  │
│ └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 三、任务模块总览

### 3.1 任务列表

| 任务ID | 任务名称 | 文档路径 | 难度 | 依赖 |
|--------|----------|----------|------|------|
| TASK-01 | 基础设施模块 | [tasks/TASK-01-infrastructure.md](tasks/TASK-01-infrastructure.md) | 低 | 无 |
| TASK-02 | 网络接口抽象层 | [tasks/TASK-02-netif.md](tasks/TASK-02-netif.md) | 中 | TASK-01 |
| TASK-03 | WireGuard隧道层 | [tasks/TASK-03-wireguard.md](tasks/TASK-03-wireguard.md) | 中 | TASK-02 |
| TASK-04 | NAT穿透模块 | [tasks/TASK-04-nat-traversal.md](tasks/TASK-04-nat-traversal.md) | 高 | TASK-01, TASK-05 |
| TASK-05 | 协调服务器 | [tasks/TASK-05-coordinator.md](tasks/TASK-05-coordinator.md) | 中 | TASK-01 |
| TASK-06 | 客户端核心 | [tasks/TASK-06-client-core.md](tasks/TASK-06-client-core.md) | 高 | TASK-02,03,04,05 |
| TASK-07 | 中继服务 | [tasks/TASK-07-relay.md](tasks/TASK-07-relay.md) | 中 | TASK-04 |

### 3.2 任务依赖图

```
TASK-01 (基础设施)
    ├── TASK-02 (网络接口) ─► TASK-03 (WireGuard) ───┐
    └── TASK-05 (协调服务器) ─► TASK-04 (NAT穿透) ───┼──► TASK-06 (客户端核心)
                                                  └──► TASK-07 (中继服务)
```

### 3.3 开发阶段与任务对应

| 阶段 | 任务 | 里程碑产出 |
|------|------|------------|
| Phase 0 | TASK-01 | 可运行的CLI框架 |
| Phase 1 | TASK-02, TASK-03 | 两节点手动直连 |
| Phase 2 | TASK-05 | 控制平面可用 |
| Phase 3 | TASK-04 | 跨NAT自动直连 |
| Phase 4 | TASK-07 | 中继保底 |
| Phase 5 | TASK-06 | MVP完整客户端 |

---

## 四、模块与项目目标的耦合关系

### 4.1 目标-模块矩阵

| | TASK-01 | TASK-02 | TASK-03 | TASK-04 | TASK-05 | TASK-06 | TASK-07 |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **G1** P2P加密连接 | | | **主要** | 支持 | | 集成 | |
| **G2** NAT自动穿透 | | | | **主要** | 支持 | 集成 | |
| **G3** 中继保底 | | | | | | 集成 | **主要** |
| **G4** 虚拟局域网 | | **主要** | 支持 | | | 集成 | |
| **G5** 跨平台 | 支持 | **主要** | 支持 | | | 集成 | |
| **G6** 无权限模式 | | **主要** | | | | 集成 | |
| **G7** 易用性 | **主要** | | | | | 集成 | |

**图例**：
- **主要**：该模块是实现此目标的核心
- 支持：该模块为实现此目标提供支撑
- 集成：该模块负责整合其他模块实现此目标

### 4.2 详细耦合说明

#### G1: P2P加密连接 → TASK-03 WireGuard隧道层

```
目标: 任意两台设备能够建立加密的P2P连接

实现路径:
TASK-03 (WireGuard) ─────► 提供加密隧道能力
    │
    ├── 使用 Noise Protocol 进行密钥交换
    ├── MVP: ChaCha20-Poly1305 数据加密 (WireGuard兼容)
    ├── 长期: 密码套件协商，支持AES-GCM硬件加速 (Wink Protocol, 见 wink-protocol-v1.md)
    └── Curve25519 ECDH 密钥协商

依赖:
TASK-02 (网络接口) ────► 提供虚拟网卡读写IP包
TASK-04 (NAT穿透) ─────► 提供可达的Endpoint
```

#### G2: NAT自动穿透 → TASK-04 NAT穿透模块

```
目标: 跨NAT环境自动穿透，无需手动配置

实现路径:
TASK-04 (NAT穿透) ─────► 提供穿透能力
    │
    ├── STUN: 获取公网映射地址
    ├── ICE:  协商最优连接路径
    └── NAT检测: 确定穿透策略

依赖:
TASK-05 (协调服务) ────► 交换ICE候选地址
```

#### G3: 中继保底 → TASK-07 中继服务

```
目标: 穿透失败时自动回退到中继，保证100%连通

实现路径:
TASK-07 (中继服务) ────► 提供TURN中继
    │
    ├── TURN服务器实现
    ├── Relay Candidate 分配
    └── 数据转发

触发条件:
TASK-04 (NAT穿透) ─────► ICE协商失败时回退
TASK-06 (客户端) ──────► 自动切换逻辑
```

补充说明：

- 这里的 G3 在当前 MVP 内只统计 `TURN relay`
- “节点 A 作为 B 到 C 的受信中继”是可行增强项，但它会跨越 `TASK-05 + TASK-06 + TASK-02/03`，不属于当前 MVP 冻结交付

#### G4: 虚拟局域网 → TASK-02 网络接口层

```
目标: 设备间像在同一网络

实现路径:
TASK-02 (网络接口) ────► 提供虚拟网卡
    │
    ├── TUN设备: 创建虚拟网络接口
    ├── IP分配: 虚拟局域网地址
    └── 路由配置: 流量导入隧道

依赖:
TASK-03 (WireGuard) ───► 隧道传输
TASK-05 (协调服务) ────► IP地址分配
```

#### G5: 跨平台 → TASK-02 网络接口层

```
目标: 支持 Windows/Linux/macOS

实现路径:
TASK-02 (网络接口) ────► 平台抽象
    │
    ├── Linux:   /dev/net/tun
    ├── macOS:   utun
    ├── Windows: WinTUN
    └── 降级:    gVisor netstack

策略:
├── 编译时: 条件编译 (build tags)
└── 运行时: 自动检测并选择后端
```

#### G6: 无权限模式 → TASK-02 网络接口层

```
目标: 无管理员权限也能使用

实现路径:
TASK-02 (网络接口) ────► 多后端支持
    │
    ├── 有权限: TUN/TAP (完整功能)
    └── 无权限: Userspace Netstack 或 SOCKS5代理

降级策略:
┌─────────────────────────────────────────┐
│ 检测权限 ─► 有 ─► 使用TUN              │
│     │                                   │
│     └─► 无 ─► 尝试Netstack ─► 成功 ─► 使用│
│              │                          │
│              └─► 失败 ─► SOCKS5代理模式  │
└─────────────────────────────────────────┘
```

#### G7: 易用性 → TASK-01 基础设施 + TASK-06 客户端核心

```
目标: 易于部署和使用

实现路径:
TASK-01 (基础设施) ────► CLI工具设计
    │
    ├── 简洁的命令: wink up / wink down
    ├── 合理的默认值
    └── 清晰的错误提示

TASK-06 (客户端) ─────► 自动化流程
    │
    ├── 自动注册到协调服务器
    ├── 自动发现并连接对等节点
    └── 网络切换自动重连
```

---

## 五、数据流图

### 5.1 连接建立流程

```
┌────────────────────────────────────────────────────────────────────────┐
│                          连接建立数据流                                  │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Node A                    Coordinator                    Node B        │
│    │                           │                            │          │
│    │  1. Register(pubkey)      │                            │          │
│    ├──────────────────────────►│                            │          │
│    │                           │                            │          │
│    │  2. OK(virtual_ip)        │                            │          │
│    │◄──────────────────────────┤                            │          │
│    │                           │                            │          │
│    │                           │  3. Register(pubkey)       │          │
│    │                           │◄───────────────────────────┤          │
│    │                           │                            │          │
│    │                           │  4. OK(virtual_ip)         │          │
│    │                           ├───────────────────────────►│          │
│    │                           │                            │          │
│    │  5. GetPeers()            │                            │          │
│    ├──────────────────────────►│                            │          │
│    │                           │                            │          │
│    │  6. PeerList(B's info)    │                            │          │
│    │◄──────────────────────────┤                            │          │
│    │                           │                            │          │
│    │  7. ICE Candidates ──────────(via Coordinator)─────────►│          │
│    │◄──────────────────────────────────────────────────────►│          │
│    │                           │                            │          │
│    │  8. ════════════ WireGuard Handshake ═══════════════   │          │
│    │◄══════════════════════════════════════════════════════►│          │
│    │                           │                            │          │
│    │  9. ════════════ Encrypted Tunnel ══════════════════   │          │
│    │◄══════════════════════════════════════════════════════►│          │
│    │                           │                            │          │
└────────────────────────────────────────────────────────────────────────┘

涉及模块:
- 步骤 1-6: TASK-05 (协调服务器) + TASK-06 (客户端)
- 步骤 7:   TASK-04 (NAT穿透/ICE)
- 步骤 8-9: TASK-03 (WireGuard)
```

### 5.2 数据传输流程

```
┌────────────────────────────────────────────────────────────────────────┐
│                          数据传输路径                                    │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  应用程序 (ping 10.100.0.2)                                             │
│      │                                                                  │
│      ▼                                                                  │
│  ┌────────────────┐                                                     │
│  │  系统协议栈     │  ← 应用通过正常socket发送                            │
│  └───────┬────────┘                                                     │
│          │ (路由到TUN设备)                                               │
│          ▼                                                              │
│  ┌────────────────┐                                                     │
│  │  TUN设备       │  ← TASK-02 提供                                     │
│  │  (wink0)       │                                                     │
│  └───────┬────────┘                                                     │
│          │ (IP包)                                                       │
│          ▼                                                              │
│  ┌────────────────┐                                                     │
│  │  WireGuard     │  ← TASK-03 提供                                     │
│  │  加密 + 封装   │                                                     │
│  └───────┬────────┘                                                     │
│          │ (加密UDP包)                                                   │
│          ▼                                                              │
│  ┌────────────────┐                                                     │
│  │  物理网络      │  ← 通过NAT穿透的路径或中继                            │
│  │  UDP发送       │     TASK-04 / TASK-07                               │
│  └───────┬────────┘                                                     │
│          │                                                              │
│          ▼                                                              │
│     [ 互联网 ]                                                          │
│          │                                                              │
│          ▼                                                              │
│     对端节点 (逆向解包)                                                  │
│                                                                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 六、接口契约

### 6.1 模块间接口

各模块需遵循以下接口契约，确保模块可独立开发和测试：

#### TASK-02 → TASK-03: 网络接口

```go
// NetworkInterface 是 TASK-02 提供给 TASK-03 的接口
type NetworkInterface interface {
    // 基本操作
    Name() string
    MTU() int
    Read(buf []byte) (int, error)
    Write(buf []byte) (int, error)
    Close() error
    
    // 配置
    SetIP(ip net.IP, mask net.IPMask) error
    AddRoute(dst *net.IPNet, gateway net.IP) error
}
```

#### TASK-04 → TASK-06: NAT穿透

```go
// NATTraversal 是 TASK-04 提供给 TASK-06 的接口
type NATTraversal interface {
    // NAT检测
    DetectNATType(ctx context.Context) (NATType, error)
    
    // ICE协商
    GatherCandidates(ctx context.Context) ([]Candidate, error)
    StartICE(ctx context.Context, remoteCandidates []Candidate) (*Connection, error)
}

type Connection interface {
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    Read(b []byte) (int, error)
    Write(b []byte) (int, error)
    Close() error
}
```

#### TASK-05 → TASK-06: 协调服务

```go
// CoordinatorClient 是 TASK-05 提供给 TASK-06 的接口
type CoordinatorClient interface {
    Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
    Heartbeat(ctx context.Context) error
    ListPeers(ctx context.Context) ([]*PeerInfo, error)
    GetPeer(ctx context.Context, nodeID string) (*PeerInfo, error)
    SendSignal(ctx context.Context, toNodeID string, signalType SignalType, payload []byte) error
    ReceiveSignal(ctx context.Context) (<-chan *Signal, error)
}
```

### 6.2 配置接口

```yaml
# MVP 统一配置结构（扁平顶层）
node:
  name: "my-node"

log:
  level: "info"

netif:
  backend: "auto"  # auto|tun|userspace|proxy
  mtu: 1280

wireguard:
  private_key: "..."
  listen_port: 51820

nat:
  stun_servers:
    - "stun:stun.l.google.com:19302"
  turn_servers:
    - url: "turn:relay.example.com:3478"
      username: "wink"
      password: "secret"

coordinator:
  url: "https://coord.example.com"
  auth_key: ""
```

---

## 七、测试策略

### 7.1 模块测试责任

| 任务 | 单元测试 | 集成测试 | 测试重点 |
|------|----------|----------|----------|
| TASK-01 | 配置解析、日志格式 | CLI命令执行 | 配置校验、错误处理 |
| TASK-02 | 各后端读写 | 跨平台适配 | 平台兼容性 |
| TASK-03 | 加密解密 | 隧道连通性 | 数据完整性 |
| TASK-04 | STUN解析、候选生成 | NAT穿透成功率 | 各种NAT类型 |
| TASK-05 | 注册、心跳逻辑 | 多节点并发 | 并发安全 |
| TASK-06 | 状态机 | 端到端流程 | 完整流程 |
| TASK-07 | 分配逻辑 | 中继传输 | 性能、稳定性 |

### 7.2 集成测试场景

```
┌─────────────────────────────────────────────────────────────┐
│                    集成测试矩阵                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  场景1: 同局域网直连                                         │
│  ├── Node A (192.168.1.100)                                 │
│  └── Node B (192.168.1.101)                                 │
│  预期: 直接建立WireGuard连接                                 │
│                                                              │
│  场景2: 跨NAT (Cone-Cone)                                   │
│  ├── Node A (NAT后, Full Cone)                              │
│  └── Node B (NAT后, Full Cone)                              │
│  预期: STUN打洞成功                                          │
│                                                              │
│  场景3: 跨NAT (Symmetric-Any)                               │
│  ├── Node A (NAT后, Symmetric)                              │
│  └── Node B (任意NAT)                                       │
│  预期: 自动回退到TURN中继                                    │
│                                                              │
│  场景4: 网络切换                                             │
│  ├── Node A: WiFi → 4G                                      │
│  └── Node B: 固定                                           │
│  预期: 自动重连，延迟恢复                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 八、开发规范

### 8.1 代码组织

```
winkyou/
├── cmd/                    # 可执行入口
│   ├── wink/               # CLI客户端
│   ├── wink-coordinator/   # 协调服务器
│   └── wink-relay/         # 中继服务器
├── pkg/                    # 公共库（可被外部引用）
│   ├── config/             # TASK-01
│   ├── logger/             # TASK-01
│   ├── version/            # TASK-01
│   ├── netif/              # TASK-02
│   ├── tunnel/             # TASK-03
│   ├── nat/                # TASK-04
│   ├── coordinator/        # TASK-05
│   │   ├── client/
│   │   └── server/
│   ├── client/             # TASK-06
│   └── relay/              # TASK-07
│       ├── client/
│       └── server/
├── api/                    # API定义 (protobuf)
│   └── proto/
├── docs/                   # 文档
│   ├── ARCHITECTURE.md     # 本文档
│   ├── EXECUTION-BASELINE.md
│   └── tasks/              # 任务文档
└── test/                   # 集成测试
```

### 8.2 Git分支策略

```
main ─────────────────────────────────────────────────►
  │
  ├── develop ────────────────────────────────────────►
  │     │
  │     ├── feature/task-01-infrastructure
  │     ├── feature/task-02-netif
  │     ├── feature/task-03-wireguard
  │     └── ...
  │
  └── release/v0.1.0
```

### 8.3 提交规范

```
<type>(<scope>): <subject>

type: feat|fix|docs|refactor|test|chore
scope: task-01|task-02|...|all

示例:
feat(task-02): implement Linux TUN backend
fix(task-04): handle STUN timeout correctly
docs(task-05): add API documentation
```

---

## 九、FAQ

### Q: 各任务可以并行开发吗？

**A:** 部分可以：
- TASK-01 必须最先完成（基础设施）
- TASK-02 和 TASK-05 可在 TASK-01 后优先并行
- TASK-03 依赖 TASK-02
- TASK-04 的 MVP 完成依赖 TASK-05 的信令能力
- TASK-07 依赖 TASK-04
- TASK-06 的开发启动依赖 TASK-02,03,04,05；TASK-07 是 MVP 发布门禁依赖

### Q: 如何处理模块间依赖进行独立测试？

**A:** 使用接口mock：
```go
// 示例: TASK-03 测试时mock TASK-02
type MockNetworkInterface struct {
    ReadFunc  func([]byte) (int, error)
    WriteFunc func([]byte) (int, error)
}

func (m *MockNetworkInterface) Read(b []byte) (int, error) {
    return m.ReadFunc(b)
}
```

### Q: 跨平台代码如何组织？

**A:** 使用Go build tags：
```go
// netif/tun_linux.go
//go:build linux

// netif/tun_windows.go
//go:build windows

// netif/tun_darwin.go
//go:build darwin
```

---

*文档版本：v1.0*
*更新日期：2026-04-02*
