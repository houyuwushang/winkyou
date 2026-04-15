# TASK-04: NAT穿透模块

> 历史任务说明：本任务文档按 legacy MVP baseline 编写。当前 active architecture baseline 为 `docs/CONNECTIVITY-SOLVER-BASELINE.md`。
> MVP 的 NAT/ICE 完成交付依赖 `TASK-05` 提供的信令能力。

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-04 |
| 任务名称 | NAT穿透模块 |
| 难度 | **高** |
| 预估工作量 | 7-10天 |
| 前置依赖 | TASK-01, TASK-05 |
| 后续依赖 | TASK-06, TASK-07 |

## 任务说明

### 背景

NAT（网络地址转换）是互联网中普遍存在的技术，它使得位于NAT后的设备无法被外部直接访问。P2P连接的核心挑战就是**NAT穿透**。

本模块实现完整的NAT穿透能力，包括：
- **STUN**: 发现自己的公网地址和NAT类型
- **ICE**: 收集候选地址，协商最优连接路径
- **打洞**: 利用NAT特性建立直接连接

### 目标

- 实现NAT类型检测
- 实现STUN客户端
- 实现ICE协商框架
- 达到 **>70%** 的穿透成功率（非对称NAT场景）

---

## 功能需求

### FR-01: NAT类型检测

**描述**: 检测本机所处的NAT类型

```go
type NATType int

const (
    NATTypeUnknown NATType = iota
    NATTypeNone           // 无NAT，公网IP
    NATTypeFullCone       // 完全锥形（最容易穿透）
    NATTypeRestrictedCone // 限制锥形
    NATTypePortRestricted // 端口限制锥形
    NATTypeSymmetric      // 对称型（最难穿透）
)

type NATDetector interface {
    // DetectNATType 检测NAT类型
    DetectNATType(ctx context.Context) (NATType, error)
    
    // GetPublicAddress 获取公网地址
    GetPublicAddress(ctx context.Context) (*net.UDPAddr, error)
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-01-1 | 区分四种NAT类型 | P0 |
| FR-01-2 | 识别无NAT（公网IP） | P0 |
| FR-01-3 | 获取公网映射地址 | P0 |
| FR-01-4 | 多STUN服务器支持 | P1 |

**NAT类型检测流程**:
```
┌─────────────────────────────────────────────────────────────┐
│                    NAT类型检测流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 向STUN服务器A发送请求                                    │
│     │                                                        │
│     ├─► 响应IP == 本地IP?  ─► 是 ─► 无NAT (公网IP)          │
│     │                                                        │
│     └─► 否，继续                                             │
│                                                              │
│  2. 向STUN服务器A请求从不同IP响应                            │
│     │                                                        │
│     ├─► 能收到? ─► 是 ─► Full Cone                          │
│     │                                                        │
│     └─► 否，继续                                             │
│                                                              │
│  3. 向STUN服务器B发送请求                                    │
│     │                                                        │
│     ├─► 映射端口 == 服务器A时的端口?                         │
│     │   │                                                    │
│     │   ├─► 是 ─► Restricted Cone 或 Port Restricted Cone  │
│     │   │                                                    │
│     │   └─► 否 ─► Symmetric NAT                             │
│     │                                                        │
│  4. 向STUN服务器A请求从不同端口响应                          │
│     │                                                        │
│     ├─► 能收到? ─► 是 ─► Restricted Cone                    │
│     │                                                        │
│     └─► 否 ─► Port Restricted Cone                          │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### FR-02: STUN客户端

**描述**: 实现STUN协议客户端

```go
type STUNClient interface {
    // Bind 发送Binding请求，获取映射地址
    Bind(ctx context.Context, serverAddr string) (*BindingResult, error)
}

type BindingResult struct {
    LocalAddr     *net.UDPAddr // 本地地址
    MappedAddr    *net.UDPAddr // NAT映射后的公网地址
    XORMappedAddr *net.UDPAddr // XOR编码的映射地址
    OtherAddr     *net.UDPAddr // STUN服务器的备用地址
    ResponseTime  time.Duration
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-02-1 | Binding Request/Response | P0 |
| FR-02-2 | XOR-MAPPED-ADDRESS解析 | P0 |
| FR-02-3 | 超时重传机制 | P0 |
| FR-02-4 | 多服务器并发查询 | P1 |

### FR-03: ICE候选收集

**描述**: 收集所有可能的连接候选地址

```go
type Candidate struct {
    Type       CandidateType
    Address    *net.UDPAddr
    Priority   uint32
    Foundation string
    RelatedAddr *net.UDPAddr // 对于srflx/relay，记录base地址
}

type CandidateType int

const (
    CandidateTypeHost  CandidateType = iota // 本地地址
    CandidateTypeSrflx                       // STUN映射地址
    CandidateTypePrflx                       // Peer反射地址
    CandidateTypeRelay                       // TURN中继地址
)

type CandidateGatherer interface {
    // Gather 收集候选地址
    Gather(ctx context.Context) ([]Candidate, error)
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-03-1 | 收集Host候选（本地IP） | P0 |
| FR-03-2 | 收集Server Reflexive候选（STUN） | P0 |
| FR-03-3 | 收集Relay候选（TURN） | P0 |
| FR-03-4 | 过滤重复候选 | P1 |
| FR-03-5 | 正确计算优先级 | P1 |

**候选优先级计算**:
```go
// RFC 8445 优先级公式
priority = (2^24 * type_preference) + 
           (2^8 * local_preference) + 
           (256 - component_id)

// 类型偏好
// Host:  126
// Srflx: 100
// Relay: 0
```

### FR-04: ICE连通性检查

**描述**: 检查候选对的连通性，选择最优路径

```go
type ICEAgent interface {
    GatherCandidates(ctx context.Context) ([]Candidate, error)
    SetRemoteCandidates(candidates []Candidate) error
    Connect(ctx context.Context) (net.Conn, *CandidatePair, error)
    GetSelectedPair() (*CandidatePair, error)
    Close() error
}

type ConnectionState int

const (
    ConnectionStateNew ConnectionState = iota
    ConnectionStateChecking
    ConnectionStateConnected
    ConnectionStateCompleted
    ConnectionStateFailed
    ConnectionStateClosed
)
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-04-1 | 构建候选对检查列表 | P0 |
| FR-04-2 | 发送STUN Binding Request检查 | P0 |
| FR-04-3 | 处理Binding Response | P0 |
| FR-04-4 | 选择最优候选对 | P0 |
| FR-04-5 | 连接状态机 | P0 |
| FR-04-6 | 处理候选对超时 | P1 |

**ICE状态机**:
```
┌─────────┐
│   New   │
└────┬────┘
     │ start()
     ▼
┌─────────┐     check failed    ┌─────────┐
│Checking │──────────────────────►│ Failed  │
└────┬────┘                      └─────────┘
     │ check succeeded
     ▼
┌─────────┐     all checks done  ┌─────────┐
│Connected│──────────────────────►│Completed│
└────┬────┘                      └─────────┘
     │ close()
     ▼
┌─────────┐
│ Closed  │
└─────────┘
```

### FR-05: 打洞协调

**描述**: 协调两端同时打洞

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-05-1 | 同时发起打洞尝试 | P0 |
| FR-05-2 | 支持角色协商（Controlling/Controlled） | P0 |
| FR-05-3 | 处理角色冲突 | P1 |

---

## 技术要求

### 技术栈

| 组件 | MVP选型 | 长期目标 | 说明 |
|------|---------|----------|------|
| STUN协议 | github.com/pion/stun | **Phase 1 自研** | 协议简单，约300-500行 |
| ICE框架 | github.com/pion/ice/v2 | **Phase 3 自研** | 复杂但有价值 |

> **抽象层设计要求**: 所有pion类型必须在封装层内完成转换，模块接口只暴露自定义类型。
> STUN封装放在`stun_pion.go`，自研实现放在`stun_native.go`。ICE同理。
> STUN协议非常简单（20字节头部+TLV属性），是自研路线中最容易启动的组件。
> 详见 [selfhost.md](../../selfhost.md)

### 目录结构

```
pkg/nat/
├── detector.go             # NAT类型检测
├── stun.go                 # STUN客户端接口
├── stun_pion.go            # STUN: 基于pion/stun（MVP）
├── stun_native.go          # STUN: 自研实现（Phase 1）
├── ice.go                  # ICE Agent接口
├── ice_pion.go             # ICE: 基于pion/ice（MVP）
├── ice_native.go           # ICE: 自研实现（Phase 3）
├── candidate.go            # 候选地址（自定义类型）
├── gatherer.go             # 候选收集
├── checker.go              # 连通性检查
├── state.go                # 连接状态机
└── types.go            # 类型定义
```

### 默认STUN服务器

```go
var DefaultSTUNServers = []string{
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
    "stun:stun.stunprotocol.org:3478",
}
```

---

## 验收标准

### AC-01: NAT检测验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | 公网IP正确识别 | 在云服务器上测试 |
| AC-01-2 | Full Cone识别 | 特定路由器环境 |
| AC-01-3 | Symmetric NAT识别 | 手机热点环境 |
| AC-01-4 | 获取公网地址正确 | 与在线工具对比 |

### AC-02: 候选收集验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | Host候选包含所有本地IP | 多网卡环境测试 |
| AC-02-2 | Srflx候选地址正确 | 与STUN工具对比 |
| AC-02-3 | 优先级计算正确 | 验证Host > Srflx > Relay |

### AC-03: ICE协商验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | 同局域网直连 | 两台内网机器 |
| AC-03-2 | 跨Cone NAT连接 | 两个家庭网络 |
| AC-03-3 | Symmetric NAT回退 | 使用手机热点 |
| AC-03-4 | 连接状态正确流转 | 观察状态机变化 |

### AC-04: 穿透成功率

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | Cone-Cone: >95% | 批量测试 |
| AC-04-2 | Cone-Symmetric: >70% | 批量测试 |
| AC-04-3 | Symmetric-Symmetric: 回退到Relay | 验证回退正确 |

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| NAT检测器 | `pkg/nat/detector.go` | NAT类型检测 |
| STUN客户端 | `pkg/nat/stun.go` | STUN协议封装 |
| ICE Agent | `pkg/nat/ice.go` | ICE协商主逻辑 |
| 单元测试 | `pkg/nat/*_test.go` | 测试代码 |
| 集成测试 | `test/nat_integration_test.go` | 真实环境测试 |

---

## 接口契约

### 提供给TASK-06的接口

```go
package nat

// 创建NAT穿透模块
func NewNATTraversal(cfg *Config) (NATTraversal, error)

type NATTraversal interface {
    // 检测NAT类型
    DetectNATType(ctx context.Context) (NATType, error)
    
    // 创建ICE Agent
    NewICEAgent(cfg *ICEConfig) (ICEAgent, error)
}

type ICEAgent interface {
    GatherCandidates(ctx context.Context) ([]Candidate, error)
    SetRemoteCandidates(candidates []Candidate) error
    Connect(ctx context.Context) (net.Conn, *CandidatePair, error)
    GetSelectedPair() (*CandidatePair, error)
    Close() error
}

func MarshalCandidate(c Candidate) ([]byte, error)
func UnmarshalCandidate(data []byte) (Candidate, error)
```

### 依赖TASK-05的接口

ICE候选交换需要通过协调服务器进行信令传递：

```go
// 需要 TASK-05 提供的信令通道
type SignalChannel interface {
    SendCandidate(to string, candidate Candidate) error
    OnRemoteCandidate(func(from string, candidate Candidate))
}
```

---

## 注意事项

### 1. pion/ice集成

pion/ice功能强大但API复杂，建议：

```go
// 封装而非直接暴露pion类型
type iceAgentWrapper struct {
    agent *ice.Agent
    log   logger.Logger
    
    // 简化的状态追踪
    state     ConnectionState
    stateMu   sync.RWMutex
    selectedPair *CandidatePair
}

func (w *iceAgentWrapper) GatherCandidates(ctx context.Context) ([]Candidate, error) {
    // 将pion的Candidate转换为我们的类型
    pionCandidates, err := w.agent.GetLocalCandidates()
    if err != nil {
        return nil, err
    }
    
    candidates := make([]Candidate, len(pionCandidates))
    for i, pc := range pionCandidates {
        candidates[i] = convertCandidate(pc)
    }
    return candidates, nil
}
```

### 2. 超时配置

```go
type ICEConfig struct {
    // 候选收集超时
    GatherTimeout time.Duration  // 默认 5s
    
    // 连通性检查超时
    CheckTimeout time.Duration   // 默认 10s
    
    // 连接建立超时
    ConnectTimeout time.Duration // 默认 30s
    
    // STUN服务器
    STUNServers []string
    
    // TURN服务器 (用于Relay候选)
    TURNServers []TURNServer
}
```

### 3. IPv4 vs IPv6

MVP阶段建议只支持IPv4：
- 简化实现
- 国内IPv6部署率不高
- 后续再添加IPv6支持

### 4. 候选数量限制

过多候选会导致：
- 协商时间长
- 信令消息大

建议限制：
- 最多8个Host候选
- 最多2个Srflx候选（不同STUN服务器）
- 最多2个Relay候选

---

## 待确认问题

| 问题 | 状态 | 影响 |
|------|------|------|
| 国内运营商NAT类型分布? | 待调研 | 影响穿透策略 |
| pion/ice长时间运行稳定性? | 待验证 | 需要压力测试 |
| 多TURN服务器故障切换? | 待设计 | 高可用相关 |
| ICE Restart机制是否需要? | 待确认 | 网络切换场景 |

---

## 参考资料

- [RFC 5389 - STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 8445 - ICE](https://tools.ietf.org/html/rfc8445)
- [pion/ice文档](https://github.com/pion/ice)
- [NAT穿透原理详解](https://tailscale.com/blog/how-nat-traversal-works)
- [WebRTC ICE实现分析](https://webrtc.github.io/webrtc-org/architecture/ice/)
