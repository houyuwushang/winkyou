# TASK-06: 客户端核心

> 当前任务以 `docs/EXECUTION-BASELINE.md` 为准。
> `TASK-07` 不是本任务的开发启动前置依赖，但属于 MVP 发布门禁依赖。

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-06 |
| 任务名称 | 客户端核心 |
| 难度 | **高** |
| 预估工作量 | 7-10天 |
| 前置依赖 | TASK-02, TASK-03, TASK-04, TASK-05 |
| 后续依赖 | 无（顶层集成模块） |

## 任务说明

### 背景

客户端核心是整个系统的集成层，负责协调其他所有模块，实现完整的P2P虚拟局域网功能。它是用户直接交互的组件，通过CLI或GUI使用。

### 目标

- 整合所有底层模块
- 实现完整的连接生命周期管理
- 提供简洁的用户接口
- 确保系统稳定可靠

---

## 功能需求

### FR-01: 核心引擎

**描述**: 整合各模块，管理整体生命周期

```go
// Engine 客户端核心引擎
type Engine interface {
    // 生命周期
    Start(ctx context.Context) error
    Stop() error
    
    // 状态查询
    Status() *EngineStatus
    
    // Peer管理
    GetPeers() []*PeerStatus
    ConnectToPeer(nodeID string) error
    DisconnectFromPeer(nodeID string) error
    
    // 事件订阅
    OnStatusChange(handler func(status *EngineStatus))
    OnPeerChange(handler func(peer *PeerStatus, event PeerEvent))
}

type EngineStatus struct {
    State       EngineState
    VirtualIP   net.IP
    NetworkCIDR *net.IPNet
    Uptime      time.Duration
    ConnectedPeers int
    BytesSent   uint64
    BytesRecv   uint64
}

type EngineState int

const (
    EngineStateStopped EngineState = iota
    EngineStateStarting
    EngineStateConnecting
    EngineStateConnected
    EngineStateReconnecting
    EngineStateStopping
)
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-01-1 | 启动/停止引擎 | P0 |
| FR-01-2 | 状态查询 | P0 |
| FR-01-3 | 状态变化通知 | P0 |
| FR-01-4 | 优雅关闭 | P1 |

### FR-02: 连接管理

**描述**: 管理与其他节点的连接

```go
type PeerStatus struct {
    NodeID       string
    Name         string
    VirtualIP    net.IP
    PublicKey    string
    State        PeerState
    Endpoint     *net.UDPAddr
    Latency      time.Duration
    LastSeen     time.Time
    TxBytes      uint64
    RxBytes      uint64
    ConnectionType ConnectionType // Direct / Relay
}

type PeerState int

const (
    PeerStateDisconnected PeerState = iota
    PeerStateConnecting
    PeerStateConnected
)

type ConnectionType int

const (
    ConnectionTypeDirect ConnectionType = iota // P2P直连
    ConnectionTypeRelay                         // 中继
)
```

说明：

- 当前 MVP 中 `ConnectionTypeRelay` 默认指 `TURN relay`
- 若后续支持“节点 A 作为 B 到 C 的受信中继”，建议拆分为 `TURNRelay` 与 `PeerRelay`
- 该扩展设计见 `../PEER-RELAY-DESIGN.md`

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-02-1 | 自动发现并连接peer | P0 |
| FR-02-2 | 连接状态追踪 | P0 |
| FR-02-3 | 连接类型识别 | P0 |
| FR-02-4 | 延迟测量 | P1 |
| FR-02-5 | 流量统计 | P1 |

### FR-03: 自动重连

**描述**: 网络故障时自动恢复

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-03-1 | 断线检测 | P0 |
| FR-03-2 | 自动重连协调服务器 | P0 |
| FR-03-3 | 自动重建peer连接 | P0 |
| FR-03-4 | 指数退避重试 | P1 |
| FR-03-5 | 网络切换处理 | P1 |

**重连策略**:
```go
type RetryPolicy struct {
    InitialInterval time.Duration // 初始间隔 (1s)
    MaxInterval     time.Duration // 最大间隔 (5min)
    Multiplier      float64       // 指数因子 (2.0)
    MaxRetries      int           // 最大重试次数 (0=无限)
}
```

### FR-04: 连接流程编排

**描述**: 协调各模块完成连接建立

```
┌─────────────────────────────────────────────────────────────┐
│                    连接建立流程                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 初始化                                                   │
│     ├── 加载配置                                             │
│     ├── 创建/加载密钥对                                      │
│     └── 创建网络接口 (TASK-02)                               │
│                                                              │
│  2. 注册到协调服务器                                         │
│     ├── 连接协调服务器 (TASK-05)                             │
│     ├── 发送注册请求                                         │
│     ├── 获取虚拟IP                                           │
│     └── 配置网络接口IP                                       │
│                                                              │
│  3. 启动WireGuard隧道                                        │
│     ├── 创建隧道 (TASK-03)                                   │
│     └── 关联网络接口                                         │
│                                                              │
│  4. 发现并连接Peers                                          │
│     ├── 从协调服务器获取peer列表                             │
│     └── 对每个peer:                                          │
│         ├── 收集ICE候选 (TASK-04)                            │
│         ├── 交换候选 (via 协调服务器)                        │
│         ├── ICE协商                                          │
│         ├── 确定Endpoint                                     │
│         └── 添加WireGuard Peer                               │
│                                                              │
│  5. 保活和维护                                               │
│     ├── 心跳协调服务器                                       │
│     ├── 监听peer变化                                         │
│     └── 处理新peer加入                                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### FR-05: CLI实现

**描述**: 完整的命令行接口

```bash
# 启动连接
wink up [--config <path>] [--verbose]

# 断开连接
wink down

# 查看状态
wink status [--json]

# 查看节点列表
wink peers [--json]

# Ping节点
wink ping <node-name|virtual-ip>

# 生成密钥
wink genkey

# 调试信息
wink debug
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-05-1 | wink up 完整实现 | P0 |
| FR-05-2 | wink down 完整实现 | P0 |
| FR-05-3 | wink status 完整实现 | P0 |
| FR-05-4 | wink peers 完整实现 | P0 |
| FR-05-5 | wink ping 实现 | P1 |
| FR-05-6 | JSON输出格式 | P1 |

**输出示例**:

```bash
$ wink status
WinkYou Status
--------------
State:         Connected
Virtual IP:    10.100.0.5/16
Uptime:        2h 30m
Peers:         3 online

$ wink peers
NAME          IP            STATUS     LATENCY   TYPE
laptop        10.100.0.2    online     5ms       direct
server        10.100.0.3    online     15ms      direct
phone         10.100.0.4    online     50ms      relay

$ wink ping laptop
PING 10.100.0.2 (laptop) via wink0
64 bytes from 10.100.0.2: time=5.2ms
64 bytes from 10.100.0.2: time=4.8ms
64 bytes from 10.100.0.2: time=5.1ms
--- 10.100.0.2 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max = 4.8/5.0/5.2 ms
```

---

## 技术要求

### 目录结构

```
pkg/client/
├── engine.go           # 核心引擎
├── engine_impl.go      # 引擎实现
├── peer_manager.go     # Peer管理
├── connection.go       # 连接管理
├── state.go            # 状态机
├── reconnect.go        # 重连逻辑
└── events.go           # 事件系统

cmd/wink/cmd/
├── root.go             # 根命令
├── up.go               # up命令
├── down.go             # down命令
├── status.go           # status命令
├── peers.go            # peers命令
├── ping.go             # ping命令
└── genkey.go           # genkey命令
```

### 核心实现

```go
type engineImpl struct {
    cfg     *config.Config
    log     logger.Logger
    
    // 底层模块
    netif       netif.NetworkInterface
    tunnel      tunnel.Tunnel
    natTraversal nat.NATTraversal
    coordinator  coordinator.CoordinatorClient
    
    // 状态管理
    state       EngineState
    stateMu     sync.RWMutex
    
    // Peer管理
    peers       map[string]*peerConnection
    peersMu     sync.RWMutex
    
    // 控制
    ctx         context.Context
    cancel      context.CancelFunc
    wg          sync.WaitGroup
    
    // 事件
    statusHandlers []func(*EngineStatus)
    peerHandlers   []func(*PeerStatus, PeerEvent)
}

func (e *engineImpl) Start(ctx context.Context) error {
    e.ctx, e.cancel = context.WithCancel(ctx)
    
    // 1. 选择并创建网络接口
    netif, err := netif.New(netif.Config{
        Backend: e.cfg.NetIf.Backend,
        MTU:     e.cfg.NetIf.MTU,
    })
    if err != nil {
        return fmt.Errorf("create netif: %w", err)
    }
    e.netif = netif
    
    // 2. 连接协调服务器
    if err := e.coordinator.Connect(e.ctx); err != nil {
        return fmt.Errorf("connect coordinator: %w", err)
    }
    
    // 3. 注册
    resp, err := e.coordinator.Register(e.ctx, &coordinator.RegisterRequest{
        PublicKey: e.cfg.WireGuard.PublicKey(),
        Name:      e.cfg.Node.Name,
    })
    if err != nil {
        return fmt.Errorf("register: %w", err)
    }
    
    // 4. 配置网络接口
    _, networkCIDR, err := net.ParseCIDR(resp.NetworkCIDR)
    if err != nil {
        return fmt.Errorf("parse network cidr: %w", err)
    }
    if err := e.netif.SetIP(net.ParseIP(resp.VirtualIP), networkCIDR.Mask); err != nil {
        return fmt.Errorf("set ip: %w", err)
    }
    
    // 5. 创建WireGuard隧道
    e.tunnel, err = tunnel.New(tunnel.Config{
        Interface:  e.netif,
        PrivateKey: e.cfg.WireGuard.PrivateKey,
        ListenPort: e.cfg.WireGuard.ListenPort,
    })
    if err != nil {
        return fmt.Errorf("create tunnel: %w", err)
    }
    
    if err := e.tunnel.Start(); err != nil {
        return fmt.Errorf("start tunnel: %w", err)
    }
    
    // 6. 启动后台任务
    e.wg.Add(3)
    go e.heartbeatLoop()
    go e.peerDiscoveryLoop()
    go e.signalHandlerLoop()
    
    e.setState(EngineStateConnected)
    return nil
}
```

### Peer连接流程

```go
func (e *engineImpl) connectToPeer(peer *coordinator.PeerInfo) error {
    e.log.Info("connecting to peer", logger.String("name", peer.Name))
    
    // 1. 创建ICE Agent
    iceAgent, err := e.natTraversal.NewICEAgent(&nat.ICEConfig{
        STUNServers: e.cfg.NAT.STUNServers,
        TURNServers: e.cfg.NAT.TURNServers,
    })
    if err != nil {
        return err
    }
    
    // 2. 收集本地候选
    localCandidates, err := iceAgent.GatherCandidates(e.ctx)
    if err != nil {
        return err
    }
    
    // 3. 通过协调服务器交换候选
    for _, c := range localCandidates {
        payload, err := nat.MarshalCandidate(c)
        if err != nil {
            return err
        }
        if err := e.coordinator.SendSignal(
            e.ctx,
            peer.NodeID,
            coordinator.SIGNAL_ICE_CANDIDATE,
            payload,
        ); err != nil {
            return err
        }
    }
    
    // 4. 接收对端候选（异步，通过signalHandler设置）
    
    // 5. 建立ICE连接
    conn, pair, err := iceAgent.Connect(e.ctx)
    if err != nil {
        return err
    }
    _ = conn

    // 6. 获取选定的Endpoint
    endpoint := pair.Remote.Address
    
    // 7. 添加WireGuard Peer
    err = e.tunnel.AddPeer(&tunnel.PeerConfig{
        PublicKey:  peer.PublicKey,
        AllowedIPs: []net.IPNet{{IP: peer.VirtualIP, Mask: net.CIDRMask(32, 32)}},
        Endpoint:   endpoint,
        Keepalive:  25 * time.Second,
    })
    if err != nil {
        return err
    }
    
    // 8. 更新状态
    e.updatePeerState(peer.NodeID, PeerStateConnected, endpoint)
    
    return nil
}
```

---

## 验收标准

### AC-01: 基本连接验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | wink up 成功启动 | 执行命令无错误 |
| AC-01-2 | 注册到协调服务器 | 日志显示注册成功 |
| AC-01-3 | 获得虚拟IP | wink status显示IP |
| AC-01-4 | wink down 正常停止 | 资源正确释放 |

### AC-02: P2P连接验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | 两节点能建立连接 | wink peers显示对方 |
| AC-02-2 | 能ping通对端 | wink ping <peer> 成功 |
| AC-02-3 | TCP通信正常 | curl/nc测试 |
| AC-02-4 | UDP通信正常 | DNS或自定义测试 |

### AC-03: 重连验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | 协调服务器断开后重连 | 重启协调服务器 |
| AC-03-2 | 网络切换后恢复 | WiFi切4G |
| AC-03-3 | Peer掉线后重连 | 重启对端 |
| AC-03-4 | 指数退避正确 | 观察日志间隔 |

### AC-04: 端到端场景验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | 同局域网直连 | 两台内网机器 |
| AC-04-2 | 跨NAT连接 | 不同网络 |
| AC-04-3 | 中继回退 | 对称NAT场景 |
| AC-04-4 | 三节点组网 | 三台机器互ping |

---

## post-MVP 扩展说明

### Trusted Peer Relay

若后续支持 `peer relay`，客户端核心需要额外承担：

- 维护 `via_node_id` 路由状态
- 将 `B -> C via A` 与 `C -> B via A` 成对安装和回收
- 在 `direct / peer-relay / turn-relay` 之间切换
- 在 `wink status` / `wink peers` 中展示 `via` 节点信息

这部分不属于当前 MVP 客户端交付，单独见 `../PEER-RELAY-DESIGN.md`。

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| 客户端引擎 | `pkg/client/` | 核心引擎代码 |
| CLI完整实现 | `cmd/wink/cmd/` | 所有命令 |
| 集成测试 | `test/e2e/` | 端到端测试 |
| 用户文档 | `docs/usage.md` | 使用指南 |

---

## 注意事项

### 1. 并发和锁

引擎涉及多个并发goroutine：
- heartbeatLoop
- peerDiscoveryLoop
- signalHandlerLoop
- 各peer的连接goroutine

需要仔细设计锁粒度，避免死锁。

### 2. 优雅关闭

```go
func (e *engineImpl) Stop() error {
    e.setState(EngineStateStopping)
    
    // 1. 取消context，通知所有goroutine
    e.cancel()
    
    // 2. 等待goroutine退出
    done := make(chan struct{})
    go func() {
        e.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        // 正常退出
    case <-time.After(10 * time.Second):
        e.log.Warn("force shutdown after timeout")
    }
    
    // 3. 清理资源
    e.tunnel.Stop()
    e.netif.Close()
    e.coordinator.Close()
    
    e.setState(EngineStateStopped)
    return nil
}
```

### 3. 信号处理

CLI需要处理系统信号：

```go
func main() {
    // 启动引擎
    engine.Start(context.Background())
    
    // 等待信号
    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
    <-sigCh
    
    // 优雅关闭
    fmt.Println("\nShutting down...")
    engine.Stop()
}
```

### 4. 守护进程模式

后续可考虑：
- Linux: systemd服务
- Windows: Windows服务
- macOS: launchd

MVP阶段前台运行即可。

---

## 待确认问题

| 问题 | 状态 | 影响 |
|------|------|------|
| 是否需要后台守护进程？ | 待决策 | MVP可不需要 |
| 多网络组支持？ | 待确认 | MVP可单网络 |
| 是否需要系统托盘？ | 待决策 | GUI相关 |
| 日志持久化方案？ | 待决策 | 文件或journald |

---

## 参考资料

- [Tailscale客户端架构](https://github.com/tailscale/tailscale/tree/main/ipn)
- [WireGuard Go实现](https://git.zx2c4.com/wireguard-go/)
- [Cobra CLI最佳实践](https://github.com/spf13/cobra/blob/main/user_guide.md)
