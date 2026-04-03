# TASK-07: 中继服务

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-07 |
| 任务名称 | 中继服务 |
| 难度 | 中 |
| 预估工作量 | 4-5天 |
| 前置依赖 | TASK-04 |
| 后续依赖 | TASK-06 |

## 任务说明

### 背景

当NAT穿透失败（如两端都是对称型NAT）时，需要通过中继服务器转发数据。中继服务是P2P连接的**保底方案**，确保100%连通性。

本模块实现：
- TURN中继服务器
- 中继客户端集成
- 智能中继选择

### 目标

- 实现标准TURN协议服务器
- 支持多中继服务器部署
- 中继流量监控和限制

---

## 功能需求

### FR-01: TURN服务器

**描述**: 实现TURN协议服务器

```go
type TURNServer interface {
    // 启动服务
    Start() error
    Stop() error
    
    // 配置
    SetCredentials(username, password string)
    SetRealm(realm string)
    
    // 监控
    GetStats() *TURNStats
    GetAllocations() []*AllocationInfo
}

type TURNStats struct {
    ActiveAllocations int
    TotalAllocations  uint64
    BytesRelayed      uint64
    CurrentBandwidth  uint64 // bytes/second
}

type AllocationInfo struct {
    ClientAddr   *net.UDPAddr
    RelayedAddr  *net.UDPAddr
    CreatedAt    time.Time
    BytesSent    uint64
    BytesRecv    uint64
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-01-1 | 支持UDP中继 | P0 |
| FR-01-2 | 支持长期凭证认证 | P0 |
| FR-01-3 | Allocation管理 | P0 |
| FR-01-4 | Permission管理 | P0 |
| FR-01-5 | Channel绑定 | P1 |
| FR-01-6 | TCP中继（可选） | P2 |

### FR-02: 中继客户端

**描述**: TURN客户端集成到NAT穿透模块

```go
type TURNClient interface {
    // 创建Allocation
    Allocate(ctx context.Context) (*Allocation, error)
    
    // 获取中继地址
    GetRelayedAddress() *net.UDPAddr
    
    // 添加权限
    AddPermission(peerAddr *net.UDPAddr) error
    
    // 创建Channel
    CreateChannel(peerAddr *net.UDPAddr) (*Channel, error)
    
    // 数据传输
    Send(data []byte, to *net.UDPAddr) error
    Receive() ([]byte, *net.UDPAddr, error)
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-02-1 | Allocation创建 | P0 |
| FR-02-2 | 数据发送/接收 | P0 |
| FR-02-3 | Allocation刷新 | P0 |
| FR-02-4 | 多服务器支持 | P1 |
| FR-02-5 | 故障切换 | P1 |

### FR-03: 智能中继选择

**描述**: 选择最优的中继服务器

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-03-1 | 延迟测量 | P1 |
| FR-03-2 | 负载均衡 | P1 |
| FR-03-3 | 地理位置优选 | P2 |
| FR-03-4 | 故障检测 | P1 |

```go
type RelaySelector interface {
    // 选择最优中继
    SelectBest(ctx context.Context) (*TURNServer, error)
    
    // 测量延迟
    MeasureLatency(server *TURNServer) (time.Duration, error)
    
    // 标记故障
    MarkFailed(server *TURNServer)
}
```

### FR-04: 流量控制

**描述**: 中继流量限制和监控

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-04-1 | 单Allocation带宽限制 | P1 |
| FR-04-2 | 总带宽限制 | P1 |
| FR-04-3 | 流量统计 | P1 |
| FR-04-4 | 异常流量告警 | P2 |

---

## 技术要求

### 技术栈

| 组件 | 选型 | 说明 |
|------|------|------|
| TURN服务器 | github.com/pion/turn/v2 | pion官方实现 |
| 认证 | 长期凭证 | RFC 5389 |

### 目录结构

```
pkg/relay/
├── server/
│   ├── server.go         # TURN服务器
│   ├── allocation.go     # Allocation管理
│   ├── auth.go           # 认证
│   └── stats.go          # 统计
├── client/
│   ├── client.go         # TURN客户端
│   ├── allocation.go     # 客户端Allocation
│   └── channel.go        # Channel管理
└── selector.go           # 中继选择器

cmd/
└── wink-relay/
    └── main.go           # 中继服务器入口
```

### TURN服务器实现

```go
import (
    "github.com/pion/turn/v2"
)

type turnServer struct {
    server *turn.Server
    config *Config
    stats  *Stats
}

func NewTURNServer(cfg *Config) (*turnServer, error) {
    // 创建认证处理器
    authHandler := func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
        // 验证用户名密码
        password, ok := cfg.GetPassword(username)
        if !ok {
            return nil, false
        }
        return turn.GenerateAuthKey(username, realm, password), true
    }
    
    // 配置服务器
    s, err := turn.NewServer(turn.ServerConfig{
        Realm:       cfg.Realm,
        AuthHandler: authHandler,
        PacketConnConfigs: []turn.PacketConnConfig{
            {
                PacketConn: udpListener,
                RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
                    RelayAddress: net.ParseIP(cfg.RelayIP),
                    Address:      "0.0.0.0",
                },
            },
        },
    })
    
    return &turnServer{server: s, config: cfg}, nil
}
```

### 中继候选集成

中继候选需要在ICE候选收集时添加：

```go
// 在 TASK-04 的 CandidateGatherer 中
func (g *gatherer) gatherRelayCandidates(ctx context.Context) ([]Candidate, error) {
    var candidates []Candidate
    
    for _, turnServer := range g.config.TURNServers {
        client, err := relay.NewClient(turnServer)
        if err != nil {
            continue
        }
        
        allocation, err := client.Allocate(ctx)
        if err != nil {
            continue
        }
        
        candidates = append(candidates, Candidate{
            Type:     CandidateTypeRelay,
            Address:  allocation.RelayedAddr,
            Priority: calculateRelayPriority(),
            RelatedAddr: client.LocalAddr(),
        })
    }
    
    return candidates, nil
}
```

---

## 验收标准

### AC-01: TURN服务器验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | 服务器能启动 | 运行wink-relay |
| AC-01-2 | 能创建Allocation | TURN客户端测试 |
| AC-01-3 | 认证正确工作 | 错误凭证被拒绝 |
| AC-01-4 | 数据能中继 | 端到端测试 |

### AC-02: 中继连接验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | 对称NAT能通过中继连接 | 手机热点测试 |
| AC-02-2 | 中继后ping能通 | wink ping |
| AC-02-3 | 中继后TCP/UDP能通 | 应用层测试 |

### AC-03: 性能验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | 中继延迟增加<50ms | 对比直连 |
| AC-03-2 | 中继吞吐>10Mbps | iperf测试 |
| AC-03-3 | 支持100+并发Allocation | 压力测试 |

### AC-04: 可靠性验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | Allocation超时正确释放 | 等待超时 |
| AC-04-2 | 服务器重启后恢复 | 重启测试 |
| AC-04-3 | 无内存泄漏 | 长时间运行 |

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| TURN服务器 | `pkg/relay/server/` | 服务器代码 |
| TURN客户端 | `pkg/relay/client/` | 客户端代码 |
| 服务器入口 | `cmd/wink-relay/` | 可执行程序 |
| Dockerfile | `deploy/relay/Dockerfile` | Docker镜像 |
| 配置示例 | `deploy/relay/config.yaml` | 配置模板 |

---

## 配置说明

### 中继服务器配置

```yaml
# relay-config.yaml
server:
  listen_udp: ":3478"
  listen_tcp: ":3478"      # 可选
  
  # 公网IP（中继地址）
  relay_ip: "1.2.3.4"
  
  # 中继端口范围
  relay_port_range:
    min: 49152
    max: 65535

auth:
  realm: "wink.relay"
  # 静态用户（开发测试）
  static_users:
    - username: "wink"
      password: "secret"
  # 或集成协调服务器认证
  coordinator_url: "https://coord.example.com"

limits:
  max_allocations: 1000
  allocation_lifetime: 600s
  max_bandwidth_per_allocation: 10Mbps
  
log:
  level: "info"
```

### 客户端配置

```yaml
# 在客户端config.yaml中
nat:
  turn_servers:
    - url: "turn:relay.example.com:3478"
      username: "wink"
      password: "secret"
    - url: "turn:relay2.example.com:3478"
      username: "wink"
      password: "secret"
```

---

## 注意事项

### 1. 认证方案

**长期凭证 vs 短期凭证**:

| 方案 | 优点 | 缺点 |
|------|------|------|
| 长期凭证 | 简单，配置固定 | 安全性较低 |
| 短期凭证 | 动态生成，更安全 | 需要与协调服务器集成 |

建议MVP使用长期凭证，后续升级为协调服务器签发短期凭证。

### 2. 中继带宽成本

中继流量产生带宽成本：
- 国内云服务器带宽约 0.5-1元/GB
- 需要限制单用户带宽
- 考虑按流量计费（后期）

### 3. 多地域部署

为降低延迟，建议：
- 部署多个中继服务器
- 客户端自动选择最近的
- 支持地理位置API查询

### 4. TURN over TCP

某些极端网络环境UDP被封锁，需要TCP回退：
- TURN协议支持TCP传输
- 性能低于UDP
- 作为最后手段

---

## 与其他模块的接口

### 提供给TASK-04的接口

```go
package relay

// NewClient 创建TURN客户端
func NewClient(server *TURNServerConfig) (TURNClient, error)

// TURNClient 见上文定义
```

### TURN凭证获取（集成协调服务器）

```go
// 从协调服务器获取临时TURN凭证
type TURNCredentials struct {
    Username string
    Password string
    TTL      time.Duration
    Servers  []string
}

// 协调服务器新增API
rpc GetTURNCredentials(GetTURNCredentialsRequest) returns (TURNCredentials);
```

---

## 待确认问题

| 问题 | 状态 | 影响 |
|------|------|------|
| 认证方案选择？ | 待决策 | 安全性相关 |
| 初期部署几个中继？ | 待决策 | 成本相关 |
| 是否需要TCP TURN？ | 待确认 | 复杂度增加 |
| 流量限制策略？ | 待设计 | 成本控制 |

---

## 部署建议

### 单机部署

```bash
# Docker方式
docker run -d --name wink-relay \
  -p 3478:3478/udp \
  -p 49152-65535:49152-65535/udp \
  -e RELAY_IP=1.2.3.4 \
  wink/relay:latest
```

### 云服务器选择

| 考虑因素 | 建议 |
|----------|------|
| 带宽 | 按量计费，初期1-5Mbps |
| 地域 | 优先华东/华北 |
| 规格 | 1核1G足够 |
| 网络 | 确保UDP不被限制 |

---

## 参考资料

- [RFC 5766 - TURN](https://tools.ietf.org/html/rfc5766)
- [RFC 8656 - TURN Allocation](https://tools.ietf.org/html/rfc8656)
- [pion/turn文档](https://github.com/pion/turn)
- [coturn项目](https://github.com/coturn/coturn) - C实现的TURN服务器参考
