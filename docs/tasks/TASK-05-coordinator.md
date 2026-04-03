# TASK-05: 协调服务器

> 当前任务以 `docs/EXECUTION-BASELINE.md` 为准。
> MVP 只冻结 `Register / Heartbeat / ListPeers / GetPeer / Signal` 五个 RPC。

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-05 |
| 任务名称 | 协调服务器 |
| 难度 | 中 |
| 预估工作量 | 5-7天 |
| 前置依赖 | TASK-01 |
| 后续依赖 | TASK-06 |

## 任务说明

### 背景

协调服务器（Coordinator）是WinkYou的控制平面，负责：
- **节点注册**: 节点上线时注册自己的公钥和信息
- **节点发现**: 帮助节点发现网络中的其他节点
- **密钥交换**: 安全地交换WireGuard公钥
- **信令传递**: 转发ICE候选地址等信令信息

协调服务器**不处理数据流量**，数据通过P2P或中继直接传输。

### 目标

- 实现协调服务器（支持自托管）
- 实现协调客户端SDK
- 设计简洁高效的协议

---

## 功能需求

### FR-01: 节点注册

**描述**: 节点上线时向协调服务器注册

```protobuf
// 注册请求
message RegisterRequest {
    string public_key = 1;      // WireGuard公钥 (Base64)
    string name = 2;            // 节点名称
    string network_id = 3;      // 网络ID（可选，用于网络组）
    map<string, string> metadata = 4; // 元信息
}

// 注册响应
message RegisterResponse {
    string node_id = 1;         // 分配的节点ID
    string virtual_ip = 2;      // 分配的虚拟IP
    int64 expires_at = 3;       // 注册过期时间
    string network_cidr = 4;    // 网络CIDR
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-01-1 | 节点注册并获得ID | P0 |
| FR-01-2 | 分配唯一的虚拟IP | P0 |
| FR-01-3 | 支持节点名称 | P0 |
| FR-01-4 | 防止重复注册（幂等） | P0 |
| FR-01-5 | 注册过期自动清理 | P1 |

### FR-02: 心跳保活

**描述**: 维持节点在线状态

```protobuf
message HeartbeatRequest {
    string node_id = 1;
    int64 timestamp = 2;
}

message HeartbeatResponse {
    int64 server_time = 1;
    repeated string updated_peers = 2; // 有更新的peer列表
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-02-1 | 定期心跳（默认30s） | P0 |
| FR-02-2 | 心跳超时判定离线（默认90s） | P0 |
| FR-02-3 | 心跳响应携带peer更新提示 | P1 |

### FR-03: 节点发现

**描述**: 查询网络中的其他节点

```protobuf
message ListPeersRequest {
    string network_id = 1;      // 网络ID过滤（可选）
    bool online_only = 2;       // 只返回在线节点
}

message ListPeersResponse {
    repeated PeerInfo peers = 1;
}

message PeerInfo {
    string node_id = 1;
    string name = 2;
    string public_key = 3;
    string virtual_ip = 4;
    bool online = 5;
    int64 last_seen = 6;
    repeated string endpoints = 7;  // 已知的公网地址
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-03-1 | 列出所有节点 | P0 |
| FR-03-2 | 获取单个节点详情 | P0 |
| FR-03-3 | 过滤在线/离线节点 | P1 |
| FR-03-4 | 按网络组过滤 | P1 |

### FR-04: 信令传递

**描述**: 在节点间转发信令消息（用于ICE协商）

```protobuf
message SignalRequest {
    string from_node = 1;
    string to_node = 2;
    bytes payload = 3;        // 信令内容（ICE候选等）
    SignalType type = 4;
}

enum SignalType {
    SIGNAL_ICE_CANDIDATE = 0;
    SIGNAL_ICE_OFFER = 1;
    SIGNAL_ICE_ANSWER = 2;
}

message SignalNotification {
    string from_node = 1;
    bytes payload = 2;
    SignalType type = 3;
    int64 timestamp = 4;
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-04-1 | 发送信令到指定节点 | P0 |
| FR-04-2 | 接收其他节点的信令 | P0 |
| FR-04-3 | 信令消息不持久化 | P0 |
| FR-04-4 | 离线节点信令丢弃 | P0 |

### FR-05: 客户端SDK

**描述**: 为客户端提供便捷的协调服务器访问接口

```go
type CoordinatorClient interface {
    // 连接管理
    Connect(ctx context.Context) error
    Close() error
    
    // 注册
    Register(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
    
    // 心跳（自动）
    StartHeartbeat(ctx context.Context, interval time.Duration) error
    StopHeartbeat()
    
    // 节点发现
    ListPeers(ctx context.Context, opts ...ListOption) ([]*PeerInfo, error)
    GetPeer(ctx context.Context, nodeID string) (*PeerInfo, error)
    
    // 信令
    SendSignal(ctx context.Context, to string, signalType SignalType, payload []byte) error
    OnSignal(handler func(signal *SignalNotification))
    
    // 事件
    OnPeerUpdate(handler func(peer *PeerInfo, event PeerEvent))
}
```

---

## 技术要求

### 技术栈

| 组件 | 选型 | 说明 |
|------|------|------|
| RPC框架 | gRPC | 双向流支持信令推送 |
| 序列化 | Protocol Buffers | 与gRPC配套 |
| 数据库 | SQLite | 轻量级，便于自托管 |
| 传输安全 | TLS | 证书可选自签名 |

### 目录结构

```
pkg/coordinator/
├── server/
│   ├── server.go           # gRPC服务器
│   ├── registry.go         # 节点注册管理
│   ├── signaling.go        # 信令转发
│   ├── heartbeat.go        # 心跳管理
│   └── storage.go          # 持久化存储
├── client/
│   ├── client.go           # 客户端SDK
│   ├── connection.go       # 连接管理
│   └── signal.go           # 信令处理
api/
└── proto/
    └── coordinator.proto   # 协议定义

cmd/
└── wink-coordinator/
    └── main.go             # 协调服务器入口
```

### API定义

```protobuf
syntax = "proto3";
package wink.coordinator.v1;

service Coordinator {
    // 节点注册
    rpc Register(RegisterRequest) returns (RegisterResponse);
    
    // 心跳
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
    
    // 节点列表
    rpc ListPeers(ListPeersRequest) returns (ListPeersResponse);
    
    // 获取节点
    rpc GetPeer(GetPeerRequest) returns (PeerInfo);
    
    // 信令通道（双向流）
    rpc Signal(stream SignalRequest) returns (stream SignalNotification);
}
```

**MVP 明确不包含**:
- `GetTURNCredentials`
- 多协调服务器同步
- PostgreSQL 高可用部署

### 数据库Schema

```sql
-- 节点表
CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    public_key TEXT UNIQUE NOT NULL,
    name TEXT,
    virtual_ip TEXT UNIQUE NOT NULL,
    network_id TEXT DEFAULT 'default',
    metadata TEXT,  -- JSON
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

-- 索引
CREATE INDEX idx_nodes_network ON nodes(network_id);
CREATE INDEX idx_nodes_last_seen ON nodes(last_seen);
CREATE INDEX idx_nodes_public_key ON nodes(public_key);

-- IP分配追踪
CREATE TABLE ip_allocations (
    virtual_ip TEXT PRIMARY KEY,
    node_id TEXT REFERENCES nodes(id),
    allocated_at INTEGER NOT NULL
);
```

---

## 验收标准

### AC-01: 节点注册验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | 新节点能注册成功 | 调用Register API |
| AC-01-2 | 返回唯一虚拟IP | 多次注册不冲突 |
| AC-01-3 | 同公钥重复注册返回相同信息 | 幂等性测试 |
| AC-01-4 | 无效公钥被拒绝 | 格式校验测试 |

### AC-02: 心跳验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | 心跳能更新last_seen | 查询数据库验证 |
| AC-02-2 | 超时后标记为离线 | 停止心跳后查询 |
| AC-02-3 | 重新心跳恢复在线 | 恢复心跳后查询 |

### AC-03: 节点发现验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | ListPeers返回所有节点 | 多节点注册后查询 |
| AC-03-2 | 在线过滤正确 | 混合在线离线节点 |
| AC-03-3 | GetPeer返回正确信息 | 核对公钥/IP |

### AC-04: 信令传递验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | A发送信令B能收到 | 端到端测试 |
| AC-04-2 | 离线节点信令不报错 | 发送给离线节点 |
| AC-04-3 | 信令延迟<100ms | 性能测试 |

### AC-05: 部署验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-05-1 | 单命令启动 | `./wink-coordinator` |
| AC-05-2 | Docker部署正常 | docker run测试 |
| AC-05-3 | 数据持久化 | 重启后数据保留 |

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| Proto定义 | `api/proto/coordinator.proto` | gRPC协议 |
| 服务器实现 | `pkg/coordinator/server/` | 协调服务器 |
| 客户端SDK | `pkg/coordinator/client/` | 客户端库 |
| 服务器入口 | `cmd/wink-coordinator/` | 可执行程序 |
| Dockerfile | `deploy/coordinator/Dockerfile` | Docker镜像 |
| 配置示例 | `deploy/coordinator/config.yaml` | 配置模板 |

---

## 接口契约

### 提供给TASK-06的接口

```go
package client

// NewClient 创建协调服务器客户端
func NewClient(cfg *Config) (CoordinatorClient, error)

type Config struct {
    ServerURL    string
    TLSConfig    *tls.Config  // nil则使用系统CA
    Timeout      time.Duration
    RetryPolicy  RetryPolicy
}

type CoordinatorClient interface {
    // 完整接口见上文
}
```

### 提供给TASK-04的接口

NAT穿透模块需要通过协调服务器交换ICE候选：

```go
// 封装信令发送
type SignalingAdapter struct {
    client CoordinatorClient
}

func (s *SignalingAdapter) SendCandidate(to string, candidate nat.Candidate) error {
    payload, _ := json.Marshal(candidate)
    return s.client.SendSignal(context.Background(), to, SIGNAL_ICE_CANDIDATE, payload)
}

func (s *SignalingAdapter) OnCandidate(handler func(from string, candidate nat.Candidate)) {
    s.client.OnSignal(func(signal *SignalNotification) {
        if signal.Type == SIGNAL_ICE_CANDIDATE {
            var candidate nat.Candidate
            json.Unmarshal(signal.Payload, &candidate)
            handler(signal.FromNode, candidate)
        }
    })
}
```

---

## 配置说明

### 服务器配置

```yaml
# coordinator-config.yaml
server:
  listen: ":443"
  tls:
    cert_file: "/etc/wink/cert.pem"
    key_file: "/etc/wink/key.pem"
    
storage:
  type: "sqlite"
  path: "/var/lib/wink/coordinator.db"
  
network:
  cidr: "10.100.0.0/16"      # 虚拟网络地址空间
  reserved:                   # 保留地址
    - "10.100.0.1"            # 网关（如需要）
    - "10.100.0.254"          # DNS（如需要）

heartbeat:
  interval: 30s              # 期望的心跳间隔
  timeout: 90s               # 超时判定离线

log:
  level: "info"
```

### 客户端配置

```yaml
# 在客户端config.yaml中
coordinator:
  url: "https://coord.example.com:443"
  timeout: 10s
  
  # 自签名证书场景
  tls:
    insecure_skip_verify: false
    ca_file: "/etc/wink/ca.pem"
```

---

## 注意事项

### 1. 并发安全

协调服务器会处理大量并发请求：
- 使用 `sync.RWMutex` 保护共享状态
- 使用连接池管理数据库连接
- 避免全局锁

### 2. 虚拟IP分配

IP分配策略：
1. 检查节点是否已有分配的IP
2. 如果有，返回现有IP（幂等）
3. 如果没有，从池中分配新IP

```go
func (r *Registry) allocateIP(nodeID string) (net.IP, error) {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    // 检查现有分配
    if ip, exists := r.nodeToIP[nodeID]; exists {
        return ip, nil
    }
    
    // 分配新IP
    for ip := r.nextIP; ; ip = r.incrementIP(ip) {
        if !r.isReserved(ip) && !r.isAllocated(ip) {
            r.nodeToIP[nodeID] = ip
            r.ipToNode[ip.String()] = nodeID
            r.nextIP = r.incrementIP(ip)
            return ip, nil
        }
    }
}
```

### 3. 信令消息安全

信令消息虽然经过TLS传输，但考虑：
- 消息不持久化，内存中转发
- 离线节点消息直接丢弃
- 可选：消息端到端加密（使用WireGuard密钥）

### 4. 自签名证书

自托管场景支持自签名证书：

```bash
# 生成CA和服务器证书
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.pem

openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365
```

---

## 待确认问题

| 问题 | 状态 | 影响 |
|------|------|------|
| 是否需要用户认证？ | 待决策 | MVP可暂不实现 |
| 网络组功能MVP是否必需？ | 待确认 | 可简化为单网络 |
| 是否支持PostgreSQL？ | 待决策 | 高可用场景需要 |
| 多协调服务器同步？ | 待设计 | V2.0功能 |

---

## 参考资料

- [Headscale源码](https://github.com/juanfont/headscale)
- [gRPC Go教程](https://grpc.io/docs/languages/go/)
- [Tailscale控制协议分析](https://tailscale.com/blog/how-tailscale-works)
