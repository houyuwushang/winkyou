# TASK-03: WireGuard隧道层

> 当前任务以 `docs/EXECUTION-BASELINE.md` 为准。
> MVP 固定交付 `wireguard-go` 封装，不将 `Wink Protocol v1` 纳入本任务交付范围。

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-03 |
| 任务名称 | WireGuard隧道层 |
| 难度 | 中 |
| 预估工作量 | 4-5天 |
| 前置依赖 | TASK-02 |
| 后续依赖 | TASK-06 |

## 任务说明

### 背景

WireGuard是一个现代化的VPN协议，以其简洁、高效和安全著称。本模块负责封装WireGuard，为上层提供简单的隧道创建和管理能力。

### 目标

- 封装 wireguard-go 库，提供简化的API
- 实现密钥对生成和管理
- 实现Peer动态添加/删除
- 支持Endpoint动态更新（漫游支持）

---

## 功能需求

### FR-01: 隧道管理

**描述**: 提供WireGuard隧道的创建、配置和管理

```go
// Tunnel WireGuard隧道
type Tunnel interface {
    // 生命周期
    Start() error
    Stop() error
    
    // 配置
    SetPrivateKey(key PrivateKey) error
    SetListenPort(port int) error
    
    // Peer管理
    AddPeer(peer *PeerConfig) error
    RemovePeer(publicKey PublicKey) error
    UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error
    
    // 状态查询
    GetPeers() []*PeerStatus
    GetStats() *TunnelStats
}

// PeerConfig Peer配置
type PeerConfig struct {
    PublicKey    PublicKey
    PresharedKey *PresharedKey  // 可选
    AllowedIPs   []net.IPNet
    Endpoint     *net.UDPAddr   // 可选，已知时设置
    Keepalive    time.Duration  // 心跳间隔，0表示禁用
}

// PeerStatus Peer状态
type PeerStatus struct {
    PublicKey           PublicKey
    Endpoint            *net.UDPAddr
    LastHandshake       time.Time
    TxBytes             uint64
    RxBytes             uint64
    AllowedIPs          []net.IPNet
}
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-01-1 | 创建WireGuard隧道 | P0 |
| FR-01-2 | 动态添加/删除Peer | P0 |
| FR-01-3 | 更新Peer的Endpoint（漫游） | P0 |
| FR-01-4 | 查询Peer状态和统计信息 | P1 |
| FR-01-5 | 支持PresharedKey增强安全 | P1 |

### FR-02: 密钥管理

**描述**: WireGuard密钥对的生成、存储和加载

```go
// 密钥类型
type PrivateKey [32]byte
type PublicKey [32]byte
type PresharedKey [32]byte

// 密钥操作
func GeneratePrivateKey() (PrivateKey, error)
func (k PrivateKey) PublicKey() PublicKey
func (k PrivateKey) String() string  // Base64编码
func ParsePrivateKey(s string) (PrivateKey, error)
func ParsePublicKey(s string) (PublicKey, error)
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-02-1 | 生成随机私钥 | P0 |
| FR-02-2 | 从私钥派生公钥 | P0 |
| FR-02-3 | Base64编码/解码 | P0 |
| FR-02-4 | 密钥文件存储（权限600） | P1 |

### FR-03: 与网络接口层集成

**描述**: 将WireGuard与TASK-02的NetworkInterface集成

```go
// Config 隧道配置
type Config struct {
    // 网络接口
    Interface   netif.NetworkInterface
    
    // WireGuard配置
    PrivateKey  PrivateKey
    ListenPort  int           // 0表示随机端口
    
    // 虚拟网络
    Address     net.IP
    Netmask     net.IPMask
}

// New 创建隧道
func New(cfg Config) (Tunnel, error)
```

### FR-04: 事件通知

**描述**: 隧道状态变化通知

```go
type TunnelEvent struct {
    Type      EventType
    PeerKey   PublicKey
    Timestamp time.Time
    Details   interface{}
}

type EventType int

const (
    EventPeerAdded EventType = iota
    EventPeerRemoved
    EventPeerHandshake
    EventPeerEndpointChanged
)

// 订阅事件
func (t *wireguardTunnel) Events() <-chan TunnelEvent
```

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-04-1 | Peer添加/删除事件 | P1 |
| FR-04-2 | 握手完成事件 | P1 |
| FR-04-3 | Endpoint变更事件 | P1 |

---

## 技术要求

### 技术栈

| 组件 | MVP选型 | 长期目标 | 说明 |
|------|---------|----------|------|
| WireGuard实现 | golang.zx2c4.com/wireguard | **自研Noise隧道** | 见 selfhost.md Phase 2 |
| 密钥库 | golang.org/x/crypto/curve25519 | 保持 | 标准库，无需替换 |

> **抽象层设计要求**: Tunnel接口定义不能包含任何wireguard-go的类型。
> 第三方封装代码必须隔离在独立文件中（`tunnel_wggo.go`）。
> `tunnel_native.go` / `tunnel_wink.go` 属于 post-MVP 轨道，不是当前任务交付物。
> 详见 [selfhost.md](../../selfhost.md) 和 [wink-protocol-v1.md](../../wink-protocol-v1.md)（字节级协议设计）

### 目录结构

```
pkg/tunnel/
├── tunnel.go               # Tunnel接口定义（永远不改）
├── tunnel_wggo.go          # wireguard-go封装（当前MVP实现）
├── tunnel_interface_test.go # 接口级测试（两个实现共用）
├── peer.go                 # Peer管理
├── key.go                  # 密钥类型和操作
├── key_test.go             # 密钥测试
├── config.go              # 配置结构
├── stats.go            # 统计信息
└── events.go           # 事件系统
```

### wireguard-go集成

```go
import (
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/tun"
)

type wireguardTunnel struct {
    device *device.Device
    uapi   net.Listener
    netif  netif.NetworkInterface
    
    mu     sync.RWMutex
    peers  map[PublicKey]*peerState
    events chan TunnelEvent
}

func (t *wireguardTunnel) Start() error {
    // 1. 创建Device
    t.device = device.NewDevice(
        t.netif,      // tun.Device接口
        conn.NewDefaultBind(),
        device.NewLogger(device.LogLevelVerbose, "wink: "),
    )
    
    // 2. 配置私钥和端口
    t.device.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=%d",
        hex.EncodeToString(t.privateKey[:]),
        t.listenPort,
    ))
    
    // 3. 启动
    t.device.Up()
    
    return nil
}
```

---

## 验收标准

### AC-01: 隧道创建验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | 能创建WireGuard隧道 | Start()无错误 |
| AC-01-2 | 能设置私钥 | 验证公钥派生正确 |
| AC-01-3 | 能设置监听端口 | netstat验证端口监听 |
| AC-01-4 | 能正确关闭隧道 | Stop()后资源释放 |

### AC-02: Peer管理验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | 能添加Peer | AddPeer()成功 |
| AC-02-2 | 能删除Peer | RemovePeer()成功 |
| AC-02-3 | 能更新Endpoint | 握手后流量走新地址 |
| AC-02-4 | AllowedIPs生效 | 只有允许的IP能通信 |

### AC-03: 端到端验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | 两端能建立隧道 | 手动配置两个节点 |
| AC-03-2 | ping能通 | ping对端虚拟IP成功 |
| AC-03-3 | TCP能通 | curl/nc测试 |
| AC-03-4 | UDP能通 | DNS查询或自定义测试 |

**端到端测试步骤**:

```bash
# 节点A
$ wink genkey
Private: aPrivateKeyBase64...
Public:  aPublicKeyBase64...

# 节点B  
$ wink genkey
Private: bPrivateKeyBase64...
Public:  bPublicKeyBase64...

# 节点A配置
interface:
  private_key: aPrivateKeyBase64...
  address: 10.100.0.1/24
  listen_port: 51820
peers:
  - public_key: bPublicKeyBase64...
    allowed_ips: 10.100.0.2/32
    endpoint: B_IP:51820

# 节点B配置
interface:
  private_key: bPrivateKeyBase64...
  address: 10.100.0.2/24
  listen_port: 51820
peers:
  - public_key: aPublicKeyBase64...
    allowed_ips: 10.100.0.1/32
    endpoint: A_IP:51820

# 测试
$ ping 10.100.0.2  # 从A ping B
PING 10.100.0.2: 64 bytes, time=5ms
```

### AC-04: 密钥管理验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | 密钥生成随机 | 多次生成不重复 |
| AC-04-2 | 公钥派生正确 | 与wg工具对比 |
| AC-04-3 | Base64编解码正确 | 与wg工具对比 |

```bash
# 对比测试
$ wg genkey | tee privatekey | wg pubkey > publickey

# 我们的实现应产生相同格式
$ wink genkey
# 验证格式一致，长度44字符(Base64)
```

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| Tunnel接口 | `pkg/tunnel/tunnel.go` | 隧道抽象 |
| WireGuard实现 | `pkg/tunnel/tunnel_wggo.go` | wireguard-go封装 |
| 密钥模块 | `pkg/tunnel/key.go` | 密钥操作 |
| CLI命令 | `cmd/wink/cmd/genkey.go` | wink genkey命令 |
| 单元测试 | `pkg/tunnel/*_test.go` | 测试代码 |

---

## 接口契约

### 提供给TASK-06的接口

```go
package tunnel

// 创建隧道
func New(cfg Config) (Tunnel, error)

// Tunnel接口（完整定义见上文）
type Tunnel interface {
    Start() error
    Stop() error
    AddPeer(peer *PeerConfig) error
    RemovePeer(publicKey PublicKey) error
    UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error
    GetPeers() []*PeerStatus
    Events() <-chan TunnelEvent
}

// 密钥操作
func GeneratePrivateKey() (PrivateKey, error)
func ParsePrivateKey(s string) (PrivateKey, error)
func ParsePublicKey(s string) (PublicKey, error)
```

### 依赖TASK-02的接口

```go
// 需要TASK-02提供的NetworkInterface
type NetworkInterface interface {
    Read(buf []byte) (int, error)
    Write(buf []byte) (int, error)
    // ...
}
```

---

## 注意事项

### 1. wireguard-go适配

wireguard-go的`tun.Device`接口与我们的`NetworkInterface`略有不同：

```go
// wireguard-go 期望的接口
type Device interface {
    File() *os.File
    Read([]byte, int) (int, error)  // 注意：有offset参数
    Write([]byte, int) (int, error)
    Flush() error
    MTU() (int, error)
    Name() (string, error)
    Events() chan Event
    Close() error
}
```

需要编写适配器：
```go
type tunAdapter struct {
    netif.NetworkInterface
}

func (a *tunAdapter) Read(buf []byte, offset int) (int, error) {
    return a.NetworkInterface.Read(buf[offset:])
}
```

### 2. IPC配置格式

wireguard-go使用IPC协议配置，格式如下：
```
private_key=hex_encoded_key
listen_port=51820
public_key=hex_encoded_peer_key
allowed_ip=10.100.0.0/24
endpoint=1.2.3.4:51820
```

### 3. Keepalive重要性

NAT后的节点需要Keepalive保持NAT映射：
- 建议默认值：25秒
- 范围：15-60秒

### 4. 并发安全

Tunnel的Peer操作可能被多个goroutine调用，需确保：
- AddPeer/RemovePeer/UpdatePeerEndpoint线程安全
- GetPeers返回快照而非引用

---

## 待确认问题

| 问题 | 状态 | 说明 |
|------|------|------|
| 是否支持IPv6? | 待确认 | MVP可只支持IPv4 |
| 最大Peer数量? | 待确认 | wireguard-go应无硬限制 |
| 密钥存储加密? | 待决策 | 是否需要额外加密存储 |

---

## 参考资料

- [WireGuard协议白皮书](https://www.wireguard.com/papers/wireguard.pdf)
- [wireguard-go源码](https://git.zx2c4.com/wireguard-go/)
- [WireGuard官方文档](https://www.wireguard.com/)
- [Noise Protocol Framework](http://noiseprotocol.org/noise.html)
