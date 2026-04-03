# WinkYou - P2P 内网穿透虚拟局域网项目规划

## 一、项目概述

### 1.1 项目背景

随着远程办公和分布式系统的普及，跨网络设备间的安全通信需求日益增长。现有解决方案存在以下问题：

- **传统VPN**：配置复杂，需要专门的服务器，延迟高
- **frp等内网穿透工具**：依赖中心服务器转发，带宽受限，单点故障
- **Tailscale**：依赖国外服务器，国内访问不稳定，数据隐私问题

WinkYou 旨在打造一个**去中心化的P2P虚拟局域网**解决方案，让任意设备之间能够安全、高效地直接通信。

### 1.2 项目定位

| 特性 | frp | Tailscale/Headscale | ZeroTier | **WinkYou** |
|------|-----|---------------------|----------|-------------|
| 网络模型 | C/S中转 | P2P+中继 | P2P+中继 | **P2P优先+智能中继** |
| 协议 | TCP/UDP/HTTP | WireGuard | 自研 | **WireGuard + 自研扩展** |
| 控制平面 | 配置文件 | 中心化 | 中心化 | **分布式/自托管** |
| NAT穿透 | 无 | STUN/DERP | 打洞 | **STUN/TURN/ICE** |
| 开源程度 | 完全开源 | 部分开源 | 部分开源 | **完全开源** |

### 1.3 核心目标

1. **P2P直连优先**：最大化节点间直连率，减少中继依赖
2. **低延迟高性能**：基于UDP的WireGuard隧道，接近原生网络性能
3. **易于部署**：一键安装，零配置上网
4. **安全可靠**：端到端加密，无中间人攻击风险
5. **跨平台支持**：Windows/Linux/macOS/Android/iOS

---

## 二、技术调研

### 2.1 竞品分析

#### 2.1.1 frp (Fast Reverse Proxy)

**架构特点**：
```
用户 --> frps(公网服务器) --> frpc(内网客户端) --> 内网服务
```

**优点**：
- 配置简单，支持TCP/UDP/HTTP/HTTPS多种协议
- 支持端口复用、负载均衡
- 完全开源，Go语言实现

**缺点**：
- 所有流量必须经过中心服务器转发
- 带宽受限于服务器配置
- 无法实现真正的P2P通信

**技术参考**：
- 多路复用：使用yamux/kcp协议
- 配置格式：TOML配置文件
- 心跳保活机制

#### 2.1.2 Tailscale / Headscale

**架构特点**：
```
                    ┌─────────────────┐
                    │ Control Server  │
                    │ (协调/密钥交换)  │
                    └────────┬────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   ┌────▼────┐         ┌─────▼─────┐        ┌────▼────┐
   │ Node A  │◄═══════►│  DERP     │◄══════►│ Node B  │
   │(WireGuard)        │ (中继服务器)         │(WireGuard)
   └────┬────┘         └───────────┘        └────┬────┘
        │                                        │
        └════════════════════════════════════════┘
                   P2P直连(优先)
```

**核心技术**：
- **WireGuard**：现代化VPN协议，使用Noise Protocol Framework
- **STUN打洞**：获取公网映射地址，尝试NAT穿透
- **DERP中继**：打洞失败时的备用方案
- **MagicDNS**：自动DNS解析

**Headscale** 是 Tailscale 控制服务器的开源实现：
- 支持自托管，数据完全可控
- 兼容Tailscale客户端
- 使用SQLite/PostgreSQL存储

#### 2.1.3 其他方案对比

| 项目 | NAT穿透 | 协议 | 控制平面 | 特点 |
|------|---------|------|----------|------|
| ZeroTier | 打洞+中继 | 自研 | Planet/Moon | 虚拟二层网络 |
| Netmaker | WireGuard | WG | 自托管 | 企业级 |
| Nebula | 打洞 | 自研 | 证书 | Slack出品 |
| n2n | 打洞 | 自研 | Supernode | 轻量级 |

### 2.2 核心技术栈

#### 2.2.1 NAT穿透技术

**NAT类型分类**：
```
┌─────────────────────────────────────────────────────────┐
│                    NAT类型                               │
├─────────────┬─────────────┬─────────────┬───────────────┤
│   Full Cone │ Restricted  │    Port     │   Symmetric   │
│   (完全锥形) │    Cone     │ Restricted  │    (对称型)    │
│             │ (限制锥形)   │   Cone      │               │
├─────────────┼─────────────┼─────────────┼───────────────┤
│  打洞难度：低 │   中等      │    较高      │    极高/不可能 │
└─────────────┴─────────────┴─────────────┴───────────────┘
```

**STUN (Session Traversal Utilities for NAT)**：
- 获取客户端的公网IP和端口映射
- 检测NAT类型
- 用于非对称NAT的打洞

**TURN (Traversal Using Relays around NAT)**：
- 当STUN失败时的中继方案
- 通过公网服务器转发数据
- 保证100%连通性

**ICE (Interactive Connectivity Establishment)**：
- 综合框架，协调STUN和TURN
- 收集所有可能的候选地址
- 优先级排序：本地 > 反射(STUN) > 中继(TURN)

#### 2.2.2 WireGuard协议

**核心特性**：
- **Noise Protocol Framework**：基于IK模式的密钥交换
- **ChaCha20-Poly1305**：数据加密
- **Curve25519**：密钥交换算法
- **BLAKE2s**：哈希函数
- **SipHash24**：哈希表索引

**协议优势**：
- 代码量小（约4000行C代码），易于审计
- 内核态实现，性能优异
- 无状态设计，天然支持漫游

**数据包格式**：
```
┌────────────┬────────────┬──────────────────┬─────────┐
│   Type     │  Reserved  │     Counter      │  Data   │
│  (1 byte)  │  (3 bytes) │    (8 bytes)     │  (...)  │
└────────────┴────────────┴──────────────────┴─────────┘
```

#### 2.2.3 虚拟网络接口技术

虚拟网络接口并非只有TUN一条路线，以下是所有可行的技术方案：

##### 方案一：TUN 设备 (Layer 3)

```
应用程序 → 系统TCP/IP协议栈 → TUN设备 → 用户态程序 → 加密/隧道发送
```

- 处理IP数据包（第三层），无以太网帧头，开销最小
- 适用于点对点隧道、VPN
- 各平台实现：Linux `/dev/net/tun`、macOS `utun`、Windows `WinTUN`
- **代表项目**：WireGuard, Tailscale

| 优点 | 缺点 |
|------|------|
| 性能最优，开销最小 | 不支持二层协议(ARP/广播/组播) |
| 跨平台支持成熟 | 需要管理员/root权限 |
| WireGuard生态原生支持 | 无法桥接到物理局域网 |

##### 方案二：TAP 设备 (Layer 2)

```
应用程序 → 系统TCP/IP协议栈 → TAP设备(虚拟以太网卡) → 用户态程序 → 发送
```

- 处理完整以太网帧（第二层），包含MAC地址
- 支持广播、组播、ARP等二层协议
- 可以桥接到物理网络，使远程设备像在同一局域网
- **代表项目**：OpenVPN(TAP模式), ZeroTier, n2n

| 优点 | 缺点 |
|------|------|
| 完整二层模拟，支持局域网发现 | 以太网帧头额外开销(14字节) |
| 可桥接物理网络 | 广播风暴风险，需要管理 |
| 适合游戏联机、局域网设备发现 | 需要管理MAC地址分配 |
| 支持非IP协议(如IPX、NetBIOS) | 跨平台实现差异较大 |

##### 方案三：用户态网络栈 (Userspace TCP/IP Stack)

```
应用程序 → 系统TCP/IP协议栈 → 内核路由 → 用户态TCP/IP栈(gVisor netstack)
    → 直接构造UDP包发送到对端
```

- 在用户态完整实现TCP/IP协议栈，无需内核TUN/TAP驱动
- 通过 `gVisor/netstack` 或 `lwIP` 等库实现
- **代表项目**：Tailscale netstack模式, sing-box, clash Premium

| 优点 | 缺点 |
|------|------|
| **无需管理员权限** | 性能低于内核态方案 |
| **无需安装驱动** | TCP重传等细节需要自行处理 |
| 跨平台行为一致 | 兼容性不如内核态透明 |
| 容器/受限环境友好 | 复杂协议支持不完整 |

##### 方案四：系统代理 (SOCKS5/HTTP Proxy)

```
应用程序(配置代理) → SOCKS5/HTTP本地代理 → 隧道转发到对端
```

- 在应用层实现流量代理，不需要虚拟网卡
- 需要应用程序主动配置代理或使用系统代理设置
- **代表项目**：SSH隧道, v2ray, shadowsocks

| 优点 | 缺点 |
|------|------|
| 实现最简单 | 只支持TCP(SOCKS5部分支持UDP) |
| 无需任何驱动/权限 | 非全局透明，需应用配合 |
| 任何平台即开即用 | ICMP(ping)等协议不支持 |
| | 无法实现真正的虚拟局域网 |

##### 方案五：透明代理 (iptables/nftables + tproxy)

```
应用程序 → 内核协议栈 → iptables REDIRECT/TPROXY → 本地代理程序 → 隧道转发
```

- Linux下通过iptables/nftables规则劫持流量到本地代理
- 应用无感知，全局生效
- **代表项目**：clash redir模式, Xray tproxy

| 优点 | 缺点 |
|------|------|
| 应用层无感知 | **仅Linux** |
| 无需虚拟网卡驱动 | 配置iptables规则复杂 |
| 可精细控制劫持范围 | UDP支持有限(需TPROXY) |
| | 不跨平台 |

##### 方案六：eBPF/XDP (Linux 内核态)

```
网卡 → XDP(驱动层) → eBPF程序(内核态极早期处理) → 重定向/封装/转发
```

- 在内核态最早期拦截和处理数据包，性能极高
- 需要 Linux kernel 4.18+，部分功能需要 5.x+
- **代表项目**：Cilium, Katran

| 优点 | 缺点 |
|------|------|
| **极致性能**，内核态零拷贝 | **仅Linux**，需要较新内核 |
| 可编程灵活度高 | 开发复杂度高(受限C) |
| 适合高吞吐场景 | 调试困难 |

##### 方案七：Windows 专用方案

| 方案 | 层级 | 说明 |
|------|------|------|
| **WinTUN** | L3 | WireGuard团队开发，高性能TUN驱动，轻量推荐 |
| **TAP-Windows (tap-windows6)** | L2 | OpenVPN项目维护，成熟稳定但性能略低 |
| **WFP (Windows Filtering Platform)** | L3-L4 | Windows内核过滤平台，可拦截/修改/重定向数据包 |
| **Npcap** | L2 | 抓包/注入库，可实现raw socket，但非主流VPN方案 |

##### 技术路线对比总结

| 方案 | 层级 | 性能 | 权限需求 | 跨平台 | 全局透明 | 适用场景 |
|------|------|------|----------|--------|----------|----------|
| **TUN** | L3 | 高 | root/admin | 好 | 是 | VPN、隧道 |
| **TAP** | L2 | 中高 | root/admin | 中 | 是 | 虚拟局域网、游戏联机 |
| **用户态网络栈** | L3 | 中 | **无需** | 好 | 是 | 受限环境、容器 |
| **系统代理** | L7 | 中 | **无需** | 好 | 否 | 轻量代理 |
| **透明代理** | L3-L4 | 中高 | root | 仅Linux | 是 | Linux网关 |
| **eBPF/XDP** | L2-L3 | **极高** | root | 仅Linux | 是 | 高性能网关 |

##### WinkYou 选型策略：分层架构 + 多后端

WinkYou 采用**抽象接口 + 多后端**的设计，根据运行环境自动选择最优方案：

```
┌─────────────────────────────────────────────┐
│        NetworkInterface 抽象层               │
│   (统一的 Read/Write IP Packet 接口)         │
├──────┬──────┬───────────┬───────┬───────────┤
│ TUN  │ TAP  │ Userspace │ Proxy │ eBPF/XDP  │
│      │      │ Netstack  │(降级) │ (高性能)   │
└──────┴──────┴───────────┴───────┴───────────┘
```

**自动选择策略**：

| 优先级 | 条件 | 选择 |
|--------|------|------|
| 1 (最优) | Linux + 管理员权限 + 新内核 | TUN (内核WireGuard) |
| 2 | 管理员权限 | TUN (WinTUN/utun/wireguard-go) |
| 3 | 需要二层功能(用户配置) | TAP |
| 4 | 无管理员权限 | 用户态网络栈 (gVisor netstack) |
| 5 (兜底) | 最小化环境 | SOCKS5代理模式 |

---

## 三、系统架构设计

### 3.1 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        WinkYou 架构                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────┐       ┌───────────────┐       ┌────────────┐ │
│  │   协调服务器   │       │   协调服务器   │       │  协调服务器 │ │
│  │  (Coordinator) │◄─────►│  (Coordinator) │◄─────►│(Coordinator)│ │
│  │   可选/自托管  │       │    可选/自托管 │       │  可选/自托管│ │
│  └───────┬───────┘       └───────┬───────┘       └──────┬─────┘ │
│          │ 控制平面               │                      │       │
│  ════════╪═══════════════════════╪══════════════════════╪═══════│
│          │ 数据平面               │                      │       │
│  ┌───────▼───────┐       ┌───────▼───────┐       ┌──────▼─────┐ │
│  │    WinkNode    │◄═════►│    WinkNode    │◄═════►│  WinkNode  │ │
│  │  (P2P客户端)   │ P2P   │  (P2P客户端)   │  P2P  │ (P2P客户端) │ │
│  └───────────────┘直连    └───────────────┘ 直连  └────────────┘ │
│         │                        │                      │        │
│         │                        │                      │        │
│   ┌─────▼─────┐            ┌─────▼─────┐          ┌─────▼─────┐  │
│   │ NetIF抽象  │            │ NetIF抽象  │          │ NetIF抽象 │  │
│   │ 10.100.0.1 │            │ 10.100.0.2 │          │10.100.0.3 │  │
│   │(TUN/TAP/  │            │(TUN/TAP/  │          │(TUN/TAP/ │  │
│   │ Netstack) │            │ Netstack) │          │ Netstack)│  │
│   └───────────┘            └───────────┘          └───────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 模块设计

#### 3.2.1 核心模块

```
winkyou/
├── cmd/
│   ├── winkd/              # 守护进程(主程序)
│   ├── wink/               # CLI工具
│   └── wink-ui/            # GUI界面(可选)
├── pkg/
│   ├── coordinator/        # 协调服务器
│   │   ├── server.go       # HTTP/gRPC服务
│   │   ├── registry.go     # 节点注册
│   │   └── keyexchange.go  # 密钥交换
│   ├── node/               # P2P节点
│   │   ├── peer.go         # 对等节点管理
│   │   ├── connection.go   # 连接管理
│   │   └── router.go       # 路由表
│   ├── tunnel/             # 隧道层
│   │   ├── wireguard.go    # WireGuard封装
│   │   └── encryption.go   # 加密处理
│   ├── netif/              # 虚拟网络接口(多后端)
│   │   ├── interface.go    # NetworkInterface 抽象接口
│   │   ├── tun.go          # TUN后端(默认)
│   │   ├── tap.go          # TAP后端(二层模式)
│   │   ├── userspace.go    # 用户态网络栈后端(gVisor netstack)
│   │   ├── proxy.go        # SOCKS5代理降级后端
│   │   └── selector.go     # 自动后端选择策略
│   ├── nat/                # NAT穿透
│   │   ├── stun.go         # STUN客户端
│   │   ├── turn.go         # TURN客户端
│   │   ├── ice.go          # ICE协商
│   │   └── detector.go     # NAT类型检测
│   ├── relay/              # 中继服务
│   │   ├── server.go       # 中继服务器
│   │   └── client.go       # 中继客户端
│   ├── network/            # 网络层
│   │   ├── ip.go           # IP分配
│   │   ├── dns.go          # DNS解析
│   │   └── route.go        # 路由管理
│   └── protocol/           # 协议定义
│       ├── messages.proto  # Protobuf定义
│       └── wire.go         # 协议编解码
├── internal/
│   ├── config/             # 配置管理
│   ├── logger/             # 日志系统
│   └── utils/              # 工具函数
└── platform/               # 平台相关
    ├── windows/            # Windows特定代码
    ├── linux/              # Linux特定代码
    └── darwin/             # macOS特定代码
```

#### 3.2.2 组件职责

| 组件 | 职责 | 技术选型 |
|------|------|----------|
| Coordinator | 节点发现、密钥交换、网络协调 | gRPC + SQLite |
| WinkNode | P2P连接、隧道管理、流量转发 | Go + WireGuard |
| NAT Traversal | NAT穿透、打洞协调 | STUN/TURN/ICE |
| Relay | 打洞失败时的流量中继 | UDP/TCP中继 |
| NetIF | 虚拟网络接口抽象层 | TUN/TAP/Userspace/Proxy多后端 |

### 3.3 网络模型

#### 3.3.1 虚拟网络分配

```
┌─────────────────────────────────────────────────────┐
│                 WinkYou 虚拟网络                     │
├─────────────────────────────────────────────────────┤
│  网络地址空间: 10.100.0.0/16 (可配置)                 │
│  子网分配:                                           │
│    - 10.100.0.0/24  : 默认网络                       │
│    - 10.100.1.0/24  : 网络组1                        │
│    - 10.100.2.0/24  : 网络组2                        │
│    ...                                              │
│  保留地址:                                           │
│    - 10.100.0.1     : 网关(如需要)                   │
│    - 10.100.0.254   : DNS服务器(如需要)              │
└─────────────────────────────────────────────────────┘
```

#### 3.3.2 连接建立流程

```
┌─────────┐                ┌─────────────┐                ┌─────────┐
│ Node A  │                │ Coordinator │                │ Node B  │
└────┬────┘                └──────┬──────┘                └────┬────┘
     │                            │                             │
     │  1. Register(PubKey,Info)  │                             │
     ├───────────────────────────►│                             │
     │                            │                             │
     │  2. OK(VirtualIP,Token)    │                             │
     │◄───────────────────────────┤                             │
     │                            │                             │
     │                            │  3. Register(PubKey,Info)   │
     │                            │◄────────────────────────────┤
     │                            │                             │
     │                            │  4. OK(VirtualIP,Token)     │
     │                            ├────────────────────────────►│
     │                            │                             │
     │  5. RequestPeer(NodeB_ID)  │                             │
     ├───────────────────────────►│                             │
     │                            │                             │
     │  6. PeerInfo(B's endpoint, │                             │
     │     pubkey, candidates)    │                             │
     │◄───────────────────────────┤                             │
     │                            │                             │
     │                       7. ICE Negotiation                 │
     │◄════════════════════════════════════════════════════════►│
     │                            │                             │
     │                       8. WireGuard Handshake             │
     │◄════════════════════════════════════════════════════════►│
     │                            │                             │
     │                       9. P2P Tunnel Established          │
     │◄═══════════════════════════════════════════════════════►│
     │                            │                             │
```

### 3.4 安全设计

#### 3.4.1 加密方案

```
┌─────────────────────────────────────────────────────────────┐
│                        加密层次                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  应用层: 用户数据                                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  WireGuard层: ChaCha20-Poly1305 加密                    │ │
│  │  - 每个对等节点独立密钥对                                 │ │
│  │  - 完美前向保密 (PFS)                                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  传输层: UDP封装                                         │ │
│  │  - 无状态，支持漫游                                      │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

#### 3.4.2 身份认证

```
┌─────────────────────────────────────────────────────────────┐
│                      身份认证流程                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 节点生成密钥对                                           │
│     ┌───────────────────────────────────────────────────┐   │
│     │  Private Key: X25519 (保存在本地)                   │   │
│     │  Public Key:  X25519 (注册到协调服务器)              │   │
│     └───────────────────────────────────────────────────┘   │
│                                                              │
│  2. 用户认证 (可选)                                          │
│     ┌───────────────────────────────────────────────────┐   │
│     │  - 预共享密钥 (Pre-shared Key)                      │   │
│     │  - OAuth2/OIDC 第三方认证                           │   │
│     │  - 邀请码机制                                       │   │
│     └───────────────────────────────────────────────────┘   │
│                                                              │
│  3. 节点授权                                                 │
│     ┌───────────────────────────────────────────────────┐   │
│     │  - ACL访问控制列表                                  │   │
│     │  - 网络组隔离                                       │   │
│     │  - 管理员审批 (可选)                                │   │
│     └───────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 四、功能规划

### 4.1 MVP版本 (Minimum Viable Product)

**核心功能**：

| 功能 | 描述 | 优先级 |
|------|------|--------|
| 节点注册与发现 | 节点向协调服务器注册，获取其他节点信息 | P0 |
| P2P直连 | 两个节点之间建立WireGuard隧道 | P0 |
| NAT穿透(STUN) | 基本的UDP打洞 | P0 |
| 中继转发 | 打洞失败时通过中继服务器转发 | P0 |
| TUN虚拟网卡 | 创建TUN虚拟网卡，分配虚拟IP(默认后端) | P0 |
| 用户态网络栈 | gVisor netstack后端，无管理员权限可用 | P0 |
| CLI工具 | 命令行管理工具 | P0 |

**技术要求**：
- 支持 Windows 10+ / Linux (kernel 4.14+) / macOS 10.14+
- Go 1.21+
- 使用 wireguard-go 用户态实现

### 4.2 V1.0 版本

**增强功能**：

| 功能 | 描述 | 优先级 |
|------|------|--------|
| ICE完整实现 | STUN + TURN + ICE完整协商 | P1 |
| NAT类型检测 | 自动检测NAT类型，选择最优策略 | P1 |
| 多协调服务器 | 支持多个协调服务器，高可用 | P1 |
| 网络组 | 支持创建多个隔离的虚拟网络 | P1 |
| ACL访问控制 | 细粒度的访问控制策略 | P1 |
| 连接质量监控 | 延迟、丢包率、带宽统计 | P1 |
| 自动重连 | 网络切换后自动重建连接 | P1 |
| TAP二层模式 | TAP后端支持，局域网发现/游戏联机 | P1 |

### 4.3 V2.0 版本

**高级功能**：

| 功能 | 描述 | 优先级 |
|------|------|--------|
| MagicDNS | 自动DNS解析(node-name.wink) | P2 |
| 子网路由 | 将整个子网暴露到虚拟网络 | P2 |
| 出口节点 | 通过特定节点访问互联网 | P2 |
| GUI客户端 | 图形化管理界面 | P2 |
| 移动端支持 | Android/iOS客户端 | P2 |
| 文件共享 | 节点间快速文件传输 | P2 |
| 服务发现 | 自动发现网络内的服务 | P2 |

### 4.4 V3.0 版本

**企业功能**：

| 功能 | 描述 | 优先级 |
|------|------|--------|
| OIDC集成 | 企业SSO登录 | P3 |
| 审计日志 | 完整的操作和访问日志 | P3 |
| 策略管理 | 集中式策略配置 | P3 |
| 多租户 | 支持多租户隔离 | P3 |
| API接口 | RESTful/gRPC管理API | P3 |
| Kubernetes集成 | K8s网络方案 | P3 |

---

## 五、技术选型

### 5.1 开发语言

| 组件 | 语言 | 理由 |
|------|------|------|
| 核心服务 | Go | 跨平台、高性能、并发友好、WireGuard生态 |
| CLI工具 | Go | 与核心服务统一 |
| GUI(桌面) | Go + Fyne/Wails | 跨平台GUI |
| GUI(移动) | Kotlin/Swift 或 Flutter | 原生体验 |

### 5.2 关键依赖

| 依赖 | 用途 | License |
|------|------|---------|
| wireguard-go | WireGuard用户态实现 | MIT |
| pion/stun | STUN协议实现 | MIT |
| pion/turn | TURN协议实现 | MIT |
| pion/ice | ICE协议实现 | MIT |
| golang.zx2c4.com/wireguard/tun | TUN设备管理 | MIT |
| gvisor.dev/gvisor/pkg/tcpip | 用户态TCP/IP协议栈(netstack) | Apache-2.0 |
| github.com/songgao/water | TAP设备管理(跨平台) | BSD-3 |
| gRPC | RPC通信 | Apache-2.0 |
| SQLite | 本地数据存储 | Public Domain |
| cobra | CLI框架 | Apache-2.0 |
| zap | 日志库 | MIT |

### 5.3 协议设计

**控制协议** (Coordinator <-> Node)：
- 传输层：gRPC over TLS
- 序列化：Protocol Buffers

**数据协议** (Node <-> Node)：
- 传输层：UDP
- 隧道：WireGuard
- 加密：Noise_IKpsk2

---

## 六、开发计划

### 6.1 阶段划分

#### 第一阶段：基础框架

**目标**：搭建项目框架，实现基本的点对点连接

**任务清单**：
- [ ] 项目初始化，目录结构搭建
- [ ] 配置管理模块
- [ ] 日志系统
- [ ] TUN设备创建与管理(Windows/Linux/macOS)
- [ ] 用户态网络栈后端(gVisor netstack，无权限降级)
- [ ] NetworkInterface抽象接口与后端自动选择
- [ ] WireGuard隧道封装
- [ ] 基本的STUN客户端
- [ ] 简单的协调服务器(节点注册)
- [ ] 两节点直连Demo

#### 第二阶段：NAT穿透

**目标**：实现完整的NAT穿透能力

**任务清单**：
- [ ] NAT类型检测
- [ ] STUN打洞实现
- [ ] TURN中继实现
- [ ] ICE协商框架
- [ ] 候选地址收集与排序
- [ ] 连接失败回退机制

#### 第三阶段：网络管理

**目标**：完善网络管理功能

**任务清单**：
- [ ] 虚拟IP分配
- [ ] 路由表管理
- [ ] 多节点组网
- [ ] 网络组功能
- [ ] ACL访问控制
- [ ] CLI工具完善

#### 第四阶段：稳定性与性能

**目标**：提升稳定性和性能

**任务清单**：
- [ ] 连接状态监控
- [ ] 自动重连机制
- [ ] 心跳保活
- [ ] 性能优化
- [ ] 内存泄漏检测
- [ ] 压力测试

#### 第五阶段：产品化

**目标**：完成产品化

**任务清单**：
- [ ] GUI客户端
- [ ] 安装包制作
- [ ] 文档编写
- [ ] 自动更新
- [ ] 遥测与反馈

### 6.2 里程碑

| 里程碑 | 目标 | 交付物 |
|--------|------|--------|
| M1 | 基础直连 | 两节点WireGuard直连Demo |
| M2 | NAT穿透 | 跨NAT的节点连接 |
| M3 | MVP | 可用的命令行工具 |
| M4 | V1.0 | 稳定版本发布 |

---

## 七、接口设计

### 7.1 CLI命令设计

```bash
# 节点管理
wink up                      # 启动并连接到网络
wink down                    # 断开并停止
wink status                  # 查看连接状态
wink login                   # 登录/认证

# 网络管理
wink network list            # 列出网络
wink network create <name>   # 创建网络
wink network join <id>       # 加入网络
wink network leave           # 离开网络

# 节点列表
wink peers                   # 列出所有节点
wink peer <name> info        # 查看节点详情
wink ping <name>             # ping节点

# 高级功能
wink route add <subnet>      # 添加子网路由
wink exit-node enable        # 启用出口节点
wink exit-node use <name>    # 使用指定出口

# 调试
wink debug                   # 调试信息
wink logs                    # 查看日志
```

### 7.2 配置文件设计

```yaml
# ~/.wink/config.yaml
node:
  name: "my-laptop"
  
coordinator:
  url: "https://coord.example.com:443"
  # 或使用内置公共服务器
  # url: "https://wink.pub:443"

network:
  # 虚拟网络配置
  ip: "auto"  # 或指定IP如 "10.100.0.5"
  dns: 
    - "10.100.0.254"
    - "8.8.8.8"
    
nat:
  stun_servers:
    - "stun:stun.l.google.com:19302"
    - "stun:stun.cloudflare.com:3478"
  relay_servers:
    - "turn:relay.example.com:3478"

advanced:
  mtu: 1280
  keepalive: 25
  log_level: "info"
  
  # 虚拟网络接口后端选择
  # auto: 自动选择最优后端(默认)
  # tun:  强制使用TUN(需管理员权限)
  # tap:  强制使用TAP(二层模式，需管理员权限)
  # userspace: 强制使用用户态网络栈(无需权限)
  # proxy: 强制使用SOCKS5代理降级模式
  netif_backend: "auto"
```

### 7.3 gRPC接口设计

```protobuf
syntax = "proto3";
package wink.v1;

service Coordinator {
  // 节点注册
  rpc Register(RegisterRequest) returns (RegisterResponse);
  
  // 节点心跳
  rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
  
  // 获取节点列表
  rpc ListPeers(ListPeersRequest) returns (ListPeersResponse);
  
  // 获取节点详情
  rpc GetPeer(GetPeerRequest) returns (GetPeerResponse);
  
  // 连接协商
  rpc Negotiate(stream NegotiateMessage) returns (stream NegotiateMessage);
}

message RegisterRequest {
  string public_key = 1;
  string name = 2;
  repeated string endpoints = 3;
  map<string, string> metadata = 4;
}

message RegisterResponse {
  string node_id = 1;
  string virtual_ip = 2;
  string network_id = 3;
  int64 expires_at = 4;
}

message PeerInfo {
  string node_id = 1;
  string name = 2;
  string public_key = 3;
  string virtual_ip = 4;
  repeated string endpoints = 5;
  bool online = 6;
}
```

---

## 八、质量保证

### 8.1 测试策略

| 测试类型 | 范围 | 工具 |
|----------|------|------|
| 单元测试 | 核心模块 | Go testing |
| 集成测试 | 组件交互 | Go testing + Docker |
| E2E测试 | 完整流程 | 自动化脚本 |
| 性能测试 | 吞吐量、延迟 | iperf3, netperf |
| NAT测试 | 各种NAT环境 | 模拟NAT环境 |

### 8.2 CI/CD流程

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│  Push   │───►│  Build  │───►│  Test   │───►│ Release │
└─────────┘    └─────────┘    └─────────┘    └─────────┘
                    │              │
                    ▼              ▼
              ┌─────────┐    ┌─────────┐
              │  Lint   │    │ Coverage│
              └─────────┘    └─────────┘
```

### 8.3 代码规范

- Go代码遵循 [Effective Go](https://golang.org/doc/effective_go)
- 使用 golangci-lint 进行静态分析
- 代码覆盖率目标：核心模块 > 80%
- 提交信息遵循 Conventional Commits

---

## 九、部署方案

### 9.1 协调服务器部署

**单机部署**：
```bash
# Docker方式
docker run -d --name wink-coordinator \
  -p 443:443 \
  -v /data/wink:/data \
  wink/coordinator:latest

# 二进制方式
./wink-coordinator --config /etc/wink/coordinator.yaml
```

**高可用部署**：
```
                    ┌─────────────────┐
                    │   Load Balancer │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
    │ Coordinator │   │ Coordinator │   │ Coordinator │
    │   Node 1    │   │   Node 2    │   │   Node 3    │
    └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
           │                 │                 │
           └─────────────────┼─────────────────┘
                             │
                    ┌────────▼────────┐
                    │   PostgreSQL    │
                    │   (共享存储)     │
                    └─────────────────┘
```

### 9.2 客户端安装

```bash
# Linux
curl -fsSL https://get.wink.dev | bash

# macOS
brew install wink

# Windows
winget install wink
# 或下载安装包
```

---

## 十、风险与挑战

### 10.1 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|----------|
| 对称型NAT穿透困难 | 部分用户无法直连 | 优化中继服务，就近部署 |
| WireGuard内核支持 | 部分旧系统不支持 | 使用wireguard-go用户态实现 |
| 跨平台兼容性 | 开发工作量大 | 优先核心平台，使用条件编译 |
| 性能瓶颈 | 高负载下性能下降 | 性能测试、优化热点代码 |

### 10.2 应对策略

1. **NAT穿透失败率**：
   - 部署多个地理分布的中继服务器
   - 实现智能路由选择
   - 提供详细的网络诊断工具

2. **安全性**：
   - 定期安全审计
   - 漏洞赏金计划
   - 及时更新依赖

---

## 十一、参考资料

### 11.1 开源项目

- [frp](https://github.com/fatedier/frp) - 内网穿透工具
- [Headscale](https://github.com/juanfont/headscale) - Tailscale开源控制服务器
- [Tailscale](https://github.com/tailscale/tailscale) - 现代VPN方案
- [WireGuard](https://www.wireguard.com/) - 现代VPN协议
- [pion](https://github.com/pion) - WebRTC Go实现(含STUN/TURN/ICE)
- [Netmaker](https://github.com/gravitl/netmaker) - WireGuard网络管理

### 11.2 技术文档

- [WireGuard Whitepaper](https://www.wireguard.com/papers/wireguard.pdf)
- [RFC 5389 - STUN](https://tools.ietf.org/html/rfc5389)
- [RFC 5766 - TURN](https://tools.ietf.org/html/rfc5766)
- [RFC 8445 - ICE](https://tools.ietf.org/html/rfc8445)
- [Noise Protocol Framework](http://noiseprotocol.org/noise.html)

### 11.3 技术博客

- [How NAT Traversal Works](https://tailscale.com/blog/how-nat-traversal-works)
- [How Tailscale Works](https://tailscale.com/blog/how-tailscale-works)

---

## 十二、术语表

| 术语 | 解释 |
|------|------|
| NAT | Network Address Translation，网络地址转换 |
| STUN | Session Traversal Utilities for NAT，NAT会话穿透工具 |
| TURN | Traversal Using Relays around NAT，NAT中继穿透 |
| ICE | Interactive Connectivity Establishment，交互式连接建立 |
| TUN | 网络层(L3)虚拟网络设备，处理IP数据包 |
| TAP | 数据链路层(L2)虚拟网络设备，处理以太网帧 |
| Userspace Netstack | 用户态TCP/IP协议栈，无需内核驱动 |
| WinTUN | WireGuard团队开发的Windows高性能TUN驱动 |
| WFP | Windows Filtering Platform，Windows内核数据包过滤平台 |
| eBPF | Extended Berkeley Packet Filter，Linux内核可编程数据包处理 |
| XDP | eXpress Data Path，Linux内核极早期数据包处理框架 |
| gVisor | Google开发的用户态内核，其netstack组件提供TCP/IP协议栈 |
| WireGuard | 现代VPN协议 |
| DERP | Designated Encrypted Relay for Packets，Tailscale的中继协议 |
| P2P | Peer-to-Peer，点对点 |
| PFS | Perfect Forward Secrecy，完美前向保密 |

---

*文档版本：v0.2*  
*创建日期：2026-04-02*  
*作者：WinkYou Team*
