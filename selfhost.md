# WinkYou 自研路线图

> 核心原则：**先用别人的跑通，再用自己的替掉。但从第一天起，就必须把墙砌好——让替换是换一个零件，而不是拆一栋楼。**
>
> 创建日期: 2026-04-02

---

## 一、问题的本质

当前方案中，数据从应用程序到对端要经过这条路径：

```
应用程序
  → 系统协议栈
    → TUN设备 [wireguard/tun]        ← 第三方
      → WireGuard加密 [wireguard-go]  ← 第三方
        → UDP发送
          → (互联网)
            → NAT穿透 [pion/ice]      ← 第三方
```

无权限模式下还多一层：

```
应用程序
  → gVisor netstack [gvisor]          ← 第三方
    → WireGuard加密 [wireguard-go]    ← 第三方
      → UDP发送
```

**每一个数据包**都要经过这些第三方代码。你调不了它的内存分配、改不了它的goroutine模型、优化不了它的系统调用方式。别人的代码是别人的设计取舍，不是为你的场景优化的。

而控制平面的代码（CLI框架、日志、gRPC、SQLite），一次连接建立后就不怎么跑了，对性能没有实质影响。

所以问题可以精确地定义为：**数据热路径上的第三方依赖，才是需要自研替换的目标。**

---

## 二、依赖全景分析

### 2.1 数据热路径依赖（必须替换）

| 依赖 | 作用 | 自研难度 | 自研价值 | 替换优先级 |
|------|------|----------|----------|-----------|
| wireguard-go | Noise协议握手 + ChaCha20加密解密 | **高** | **极高** — 每个包都过 | P0 |
| wireguard/tun | TUN设备创建和读写 | **低** | **高** — 系统调用优化空间大 | P1 |
| gVisor netstack | 用户态TCP/IP协议栈 | **极高** | **高** — 无权限模式核心 | P2 |
| pion/ice | ICE协商、候选收集、连通性检查 | **中高** | **中** — 只在连接建立时 | P2 |
| pion/stun | STUN Binding解析 | **低** | **低** — 协议很简单 | P1 |
| pion/turn | TURN中继客户端 | **中** | **低** — 中继本身就是备选 | P3 |

### 2.2 控制平面依赖（不替换 / 低优先级）

| 依赖 | 作用 | 替换必要性 |
|------|------|-----------|
| cobra/viper | CLI框架/配置 | **无** — 工具性代码，不影响性能 |
| zap | 日志 | **无** — 生产环境可关闭热路径日志 |
| gRPC/protobuf | 控制协议 | **低** — 可考虑自研轻量协议，但不紧急 |
| SQLite | 存储 | **无** — 不在数据路径上 |

### 2.3 自研价值分析

```
自研价值 = 性能提升空间 × 调用频率 × 可控性收益

wireguard-go:  极高 × 每包 × 极大  = ★★★★★  最值得
TUN读写:       中   × 每包 × 大    = ★★★★   值得，且简单
netstack:      高   × 每包 × 极大  = ★★★★   值得，但极难
STUN:          低   × 仅连接时 × 中 = ★★     简单，可早做
ICE:           中   × 仅连接时 × 大 = ★★★    复杂但有价值
TURN:          低   × 备选路径 × 中 = ★      最不紧急
```

---

## 三、抽象层设计原则

这是整个策略成功的关键。**抽象层不对，后面全白搭。**

### 3.1 核心原则

**1. 第三方类型绝不泄漏**

```go
// 错误 ❌ — pion的类型暴露到了模块接口上
type ICEAgent struct {
    agent *ice.Agent  // pion类型
}
func (a *ICEAgent) GetCandidates() []ice.Candidate { ... }  // 泄漏

// 正确 ✅ — 自定义类型，第三方只在实现内部
type ICEAgent interface {
    GatherCandidates(ctx context.Context) ([]Candidate, error)  // 自己的类型
}

type Candidate struct {  // 自己定义，不是pion的
    Type     CandidateType
    Address  netip.AddrPort
    Priority uint32
}
```

**2. 抽象层的接口按"自研时需要什么"来设计，而不是按第三方库的API来设计**

```go
// 错误 ❌ — 照搬wireguard-go的API设计
type Tunnel interface {
    IpcSet(config string) error  // 这是wireguard-go的UAPI，不是通用接口
}

// 正确 ✅ — 按隧道的本质需求设计
type Tunnel interface {
    // 数据路径 — 这才是隧道的本质
    EncryptAndSend(plaintext []byte, peer PeerID) error
    ReceiveAndDecrypt() ([]byte, PeerID, error)
    
    // Peer管理
    AddPeer(cfg PeerConfig) error
    RemovePeer(id PeerID) error
    UpdateEndpoint(id PeerID, endpoint netip.AddrPort) error
}
```

**3. 一个依赖一个包，替换时换一个文件，不动其他任何代码**

```
pkg/tunnel/
├── tunnel.go              # 接口定义 — 永远不改
├── tunnel_wireguardgo.go  # 当前实现：封装wireguard-go
├── tunnel_native.go       # 未来实现：自研Noise+ChaCha20
└── tunnel_test.go         # 面向接口的测试 — 两个实现都跑同一套测试
```

### 3.2 每个抽象层的边界

```
┌─────────────────────────────────────────────────────────────┐
│                      应用层（TASK-06）                        │
│                  只看到接口，不知道背后是谁                    │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐  ┌───────────┐  ┌───────────┐  ┌────────┐ │
│  │   Tunnel     │  │  NetIF    │  │    NAT    │  │ Relay  │ │
│  │  interface   │  │ interface │  │ interface │  │  iface │ │
│  └──────┬──────┘  └─────┬─────┘  └─────┬─────┘  └───┬────┘ │
│         │               │              │             │      │
│  ═══════╪═══════════════╪══════════════╪═════════════╪══════│
│  抽象墙 │               │              │             │      │
│  ═══════╪═══════════════╪══════════════╪═════════════╪══════│
│         │               │              │             │      │
│  ┌──────▼──────┐  ┌─────▼─────┐  ┌─────▼─────┐  ┌──▼─────┐│
│  │wireguard-go │  │ wg/tun    │  │ pion/ice  │  │pion/   ││
│  │  (当前)     │  │  (当前)    │  │  (当前)    │  │turn    ││
│  ├─────────────┤  ├───────────┤  ├───────────┤  │(当前)  ││
│  │ 自研Noise   │  │ 自研TUN   │  │ 自研ICE   │  ├────────┤│
│  │  (将来)     │  │  (将来)    │  │  (将来)    │  │自研    ││
│  └─────────────┘  └───────────┘  └───────────┘  │(将来)  ││
│                                                   └────────┘│
└─────────────────────────────────────────────────────────────┘
```

---

## 四、分阶段自研路线

### Phase 0: MVP — 用第三方跑通（当前阶段）

```
目标: 产品可用，验证架构
策略: 全部使用第三方实现，但严格遵守抽象层设计

重点:
- 每个第三方库都隔离在独立的实现文件中
- 接口测试覆盖率 > 90%（测试面向接口，不面向实现）
- 记录每个第三方的性能瓶颈点
```

MVP 期间的代码结构：

```
pkg/tunnel/
├── tunnel.go                  # Tunnel接口
├── tunnel_wggo.go             # wireguard-go 实现
├── tunnel_wggo_test.go        # 实现级测试
└── tunnel_interface_test.go   # 接口级测试（替换后仍跑这套）

pkg/crypto/
├── noise.go                   # Noise协议接口
├── noise_wggo.go              # 基于wireguard-go的实现（当前）
├── cipher.go                  # 对称加密接口
└── cipher_chacha20.go         # 基于x/crypto的实现（当前）

pkg/netif/
├── interface.go               # NetworkInterface接口
├── tun_linux.go               # 基于wireguard/tun（当前）
├── tun_linux_native.go        # 自研syscall实现（将来）
├── userspace.go               # 基于gVisor（当前）
└── userspace_native.go        # 自研协议栈（将来，如果做的话）

pkg/nat/
├── traversal.go               # NATTraversal接口
├── stun.go                    # STUN接口
├── stun_pion.go               # 基于pion/stun（当前）
├── stun_native.go             # 自研STUN（将来）
├── ice.go                     # ICE接口
├── ice_pion.go                # 基于pion/ice（当前）
└── ice_native.go              # 自研ICE（将来）
```

### Phase 1: TUN设备 + STUN自研

**为什么先做这两个**: 最简单，投入产出比最高。

#### 1a. TUN设备自研

**难度**: 低（各平台就是几个系统调用）

**当前**: wireguard/tun 库提供跨平台TUN，但它是通用实现。

**自研收益**:
- 直接控制系统调用（减少一层封装开销）
- 可以做平台特定优化（如Linux的io_uring、Windows的Overlapped IO）
- 去掉不需要的功能，减小二进制

**实现规模**: 每个平台约 200-400 行代码

```go
// Linux: 直接 ioctl
func createTUN(name string) (*TUNDevice, error) {
    fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
    if err != nil {
        return nil, err
    }
    var ifr [unix.IFNAMSIZ + 64]byte
    copy(ifr[:], name)
    *(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = unix.IFF_TUN | unix.IFF_NO_PI
    _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
    // ...
}

// Windows: 直接调用WinTUN DLL
// macOS: 直接创建utun socket
```

#### 1b. STUN客户端自研

**难度**: 低（STUN协议非常简单，本质上就是一个20字节头部+若干TLV属性的UDP包）

**STUN报文格式**:
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0 0|     STUN Message Type     |         Message Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Magic Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Transaction ID (96 bits)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**实现规模**: 约 300-500 行代码

```go
// STUN Binding Request/Response 就是解析几个固定字段
type STUNMessage struct {
    Type          uint16
    Length        uint16
    MagicCookie   uint32  // 固定值 0x2112A442
    TransactionID [12]byte
    Attributes    []Attribute
}

// XOR-MAPPED-ADDRESS 解析: 与 MagicCookie 做异或就得到真实地址
func parseXORMappedAddress(data []byte, txID [12]byte) (netip.AddrPort, error) {
    // ~50行代码
}
```

**NAT类型检测也一并自研**: 就是向不同STUN服务器发几个包，对比结果，约200行逻辑。

### Phase 2: WireGuard协议自研

**这是核心中的核心，也是最有价值的自研目标。**

**难度**: 高，但有明确的参考。

**WireGuard协议的组成**:

| 组件 | 复杂度 | 自研所需 |
|------|--------|----------|
| Noise IK握手 | 中 | Curve25519(标准库有) + 状态机（长期演进为Noise KK，见wink-protocol-v1.md） |
| ChaCha20-Poly1305 数据加密 | 低 | Go标准库 `x/crypto` 已有原语 |
| 密钥轮换 (Rekey) | 中 | 计时器 + 重新握手 |
| 抗重放 (Anti-Replay) | 低 | 滑动窗口位图 |
| Cookie机制 (DoS防护) | 低 | HMAC-BLAKE2s |
| 计时器状态机 | 中 | 6种计时器事件 |

**关键认知**: WireGuard协议之所以被称为优雅，正是因为它**简单**。整个Linux内核实现只有约4000行C代码。一个Go用户态实现，核心逻辑大约在 **2000-3000行** 量级。

**拆解步骤**:

```
Step 1: 密钥操作（约200行）
  - Curve25519 密钥生成（标准库: x/crypto/curve25519）
  - BLAKE2s 哈希（标准库: x/crypto/blake2s）
  - ChaCha20-Poly1305 AEAD（标准库: x/crypto/chacha20poly1305）
  → 这步零风险，全是标准库调用

Step 2: Noise IK 握手（约500行，MVP兼容WireGuard）
  - Initiator → Responder: 第一个消息（ephemeral + static + timestamp）
  - Responder → Initiator: 第二个消息（ephemeral + empty）
  - 派生传输密钥
  → 长期目标: 演进为Noise KK模式（去掉encrypted_static，消息1缩短至96字节），详见 wink-protocol-v1.md
  → WireGuard白皮书里有完整的伪代码

Step 3: 数据传输（约300行）
  - 封装: plaintext → AEAD加密 → UDP发送
  - 解封: UDP接收 → AEAD解密 → plaintext
  - 计数器管理（防重放）
  → 最核心的热路径，也是优化空间最大的地方

Step 4: 计时器和状态机（约500行）
  - 握手超时重传
  - Keepalive发送
  - 密钥轮换触发
  - 连接空闲检测
  → 参照wireguard-go的timers.go

Step 5: 性能优化
  - 零拷贝：直接在TUN读写缓冲区上加密
  - 缓冲池：sync.Pool减少GC压力
  - 批量发送：sendmmsg/recvmmsg（Linux）
  - 多核并行：per-CPU加密流水线
```

**为什么wireguard-go值得替换**:
```
wireguard-go 为了通用性做了很多我们不需要的:
- UAPI接口 (Unix socket命令接口) — 我们不需要，直接API调用
- 兼容原生wg工具 — 我们有自己的CLI
- 通用的tun.Device适配 — 我们有自己的NetIF抽象

去掉这些后，代码量可以砍掉一半以上。
而且关键路径上可以做:
- 内存零拷贝（TUN读出的buffer直接进加密，加密后直接进UDP发送）
- 减少goroutine切换（热路径单goroutine+polling模型）
- 减少接口虚拟调用（在热路径上用具体类型替代interface{}）
```

### Phase 3: ICE协商自研

**难度**: 中高

**ICE协议拆解**:

| 组件 | 复杂度 | 行数估计 |
|------|--------|---------|
| 候选收集 (Host/Srflx/Relay) | 低 | 200行 |
| 候选排序和配对 | 低 | 150行 |
| 连通性检查 (STUN Binding) | 中 | 300行 |
| 角色协商 (Controlling/Controlled) | 低 | 100行 |
| 状态机 | 中 | 300行 |
| Trickle ICE (渐进式候选) | 中 | 200行 |

**总计约 1200-1500 行代码**。注意ICE本身不在数据路径上（连接建立完成后就不跑了），所以自研价值低于WireGuard，但控制力上的收益仍然显著：可以针对国内NAT环境做专门优化。

### Phase 4: 用户态协议栈（可选/长期）

**难度**: 极高

**现实判断**: gVisor netstack 是 Google 投入大量工程资源的项目，从零自研一个完整的TCP/IP协议栈不现实。但可以做的是：

```
方案A: 精简版协议栈
  - 只实现 TCP + UDP + ICMP
  - 不需要完整的 socket API
  - 不需要支持所有 TCP 扩展
  - 估计 3000-5000 行代码
  - 参考: smoltcp (Rust), lwIP (C)

方案B: 保持使用 netstack，但包一层优化
  - 自定义内存分配器
  - 减少不必要的拷贝
  - 调整缓冲区策略

建议: 方案B 为主，方案A 作为长期研究项目
```

---

## 五、替换优先级时间线

```
MVP阶段              Phase 1               Phase 2              Phase 3
(全部第三方)         (小组件自研)          (核心自研)           (深度自研)
                                                                
wireguard-go ·····→ wireguard-go ·······→ 自研Noise隧道 ····→  持续优化
wireguard/tun ····→ 自研TUN读写  ·······→ + io_uring ········→ + zero-copy
pion/stun ········→ 自研STUN客户端 ·····→                      
pion/ice ·········→ pion/ice ···········→ pion/ice ··········→  自研ICE
pion/turn ········→ pion/turn ··········→ pion/turn ·········→  自研TURN
gVisor netstack ··→ gVisor netstack ····→ gVisor+优化 ·······→  精简TCP/IP
cobra/viper ······→ cobra/viper(不替换) ·······························→
zap ··············→ zap(不替换) ····················································→
gRPC/protobuf ···→ gRPC/protobuf ······→ 可考虑自研轻量协议 ·→
```

---

## 六、自研质量保证

### 6.1 接口级测试

```go
// tunnel_interface_test.go
// 这套测试不管底层是wireguard-go还是自研，都必须通过

func TestTunnel_Handshake(t *testing.T) {
    for _, impl := range []string{"wggo", "native"} {
        t.Run(impl, func(t *testing.T) {
            tunnel := createTunnel(impl)
            // 测试握手...
        })
    }
}

func TestTunnel_DataTransfer(t *testing.T) { ... }
func TestTunnel_Rekey(t *testing.T) { ... }
func TestTunnel_AntiReplay(t *testing.T) { ... }
```

### 6.2 对比基准测试

```go
// tunnel_bench_test.go
// 自研实现必须在基准测试中达到或超过第三方

func BenchmarkEncrypt_WireguardGo(b *testing.B) { ... }
func BenchmarkEncrypt_Native(b *testing.B) { ... }

func BenchmarkTUNRead_WireguardTun(b *testing.B) { ... }
func BenchmarkTUNRead_Native(b *testing.B) { ... }
```

### 6.3 替换准入条件

一个自研实现要替换第三方，必须同时满足:

1. **通过全部接口级测试** — 功能完备
2. **基准测试性能 >= 第三方** — 性能不退化
3. **72小时压力测试无异常** — 稳定可靠
4. **代码经过审查** — 无安全漏洞

---

## 七、开发语言考量

当前选型是 Go。对于自研路线需要注意：

**Go 的优势**:
- 跨平台编译简单
- goroutine 模型适合网络编程
- 密码学标准库质量高（x/crypto）
- 编译快，迭代快

**Go 在热路径上的劣势**:
- GC 会导致延迟毛刺（可通过 `sync.Pool` + `GOGC` 缓解）
- 接口调用有虚拟分派开销（可在热路径上避免接口）
- 不支持 SIMD 内联（加密运算略慢于 C/Rust，但 Go 的 crypto 库内部已用汇编优化）

**结论**: Go 足以做出高性能实现。真正的性能瓶颈不在语言，而在：
- 内存拷贝次数
- 系统调用次数
- 锁竞争程度
- 缓冲区管理策略

这些都可以在 Go 里解决，不需要为了性能换语言。

---

## 八、核心收益总结

全部自研完成后，WinkYou 将拥有:

| 特性 | 竞品 (Tailscale等) | WinkYou 自研 |
|------|---------------------|-------------|
| 加密隧道 | 通用 wireguard-go | 针对场景优化的精简实现 |
| 内存拷贝 | 多次（跨库边界） | 零拷贝流水线 |
| 依赖体积 | 大量间接依赖 | 最小依赖树 |
| 问题排查 | 黑盒第三方库 | 完全可控可调试 |
| 安全审计 | 依赖上游修复 | 自主修复能力 |
| 许可证风险 | 依赖多个许可证 | 自主知识产权 |
| 优化空间 | 受限于通用设计 | 可做极致优化 |

---

*文档版本: v1.0*
*创建日期: 2026-04-02*
