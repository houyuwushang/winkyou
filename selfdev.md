# WinkYou 完全自研开发计划

> 本文档描述：如果核心组件全部自己写，具体要写什么、怎么写、按什么顺序。
> 
> 与 selfhost.md 的关系：selfhost.md 是"先跑通再替换"的渐进策略，本文档是那个"替换"阶段的详细施工图纸。两份文档配合使用：MVP阶段看TASK文档，自研阶段看本文档。
>
> 创建日期: 2026-04-02

---

## 零、先搞清楚到底要写多少东西

完全自研意味着替掉数据路径上的全部第三方库。下面是一张总表：

| 替换目标 | 它干了什么 | 自研代码量估计 | 涉及的RFC/规范 | 前置知识 |
|----------|-----------|---------------|----------------|----------|
| wireguard/tun | 创建TUN设备、读写IP包 | ~800行 | Linux tuntap文档、macOS utun、WinTUN API | 系统调用、ioctl |
| STUN客户端 | 发UDP包、解析响应、得到公网地址 | ~500行 | RFC 5389 | UDP编程 |
| NAT类型检测 | 向多个STUN服务器发包、对比结果 | ~300行 | RFC 5780 | STUN基础 |
| Noise IK握手 | 密钥协商、身份认证 | ~600行 | Noise Protocol Framework规范 | 密码学基础 |
| WireGuard数据传输 | 加密封装IP包、解密还原 | ~400行 | WireGuard白皮书 | AEAD加密 |
| WireGuard计时器 | 重传、Keepalive、密钥轮换 | ~500行 | WireGuard白皮书 | 状态机设计 |
| WireGuard抗重放 | 滑动窗口过滤重复包 | ~100行 | WireGuard白皮书 | 位运算 |
| Cookie机制 | DoS防护 | ~200行 | WireGuard白皮书 | HMAC |
| ICE候选收集 | 枚举本地IP、查询STUN、申请TURN | ~400行 | RFC 8445 | 网络编程 |
| ICE连通性检查 | 候选配对、发STUN检查、选最优 | ~600行 | RFC 8445 | STUN基础 |
| ICE状态机 | 管理协商生命周期 | ~400行 | RFC 8445 | 状态机设计 |
| TURN客户端 | 申请中继地址、通过中继收发数据 | ~600行 | RFC 5766 | STUN基础 |
| TURN服务器 | 管理Allocation、转发数据 | ~1000行 | RFC 5766 | 并发编程 |
| 用户态TCP/IP栈 | 在用户空间处理IP/TCP/UDP/ICMP | ~4000-6000行 | RFC 791/793/768/792 | 协议栈原理 |
| **合计** | | **~10000-12000行核心代码** | | |

注：这里不含测试代码。测试代码通常是实现代码的1-2倍。

一万行核心代码看起来多，但分散到十几个独立模块里，每个模块几百行，每一个都是可以独立理解、独立测试的。

---

## 一、模块S1: TUN设备自研

### 要做什么

绕过wireguard/tun库，自己调用系统API创建和操作TUN虚拟网卡。

### 每个平台要写的东西

#### Linux (~200行)

```
用到的系统调用:
  open("/dev/net/tun")      → 拿到文件描述符
  ioctl(TUNSETIFF)          → 创建TUN设备，指定名称和标志
  ioctl(SIOCSIFADDR)        → 设置IP地址
  ioctl(SIOCSIFNETMASK)     → 设置子网掩码
  ioctl(SIOCSIFMTU)         → 设置MTU
  ioctl(SIOCADDRT)          → 添加路由
  read(fd)                  → 从TUN读一个IP包
  write(fd)                 → 向TUN写一个IP包

实现结构:
  tunLinux struct {
      fd   int          // 文件描述符
      name string       // 设备名 wink0
      mtu  int
  }

  func (t *tunLinux) Read(buf []byte) (int, error)   → unix.Read(t.fd, buf)
  func (t *tunLinux) Write(buf []byte) (int, error)  → unix.Write(t.fd, buf)
  func (t *tunLinux) Close() error                   → unix.Close(t.fd)
```

关键点: Linux TUN设备默认带4字节协议头(PI header)，用`IFF_NO_PI`标志去掉，这样读写的就是纯IP包。

#### macOS (~200行)

```
用到的系统调用:
  socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) → 创建控制socket
  connect(fd, utun控制信息)                        → 创建utun设备
  read/write                                       → 读写IP包

注意: macOS的utun接口名是系统分配的(utun0, utun1...)，不能自定义名称。
      macOS的utun读写带4字节AF头(地址族)，需要处理。
```

#### Windows (~250行)

```
用到的API (通过WinTUN DLL):
  WintunCreateAdapter()     → 创建适配器
  WintunStartSession()      → 开始会话
  WintunAllocateSendPacket() → 分配发送缓冲区
  WintunSendPacket()        → 发送
  WintunReceivePacket()     → 接收
  WintunReleaseReceivePacket()

实现方式: 嵌入wintun.dll，运行时释放并用syscall.LoadDLL加载。
WinTUN是纯ring buffer设计，性能很好。

路由配置: 调用netsh或Windows route API
  exec.Command("netsh", "interface", "ip", "add", "address", ...)
  或使用 MIB API: CreateIpForwardEntry2
```

### 性能优化空间

```
基础版: read/write系统调用，每次一个包
  ↓
优化1: Linux上用readv/writev批量读写
  ↓
优化2: Linux上用recvmmsg/sendmmsg一次系统调用收发多个包
  ↓
优化3: Linux上用io_uring异步IO（Go 1.22+有实验性支持）
  ↓
优化4: 缓冲区预分配 + sync.Pool，消除GC压力
```

### 验证标准

```bash
# 创建TUN设备
$ sudo go test -run TestCreateTUN
# 预期: ip link show wink0 能看到设备

# 读写测试
$ sudo go test -run TestTUNReadWrite
# 预期: 一端写入ICMP包，另一端能读到

# 性能基准
$ sudo go test -bench BenchmarkTUNReadWrite
# 预期: >= wireguard/tun库的性能
```

---

## 二、模块S2: STUN客户端 + NAT检测自研

### 要做什么

实现STUN协议(RFC 5389)的客户端部分，用来发现自己的公网地址和NAT类型。

### STUN协议有多简单

整个STUN消息就这个格式:

```
 字节  0       1       2       3
     +-------+-------+-------+-------+
  0  | 类型(2B)      | 长度(2B)      |   ← 消息类型 + 属性总长度
     +-------+-------+-------+-------+
  4  | Magic Cookie (0x2112A442)     |   ← 固定值
     +-------+-------+-------+-------+
  8  | Transaction ID (12字节)       |   ← 随机标识
     +-------+-------+-------+-------+
 20  | 属性TLV ...                   |   ← 类型(2B) + 长度(2B) + 值
     +-------+-------+-------+-------+
```

我们只需要实现:
- **Binding Request**: 空消息体，只有头部20字节
- **解析Binding Response**: 从中提取 XOR-MAPPED-ADDRESS 属性

XOR-MAPPED-ADDRESS 的解码:

```
IP  = 响应中的IP  XOR MagicCookie的高2字节
Port = 响应中的Port XOR MagicCookie的高2字节

就这么简单。
```

### 实现拆分

```
stun_message.go (~150行)
├── 编码Binding Request  → 填20字节头部
├── 解码Response         → 解析头部 + 遍历TLV属性
├── 解码XOR-MAPPED-ADDRESS → 异或运算得到真实地址
└── 解码MAPPED-ADDRESS     → 直接读取（兼容旧服务器）

stun_client.go (~200行)
├── Send(server string) → 发UDP包，等响应，带重传
├── 重传逻辑            → 500ms, 1s, 2s, 4s 指数退避
└── 多服务器并发查询    → goroutine并发，取最快响应

nat_detect.go (~200行)
├── 检测算法（RFC 5780描述的流程）:
│   1. 向服务器A发Binding → 得到映射地址M1
│   2. M1 == 本地地址?    → 是: 无NAT
│   3. 请求服务器A从另一IP回复 → 收到? → Full Cone
│   4. 向服务器B发Binding → 得到映射地址M2
│   5. M1 == M2?          → 否: Symmetric NAT
│   6. 请求服务器A从另一端口回复 → 收到? → Restricted Cone
│   7. 否则                → Port Restricted Cone
└── 返回 NATType枚举值
```

### 实现的关键代码骨架

```go
// 整个STUN Binding Request就是这么短
func buildBindingRequest(txID [12]byte) []byte {
    msg := make([]byte, 20)
    // 类型: 0x0001 (Binding Request)
    binary.BigEndian.PutUint16(msg[0:2], 0x0001)
    // 长度: 0 (无属性)
    binary.BigEndian.PutUint16(msg[2:4], 0)
    // Magic Cookie
    binary.BigEndian.PutUint32(msg[4:8], 0x2112A442)
    // Transaction ID
    copy(msg[8:20], txID[:])
    return msg
}

// 解析XOR-MAPPED-ADDRESS
func parseXORMappedAddr(attr []byte, txID [12]byte) (netip.AddrPort, error) {
    family := attr[1] // 0x01=IPv4, 0x02=IPv6
    xorPort := binary.BigEndian.Uint16(attr[2:4])
    port := xorPort ^ 0x2112 // XOR with magic cookie high 16 bits
    
    if family == 0x01 {
        var ip [4]byte
        xorIP := binary.BigEndian.Uint32(attr[4:8])
        binary.BigEndian.PutUint32(ip[:], xorIP^0x2112A442)
        return netip.AddrPortFrom(netip.AddrFrom4(ip), port), nil
    }
    // IPv6 类似，XOR还要用上txID
    // ...
}
```

### 验证标准

```bash
# 向公共STUN服务器查询
$ go test -run TestSTUNBinding
# 预期: 返回的公网IP与 curl ifconfig.me 一致

# NAT类型检测
$ go test -run TestNATDetect
# 预期: 在不同网络环境返回正确的NAT类型
```

---

## 三、模块S3: WireGuard协议自研 (核心)

这是工作量最大、价值最高的模块。拆成5个子步骤。

### 前置知识

需要理解的密码学原语（全部有Go标准库实现，不需要自己写算法）:

```
Curve25519       — 椭圆曲线密钥交换    → x/crypto/curve25519
ChaCha20-Poly1305 — AEAD对称加密       → x/crypto/chacha20poly1305
BLAKE2s          — 哈希函数             → x/crypto/blake2s
HMAC-BLAKE2s     — 消息认证码          → BLAKE2s + 标准HMAC构造
```

你不需要理解这些算法的内部实现，只需要会调用它们的API。就像你用`sha256.Sum256()`不需要知道SHA256内部怎么压缩一样。

### 步骤3a: 密码学工具层 (~200行)

```
crypto.go — 封装所有密码学操作

需要实现的函数:
  DH(private, public) → shared         // Curve25519
  Encrypt(key, counter, plain, ad) → cipher  // ChaCha20-Poly1305
  Decrypt(key, counter, cipher, ad) → plain
  Hash(data) → [32]byte               // BLAKE2s-256
  MAC(key, data) → [16]byte           // Keyed BLAKE2s-128
  HMAC(key, data) → [32]byte          // HMAC-BLAKE2s-256
  KDF(key, input) → (k1, k2, k3)     // HKDF基于HMAC-BLAKE2s

底层调用:
  curve25519.ScalarMult(dst, scalar, point)
  chacha20poly1305.NewX(key)  // 构造AEAD
  aead.Seal(dst, nonce, plain, ad)
  aead.Open(dst, nonce, cipher, ad)
  blake2s.New256()
```

这200行代码是纯粹的"胶水"——调用标准库，包装成WireGuard协议需要的名字。

### 步骤3b: Noise IK握手 (~600行)

> **演进说明**: 本节描述的是WireGuard兼容的Noise IK实现（用于MVP和tunnel_wggo.go）。
> 长期目标的Wink Protocol使用Noise KK模式，消息1缩短至96字节，详见 wink-protocol-v1.md。

WireGuard的握手就是Noise_IKpsk2模式，总共只有**2条消息**:

```
消息1: Initiator → Responder  (148字节)
┌─────────────────────────────────────────────────────┐
│ Type(1B)=1 │ Sender(4B) │ Ephemeral(32B) │          │
│ Static(encrypted, 48B) │ Timestamp(encrypted, 28B) │ │
│ MAC1(16B) │ MAC2(16B)                               │
└─────────────────────────────────────────────────────┘

消息2: Responder → Initiator  (92字节)
┌─────────────────────────────────────────────────────┐
│ Type(1B)=2 │ Sender(4B) │ Receiver(4B) │            │
│ Ephemeral(32B) │ Empty(encrypted, 16B) │             │
│ MAC1(16B) │ MAC2(16B)                               │
└─────────────────────────────────────────────────────┘

握手完成后: 双方派生出两个对称密钥(send_key, recv_key)
```

握手的加密流程（Noise IK模式）:

```
Initiator构造消息1:
  1. 生成临时密钥对 (ephemeral)
  2. e_pub 明文发送
  3. DH(e_priv, responder_static_pub) → 混入链式密钥
  4. 用链式密钥加密自己的static_pub → 密文发送
  5. DH(s_priv, responder_static_pub) → 混入链式密钥
  6. 用链式密钥加密TAI64N时间戳 → 密文发送
  7. 计算MAC1, MAC2

Responder处理消息1 + 构造消息2:
  1. 读取对方的ephemeral_pub
  2. DH(s_priv, initiator_e_pub) → 恢复链式密钥
  3. 解密得到对方的static_pub → 知道是谁了
  4. DH(s_priv, initiator_s_pub) → 恢复链式密钥
  5. 解密得到时间戳 → 防重放
  6. 生成自己的临时密钥对
  7. DH(e_priv, initiator_e_pub) → 混入链式密钥
  8. DH(e_priv, initiator_s_pub) → 混入链式密钥
  9. 如有PSK: 混入PSK
  10. 派生传输密钥 → (send_key, recv_key)

就这些。没有证书、没有多轮协商、没有复杂状态。
```

实现结构:

```
handshake.go (~400行)
├── type HandshakeState struct {
│       localStatic   PrivateKey
│       remoteStatic  PublicKey      // Responder的公钥（Initiator预先知道）
│       localEphemeral PrivateKey    // 每次握手新生成
│       chainingKey   [32]byte       // 链式密钥，贯穿整个握手
│       hash          [32]byte       // 握手hash，贯穿整个握手
│   }
├── CreateInitiation()  → []byte     // 构造消息1
├── ConsumeInitiation() → error      // 处理消息1
├── CreateResponse()    → []byte     // 构造消息2
├── ConsumeResponse()   → error      // 处理消息2
└── DeriveKeys() → (sendKey, recvKey) // 派生传输密钥

noise.go (~200行)
├── mixHash(data)        // hash = HASH(hash || data)
├── mixKey(input)        // chainingKey, key = KDF(chainingKey, input)
├── encryptAndHash(key, plain) // 加密并混入hash
└── decryptAndHash(key, cipher) // 解密并混入hash
```

### 步骤3c: 数据传输 (~400行)

握手完成后，所有数据包用这个格式:

```
数据包格式 (Transport Data):
┌──────────────────────────────────────────────┐
│ Type(1B)=4 │ Receiver(4B) │ Counter(8B) │    │
│ Encrypted Payload (N+16 bytes)               │
└──────────────────────────────────────────────┘

加密: ChaCha20-Poly1305(key=send_key, nonce=counter, plain=IP包, ad=空)
就这一步。没有别的了。
```

实现:

```
transport.go (~250行)
├── type TransportKeypair struct {
│       sendKey    [32]byte
│       recvKey    [32]byte
│       sendNonce  atomic.Uint64   // 递增，永不重复
│       recvWindow ReplayWindow    // 抗重放窗口
│       created    time.Time       // 用于密钥轮换判断
│   }
├── Encrypt(plainIP []byte) → []byte  // 封装
└── Decrypt(packet []byte) → []byte   // 解封

replay.go (~100行)
├── type ReplayWindow struct {
│       bitmap  [2048/64]uint64  // 位图，跟踪最近2048个序号
│       last    uint64           // 收到的最大序号
│   }
└── Check(counter uint64) → bool // 是否重放
    // 算法: 如果counter > last，更新窗口
    //       如果counter在窗口内，检查对应bit
    //       如果counter太旧（< last-2048），拒绝
```

### 步骤3d: 计时器和状态机 (~500行)

WireGuard有6种计时器事件:

```
timers.go:

1. REKEY_AFTER_MESSAGES (2^60个包后)    → 触发重新握手
2. REJECT_AFTER_MESSAGES (2^64-2^4-1后) → 拒绝使用当前密钥
3. REKEY_AFTER_TIME (120秒后)           → 触发重新握手
4. REJECT_AFTER_TIME (180秒后)          → 强制丢弃密钥对
5. KEEPALIVE_TIMEOUT (25秒无发送)       → 发送空Keepalive
6. REKEY_TIMEOUT (5秒无握手响应)        → 重试握手

状态机:
  Idle → 需要发数据 → 发起握手
  Handshake Initiating → 收到响应 → Active
  Active → 计数器到期 → 发起重握手
  Active → 超时无数据 → 发送Keepalive
```

### 步骤3e: Cookie DoS防护 (~200行)

```
cookie.go:

当服务器过载时，回复一个cookie:
  消息3: Cookie Reply (64字节)
  ┌────────────────────────────────────────────┐
  │ Type(1B)=3 │ Receiver(4B) │                │
  │ Nonce(24B) │ Encrypted Cookie(32B)         │
  └────────────────────────────────────────────┘

客户端收到后，下次握手在MAC2字段填入cookie。
服务器只在过载时才检查MAC2，平时忽略。

实现量不大，核心就是:
  GenerateCookie(sourceIP) → cookie
  ValidateMAC2(message, cookie) → bool
```

### 整个WireGuard自研的集成

```
device.go (~300行) — 把上面所有部分组装起来
├── type Device struct {
│       tun        TUNDevice        // 读写虚拟网卡
│       bind       UDPBind          // 读写真实网络
│       staticKey  PrivateKey
│       peers      map[PublicKey]*Peer
│   }
│
├── 读循环 (从TUN读):
│   for {
│       ipPacket := tun.Read()
│       peer := lookupPeer(ipPacket.DstIP)  // 查AllowedIPs
│       encrypted := peer.keypair.Encrypt(ipPacket)
│       bind.SendTo(encrypted, peer.endpoint)
│   }
│
└── 写循环 (从UDP读):
    for {
        packet, addr := bind.ReadFrom()
        switch packet.Type {
        case 1: handleInitiation(packet, addr)
        case 2: handleResponse(packet, addr)
        case 3: handleCookie(packet)
        case 4:
            peer := lookupPeerByReceiver(packet.Receiver)
            ipPacket := peer.keypair.Decrypt(packet)
            tun.Write(ipPacket)
        }
    }
```

### 验证标准

```
1. 互操作测试 — 自研实现 ↔ wireguard-go 能握手通信
   这是最关键的测试。协议是标准的，两边实现必须能对话。

2. 抗重放测试 — 重复发送同一个包，第二次被拒绝

3. 密钥轮换测试 — 120秒后自动重新握手，新密钥生效

4. 性能基准 — 加密吞吐 >= wireguard-go
```

---

## 四、模块S4: ICE协商自研

### 要做什么

实现RFC 8445的核心部分，让两个NAT后面的节点找到彼此能通信的路径。

### ICE协议的核心流程（其实不复杂）

```
两边各自:
1. 收集候选地址
   ├── Host: 列出所有本地IP（net.Interfaces()）
   ├── Server Reflexive: 向STUN服务器查询公网映射
   └── Relay: 向TURN服务器申请中继地址

2. 交换候选（通过协调服务器的信令通道）
   A的候选 → 协调服务器 → B
   B的候选 → 协调服务器 → A

3. 配对和检查
   ├── 将本地候选和远端候选两两配对
   ├── 按优先级排序
   └── 从高到低逐对发STUN Binding Request检查
       ├── 对方收到后回STUN Binding Response
       ├── 双方都收到Response → 这对能通！
       └── 选优先级最高的能通的对

4. 完成
   └── 返回选中的通信地址对
```

### 实现拆分

```
gatherer.go (~300行) — 候选收集
├── gatherHostCandidates()
│   └── 遍历net.Interfaces()，过滤回环/link-local
├── gatherServerReflexiveCandidates()
│   └── 调用自研STUN客户端
└── gatherRelayCandidates()
    └── 调用TURN客户端申请Allocation

candidate.go (~150行) — 候选类型和优先级
├── type Candidate struct { ... }
├── Priority() uint32
│   └── RFC 8445公式: (2^24)*type + (2^8)*local + (256-component)
└── PairPriority(local, remote) uint64
    └── RFC 8445公式: 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)

checklist.go (~400行) — 连通性检查
├── type CheckList struct {
│       pairs     []CandidatePair      // 按优先级排序
│       triggered chan *CandidatePair   // 触发检查队列
│   }
├── BuildCheckList(local, remote []Candidate) — 两两配对
├── RunChecks(ctx) — 按优先级逐个检查
│   └── 对每一对:
│       1. 从local.Address发STUN Binding Request到remote.Address
│       2. 等待Response（超时500ms重传，最多重试7次）
│       3. 收到Response → 标记成功
│       4. 对方也收到我们的Response → 这对validated
└── SelectPair() → 返回优先级最高的validated对

agent.go (~350行) — ICE Agent主逻辑
├── type Agent struct {
│       role        Role  // Controlling / Controlled
│       localCands  []Candidate
│       remoteCands []Candidate
│       checkList   *CheckList
│       selected    *CandidatePair
│       state       ConnectionState
│   }
├── GatherCandidates()     → 收集本地候选
├── AddRemoteCandidate()   → 添加远端候选（支持Trickle ICE）
├── Start()                → 开始连通性检查
├── GetSelectedPair()      → 获取选中的地址对
└── 角色冲突处理
    └── 两边都是Controlling → 比较tie-breaker数字，小的变Controlled
```

### 一个精简ICE不需要的东西

RFC 8445很厚，但很多内容是给SIP/WebRTC用的，我们不需要:

```
不需要:
- ICE-TCP (我们只用UDP)
- SDP编码 (我们有自己的信令格式)
- SRTP/DTLS (我们用WireGuard加密，不用WebRTC的)
- 多Component (WebRTC有RTP+RTCP两个component，我们只有一个)
- ICE Lite完整兼容 (我们两端都是Full ICE)

需要:
- Host/Srflx/Relay 候选收集       ✓
- 候选配对和排序                   ✓
- STUN连通性检查                   ✓
- Controlling/Controlled 角色      ✓
- Trickle ICE (渐进式添加候选)     ✓
- Nominated pair 选择              ✓
```

砍掉这些后，工作量大幅降低。

---

## 五、模块S5: TURN自研

### TURN客户端 (~600行)

```
TURN在STUN基础上扩展了几种新消息:

Allocate Request/Response    → 申请中继地址
Refresh Request/Response     → 刷新分配（续期）
CreatePermission Request     → 授权某个IP向你中继
ChannelBind Request          → 绑定通道号（优化）
Send Indication              → 发数据（走中继）
Data Indication              → 收数据（走中继）

长期凭证认证:
  key = MD5(username:realm:password)
  HMAC-SHA1(key, message) → MESSAGE-INTEGRITY属性

实现拆分:
  turn_client.go (~350行)
  ├── Allocate() → 发请求，处理401挑战，得到中继地址
  ├── Refresh()  → 续期
  ├── AddPermission(peerIP) → 授权
  ├── Send(data, peerAddr) → 通过Send Indication发数据
  └── Recv() → 从Data Indication读数据

  turn_auth.go (~100行)
  ├── 长期凭证计算
  └── MESSAGE-INTEGRITY 生成和验证

  turn_channel.go (~150行)
  ├── ChannelBind(peerAddr) → 绑定通道号
  └── ChannelData 收发（比Indication少40字节开销）
```

### TURN服务器 (~1000行)

```
turn_server.go (~500行)
├── 监听UDP端口
├── 解析STUN/TURN消息
├── 分发到对应处理函数
├── Allocate处理 → 创建Allocation对象
├── Refresh处理  → 更新过期时间
├── CreatePermission处理 → 添加权限条目
└── Send处理 → 转发数据到对端

allocation.go (~300行)
├── type Allocation struct {
│       clientAddr   netip.AddrPort  // 客户端地址
│       relayAddr    netip.AddrPort  // 中继地址（服务器分配）
│       relayConn    *net.UDPConn    // 中继socket
│       permissions  map[netip.Addr]time.Time
│       channels     map[uint16]netip.AddrPort
│       expires      time.Time
│   }
├── 数据转发循环:
│   clientData → 检查permissions → 从relayConn发出
│   relayConn收到 → 检查permissions → 发回client
└── 过期清理

stats.go (~200行)
├── 流量统计
├── 连接数统计
└── 带宽限制
```

---

## 六、模块S6: 用户态TCP/IP栈 (长期目标)

### 为什么最难

一个最小可用的TCP实现需要处理:

```
TCP状态机（11种状态）:
  CLOSED → LISTEN → SYN_RECEIVED → ESTABLISHED
  ESTABLISHED → FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
  ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED

加上:
  - 三次握手 / 四次挥手
  - 滑动窗口流控
  - 拥塞控制 (至少实现Reno或Cubic)
  - 重传计时器 (RTO计算)
  - 慢启动 / 拥塞避免
  - 快速重传 / 快速恢复
  - Nagle算法
  - Delayed ACK
  - Keep-alive
  - MSS协商
  - Window Scaling
  - SACK (可选但重要)
```

### 最小可行实现策略

```
不做完整的通用TCP/IP栈，只做我们需要的:

IP层 (~400行):
  - IPv4报头解析和构造
  - 校验和计算
  - 分片? → 不做。设MTU让上层不超过。

ICMP (~150行):
  - Echo Request/Reply (ping)
  - Destination Unreachable

UDP (~200行):
  - 报头解析和构造
  - 校验和
  - 端口复用

TCP (~3000-4000行):
  - 最小状态机 (不需要全部11种状态的所有边界转换)
  - 简化的拥塞控制 (New Reno)
  - 基本窗口管理
  - 重传

连接管理 (~500行):
  - 监听端口
  - 建立连接
  - 关闭连接
  - 连接表管理
```

### 替代方案

```
方案A: 自研精简栈 (~4000-6000行)
  优点: 完全可控
  缺点: TCP非常难写对，边界情况极多

方案B: 保持gVisor，针对性优化
  优点: 省力，gVisor已经过大量测试
  缺点: 仍是第三方依赖

方案C: 移植smoltcp (Rust)为Go
  优点: smoltcp设计精简，约8000行Rust
  缺点: 跨语言移植工作量大

建议: 方案B为主，方案A作为学习和研究项目
      如果gVisor某天出现无法解决的问题，方案A作为备胎
```

---

## 七、完全自研的工作顺序

```
第一阶段: 基础 + 简单协议
═══════════════════════════════════
 S1: TUN设备 ←── 最简单，立竿见影
 S2: STUN + NAT检测 ←── 协议简单，500行搞定

第二阶段: 核心加密隧道
═══════════════════════════════════
 S3a: 密码学工具层 ←── 调标准库，200行
 S3b: Noise IK握手 ←── 整个自研最关键的600行（长期演进为Noise KK，见wink-protocol-v1.md）
 S3c: 数据传输 ←── 热路径核心，400行
 S3d: 计时器 ←── 保证稳定运行
 S3e: Cookie ←── DoS防护

 ★ 里程碑: 两个节点手动配置IP，能ping通 ★

第三阶段: 连接自动化
═══════════════════════════════════
 S4: ICE协商 ←── 自动找到能通信的路径
 S5: TURN ←── 穿透失败的备选

 ★ 里程碑: 两个NAT后的节点自动建立连接 ★

第四阶段: 无权限模式 (可选)
═══════════════════════════════════
 S6: 用户态TCP/IP ←── 最难，酌情考虑

 ★ 里程碑: 无管理员权限也能用 ★
```

### 每个阶段的验证检查点

```
第一阶段完成检查:
  □ 三个平台都能创建TUN设备并读写IP包
  □ 能检测出正确的NAT类型
  □ 能获取正确的公网映射地址
  □ 性能 >= 第三方库

第二阶段完成检查:
  □ 自研实现能与wireguard-go互操作握手 ← 最关键
  □ 加密数据传输正确（对比解密结果）
  □ 密钥轮换正常工作
  □ 抗重放有效
  □ 加密吞吐量 >= wireguard-go

第三阶段完成检查:
  □ 同局域网两节点自动连接
  □ 跨Cone NAT两节点自动连接
  □ Symmetric NAT自动回退到TURN
  □ TURN中继数据正确

第四阶段完成检查:
  □ TCP建连、传输、断连正常
  □ UDP收发正常
  □ ping正常
  □ 无root权限运行正常
```

---

## 八、需要读的文档

按模块列出必读材料，没有一份是废话，每一份都对应具体的代码。

### S1: TUN设备

| 文档 | 用途 | 读多久 |
|------|------|--------|
| Linux tuntap.txt | ioctl参数和标志 | 30分钟 |
| macOS utun接口文档 | socket创建方式 | 30分钟 |
| WinTUN API头文件 | DLL函数签名 | 20分钟 |

### S2: STUN

| 文档 | 用途 | 读多久 |
|------|------|--------|
| RFC 5389 第6-7章 | 消息格式、属性编码 | 1小时 |
| RFC 5780 第4章 | NAT检测算法 | 30分钟 |

### S3: WireGuard

| 文档 | 用途 | 读多久 |
|------|------|--------|
| WireGuard白皮书 (全文) | 完整协议定义 | 3小时 |
| Noise Protocol Framework 第7章 (IK模式) | 握手状态机 | 2小时 |
| wireguard-go源码 noise-protocol.go | 参考实现 | 2小时 |
| wireguard-go源码 timers.go | 计时器参考 | 1小时 |

### S4: ICE

| 文档 | 用途 | 读多久 |
|------|------|--------|
| RFC 8445 第5-8章 | 候选收集、配对、检查 | 3小时 |
| RFC 8838 (Trickle ICE) | 渐进式候选 | 1小时 |

### S5: TURN

| 文档 | 用途 | 读多久 |
|------|------|--------|
| RFC 5766 第2-4章 | Allocation流程 | 2小时 |
| RFC 5389 第10章 | 长期凭证认证 | 30分钟 |

### S6: TCP/IP栈

| 文档 | 用途 | 读多久 |
|------|------|--------|
| RFC 793 (TCP) | 状态机、可靠传输 | 4小时 |
| RFC 5681 (拥塞控制) | 慢启动、拥塞避免 | 2小时 |
| smoltcp源码 | 精简实现参考 | 4小时 |

---

## 九、两种路线的对比

| 维度 | 先跑通再替换 (selfhost.md) | 完全自研 (本文档) |
|------|--------------------------|-------------------|
| MVP出来速度 | 快 | 慢 |
| 最终性能上限 | 高 | 最高 |
| 技术深度 | 中 | 极深 |
| 风险 | 低 | 中（协议实现可能有bug）|
| 适合团队 | 有经验的Go开发者 | 熟悉网络协议的开发者 |
| 核心优势 | 快速验证市场 | 完全自主可控 |

**两条路不矛盾。** selfhost.md 的 Phase 0 (MVP) 和本文档的第一阶段可以同时进行——一组人用第三方库搭产品，另一组人开始写自研模块，写完一个替换一个。

---

*文档版本: v1.0*
*创建日期: 2026-04-02*
