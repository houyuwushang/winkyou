# Wink Protocol v1 — 详细设计

> 本文档是 brainstorm.md 第一版方案的完整展开。
> 精确到字节级的消息格式、精确到每一步的密钥派生、可以直接写代码的骨架。
>
> 创建日期: 2026-04-02

---

## 零、一个关键设计决策

**握手阶段和数据阶段用不同的密码原语。**

```
握手阶段: 固定使用 ChaCha20-Poly1305 + Curve25519 + BLAKE2s
  - 握手只有2条消息，性能无关紧要
  - 固定原语保证Noise框架的安全证明不受影响
  - 和WireGuard完全相同的安全性

数据阶段: 使用协商的密码套件
  - 这才是大量数据包经过的热路径
  - 在这里切换到AES-GCM获得硬件加速
```

这样做的好处：
1. 握手的安全性分析和WireGuard完全一样——Noise框架的证明直接适用
2. 数据传输获得硬件加速
3. 协商过程受握手密钥保护，不能被篡改

---

## 一、密码套件定义

### 1.1 套件列表

```
套件ID  名称                    AEAD               哈希(KDF用)   密钥长度
0x01    WINK_CHACHA20_BLAKE2S   ChaCha20-Poly1305  BLAKE2s       32字节
0x02    WINK_AES128_SHA256      AES-128-GCM        SHA-256       16字节
0x03    WINK_AES256_SHA256      AES-256-GCM        SHA-256       32字节
```

### 1.2 性能实测数据（单核MB/s，越大越好）

```
来源: ashvardanian.com 2025年测试

                       ChaCha20-Poly1305    AES-256-GCM    提升倍数
AMD Zen 5:             467-1580             862-3731       2-3x
Intel Ice Lake:        396-1158             577-2617       1.5-2.3x
Intel Sapphire Rapids: 393-1195             614-2891       1.6-2.4x
Apple M2 Pro:          327-1088             661-3131       2-3x

结论: 在所有现代CPU上（包括ARM Mac），AES-GCM都更快。
ChaCha20只在没有硬件加速的老设备上有优势。
```

### 1.3 套件选择逻辑

```go
func detectBestSuite() CipherSuite {
    // 用一个小benchmark来决定
    // 各加密100KB，谁快用谁
    
    chachaTime := benchmarkChaCha20(100 * 1024)
    aesTime := benchmarkAESGCM(100 * 1024)
    
    if aesTime < chachaTime {
        return WINK_AES256_SHA256
    }
    return WINK_CHACHA20_BLAKE2S
}
```

为什么不直接检测 CPU flag？
- Go标准库的 `crypto/aes` 已经自动使用 AES-NI（如果有）
- 直接 benchmark 比检测 flag 更准确——测的是真实性能，不是理论能力
- benchmark 100KB 只需不到1ms，启动时一次就行

---

## 二、消息格式（字节级）

### 2.1 消息类型

```
Type 0x01: Handshake Initiation
Type 0x02: Handshake Response
Type 0x03: Cookie Reply (DoS防护，和WireGuard相同)
Type 0x04: Transport Data (短头部)
Type 0x05: Transport Data (长头部)
```

### 2.2 Handshake Initiation (消息1: Initiator → Responder)

```
偏移  长度  字段                 说明
──────────────────────────────────────────────────────────
0     1     type                 = 0x01
1     1     suites               支持的套件位图
2     2     sender_index         发送方索引 (用于关联响应)
4     32    ephemeral            Initiator的临时公钥
36    28    encrypted_timestamp  加密的TAI64N时间戳 (12+16tag)
64    16    mac1                 MAC(hash(responder_pub), msg[0:64])
80    16    mac2                 MAC(cookie, msg[0:64]) 或全零
──────────────────────────────────────────────────────────
总长: 96字节

注意: Noise KK模式下，双方已通过协调服务器预知对方静态公钥，
因此不需要像Noise IK那样加密传输Initiator静态公钥(encrypted_static)。
这比WireGuard的消息1少了48字节。

suites字段 (位图):
  bit 0: 支持 WINK_CHACHA20_BLAKE2S
  bit 1: 支持 WINK_AES128_SHA256
  bit 2: 支持 WINK_AES256_SHA256
  bit 3-7: 保留

例: suites=0x07 表示三种都支持
```

**和WireGuard消息1的区别：**
- 使用Noise KK而非IK: 不需要加密传输Initiator静态公钥，去掉了 `encrypted_static`(48字节)
- 多了1字节 `suites` 字段
- `reserved`(3B) 变成 `suites`(1B) + `sender_index`(2B)
- 总长从148字节变成96字节（去掉encrypted_static节省48字节, sender_index缩短节省2字节, suites占用1字节, reserved去掉3字节）

### 2.3 Handshake Response (消息2: Responder → Initiator)

```
偏移  长度  字段                 说明
──────────────────────────────────────────────────────────
0     1     type                 = 0x02
1     1     suite                选定的套件ID
2     2     sender_index         Responder的索引
4     2     receiver_index       对应Initiator的sender_index
6     32    ephemeral            Responder的临时公钥
38    16    encrypted_nothing    加密的空payload (0+16tag)
54    16    mac1
70    16    mac2
──────────────────────────────────────────────────────────
总长: 86字节

suite字段:
  Responder从Initiator的suites位图中
  选择自己也支持的、优先级最高的套件
```

### 2.4 Transport Data — 短头部 (Type 0x04)

```
偏移  长度  字段                 说明
──────────────────────────────────────────────────────────
0     1     type_and_receiver    高4位=0x4, 低4位=receiver_index低4位
1     3     counter              包序号 (最大16,777,215)
4     N+16  encrypted_data       AEAD加密的IP包 + 认证标签
──────────────────────────────────────────────────────────
总开销: 4 + 16 = 20字节

适用条件:
  - receiver_index < 16
  - counter < 2^24

当counter即将溢出时，触发密钥轮换（重新握手）。
```

**和WireGuard对比：**
```
WireGuard:  Type(1) + Reserved(3) + Receiver(4) + Counter(8) + Tag(16) = 32字节
Wink短头部: TypeRecv(1) + Counter(3) + Tag(16) = 20字节
节省: 12字节/包

对1400字节的包: 1432 vs 1420, 差别不大
对40字节TCP ACK: 72 vs 60, Wink小17%
```

### 2.5 Transport Data — 长头部 (Type 0x05)

```
偏移  长度  字段                 说明
──────────────────────────────────────────────────────────
0     1     type                 = 0x05
1     2     receiver_index       完整的接收方索引
3     8     counter              完整的64位包序号
11    N+16  encrypted_data       AEAD加密的IP包 + 认证标签
──────────────────────────────────────────────────────────
总开销: 11 + 16 = 27字节

用于:
  - receiver_index >= 16
  - counter >= 2^24（极长连接）
```

---

## 三、握手密钥派生（逐步）

握手阶段固定使用 ChaCha20-Poly1305 + Curve25519 + BLAKE2s，和WireGuard完全一致。
下面用 Noise KK 模式。

### 3.1 符号约定

```
DH(a, B)           = Curve25519(a, B)               密钥交换
HASH(data)          = BLAKE2s-256(data)              哈希
HMAC(key, data)     = HMAC-BLAKE2s(key, data)        消息认证
KDF_n(key, input)   = HKDF-BLAKE2s 派生n个密钥       密钥派生
AEAD_ENC(k, n, ad, pt) = ChaCha20-Poly1305.Seal      握手阶段加密
AEAD_DEC(k, n, ad, ct) = ChaCha20-Poly1305.Open      握手阶段解密

s_i, S_i            = Initiator的静态私钥、公钥
s_r, S_r            = Responder的静态私钥、公钥
e_i, E_i            = Initiator的临时私钥、公钥 (每次握手新生成)
e_r, E_r            = Responder的临时私钥、公钥 (每次握手新生成)
```

### 3.2 预计算（连接建立前）

```
双方通过协调服务器交换了对方的静态公钥后:

Initiator预计算:
  ss = DH(s_i, S_r)          // 静态-静态 DH，固定结果

Responder预计算:
  ss = DH(s_r, S_i)          // 同一个值

这个值在对方公钥不变期间可以一直复用。
```

### 3.3 消息1构造（Initiator侧）

```
初始化:
  C = HASH("Wink Protocol v1")                  // 链式密钥
  H = HASH(C || "KK")                           // 握手哈希
  H = HASH(H || S_i)                            // 混入Initiator公钥
  H = HASH(H || S_r)                            // 混入Responder公钥

步骤1: 生成临时密钥
  e_i, E_i = GenerateKeypair()

步骤2: 发送临时公钥（明文）
  H = HASH(H || E_i)                            // 混入哈希

步骤3: DH(e_i, S_r)
  C, k1 = KDF_2(C, DH(e_i, S_r))               // 临时-静态

步骤4: DH(s_i, S_r) — 使用预计算结果
  C, k2 = KDF_2(C, ss)                          // 静态-静态（预计算）

步骤5: 加密timestamp
  encrypted_timestamp = AEAD_ENC(k2, 0, H, timestamp)
  H = HASH(H || encrypted_timestamp)

步骤6: 计算MAC
  mac1 = MAC(HASH(S_r), msg[0:64])

发送: type || suites || sender_index || E_i || encrypted_timestamp || mac1 || mac2

注意: Noise KK不加密静态公钥（因为双方已预知），去掉了encrypted_static字段。
      这比IK模式少了一步加密（不需要加密静态公钥），少了一次运行时DH（ss可预计算）。
      k1在步骤3中生成但不用于加密——它仅参与链式密钥C的更新。
```

### 3.4 消息2构造（Responder侧）

```
步骤1: 验证消息1
  解码E_i
  重建H和C（同Initiator的步骤）
  验证timestamp（防重放）

步骤2: 生成临时密钥
  e_r, E_r = GenerateKeypair()
  H = HASH(H || E_r)

步骤3: DH(e_r, E_i) 
  C, k3 = KDF_2(C, DH(e_r, E_i))               // 临时-临时

步骤4: DH(e_r, S_i)
  C, k4 = KDF_2(C, DH(e_r, S_i))               // 临时-静态

步骤5: 加密空payload
  encrypted_nothing = AEAD_ENC(k4, 0, H, "")
  H = HASH(H || encrypted_nothing)

步骤6: 派生传输密钥
  transport_key_material = C                      // 链式密钥就是最终材料

发送: type || suite || sender_index || receiver_index || E_r || encrypted_nothing || mac1 || mac2
```

### 3.5 传输密钥派生（在选定的密码套件下）

```
根据协商的套件，选择不同的KDF哈希和密钥长度:

if suite == WINK_CHACHA20_BLAKE2S:
    KDF = HKDF-BLAKE2s
    key_len = 32
elif suite == WINK_AES128_SHA256:
    KDF = HKDF-SHA256
    key_len = 16
elif suite == WINK_AES256_SHA256:
    KDF = HKDF-SHA256
    key_len = 32

// 派生传输密钥
send_key = KDF(transport_key_material, "wink-initiator", key_len)
recv_key = KDF(transport_key_material, "wink-responder", key_len)

// Initiator用send_key发送、recv_key接收
// Responder交换: 用recv_key发送、send_key接收
```

**为什么KDF也跟着变？**

BLAKE2s和SHA-256的安全性相当，但：
- 用AES-GCM时配SHA-256，两者都走硬件加速
- 用ChaCha20时配BLAKE2s，两者都走软件实现
- 保持同一条路径上的一致性，避免混搭

---

## 四、数据加密和解密

### 4.1 加密流程

```go
func (kp *Keypair) Encrypt(plaintext []byte) ([]byte, error) {
    // 1. 递增counter
    counter := kp.sendCounter.Add(1) - 1
    
    // 2. 检查counter是否溢出短头部
    useShortHeader := counter < (1<<24) && kp.receiverIndex < 16
    
    // 3. 构造nonce (12字节)
    var nonce [12]byte
    binary.LittleEndian.PutUint64(nonce[4:], counter)
    
    // 4. 构造header
    var header []byte
    if useShortHeader {
        header = make([]byte, 4)
        header[0] = 0x40 | byte(kp.receiverIndex & 0x0F) // type=4的高4位 + receiver低4位
        header[1] = byte(counter)
        header[2] = byte(counter >> 8)
        header[3] = byte(counter >> 16)
    } else {
        header = make([]byte, 11)
        header[0] = 0x05
        binary.LittleEndian.PutUint16(header[1:3], kp.receiverIndex)
        binary.LittleEndian.PutUint64(header[3:11], counter)
    }
    
    // 5. AEAD加密
    //    ad = header (绑定头部，防止篡改receiver和counter)
    ciphertext := kp.sendAEAD.Seal(nil, nonce[:], plaintext, header)
    
    // 6. 组装输出
    packet := make([]byte, len(header)+len(ciphertext))
    copy(packet, header)
    copy(packet[len(header):], ciphertext)
    
    return packet, nil
}
```

### 4.2 解密流程

```go
func (kp *Keypair) Decrypt(packet []byte) ([]byte, error) {
    // 1. 解析头部
    var headerLen int
    var counter uint64
    
    if packet[0]&0xF0 == 0x40 {
        // 短头部
        headerLen = 4
        counter = uint64(packet[1]) | uint64(packet[2])<<8 | uint64(packet[3])<<16
    } else if packet[0] == 0x05 {
        // 长头部
        headerLen = 11
        counter = binary.LittleEndian.Uint64(packet[3:11])
    } else {
        return nil, ErrInvalidPacket
    }
    
    header := packet[:headerLen]
    ciphertext := packet[headerLen:]
    
    // 2. 抗重放检查
    if !kp.replayWindow.Check(counter) {
        return nil, ErrReplay
    }
    
    // 3. 构造nonce
    var nonce [12]byte
    binary.LittleEndian.PutUint64(nonce[4:], counter)
    
    // 4. AEAD解密
    plaintext, err := kp.recvAEAD.Open(nil, nonce[:], ciphertext, header)
    if err != nil {
        return nil, ErrDecryptFailed
    }
    
    // 5. 更新重放窗口
    kp.replayWindow.Update(counter)
    
    return plaintext, nil
}
```

### 4.3 AEAD构造器

```go
// 根据协商的密码套件创建AEAD实例
func newAEAD(suite CipherSuite, key []byte) (cipher.AEAD, error) {
    switch suite {
    case WINK_CHACHA20_BLAKE2S:
        return chacha20poly1305.New(key)
        
    case WINK_AES128_SHA256:
        block, err := aes.NewCipher(key[:16])
        if err != nil {
            return nil, err
        }
        return cipher.NewGCM(block)
        
    case WINK_AES256_SHA256:
        block, err := aes.NewCipher(key[:32])
        if err != nil {
            return nil, err
        }
        return cipher.NewGCM(block)
        
    default:
        return nil, ErrUnknownSuite
    }
}
```

**Go标准库的crypto/aes在有AES-NI时自动使用硬件加速，不需要额外操作。**

---

## 五、完整代码结构

```
pkg/crypto/
├── suite.go              # 密码套件定义和选择
├── suite_test.go         # 套件benchmark测试
├── noise.go              # Noise KK协议状态机
├── noise_test.go         # 握手测试（含互操作）
├── handshake.go          # 握手消息构造和解析
├── handshake_test.go
├── transport.go          # 数据传输加密解密
├── transport_test.go
├── kdf.go                # 密钥派生函数
├── kdf_test.go
├── replay.go             # 抗重放窗口
├── replay_test.go
├── cookie.go             # Cookie DoS防护
├── key.go                # 密钥类型和操作
└── key_test.go

pkg/tunnel/
├── tunnel.go             # Tunnel接口（不变）
├── tunnel_wink.go        # 基于Wink Protocol的隧道实现
├── tunnel_wggo.go        # 基于wireguard-go的隧道实现（兼容）
├── tunnel_test.go        # 接口级测试
├── device.go             # 设备管理（读写循环）
├── peer.go               # Peer管理
├── timers.go             # 计时器
└── header.go             # 头部编解码
```

### 5.1 核心类型定义

```go
package crypto

// ---- 密码套件 ----

type CipherSuite byte

const (
    WINK_CHACHA20_BLAKE2S CipherSuite = 0x01
    WINK_AES128_SHA256    CipherSuite = 0x02
    WINK_AES256_SHA256    CipherSuite = 0x03
)

// SuiteSet 套件位图，用于握手协商
type SuiteSet byte

func (s SuiteSet) Supports(suite CipherSuite) bool {
    return s&(1<<(suite-1)) != 0
}

func (s SuiteSet) Best() CipherSuite {
    // 从高到低检查，返回本地支持的最佳套件
    // 优先级: AES256 > AES128 > ChaCha20 (有AES-NI时)
    //         ChaCha20 > AES256 > AES128 (无AES-NI时)
}

func LocalSuiteSet() SuiteSet {
    // 运行benchmark检测最优，构造位图
}


// ---- 密钥类型 ----

type PrivateKey [32]byte
type PublicKey  [32]byte

func GenerateKeypair() (PrivateKey, PublicKey, error) {
    var priv PrivateKey
    if _, err := rand.Read(priv[:]); err != nil {
        return PrivateKey{}, PublicKey{}, err
    }
    // Curve25519 clamping
    priv[0] &= 248
    priv[31] &= 127
    priv[31] |= 64
    
    pub := derivePublic(priv)
    return priv, pub, nil
}


// ---- 握手状态 ----

type HandshakeState struct {
    localStatic     PrivateKey
    localStaticPub  PublicKey
    remoteStaticPub PublicKey
    
    localEphemeral     PrivateKey
    localEphemeralPub  PublicKey
    
    precomputedSS   [32]byte    // DH(local_static, remote_static) 预计算
    
    chainingKey     [32]byte    // C
    handshakeHash   [32]byte    // H
    
    localIndex      uint16
    remoteIndex     uint16
    
    localSuites     SuiteSet
    selectedSuite   CipherSuite
}


// ---- 传输密钥对 ----

type Keypair struct {
    suite         CipherSuite
    sendAEAD      cipher.AEAD
    recvAEAD      cipher.AEAD
    sendCounter   atomic.Uint64
    replayWindow  ReplayWindow
    receiverIndex uint16
    created       time.Time
    isInitiator   bool
}
```

### 5.2 握手实现

```go
// CreateInitiation 构造消息1
func (hs *HandshakeState) CreateInitiation() ([]byte, error) {
    msg := make([]byte, 96)  // Noise KK: 无encrypted_static
    
    // Header
    msg[0] = 0x01                                    // type
    msg[1] = byte(hs.localSuites)                    // suites
    binary.LittleEndian.PutUint16(msg[2:4], hs.localIndex) // sender
    
    // 生成临时密钥
    ePriv, ePub, err := GenerateKeypair()
    if err != nil {
        return nil, err
    }
    hs.localEphemeral = ePriv
    hs.localEphemeralPub = ePub
    
    // 初始化Noise KK
    hs.chainingKey = blake2sHash([]byte("Wink Protocol v1"))
    hs.handshakeHash = blake2sHash(append(hs.chainingKey[:], []byte("KK")...))
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], hs.localStaticPub[:]...))
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], hs.remoteStaticPub[:]...))
    
    // E: 发送临时公钥
    copy(msg[4:36], ePub[:])
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], ePub[:]...))
    
    // es: DH(e_i, S_r)
    es := dh(ePriv, hs.remoteStaticPub)
    hs.chainingKey, _ = kdf2(hs.chainingKey[:], es[:])  // k1未使用（KK无需加密静态公钥）
    
    // ss: DH(s_i, S_r) — 预计算
    hs.chainingKey, k2 := kdf2(hs.chainingKey[:], hs.precomputedSS[:])
    
    // 加密timestamp
    timestamp := tai64nNow()
    encTimestamp := aeadEncrypt(k2[:], 0, hs.handshakeHash[:], timestamp)
    copy(msg[36:64], encTimestamp) // 12字节timestamp + 16字节tag = 28字节
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], encTimestamp...))
    
    // MAC1
    mac1Key := blake2sHash(hs.remoteStaticPub[:])
    mac1 := blake2s128MAC(mac1Key[:], msg[:64])
    copy(msg[64:80], mac1[:])
    
    // MAC2 (cookie或全零)
    // ...
    
    return msg, nil
}


// ConsumeInitiation 处理消息1 (Responder侧)
func (hs *HandshakeState) ConsumeInitiation(msg []byte) error {
    if len(msg) != 96 || msg[0] != 0x01 {
        return ErrInvalidMessage
    }
    
    // 解析suites
    remoteSuites := SuiteSet(msg[1])
    hs.remoteIndex = binary.LittleEndian.Uint16(msg[2:4])
    
    // 选择最佳套件
    hs.selectedSuite = selectBest(hs.localSuites, remoteSuites)
    if hs.selectedSuite == 0 {
        return ErrNoCommonSuite
    }
    
    // 解析临时公钥
    var remoteEphemeral PublicKey
    copy(remoteEphemeral[:], msg[4:36])
    
    // 重建Noise状态 (和Initiator相同的步骤)
    hs.chainingKey = blake2sHash([]byte("Wink Protocol v1"))
    hs.handshakeHash = blake2sHash(append(hs.chainingKey[:], []byte("KK")...))
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], hs.remoteStaticPub[:]...))
    // 注意: 这里remoteStaticPub是Initiator的公钥
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], hs.localStaticPub[:]...))
    
    // E
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], remoteEphemeral[:]...))
    
    // es: DH(s_r, E_i)
    es := dh(hs.localStatic, remoteEphemeral)
    hs.chainingKey, _ = kdf2(hs.chainingKey[:], es[:])  // k1未使用
    
    // ss: DH(s_r, S_i) — 预计算
    hs.chainingKey, k2 := kdf2(hs.chainingKey[:], hs.precomputedSS[:])
    
    // 解密timestamp
    timestamp, err := aeadDecrypt(k2[:], 0, hs.handshakeHash[:], msg[36:64])
    if err != nil {
        return ErrDecryptFailed
    }
    hs.handshakeHash = blake2sHash(append(hs.handshakeHash[:], msg[36:64]...))
    
    // 验证timestamp (防重放)
    if !isTimestampValid(timestamp) {
        return ErrReplayedHandshake
    }
    
    // 验证MAC1
    mac1Key := blake2sHash(hs.remoteStaticPub[:])
    expectedMAC1 := blake2s128MAC(mac1Key[:], msg[:64])
    if !hmac.Equal(expectedMAC1[:], msg[64:80]) {
        return ErrInvalidMAC
    }
    
    return nil
}


// CreateResponse + ConsumeResponse 类似，省略
// 关键: 消息2中包含selectedSuite，Initiator收到后用它构造AEAD
```

### 5.3 传输密钥派生

```go
// DeriveTransportKeys 从握手状态派生传输密钥对
func (hs *HandshakeState) DeriveTransportKeys() (*Keypair, error) {
    // 根据选定套件选择KDF和密钥长度
    var kdfFunc func(secret, info []byte, keyLen int) []byte
    var keyLen int
    
    switch hs.selectedSuite {
    case WINK_CHACHA20_BLAKE2S:
        kdfFunc = hkdfBLAKE2s
        keyLen = 32
    case WINK_AES128_SHA256:
        kdfFunc = hkdfSHA256
        keyLen = 16
    case WINK_AES256_SHA256:
        kdfFunc = hkdfSHA256
        keyLen = 32
    }
    
    // 派生两个方向的密钥
    sendKey := kdfFunc(hs.chainingKey[:], []byte("wink-initiator"), keyLen)
    recvKey := kdfFunc(hs.chainingKey[:], []byte("wink-responder"), keyLen)
    
    // 如果是Responder，交换方向
    if !hs.isInitiator {
        sendKey, recvKey = recvKey, sendKey
    }
    
    // 构造AEAD
    sendAEAD, err := newAEAD(hs.selectedSuite, sendKey)
    if err != nil {
        return nil, err
    }
    recvAEAD, err := newAEAD(hs.selectedSuite, recvKey)
    if err != nil {
        return nil, err
    }
    
    kp := &Keypair{
        suite:         hs.selectedSuite,
        sendAEAD:      sendAEAD,
        recvAEAD:      recvAEAD,
        receiverIndex: hs.remoteIndex,
        created:       time.Now(),
        isInitiator:   hs.isInitiator,
    }
    
    // 清除握手密钥材料
    clear(hs.chainingKey[:])
    clear(hs.precomputedSS[:])
    clear(hs.localEphemeral[:])
    
    return kp, nil
}
```

---

## 六、测试方案

### 6.1 密码套件切换测试

```go
func TestSuiteNegotiation(t *testing.T) {
    tests := []struct {
        name           string
        initiatorSuites SuiteSet
        responderSuites SuiteSet
        expectSuite    CipherSuite
    }{
        {
            name:            "both_support_aes256",
            initiatorSuites: 0x07, // all
            responderSuites: 0x07, // all
            expectSuite:     WINK_AES256_SHA256, // 最优
        },
        {
            name:            "only_common_chacha20",
            initiatorSuites: 0x01, // chacha only
            responderSuites: 0x07, // all
            expectSuite:     WINK_CHACHA20_BLAKE2S,
        },
        {
            name:            "no_common_suite",
            initiatorSuites: 0x01, // chacha
            responderSuites: 0x06, // aes only
            expectSuite:     0,    // 协商失败
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // 构造双方、执行握手、验证选定套件
        })
    }
}
```

### 6.2 端到端加密测试

```go
func TestEndToEnd(t *testing.T) {
    suites := []CipherSuite{
        WINK_CHACHA20_BLAKE2S,
        WINK_AES128_SHA256,
        WINK_AES256_SHA256,
    }
    
    for _, suite := range suites {
        t.Run(suite.String(), func(t *testing.T) {
            // 1. 握手
            initiator, responder := setupHandshake(suite)
            
            // 2. Initiator加密
            plain := []byte("Hello, Wink!")
            encrypted, err := initiator.Encrypt(plain)
            require.NoError(t, err)
            
            // 3. Responder解密
            decrypted, err := responder.Decrypt(encrypted)
            require.NoError(t, err)
            require.Equal(t, plain, decrypted)
            
            // 4. 反方向
            encrypted2, _ := responder.Encrypt([]byte("Hello back!"))
            decrypted2, _ := initiator.Decrypt(encrypted2)
            require.Equal(t, []byte("Hello back!"), decrypted2)
        })
    }
}
```

### 6.3 性能基准测试

```go
func BenchmarkEncrypt(b *testing.B) {
    sizes := []int{64, 256, 1024, 1400}
    suites := []CipherSuite{
        WINK_CHACHA20_BLAKE2S,
        WINK_AES128_SHA256,
        WINK_AES256_SHA256,
    }
    
    for _, suite := range suites {
        for _, size := range sizes {
            name := fmt.Sprintf("%s/%d", suite, size)
            b.Run(name, func(b *testing.B) {
                kp := setupKeypair(suite)
                data := make([]byte, size)
                b.SetBytes(int64(size))
                b.ResetTimer()
                
                for i := 0; i < b.N; i++ {
                    kp.Encrypt(data)
                }
            })
        }
    }
}

// 预期输出:
// BenchmarkEncrypt/CHACHA20/1400-8    500000    3200 ns/op    437 MB/s
// BenchmarkEncrypt/AES128/1400-8     1200000    1100 ns/op   1272 MB/s
// BenchmarkEncrypt/AES256/1400-8     1000000    1300 ns/op   1077 MB/s
//                                                             ~~~~
//                                                             AES快2-3倍
```

### 6.4 WireGuard互操作测试（兼容模式）

```go
func TestWireGuardCompat(t *testing.T) {
    // 当双方都只支持WINK_CHACHA20_BLAKE2S时
    // 行为应与标准WireGuard完全一致（除了头部格式）
    
    // 1. 用wireguard-go建立一端
    // 2. 用Wink Protocol建立另一端（ChaCha20模式）
    // 3. 验证能通信
    
    // 注意: 头部格式不同，所以不是线上兼容
    // 但密码学操作相同，可以用相同的测试向量验证
}
```

---

## 七、安全性分析

### 7.1 Noise KK的安全属性

```
Noise KK 提供 (参考 Noise Protocol Framework 规范):
  
消息1后:
  - Initiator认证: 否 (Responder还没验证Initiator)
  - Responder认证: 否
  - 保密性: 2级 (加密但无前向保密)

消息2后:
  - Initiator认证: 是
  - Responder认证: 是
  - 保密性: 5级 (前向保密 + 双向认证)

与Noise IK的区别:
  IK提供身份隐藏 (Initiator的静态公钥被加密)
  KK不提供 (双方公钥都预知，不需要加密传输)
  
  安全性其他方面完全相同。
```

### 7.2 密码套件协商的安全性

```
威胁: 降级攻击
  中间人能否强制双方使用弱套件？

分析:
  1. suites字段在消息1中，消息1经过MAC保护
  2. selectedSuite在消息2中，消息2用握手密钥加密
  3. 中间人无法篡改（不知道握手密钥）
  4. 中间人也无法降级（所有套件安全性相当）

结论: 协商安全。
    即使攻击者能篡改suites字段（比如改成只支持ChaCha20），
    后果也只是使用ChaCha20（性能差一点但同样安全）。
    没有"弱套件"可以被降级到。
```

### 7.3 短头部的安全性

```
威胁: 头部被篡改
  攻击者能否修改receiver或counter字段？

分析:
  头部作为AEAD的AD（附加数据）参与认证:
    ciphertext = AEAD(key, nonce, plaintext, ad=header)
  
  篡改头部 → AEAD解密失败 → 包被丢弃

结论: 安全。和WireGuard的保护方式相同。
```

---

## 八、和现有TASK文档的关系

```
本文档影响的TASK:

TASK-03 (WireGuard隧道层):
  - tunnel.go接口不变
  - 新增 tunnel_wink.go 实现
  - pkg/crypto/ 是新增的子包

TASK-04 (NAT穿透):
  - 不受影响。Wink Protocol只改加密层，NAT穿透仍在加密之外。

TASK-06 (客户端核心):
  - 配置文件新增: cipher_suite 选项
  - 默认 "auto"（自动检测硬件选择最优）
  - 可手动指定 "chacha20" / "aes128" / "aes256"

其余TASK: 不受影响
```

---

*文档版本: v1.0*
*创建日期: 2026-04-02*
