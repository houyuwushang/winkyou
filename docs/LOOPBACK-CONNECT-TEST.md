# Phase 1a 回环 connect_test

- 状态：**已合入 main；仅 literal loopback；非回环仍为 NO-GO**
- 入口：`wink solver serve --stdio` 的 `connect_test`
- 唯一组合边界：`internal/v2/loopbackcarrier`
- 协议基础：`internal/v2/pairingcontext`、`internal/v2/noisecore`、`internal/v2/punchproto`
- I/O 强制点：`internal/probeio`

本切片第一次让完整管线使用真实 OS UDP socket，但地址范围被编译期和解析期共同收紧为
数值 loopback。它不授权 LAN、公网、家庭网络、STUN server、DNS、daemon、scheduler、
恢复控制器、birthday 求解或 WireGuard 数据面。非回环启用必须另开 ADR/PR 和安全评审。

## 1. 固定顺序

```text
显式 connect_test
  -> 严格解析完整 bundle（零 I/O）
  -> literal loopback + machine scope 检查（零 I/O、零 burn）
  -> machine peer + 完整 AttemptLease
  -> PairingAdmissionGate.Commit（durable burn）
  -> ConsumeForCarrier（一次性、不可伪造授权）
  -> probeio loopback UDP socket + RegisterTarget
  -> 脱敏 loopback_socket_ready progress（无 endpoint/handle）
  -> BeforeFirstEmission
  -> 同 socket 上 Noise NNpsk0 两消息握手
  -> TakePacketCipher
  -> AEAD 保护的 SYN / SYN_ACK / ACK
  -> PromoteTerminal
  -> 立即关闭 transport
  -> durable FINISH
  -> attempt 排水与关闭
```

顺序不可调换。bundle 缺失、重复键、未知字段、非 canonical base64url/UTC/AddrPort、
fingerprint 不一致、时效错误、非回环地址或非 machine scope 都在 attempt 与 burn 之前失败。
一旦 burn 成功，协议错误、取消、超时、崩溃和失败都消耗 credential 与完整最坏预算。

## 2. 协议与终局

双方使用同一只 `ProbeSocket` 完成两条固定 48-byte
`Noise_NNpsk0_25519_ChaChaPoly_SHA256` 握手消息。prologue 是固定 label 与受限 JCS
`PairingContext`，payload 必须为空；PSK 从 OFFER 的 32-byte `pairing_secret` 一次性装载，
随后进行 best-effort zeroization。

握手完成后，未使用的 Split 双向密钥被原子移交给 `PacketCipher`。打洞报文固定为
加密 `SYN=0`、`SYN_ACK=1`、`ACK=2`；role、attempt、generation、frame type 与 header
均受 AEAD 绑定。PSK 不一致、篡改、乱序、重放、源 endpoint 不匹配和认证失败都会终止，
不存在明文 fallback。

`PromoteTerminal` 只证明该次安全通道建立且双向可达。提升后 transport 立即关闭，随后
写入 FINISH；不会向 stdio 调用方返回 socket/transport，不传业务 payload，也不保留长连。

## 3. 最坏资源预算

| 资源 | 每端上限 |
| --- | ---: |
| socket | 1 |
| target | 1 |
| five-tuple | 1 |
| 出站 packet | 3 |
| 出站 PPS | 3 |
| attempt 时长 | 15 seconds |
| heavyweight | true |

initiator 的最坏出站序列为 Noise message 1、SYN、ACK，共 3 包；responder 为 Noise
message 2、SYN_ACK，共 2 包。没有重传，因此失败成本不会超过预留 envelope。

attempt 时长 15 seconds 是预留的最坏 envelope；carrier 在 envelope 内部自我设限为
13 seconds（保留 2 seconds 终局余量）。对端始终缺席或停滞时，carrier 在 13 seconds
处以 `expired` 干净终局：写入 durable FINISH、排水并关闭，不触发持久 safety trip。
预算照常全额消耗，不退款。probeio 的 15-second duration tripwire 仍然保留，只作为
carrier 本身卡死时的持久兜底。

## 4. 证据与剩余门禁

测试使用真实回环 UDP proxy 作为进程外 packet witness，核对正常路径 3/2 包以及错误
路径不越过每端 3 包。测试还覆盖 PSK 不一致、密文篡改、重放、严格 bundle、非回环
pre-admission 阻断、终局 FINISH 先于 attempt close，以及结束后端口可重新绑定和无
goroutine 残留。既有 `pairing_gate_subprocess` 矩阵继续负责 durable burn、并发竞争、
进程崩溃、1000 次重启和 FINISH torn-write 的零发射证明。

这些证据不构成非回环授权。真实 NAT/公网现场测试、信令、候选交换、数据面、
自动恢复和任何重试策略仍为独立 NO-GO 边界。

## 5. 可重复验证入口

从仓库根目录运行：

```powershell
./scripts/verify-loopback-connect.ps1
```

使用 Make 的环境可运行等价目标：

```bash
make test-loopback-connect
```

验证入口固定执行三组证据：stdio framing/handshake/method 与脱敏契约、真实 OS 回环 UDP
上的双子进程成功/崩溃/对端缺席矩阵，以及网络能力与唯一 consumer 架构门禁。成功标志为
`LOOPBACK_CONNECT_PROOF: PASS`。GitHub CI 在 Linux 和 Windows 上分别运行同一 PowerShell
入口，避免本地命令与合并门禁漂移。

这是一组组合式回归证据，不是假装成产品现场验收：双 carrier 子进程使用互相独立的临时
machine-scope 测试 namespace，stdio server 契约与真实 carrier 分别受测。它不会修改
canonical machine namespace，不启动已安装的 `wink` runtime，不访问 DNS/LAN/公网，也不
证明两个生产 stdio owner 可以在同一机器并存。生产设计仍坚持一个机器级 owner；若已有
owner，第二个进程必须 fail-closed。

## 6. 下一权限边界

非回环的下一步不是把 loopback 地址检查替换为 unicast。真实 NAT 路径必须解决同一
UDP socket 的 STUN 观测、受认证 endpoint 交换、一次 Noise/PSK 使用、rendezvous
carrier 计费，以及独立现场授权。候选设计见
[`adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md`](./adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md)
与 [Issue #70](https://github.com/houyuwushang/winkyou/issues/70)。

在该 Draft ADR 通过维护者和安全评审前，本文件的 literal-loopback 限制与
`non_loopback_blocked` 行为保持不变。
