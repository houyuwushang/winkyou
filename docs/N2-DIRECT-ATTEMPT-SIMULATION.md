# N2 非回环 direct-attempt 零网络模拟证明

- 状态：**N2a/N2b Draft 实现证据，等待独立评审；不授权 N2c、产品入口或现场 I/O**
- 协议权威：[`TEST-ONLY-PAIRING-MINI-SPEC.md`](./TEST-ONLY-PAIRING-MINI-SPEC.md) §7.1
- 权限边界：[`adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md`](./adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md) §6
- 实现：`internal/v2/directattempt`、`internal/v2/directsim`、`internal/natsim`

## 1. 证明边界

本切片只证明协议顺序、同一模拟 socket 的 STUN 映射与 punch、Noise nonce/AD 分域、
NAT filtering 行为、固定预算和失败终局。全部 carrier、PacketConn 和 NAT 都在内存中，
不创建 OS socket，不解析 DNS，不访问 LAN/公网，不接 stdio、CLI、runtime、daemon、
scheduler、`wink-signal` 或真实 rendezvous。

`internal/architecture` 把 `directsim` 固定为 simulation-only，只允许它精确导入
`directattempt`、`noisecore`、`pairingcontext` 与 `natsim`。生产路径导入、raw `net`、
`probeio`、signaling 或其他 WinkYou 能力均由变异测试证明会失败。

## 2. 固定顺序与 burn 边界

成功路径只能按以下事件序列前进：

```text
presence
  -> durable_burn
  -> first_handshake_byte
  -> prepare
  -> same_socket_stun
  -> ready
  -> fire
  -> simultaneous_punch
  -> verify
  -> terminal
```

内存 rendezvous 的 presence 只有固定 profile、16-byte opaque association ID 与
`a|b` transport slot；没有 credential、attempt、participant、generation、role、endpoint、
payload 或 secret。双方 presence 完成前不能 burn，双方 endpoint-local burn 完成前不能
发送或接收第一条 Noise handshake frame。每方向只能有一条 48-byte 空-payload NNpsk0
握手帧，握手完成前不能进入加密控制队列。

burn 后的 Noise、READY、NAT、punch、认证、取消或预算失败全部保留 burned 状态；模拟
ledger 没有 refund API。这个内存 ledger 只证明顺序，不声称具有跨进程或跨重启耐久性。

## 3. NAT 矩阵结果

矩阵使用同一个 `natsim.PacketConn` 先向模拟 STUN target 建图，再向认证 READY endpoint
打洞。每个 mapping × filtering 组合从空 Network 重复 100 次：

| initiator × responder mapping | address/address+port filtering 组合 | 结果 |
| --- | ---: | --- |
| EIM × EIM | 4 × 100 | **400/400 成功** |
| EIM × EDM | 4 × 100 | **400/400 有界失败** |
| EDM × EIM | 4 × 100 | **400/400 有界失败** |
| EDM × EDM | 4 × 100 | **400/400 有界失败** |
| 合计 | 16 × 100 | 400 成功，1200 有界失败 |

EDM 失败不是 flake：对 STUN 目标观测到的 destination-specific mapping 不能证明随后对
peer target 使用同一外部 endpoint。本切片禁止预测、候选替换和换端口重试，因此把它
稳定归类为本次 direct 失败；后续若讨论预测策略，必须另走策略与预算评审。

在 address+port-dependent filtering 下，initiator 的首个 SYN 可以被 NAT 丢弃；
responder 在 FIRE 后不等待 SYN，先盲发 SYN_ACK 打开自己的 pinhole，initiator 收到后
发送 ACK，仍能完成双向 VERIFY。这正是 N2 状态机与 loopback `/1` 被动 responder
语义不同的原因。

## 4. 故障与负面矩阵

| 注入 | 冻结结果 |
| --- | --- |
| 丢 SYN | EIM filtering 组合仍可凭盲发 SYN_ACK 成功 |
| direct 报文乱序 | ACK 在延迟 SYN 前到达仍可成功；不产生第二个 SYN_ACK |
| 丢 SYN_ACK / 丢 ACK | 有界失败，0 重试 |
| 重复 SYN / SYN_ACK / ACK | replay 终局，0 额外 sender emission |
| duplicate / replay control | 整个 attempt 终局 |
| wrong role / generation / context | 分别在 frame、零 I/O generation gate、Noise prologue gate 终局 |
| non-canonical READY endpoint | peer target 登记和 direct emission 前终局 |
| 跨 AD domain 重放 / oversize / 认证篡改 | 终局，后续 frame 全拒绝 |
| burn 前 cancel | 不 burn、零 handshake/control/UDP emission |
| handshake 后或 FIRE 后 CANCEL | 单一 sequence 7，已 burn、不退款、零后续 punch/VERIFY |
| 成功终局后 CANCEL | 稳定拒绝，不产生 sequence 7 emission |

所有失败报告都满足固定成本、`refunds=0`，模拟 Network 关闭后 active PacketConn、mapping
与 queued packet 均为零。故障注入只复制、丢弃或重排已经发出的内存 delivery，不增加
发送端 packet 计数，也不形成重试入口。

## 5. 冻结最坏成本

以下是编译期 hard ceiling；配置只能降低：

| 资源 | 每端上限 |
| --- | ---: |
| rendezvous carrier connection / target | 1 / 1 |
| DNS resolution | 1（固定 adapter 若使用 literal endpoint 则为 0） |
| governed UDP socket | 1 |
| UDP target / five-tuple | 2（STUN + peer） |
| STUN outbound packet | 3 |
| direct outbound packet | initiator 2 / responder 1 |
| UDP outbound total | initiator 5 / responder 4 |
| authenticated control envelope | initiator 4 / responder 3，另加全局最多一次 CANCEL |
| Noise handshake frame | 每方向 1 |
| presence envelope | 3 seconds |
| attempt envelope | 15 seconds，且短于 credential expiry |
| retry / reconnect / fallback | 0 |

成功模拟的实际值更低：每端 STUN 1 包；direct 为 initiator 2、responder 1；其余恰好命中
控制与握手上限。N2c 仍须另外冻结 carrier application-byte 上限、TCP coarse reservation、
deadline 与 drain；它只能落入本表，不能借 adapter 实现抬高 ceiling。

## 6. 后续门禁

本证据不选择真实 rendezvous 的部署或信任模型，不实现 same-socket `stunobserve` adapter，
不提供 non-loopback carrier，也不改变 `connect_test` 的 fail-closed 产品边界。下一步只有
在 N2a/N2b 独立评审并按栈顺序合入后，才可按 ADR §9 单独提出 N2c Draft PR。
