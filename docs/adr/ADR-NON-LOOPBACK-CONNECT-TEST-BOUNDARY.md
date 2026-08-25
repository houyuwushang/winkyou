# ADR：首次非回环 connect-test 权限边界

- 状态：**Accepted (2026-08-24)：N1、N2a、N2b、N2c、N2d 已合入；N3a docs-only 设计正在 Draft 评审；产品入口和现场 I/O 仍未授权**
- 日期：2026-08-24
- 跟踪议题：[#70](https://github.com/houyuwushang/winkyou/issues/70)
- 决策人：WinkYou 维护者与独立安全评审
- 当前权限：**已合入的 N2d 仍仅限 `linux && natlab`、RFC 5737 TEST-NET、双进程与受控 NAT；N3b、产品入口、LAN/公网与现场测试仍未授权**
- 前置证据：[`LOOPBACK-CONNECT-TEST.md`](../LOOPBACK-CONNECT-TEST.md)

> 本 ADR 冻结 #68 之后下一阶段的权限设计，不是联网许可。它不改变
> [`CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) 的权威，
> 不改变 stdio `connect_test` 的 literal-loopback 限制，也不解除
> [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](../INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)
> 所记录的 NO-GO。

## 1. 背景

已合入的 Phase 1a 回环切片证明了以下最小管线能够在真实 OS UDP socket 上工作：

```text
strict bundle
  -> machine governor
  -> durable BURN_AND_ADMIT
  -> probeio
  -> Noise NNpsk0
  -> authenticated SYN/SYN_ACK/ACK
  -> PromoteTerminal
  -> FINISH + drain
```

它刻意要求双方 endpoint 在 socket 创建前已经固定为 literal loopback。真实 NAT 的
顺序相反：本地 ephemeral socket 创建后，才能通过 STUN 得到该 socket 的映射；对端又
必须在 attempt 内及时获得这个映射。因此，直接把
`AllowedTargetScopeLoopback` 改成 `AllowedTargetScopeUnicast` 会留下三个错误：

1. 完整 bundle 中预填的公网 endpoint 未必属于随后打开的 socket；
2. STUN 与 punch 若使用不同 socket，NAT 映射可能变化；
3. 当前 `wink-signal` 是明文、test-only、未接线的 observation mailbox，不是获批的
   配对通道，也不能让它获得 pairing secret 或明文 endpoint。

非回环的第一步必须先解决权限、顺序和单次密钥使用，而不是扩大地址匹配范围。

## 2. 产品切片

| 项目 | 定义 |
| --- | --- |
| 目标用户 | 需要临时访问 NAT 后 GPU、实验室主机、云边缘设备的个人开发者和小团队 |
| 用户任务 | 无需控制两侧路由器，人工发起一次有期限、有解释、资源有上限的直连测试 |
| 可观察成功 | 同一受管 UDP socket 完成映射观测、认证候选交换和双向加密可达性证明；终局无残留 |
| 失败语义 | 失败是正常结果；返回阶段与稳定错误类，不自动换候选、换 bundle 或重试 |
| 初始成本 | 一次带外配对、一次短时 rendezvous、每端一个 UDP socket；不要求常驻 daemon |
| 差异化 | 提供可嵌入、可审计的连接求解证据；不要求预先部署应用反向代理或已有 overlay |

relay 仍是正常的产品结果。这个切片只回答“本次 direct 是否安全可达”，不把 direct
包装成所有网络都必须成功。

## 3. 不可变安全条件

本 ADR 的任何后续实现都必须同时满足：

1. **现有回环行为不变。** 当前 bundle、profile、空 Noise handshake payload、包数和
   `non_loopback_blocked` 行为不能被静默放宽。
2. **machine scope only。** 第一版非回环实验不接受 `user_acknowledged` 降级。
3. **一次凭证、一次握手。** raw pairing secret 只进入一次 NNpsk0；禁止先建立一个
   PSK 控制通道，再用同一 PSK 建第二个 direct 通道。
4. **先 burn，后 attempt 数据。** 第一条 secure-channel handshake byte 与第一条
   attempt UDP packet 之前，必须已有 durable `BURN_AND_ADMIT`、完整预算预扣和
   `BeforeFirstEmission` 见证；失败不退款。
5. **STUN 与 punch 共用 socket。** socket 创建、STUN、peer target 登记、punch 和
   terminal promote 必须属于同一个 `AttemptLease`。
6. **无 raw capability。** 调用方不能取得 `*net.UDPConn`、fd、`PacketConn`、
   任意 send、任意 bind 或提高上限的方法。
7. **一次失败即终局。** 无 ticker、后台恢复、自动新 attempt、批量目标、端口扫描或
   birthday 求解。
8. **观测不是标签。** STUN 结果只属于本次 observation generation，不写永久 NAT
   类型。
9. **默认断开。** 在明确的入口激活 PR 通过前，新包不得被 stdio、CLI、runtime、
   daemon、scheduler 或 legacy strategy 导入。
10. **现场测试另行授权。** 合入文档、模拟器或 namespace 证据都不等于 LAN/公网许可。

## 4. 三道权限门

| 门 | 目标 | 允许的网络 | 产品入口 | 当前状态 |
| --- | --- | --- | --- | --- |
| N1 | 隔离 unicast 传输与排水证明 | 仅 Linux network namespace 内的测试地址 | 无 | 已实现并合入：隔离 harness + 必跑 Linux CI；不授权 N2/N3 或现场 I/O |
| N2 | 同 socket NAT attempt | 先纯状态机，再隔离 namespace/NAT lab | 无 | N2a/N2b/N2c/N2d 已合入；所有证据仍为 test-only，不授权产品或现场 I/O |
| N3 | 用户入口与命名现场窗口 | 单独批准的受控环境 | 审查后才可讨论 | N3a 已 Accepted，N3b 可按其 §6 验收门开工；live I/O 仍为 NO-GO |

门必须按顺序通过。N1 成功不能自动批准 N2；N2 的隔离成功也不能自动批准 N3。

## 5. N1：隔离 unicast 传输证明

### 5.1 建议范围

N1 建议只做 integration-test harness，不新建可由产品代码导入的通用
`unicastcarrier`：

- 两个 Linux network namespace，使用仓库内固定的文档测试网段；
- 每端通过现有 `probeio.NewUDPFactory` 显式请求 unicast scope；
- 本地仍只允许 wildcard + ephemeral port，不新增任意接口或固定端口绑定；
- harness 将 namespace 的预置地址与 `ProbeSocket.LocalAddr` 返回的端口组合成临时
  endpoint，并且只在测试进程内交换；
- 仅发送固定的三报文测试序列，不接入 stdio、CLI、Noise、STUN、DNS、信令或
  WireGuard。

N1 的职责是验证 unicast 地址下的 governor ownership、exact target、PPS/packet
计费、取消、崩溃排水和 OS 见证。Noise 与 punch 状态机已经分别由回环和纯内存矩阵
验证，N1 不重复制造一个未接产品入口的 carrier。

### 5.2 固定成本

| 资源 | 每端上限 |
| --- | ---: |
| UDP socket | 1 |
| target | 1 |
| five-tuple | 1 |
| outbound packet | 3 |
| outbound PPS | 3 |
| attempt envelope | 15 seconds |
| harness 内部终止 | 不晚于 13 seconds |
| 自动重试 | 0 |

GitHub Linux CI 必须执行该证明；开发机缺少 namespace 权限时可以明确 skip，但不能把
必跑 CI 变成可选。Windows 不因 N1 获得非回环权限。

### 5.3 必过证据

- 正常双向报文计数不超过声明；
- 未登记 target、第二个 target、第四个 packet 和超 PPS 全部 fail-closed；
- 对端静默、主动取消、writer error、父进程终止和子进程崩溃均有界结束；
- 进程外 packet/socket/conntrack witness 证明结束后无残留；
- architecture 自测证明生产入口或其他包尝试消费 N1 能力会失败；
- 日志、fixture 与 CI artifact 不包含真实 IP、hostname、用户名或本机路径。

N1 只证明隔离 unicast transport 可被控制，不证明 NAT 穿透或产品可用。

## 6. N2：同 socket NAT attempt 候选

### 6.1 推荐顺序

```text
严格验证新的非回环 OOB artifact 与 machine scope（零 I/O）
  -> 预解析并连通一个已审查、受管的 rendezvous carrier
     （不发送 pairing 数据；TCP/DNS 单独计费；零自动重试）
  -> 经 rendezvous 取得有界的双方在场见证（presence，不含配对数据）
  -> 注册 carrier drain witness
  -> 复核 owner/scope/lease/safety/journal
  -> durable BURN_AND_ADMIT，预扣完整最坏 envelope
  -> BeforeFirstEmission
  -> 无 wait/dial/DNS 间隙，立即经 carrier 交换两条空 payload NNpsk0 握手帧
  -> TakePacketCipher 一次性移交尚未使用的 Split keys
  -> 每方向经 rendezvous 发送一条加密 PREPARE
  -> 打开一个 governed wildcard-ephemeral UDP socket
  -> 在该 socket 上执行有界 STUN Binding observation
  -> 每方向经 rendezvous 发送一条含 observed endpoint 的加密 READY
  -> RegisterTarget(peer authenticated endpoint)
  -> initiator 经 rendezvous 发送加密 FIRE
  -> 用同一 PacketCipher 的固定后续 sequence 在同一 UDP socket 上 punch
  -> 每方向经 rendezvous 发送加密 VERIFY
  -> 双方均收妥 VERIFY 后 PromoteTerminal
  -> 关闭 UDP 与 rendezvous，durable FINISH，排水
```

预连接只允许建立一次无 pairing 数据的受管 carrier；它不是重试漏洞。若预连接失败或
对端未在有界 presence 窗口内接入 rendezvous，本地必须有界结束且不 burn credential：
presence 只见证“双方均已连接本次 attempt 的 rendezvous”，不含任何配对数据，因此
把它置于 burn 之前不违反“先 burn、后 attempt 数据”。只要开始发送或接受第一条
Noise handshake byte，credential 必须已经 burn，此后所有失败均消费完整预算。

### 6.2 为什么不能有第二次 Noise

现有 profile 明确禁止 reusable credential 和同一 attempt 的第二个 secure-channel。
因此以下设计不可接受：

```text
pairing_secret -> control Noise
pairing_secret -> direct UDP Noise
```

推荐候选只执行一次空 payload NNpsk0。握手完成后，
`Session.TakePacketCipher` 原子移交未使用的双向 Split keys；后续加密控制 envelope
与 UDP punch 共用这一对有界 cipher state，但使用互不冲突的固定 sequence 与
additional-data domain。任何方向的 nonce 都不得复用。该跨 carrier 用法必须由
wrapper 的 exact type/role/sequence 表、负面测试和独立密码评审共同接受。

### 6.3 控制状态机与 READY endpoint payload

候选保留
[`TEST-ONLY-PAIRING-MINI-SPEC.md`](../TEST-ONLY-PAIRING-MINI-SPEC.md)
已经固定的 `PREPARE -> READY -> FIRE -> VERIFY` 方法集，不增加 `candidate` 或第二套
控制协议。真实 adapter 与当前零密码模拟器的区别是：Noise 握手完成后的每个控制
envelope 都必须先由 `PacketCipher` 认证加密，rendezvous 只看到有界 ciphertext。

固定语义为：

- `PREPARE` 每方向恰好一条，payload 为空；
- 收到对端 `PREPARE` 后才开始本次同 socket STUN；
- `READY` 每方向恰好一条，其受加密 payload 包含 final handshake hash、sender role、
  attempt context digest、observation generation、canonical `netip.AddrPort` 和
  direct-attempt profile；
- 只有双方都发送并接收 `READY` 后，initiator 才能发送一次 `FIRE`；
- 只有收到 `FIRE` 后才开始 UDP punch；
- 本地 punch 成功后发送一次 `VERIFY`；发送并收到 `VERIFY` 是唯一成功终局；
- `CANCEL` 仍只能在非终局状态发送一次；握手完成前的取消直接关闭 carrier，握手完成后
  的取消使用其唯一固定 cipher sequence；
- `READY` payload 不含 pairing secret、PSK、private key、raw bundle、资源请求或
  governor 选择；
- 收到 `FIRE`（initiator 为发送 `FIRE` 后，不等待确认）时，双方各自**立即**发送
  本 role 唯一的开洞报文：initiator 发送 SYN，responder **盲发** SYN_ACK，均不以
  收到对端报文为前置条件。该报文同时充当对 address-dependent filtering NAT 的
  pinhole opener；若把 SYN_ACK 冻结为“收到 SYN 后的回复”，port-restricted ×
  port-restricted 组合将必然失败，回环 carrier 的被动 responder 语义不得照搬；
- initiator 收到 SYN_ACK 后发送一次 ACK；responder 以收到 ACK 为本地 punch 完成
  见证，不补发第二个 SYN_ACK。UDP 丢包造成的不对称由双向 `VERIFY` 终局裁决；
- duplicate、wrong role、wrong generation、wrong context、non-canonical endpoint、
  replay、乱序、oversize 和认证失败均终止整个 attempt；
- peer endpoint 只有通过 `READY` 认证后才能交给 `RegisterTarget`；
- endpoint 不写日志、不进错误文本、不持久化，脱敏报告只保留地址族、阶段和错误类。

推荐的 Noise transport nonce 规划按 frame type 固定为：

| sequence | frame type | sender | carrier / AD domain |
| ---: | --- | --- | --- |
| 0 | PREPARE | 双方各一次 | rendezvous-control |
| 1 | READY(endpoint) | 双方各一次 | rendezvous-control |
| 2 | FIRE | initiator | rendezvous-control |
| 3 | SYN | initiator | direct-punch |
| 4 | SYN_ACK | responder | direct-punch |
| 5 | ACK | initiator | direct-punch |
| 6 | VERIFY | 双方各一次 | rendezvous-control |
| 7 | CANCEL | 任一方至多一次 | rendezvous-control |

发送方向各自使用独立 Split key；每个方向的合法 sequence 是上表允许其 role 的固定
**集合**（responder 方向在 2、3、5 处天然留空），收到集合外、type/sequence 不一致或
重复的 sequence 一律终局；集合内的到达顺序按与 loopback `/1` 相同的有界窗口处理。
wrapper 把上限固定为 7，拒绝任意 nonce 设置。现有控制 envelope 内部的协议 sequence
仍按 mini-spec 从 1 递增，不能与 Noise nonce 混为一层。

Rendezvous control 与 UDP punch 的 AD label、header、字节序、最大 frame 长度以及
`READY` payload schema 都必须在 N2 实现前由 mini-spec 修订和跨语言 golden vector
冻结。当前 Draft 不授权修改 `/1` 实现。

### 6.4 Rendezvous carrier

Rendezvous 解决“双方如何及时交换一次性信息”，不授予对端身份、资源或网络权限。
首个 adapter 必须满足：

- caller 交入已取得的 carrier lease；adapter 不能自己申请 governor；
- 至多一个连接、一个目标、一个 DNS resolution，均有 deadline、字节上限和 drain；
- 不传 raw socket/fd/stream 给协议包；
- pairing secret 永不离开 endpoint；服务端最多看到有界 opaque frames 与不可避免的
  transport metadata；
- 无离线队列、无限 mailbox、轮询循环、重连、fallback 或跨 attempt 复用；
- 必须提供一个有界、不含配对数据的双方在场见证，供 caller 在 durable burn 前
  确认对端已接入本次 attempt；presence 超时是未 burn 的 preflight 失败；
- 接收方在 durable burn 前不得订阅、读取或接受第一条 secure-channel frame；
- server TLS/auth 只能保护 transport，不能替代 Noise 的端到端 pairing 证明。

当前 `wink-signal` 不符合这个权限模型，不能直接接线。后续可以评估复用
coordinator TLS/auth transport 或定义更窄的 rendezvous adapter，但选择必须单独
记录其 DNS/TCP 成本、信任边界和部署成本。

这里追求的是“rendezvous 不是信任锚、数据不经 coordinator”，不是声称两个从未互知
地址的 NAT endpoint 可以在没有任何发现渠道时凭空相遇。首个产品 adapter 可以使用
自托管的短时 rendezvous，服务端只转发端到端密文；未来若加入已有控制 underlay、
手工/二维码交付或去中心化发现，也必须实现同一窄接口并分别通过资源与隐私评审。
无论使用哪个 adapter，成功后的数据路径仍是端到端 direct，rendezvous 不获得
membership、target 或恢复权限。

维护者决策（2026-08-24）：rendezvous 必须以**同一个窄 adapter 接口**支持两个部署
档位——

1. **自托管档**：跑在维护者自己控制的节点上，用于自举启动；运营方掌握可用性、
   日志与元数据留存策略；
2. **最低信任档**：由任意第三方运营也可用；协议上服务端只见有界密文与不可避免的
   transport metadata。

两档的密码学信任假设完全相同：端到端 NNpsk0 是唯一配对证明，自托管档同样不得把
server TLS/auth、运营者身份或部署位置当作信任锚，不得因“自己的服务器”而放宽任何
帧上限、时限或 fail-closed 规则。N2c 只审一次协议信任边界；每个部署档位单独通过
资源与隐私评审。

### 6.5 同 socket STUN

`stunobserve` 必须增加“使用调用方已有 `ProbeSocket`”的窄 adapter；它不能为了复用
现有 API 再开第二个 socket。固定约束：

- 一个 UDP socket；
- 先登记一个 STUN target，完成后再登记一个 peer target；
- 两个 target/five-tuple 都计入同一 attempt；
- STUN 最多三次有界发送，结果只属于当前 generation；
- peer endpoint 来自受认证 frame，不来自 DNS、日志、用户自由文本或永久缓存；
- STUN 失败、源地址不匹配、协议错误或 endpoint 不一致均直接终局。

### 6.6 Artifact 与版本

现有 loopback complete bundle 在 socket 创建前包含 `local_endpoint` 和
`peer_endpoint`，不能复用于 N2。N2 必须定义不同的 artifact/profile 标识：

- OOB artifact 只固定 pairing、role、generation、governor scope、期限和 rendezvous
  关联信息，不预填 direct endpoint；
- profile 不协商、不 fallback，未知值在任何网络 I/O 前拒绝；
- 新 schema 不修改或放宽当前 loopback parser；
- direct-attempt control profile 与 `READY` payload profile 必须进入双方已认证的
  context 或固定 AD，避免 downgrade；
- exact identifier、fingerprint 顺序、JCS 字段和未知字段策略须有 golden vectors。

N2a 将精确 identifier、fingerprint、prologue/AD、READY 和 sequence 冻结在
[`TEST-ONLY-PAIRING-MINI-SPEC.md`](../TEST-ONLY-PAIRING-MINI-SPEC.md) §7.1；它没有修改
loopback parser，也没有新增 carrier 或产品导入路径。

### 6.7 冻结最坏成本

N2b 对 16 个 EIM/EDM × address/address+port filtering 组合各重复 100 次，并覆盖丢包、
乱序、重复、认证失败与 CANCEL 矩阵后，冻结 UDP 与协议成本。N2c 再按真实 literal-loopback
TCP/UDP adapter 实测冻结 carrier 字节、DNS、deadline 与 drain 成本。以下数值均为编译期
hard ceiling，配置只能降低、不能提高；冻结成本仍不是 N2d、产品或现场实现授权。

| 资源 | 每端冻结上限 |
| --- | ---: |
| rendezvous carrier connection | 1 |
| rendezvous target | 1 |
| DNS resolution | 1（literal endpoint 实测为 0；package-test 注入式 resolver 实测恰好 1 次调用） |
| DNS coarse reservation | 1 socket / 1 target / 1 five-tuple（最坏情况预留） |
| rendezvous application frame | 每方向 8 |
| rendezvous application bytes | 每方向 8,256 bytes；双向合计 16,512 bytes |
| governed UDP socket | 1 |
| UDP target / five-tuple | 2（STUN + peer） |
| STUN outbound packet | 3 |
| direct outbound packet | initiator 2 / responder 1 |
| UDP outbound total | initiator 5 / responder 4 |
| authenticated control envelope | initiator 4 / responder 3，另加全局最多一次 CANCEL |
| Noise handshake frame | 每方向 1 |
| presence envelope | 不超过 3 seconds，不含 pairing 数据 |
| active carrier deadline | 不超过 13 seconds，预留 2 seconds 排水余量 |
| attempt envelope | 不超过 15 seconds，且短于 credential expiry |
| 自动 retry / reconnect | 0 |

矩阵统计为 EIM×EIM 的四种 filtering 组合 400/400 成功；任何一侧为 EDM 的十二种组合
1200/1200 有界失败。后者说明对 STUN 目标的 destination-specific observation 不能被
偷换成 peer mapping，不授权 prediction 或 candidate replacement。详见
[`N2-DIRECT-ATTEMPT-SIMULATION.md`](../N2-DIRECT-ATTEMPT-SIMULATION.md)。

TCP 的 OS packet 数不能仅靠应用帧数推导，因此上表不为 TCP 伪造 packet 计数。coarse
machine reservation 固定为同一个 heavyweight attempt 的 3 sockets、4 targets、4
five-tuples、5 UDP packets/5 PPS，机器级 governor 同时最多容纳 1 个 heavyweight attempt。
carrier 自身另守住 1 connection、1 rendezvous target、最多 1 次 DNS、每方向 8 个 frame
与 8,256 application bytes；DNS/TCP 前消费 attempt-lifetime exclusive claim，失败后不释放，
从而禁止同 attempt 重连。N2c 的进程外崩溃见证由父测试进程终止 carrier 子进程，并从独立
loopback server 观察 active connection 回到 0。N2d Draft 在不改变上表 ceiling 的前提下，
进一步组合真实 namespace socket、EIM/EDM、same-socket STUN 与 durable restart rejection，
并以 iptables、`ss`、conntrack、netns process 和 server active connection 作为进程外见证。
应用 frame 数不得写成 TCP OS packet 数。详见
[`N2C-RENDEZVOUS-CARRIER.md`](../N2C-RENDEZVOUS-CARRIER.md)。
N2d 证据与复现边界见 [`N2D-NAMESPACE-E2E.md`](../N2D-NAMESPACE-E2E.md)。

### 6.8 失败与终局

| 失败阶段 | credential | 结果 |
| --- | --- | --- |
| artifact / scope / preflight 校验失败 | 未 burn | 零 attempt I/O，稳定拒绝 |
| 单次 carrier 预连接失败 | 未 burn | 有界 preflight 失败，不重连 |
| 对端未在 presence 窗口内接入 rendezvous | 未 burn | 有界 preflight 失败，不等待、不重试 |
| burn、预算或 owner 复核失败 | fail-closed | 零 pairing/UDP emission |
| Noise、STUN、加密控制 envelope、punch 或 promote 失败 | 已消费 | FINISH + drain，不退款 |
| drain 超时、持续 writer failure、预算矛盾 | 已消费 | 持久 safety trip |

任何崩溃后的新进程只能读取 ledger 并拒绝旧 credential；不得恢复旧 socket、继续
sequence 或补发报文。

## 7. N3：产品入口与现场门禁

N3 只有在 N1/N2 全部经过独立评审并合入后才能提出。至少需要：

1. stdio schema 与稳定错误类的独立版本审查；
2. 明确命名的测试环境、目标设备、开始/结束时间和 operator；
3. 测试前确认 safety trip、machine owner、无遗留进程和无计划任务；
4. 独立 kill switch；
5. packet、socket、process、conntrack 和 ledger 的进程外见证；
6. 成功、对端缺席、错误 PSK、篡改、重放、STUN 静默和进程崩溃矩阵；
7. teardown 后第二人复核；
8. 公开记录只保留脱敏事实，不出现个人 IP、hostname、用户名、本机路径或拓扑。

N3a 对入口版本、request schema、stable error、one-shot rendezvous、配对材料与签发格式的
Draft 冻结见
[`ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)，空白模板见
[`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](../N3-LIVE-AUTHORIZATION-TEMPLATE.md)。这两份文档
不激活代码，也不是现场许可。

N3 的一个授权实例只允许一个显式 attempt；不启动自动重试/恢复，不接数据面。首次
campaign 的对端缺席、错误 PSK、密文篡改、重放、STUN 静默、进程崩溃和正常成功各使用
独立签发实例与独立 credential，不把失败矩阵包装成一个内部多次尝试的命令。

## 8. 拒绝的替代方案

| 方案 | 拒绝原因 |
| --- | --- |
| 直接把 loopback scope 改为 unicast | endpoint 与实际 socket 映射不一致，且绕过新权限审查 |
| 为测试允许任意 local bind | 扩大 socket 能力；NAT 客户端并不需要固定公网端口 |
| STUN 后重新开 punch socket | 映射可能改变，观测失去证明力 |
| 在 OOB bundle 预填公网 endpoint | endpoint 产生顺序错误，且会变成陈旧标签 |
| 明文 mailbox 交换 endpoint | 可替换、重放、关联 attempt，并造成错误 target 授权 |
| 两次 NNpsk0 复用同一 PSK | 违反一次凭证/一次 channel，并扩大 nonce/key misuse 面 |
| handshake payload 偷渡 endpoint | 当前 profile 的 adapter 明确要求空 payload；不能静默改变 |
| 使用 pion/ICE 快速接线 | 第三方自行开 socket，绕过 `probeio` 强制点 |
| 失败后换端口/候选继续试 | 把单次测试变成不可预测的求解与恢复循环 |
| namespace 成功后直接公网测试 | 缺少单独 live authorization、kill switch 与 teardown 证据 |

## 9. 接受后建议的实现顺序

本 ADR 只有在状态由维护者改为 Accepted 后，才允许按以下顺序开独立 Draft PR：

1. **N1 PR：** integration-test-only namespace unicast proof；
2. **N2a PR：** 纯函数 direct-attempt artifact、`READY` endpoint payload、
   AD/sequence 与 golden vectors，不含网络；
3. **N2b PR：** 纯内存 rendezvous + NAT simulation，证明单次 Noise、sequence 和
   failure matrix；
4. **N2c PR：** 断开产品入口的 governed rendezvous carrier 与 same-socket
   `stunobserve` adapter；
5. **N2d PR：** namespace/NAT-lab 双进程组合证明，仍不接 stdio；
6. **N3a docs-only ADR/PR：** 冻结产品入口、one-shot server、配对工具与空白现场模板；
7. **N3b implementation PR：** 只有 N3a 独立评审接受后才实现；仍不自动授权 live I/O；
8. **N3 named authorization：** N3b 独立评审接受后，由维护者与第二人按模板逐实例签发。

每个 PR 均需独立 CI、architecture gate、race、重复运行、故障注入和专家审查；不得用
stacked merge 绕过某一道权限门。

N2a/N2b/N2c/N2d 已分别合入。N2d 仍只提供 namespace/NAT-lab 证据；N3a Draft 创建、CI
通过、合并或本节待决项被实现勾选，都不构成 N3b 或现场 I/O 自动授权。

## 10. Accepted 后的剩余待决项

接受本 ADR 冻结了权限门顺序、N1 范围与 §3 不可变条件，并确认 N1 只做
integration harness、不创建 production-importable carrier。以下事项仍未决，
必须在对应的 N2 实现 PR（§9 第 2–5 步）之前逐项冻结：

- [x] N2c Draft 用同一窄接口固定自托管档与最低信任档；两档使用完全相同的端到端
  Noise、domain binding 与资源边界，server TLS/运营者身份均不是配对信任锚；是否接受
  该实现仍由独立评审决定；
- [x] 冻结 carrier preconnect/presence 与 durable burn 的精确边界：presence 不含
  pairing 数据，双方 burn 后才能接受第一条握手 byte；N2c 必须实现同一边界；
- [x] 冻结新的 artifact/profile identifier 和 downgrade 规则；
- [x] 冻结加密控制 envelope 与 `READY` endpoint payload 的 canonical schema、AD
  bytes、sequence 与长度；
- [x] 用 NAT 模拟矩阵验证双侧同时开洞语义（含 responder 盲发 SYN_ACK 在丢包、
  乱序与 filtering NAT 组合下的行为），并据此冻结 punch 状态机；
- [x] 冻结 rendezvous presence 见证的形式、3-second 上限与“不含配对数据”边界；
- [x] 证明同一 `PacketCipher` 跨 rendezvous/UDP 使用的 nonce 与 domain separation；
- [x] N2c Draft 冻结 TCP/DNS coarse reservation、每方向 8,256-byte 上限、13-second
  active deadline、2-second drain margin，并给出 literal=0 / injected resolver=1 与
  子进程崩溃后 active connection=0 的见证；
- [x] 用 1600 次基础 NAT 矩阵及故障矩阵校准并固定 N2 最坏成本；
- [x] N2d Draft 的双进程 EIM/EDM、缺席、崩溃重启、硬违规与 OS 残留矩阵通过必跑
  Linux race CI；实测计数与残留摘要见 `N2D-NAMESPACE-E2E.md` §6；
- [ ] 独立安全评审接受 N2d 的组合实现与证据；
- [x] N3a Draft 定义 stdio v2 分流、stable error、one-shot rendezvous、配对材料与
  live authorization 空白模板；这只表示文档齐备，不表示设计已接受或入口已激活；
- [x] 独立安全评审接受 N3a 设计与空白模板（2026-08-25，评审记录见 PR #80/#81）；
  N3b 实现仍须按其 §6 验收门独立评审；
- [ ] 独立安全评审明确接受以上决策。

在全部项目闭合前，#70 保持开放，`connect_test` 非回环仍为稳定 fail-closed；
Accepted 状态本身不授予 N2/N3 任何提前开工权限。
