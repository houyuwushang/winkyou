# ADR：N3c 带外控制流到可复用直连数据面的交接

- 状态：**Accepted（含 §16 handoff 顺序修订，2026-08-27）：§15 七条答复具约束力，仅授权
  Gate A 实现（memory/loopback/required netns 证据）。SSH assembly、WireGuard/memory-TUN、
  产品入口、Gate B2 与任何现场 I/O 均未授权**
- 日期：2026-08-25
- 基线：`main` = `edca985e91333b17bbd0c88e7878b08ad94bc36b`
- 跟踪议题：[#85](https://github.com/houyuwushang/winkyou/issues/85)
- 上位决策：[`ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)、
  [`CANCELLATION-DRAIN-CONTRACT.md`](../CANCELLATION-DRAIN-CONTRACT.md)、
  [`PAIRING-RESTART-SAFETY-CONTRACT.md`](../PAIRING-RESTART-SAFETY-CONTRACT.md)

> 本 ADR 只提出一个新的评审边界。它不修改 `winkyou.stdio/v2`，不签发 live
> authorization，不允许运行 legacy birthday puncher，也不允许在 LAN、公网或真实设备上
> 发起一次 N3c attempt。即使本文以后 Accepted，现场 I/O 仍须逐实例签发。

## 1. 问题与目标

N3b 已证明以下能力可以在一个 15 秒、一次性、受 governor 管理的 attempt 中组合：

- durable credential burn；
- NNpsk0 handshake 与 authenticated control；
- 同一 `ProbeSocket` 上的 STUN 观测与固定 peer endpoint 打洞；
- 双向 VERIFY 后 `PromoteTerminal`；
- 终局关闭 transport、记录 FINISH 并排空所有资源。

它刻意**不**解决两件事：

1. 建立阶段必须连接 one-shot `wink-rendezvous`，不能消费调用方已有的全双工管理信道；
2. `PromoteTerminal` 后 transport 会被关闭，不会移交给 WireGuard、mesh/session 或业务数据面。

N3c 的目标是覆盖一个更窄、但产品价值更直接的工作：

> 两个已通过现有管理信道可达的节点，用该信道只交换有界、端到端加密的建立控制；若独立
> UDP 直连通过双向验证，则把同一个 verified socket 原子移交给一个有独立 lease 与 shutdown
> witness 的数据面。建立失败时保留原管理信道，不重试、不扩大候选、不启动恢复循环。

这里的“无中间服务器”精确定义为：**不新增 WinkYou rendezvous、signaling、coordinator
或 relay 服务，最终数据包不经过 OOB relay。** 建立阶段仍依赖 operator-approved 的现有
overlay/SSH 与明确获准的 STUN observation service。因此不得把 N3c 宣传为完全去中心化、
零第三方依赖或普适 serverless NAT traversal。

## 2. 已核验事实与限制

### 2.1 当前代码边界

- `internal/v2/directconnect` 直接持有具体 `*rendezvouscarrier.Carrier`，不是可替换接口；
- N3b artifact、prologue、presence/burn 顺序和 carrier-domain binding 都绑定当前 profile；
- `probeio.PromoteTerminal` 保留 attempt lease，只允许调用方短暂验证并随后关闭；
- `probeio.Promote` 虽能返回 `transport.PacketTransport`，但
  [`CANCELLATION-DRAIN-CONTRACT.md`](../CANCELLATION-DRAIN-CONTRACT.md) 明确禁止生产 adapter
  在接收 session 拥有独立资源 lease 与 shutdown witness 前启用该交接；
- `winkyou.stdio/v2` schema 已冻结，不能把新 arm 静默加入同一版本。

### 2.2 现场前置观测的可公开结论

一次经明确授权的只读预检只保留以下脱敏事实：

- 两个不同网络环境都支持 UDP 和 IPv4；
- 两侧短时观测均显示 mapping 随目标变化；
- 两侧均未发现 UPnP、PMP 或 PCP；
- 只有一侧具有 IPv6，因此不能把 IPv6 作为双方共同直连路径；
- 现有 overlay 在观测窗口内未形成 direct path；
- 两端均没有 ready machine-safety namespace，且其中一端没有 WinkYou binary。

这些事实只说明当前环境属于 N3c 的困难输入，不能升级为永久 NAT 标签，也不能证明任何
ISP、设备或地点的性质。真实 hostname、IP、端口、用户名、路径和 host-key fingerprint
不得进入仓库、issue 或 PR。

### 2.3 Tailscale endpoint 不能直接变成 WinkYou endpoint

Tailscale 的 `debug netmap` 能显示 tailscaled 当前 endpoint，但不能作为 WinkYou 新 UDP
socket 的映射证明：

- 该命令在 CLI 中明确属于不稳定 debug interface；官方实现通过 LocalAPI
  `debug?action=current-netmap` 读取内部 network map；
- endpoint 属于 tailscaled/magicsock 已有 UDP socket；NAT 映射绑定本地 socket、目标和
  时间窗，不能移交给另一个 `probeio` socket；
- 在 mapping 随目标变化时，把 tailscaled endpoint 复制为 WinkYou READY 内容尤其错误；
- 解析 debug netmap 还会把大范围私有 topology 和 key metadata 暴露给新进程。

因此 N3c 不读取、缓存或解析 Tailscale debug netmap。官方实现参考仅用于说明拒绝理由：

- <https://github.com/tailscale/tailscale/blob/main/cmd/tailscale/cli/debug.go>
- <https://github.com/tailscale/tailscale/blob/main/ipn/localapi/localapi.go>

## 3. 总体拆分裁决

N3c 必须拆为三个顺序 gate，不能在一个 PR 中同时取得产品入口和现场权限。

### Gate A：OOB carrier 与 session ownership

只实现：

- caller-provided bounded byte stream；
- 新 artifact/profile 与 carrier-domain binding；
- N3b 协议状态机复用；
- 独立 session lease、原子 transport handoff 和 shutdown witness；
- memory、loopback、netns 证明。

Gate A 对 mapping 随目标变化的结果必须 fail-closed，不实现预测、端口窗口或 birthday
coverage，也不提供真实 SSH/Tailscale 产品入口。

### Gate B：endpoint-dependent NAT 求解

只有 Gate A 独立评审通过后才讨论。它必须单独冻结：

- observation 来源与证据等级；
- allocation signal 的 socket 数、目标、时间窗与适用条件；
- candidate 生成函数与最大 candidate 数；
- socket/target/five-tuple/PPS/packet/duration 的完整成本表；
- 失败即终局、无 retry、跨进程/重启 ledger；
- 进程外 emission witness 与 mutation tests。

`port_dependent`、`apparently_random`、`insufficient_data` 或不满足证据门的输入默认结束为
稳定的 `mapping_not_directly_usable`，direct UDP 发射为零。

### Gate C：产品入口与现场窗口

Gate A/B 的 exact head、required CI 和独立安全评审全部接受后，才设计产品 CLI/stdio
version、SSH adapter 与现场 campaign。N3b 的 v2 schema、artifact 和 error classes 不变。

## 4. Gate A 协议提案

以下 identifier 都是 Draft 输入，未获评审前不得出现在可运行产品入口：

```text
artifact_profile: winkyou-test-direct-oob-attempt/1
oob_carrier_profile: caller-provided-bounded-stream/1
direct_attempt_profile: winkyou-test-direct-oob-control/1
observation_profile: same-socket-multi-stun/1
secure_channel_profile: noise-nnpsk0-25519-chachapoly-sha256/1
```

### 4.1 artifact

新 artifact 与 N3b `winkyou-test-direct-attempt-oob/1` 严格分离：

- 不含 direct endpoint；
- 不含 rendezvous endpoint、TLS 配置或 server admission；
- 不含命令、SSH username、hostname、path 或环境变量；
- 固定 role、generation、双侧 machine scope、十分钟时效、五个 pairwise-distinct ID；
- 用 `oob_channel_id` 替代 rendezvous association；它只作一次 attempt 的 context binding，
  不是可路由地址；
- profile、carrier role、observation profile 与 runtime fallback 全部进入 Noise prologue；
- `runtime_fallback=disabled`，未知值在 authority、进程启动和网络 I/O 前拒绝。

一次离线生成只产生 initiator、responder 与 secret-free manifest 三个文件。新命令形态、
manifest JSON 与 clipboard 语义由 Gate C 另行冻结，不能复用 N3b 四文件 manifest 后删字段。

### 4.2 OOB stream carrier

`internal/v2/oobcarrier`（暂定名）只能接受调用方已经建立、专属于本次 attempt 的
`BoundedStream`（暂定窄接口）：

```go
type BoundedStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetDeadline(time.Time) error
}
```

`Close` 必须解除并等待所有在途 `Read`/`Write`；不满足该契约的 pipe、复用层或 SDK
channel 必须在进入 carrier 前由 assembly 包装并证明，不能靠 goroutine 泄漏模拟取消。

- stream 必须是父管理连接上的独立子流；carrier 关闭该子流，但不拥有或关闭父连接；

- 包内不得 import `net`、`os/exec`、SSH/Tailscale SDK 或打开 fd/socket；
- 最多一个 stream，不能 reconnect、dial、listen、DNS、poll、queue 或跨 attempt 复用；
- 继续使用 WYRC 的长度上限、半帧/粘帧处理和每方向 8 frame/8,256 byte ceiling；
- 3 秒 presence、13 秒 active envelope、2 秒 drain；
- stream EOF、deadline、parent cancellation 或 child death 全部终局；
- pairing PSK 永不进入 carrier；authenticated direct-punch 域帧进入 OOB carrier 仍是终局；
- carrier witness 报 frames/bytes、deadline、EOF、drained/closed，不报告 stream endpoint、
  command、PID 或 transport metadata。

未来 SSH assembly 必须在包外，并满足：host key pin、key-based authentication、无 password
参数/环境/日志、一个 child、无 ControlMaster/重连、固定 remote command、13 秒后强制 kill
和 child/process drain witness。首次 Gate A 不实现该 assembly。

### 4.3 presence、burn 与 handshake 顺序

顺序固定为：

```text
local artifact/scope/ledger preflight
  -> acquire complete attempt reservation
  -> adopt exactly one bounded stream
  -> exchange secret-free presence
  -> durable local credential burn
  -> ACTIVATE / ACTIVATE_READY
  -> first Noise handshake byte
  -> PREPARE
  -> open one governed wildcard-ephemeral UDP socket
  -> same-socket mapping observation
  -> READY / FIRE / direct punch / bidirectional VERIFY
  -> atomic session handoff or terminal drain
```

presence 前不得传 artifact、fingerprint、PSK、context digest 或 direct endpoint。presence
之后任何失败均按已发生的本地 burn 记录，不退款。两侧 burn 不是分布式事务；一侧 burn、
另一侧失败是允许的保守终局。

## 5. Mapping observation 与容易路径

Gate A 只允许 operator 显式传入 2 个去重后的 literal STUN endpoint；无默认域名、DNS、
公共列表或 fallback。目标必须经现场授权，且属于同一地址族。

Tailscale 官方 DERP 实现通常同时在 UDP/3478 提供 STUN，官方说明 tailscaled 会向 DERP
STUN 目标判断 easy/hard NAT：

- <https://tailscale.com/docs/reference/stun-protocol>
- <https://tailscale.com/docs/reference/faq/firewall-ports>
- <https://github.com/tailscale/tailscale/blob/main/cmd/derper/derper.go>

这只说明技术能力，不自动授权 WinkYou 把第三方 DERP 当通用 STUN。现场模板必须记录
observation service 的 operator permission；没有明确许可时不得使用。

两个 STUN exchange 必须复用将来 punch 的同一 `ProbeSocket`，并保留 time-window-only
证据。Gate A 只接受：

```text
mapping_behavior = consistent_same_address
successful_targets = 2
mapped endpoint is canonical and belongs to the same socket/generation
```

其余结果在 READY 前终止为 `mapping_not_directly_usable`：credential 已 burn，direct
packets=0，不换 STUN、不增加 target、不切换 address family、不进入 Gate B。

## 6. Gate A 冻结成本提案

以下为评审输入，只可下调；评审前不进入生产常量：

| 资源 | initiator | responder | 说明 |
| --- | ---: | ---: | --- |
| heavyweight attempt | 1 | 1 | 单 credential、single-flight |
| OOB stream | 1 | 1 | caller-provided；WinkYou 包内不 dial |
| OOB child process | 0（Gate A） | 0（Gate A） | SSH assembly 留 Gate C |
| governed UDP socket | 1 | 1 | wildcard + ephemeral |
| STUN targets/five-tuples | 2 | 2 | 串行、同一 socket |
| direct target/five-tuple | 1 | 1 | 只在 mapping gate 通过后登记 |
| STUN outbound | 6 | 6 | 每目标最多 3；实际成功通常 2 |
| direct outbound | 2 | 1 | 沿用 SYN/SYN_ACK/ACK |
| UDP outbound total | 8 | 7 | 硬上限，不是目标值 |
| UDP PPS | 5 | 5 | 编译期 ceiling |
| active / drain | 13s / 2s | 13s / 2s | 无 retry |
| OOB frames / bytes | 8 / 8,256 | 8 / 8,256 | 每方向 application ceiling |

任何成本不匹配必须在打开 stream 或 socket 前拒绝。hard cap 违规触发持久 safety trip；
普通 `mapping_not_directly_usable`、peer absence 或 timeout 是干净终局，不触发 trip。

## 7. Session lease 与 transport handoff

这是 N3c 与 N3b 最大的新增权限，必须独立实现和评审。

### 7.1 接收方先持有 lease

在调用 `Promote` 前，数据面 consumer 必须取得一个窄 `TransportLease`（暂定名）：

- 绑定 peer ID、attempt ID、generation、path ID 与 consumer kind；
- 只允许接收一个 fixed-target `PacketTransport`；
- 不允许 consumer 打开 socket、改变 endpoint、注册第二 target 或触发新 attempt；
- 拥有自己的 cancellation、drain handle、process/session shutdown witness；
- 明确区分“建立流量预算”与“用户数据流量”。它不把 WireGuard 用户流量错误计入 5 PPS
  probe ceiling，但保持一个 socket/一个 target/一个 owner 的资源所有权；
- consumer attach 失败或超时必须关闭 transport，不得退回 ProbeSocket 或重试 Promote。

### 7.2 原子交接

新的 handoff helper 必须按顺序：

1. 验证 direct protocol 已双向 VERIFY；
2. 验证 `TransportLease` 已签发、未被消费且绑定相同 peer/attempt/generation；
3. lease-bound `ProbeSocket.PromoteToLease`：原子关闭 sibling、毒化旧句柄，把 fixed-target
   transport 转入 `active=false` 的 `TransportLease`；governor attempt lease 此时**保留**
   （§16 修订：不得在 adopt/challenge 结果可知前释放）；
4. consumer 在 1 秒内 adopt exact transport；
5. adopt 成功后才把 direct path 标记为 standby/usable；
6. 独立 data-plane challenge 通过后，调用方才可选择该 path；
7. adopt 与 data-plane challenge 结束后（无论成败）先记录 durable FINISH，再关闭并释放
   attempt lease；任一步失败还必须关闭 transport、session lease 和 OOB carrier。成功后
   `TransportLease` 独立持有 transport，其生命周期不再依赖已 FINISH 的 attempt。

OOB 父管理信道不是 WinkYou 所有，N3c 不关闭、重配或禁用它；只关闭为本次 attempt
交入的独立子流。direct 失败只返回稳定原因，不会为了“迁移”破坏现有可达性。

### 7.3 Gate A 的数据面证明

Gate A 只使用 test consumer：在 promoted transport 上双向交换固定 3 个合成 packet，随后
主动关闭并证明 drain。WireGuard、mesh shortcut、stdio/CLI/runtime 接线全部留 Gate C。

## 8. 稳定失败类提案

Gate A 至少需要以下新 class，成员仍为 `class/stage/credential_burned/retryable=false`，
不得携带 endpoint 或底层 error：

| class | stage | direct UDP | 含义 |
| --- | --- | ---: | --- |
| `oob_stream_invalid` | preflight | 0 | stream/profile/参数不合法 |
| `oob_presence_timeout` | present | 0 | 3 秒内未完成双侧 presence；未 burn |
| `oob_stream_closed` | 任意 | 以实际值 | EOF/child death/cancel |
| `oob_protocol_violation` | carrier | 以实际值 | framing/order/domain 违规 |
| `mapping_not_directly_usable` | stun | 0 | 两目标证据不满足容易路径 |
| `transport_lease_unavailable` | handoff | 以实际值 | consumer lease 未取得或不匹配 |
| `transport_handoff_failed` | handoff | 以实际值 | Promote/adopt 原子交接失败 |
| `data_plane_challenge_failed` | handoff | 以实际值 | standby transport 未通过固定 challenge |

progress 在 N3b 前缀上把 `rendezvous preconnect/presence` 替换为 `oob_adopt/present`，并在
`verify` 后增加 `transport_lease -> handoff -> data_plane_challenge -> terminal`。完整序列与
golden 由 Gate A mini-spec 冻结。

## 9. Architecture gate

Gate A 必须证明：

- `oobcarrier` 是 zero-network-capability zone；
- 只有新的 simulation/netns harness 能构造 carrier；stdio v1/v2、CLI、runtime、legacy、
  scheduler、`wink-signal`、WireGuard 均不能导入；
- carrier interface 只能由 `directconnect` 的内部 adapter 消费，不能暴露 raw stream/frame；
- `TransportLease` 只能由明确白名单 consumer 创建，不能由 strategy、artifact 或远端消息
  申请；
- mutation test 对任意 product import、`net.Dial/Listen`、`os/exec`、第二 socket/target、
  调用 `Promote` 前无 lease、handoff 后复用旧句柄均必须失败；
- N3b v2 golden、成本、parser 与唯一 consumer 路径逐字节不变。

## 10. Gate A 必过测试

### 10.1 纯内存与 framing

- presence/burn/handshake/control 完整顺序；
- 半帧、粘帧、超长、EOF、cancel、deadline、writer error；
- burn 前 secure frame、direct-punch 域跨 carrier、replay、wrong role/generation/context；
- 双方并发发送有界，不因 stream backpressure 永久停滞；
- 关闭后 goroutine/process/fd witness 为零。

### 10.2 NAT simulation

- EIM×EIM easy path 成功并移交；
- 任一侧 EDM/port-dependent 在 READY 前以 `mapping_not_directly_usable` 终止，direct=0；
- STUN 一个目标静默/错源/协议错均终局；
- mapping 在 attempt 中途变化时不能沿用旧 READY；
- 丢包、乱序、duplicate 仍不产生第二 attempt 或越界发射。

### 10.3 session handoff

- lease-before-Promote 双向断言；
- peer/attempt/generation/target 不匹配全部零 handoff；
- consumer adopt timeout/failure 关闭 transport；
- successful adopt 后旧 ProbeSocket、Controller 句柄不可用；attempt lease 冻结为零新发射，
  直至 challenge 后 durable FINISH 先落盘再释放（§16 顺序）；
- test consumer 3-packet challenge 精确计数；
- consumer crash、parent kill 和 cancellation 后 transport/session/OOB 全部有界排空；
- 100 次 fresh run，`-race -count=20`，无 goroutine/fd/lock residue。

### 10.4 required Linux netns

两个 endpoint 子进程用 socketpair/pipe 模拟已有 OOB stream，并通过真实 OS UDP socket 组合
easy mapping、hard mapping bounded failure、peer absence、post-burn crash 与 handoff consumer
crash。必须使用 `WINKYOU_*_REQUIRED=1` 防静默 skip，进程外核对 packet/socket/process/
conntrack/governor lock 全部归零。

## 11. Gate B 的硬问题

现场脱敏观测显示困难输入不是理论边角。Gate B 开工前必须回答：

1. 单 socket、双 STUN 的 port-dependent 结果如何与 multi-socket allocation signal 关联；
2. 什么证据允许生成 prediction window，什么结果必须直接失败；
3. prediction target 是否仍是同一 public IP，如何避免变成端口扫描；
4. socket×candidate 是否产生乘积发射，完整成本如何在 admission 前冻结；
5. 24 小时 2,048 packet ledger 如何覆盖进程 crash/restart，而不是仅覆盖内存 attempt；
6. 成功概率、网络负担与失败成本是否值得产品化。

legacy `pkg/nat/puncher` 和 Pion 路径不满足 v2 probeio 强制点、单一 machine governor 和
restart ledger 要求，不能通过 adapter 包装后复用。任何 birthday 提案必须重新实现为
governor-owned capability，并证明违反上限时在 OS I/O 前被拒绝。

## 12. 现场授权门

Gate C 的首次 campaign 不复用 N3b credential 或授权实例。至少分别签发：

1. peer absent（pre-burn）；
2. wrong PSK；
3. OOB EOF after burn；
4. mapping not directly usable（direct=0）；
5. transport lease mismatch（handoff=0）；
6. consumer crash after Promote；
7. nominal easy-NAT success。

只有 Gate B 获准后，才可另加 endpoint-dependent prediction/birthday scenario。当前已观测的
困难环境不能冒充 easy-NAT nominal；在 Gate B 未接受前，它的唯一合法 N3c 结果是有界失败。

每个实例仍要求两个不同的人事前签发、exact SHA/checksum、machine scope ready、safety
trip clear、ledger capacity、kill switch、packet/socket/process/conntrack/transport witness 与
事后第二人复核。密码、SSH host key、真实 endpoint、命令路径和 topology 只留受控私有记录。

## 13. 明确拒绝的捷径

- **复用 Tailscale netmap endpoint：**属于另一个 socket，且接口不稳定；拒绝。
- **强制关闭 DERP 再观察：**会先破坏唯一管理信道，不能证明 direct；拒绝。
- **把 SSH 当 pairing trust anchor：**OOB operator 仍不应拥有配对身份；拒绝。
- **在 v2 增加可选 OOB 字段：**破坏 exact-version 与 downgrade 边界；拒绝。
- **N3b `PromoteTerminal` 返回 raw transport：**绕过 session lease 与 drain；拒绝。
- **调用 legacy birthday/Pion：**绕过 v2 socket/governor 边界；拒绝。
- **失败后自动再试或扩大窗口：**违反 credential、ledger 与现场授权单位；拒绝。
- **产品命令接收 password、任意 shell command 或 host-key bypass：**泄密与命令注入；拒绝。

## 14. 评审问题

在 Gate A 开工前，请独立评审明确回答：

1. 新 artifact/profile 是否足以与 N3b rendezvous profile 防降级隔离；
2. OOB stream 的 presence/burn 顺序是否允许 carrier operator 造成不可接受的 burn-only DoS；
3. `TransportLease` 的 owner、创建层和 FINISH/drain 顺序应落在哪个 package；
4. Gate A 是否只允许 test consumer，还是可以同时接 WireGuard memory-TUN；
5. 两个 STUN target 与 8/7 packet ceiling 是否合理；第三方 observation service 的授权如何
   进入现场模板而不进入 artifact；
6. `mapping_not_directly_usable` 是否必须永久阻断 Gate B 自动 fallback；
7. Gate A/Gate B/Gate C 的 PR 和 ADR 是否还需要进一步拆分。

未答复并接受这些问题前，下一步只能是 zero-network 实现证据；不能安装远端 binary、创建
machine scope、运行 active STUN、修改 firewall 或发起 direct attempt。

## 15. 独立评审答复（2026-08-25）

1. **Profile 隔离：足够。** 新 identifier 与 N3b 严格不同且全部进入 Noise prologue，跨
   profile 降级在 AEAD 层不可能成立。Gate A 必过测试补一条硬要求：两套 parser 必须互相
   拒绝对方的 artifact，并作为 golden 负向用例冻结。
2. **Burn-only DoS：可接受，不加新机制。** presence 在 burn 之前；OOB operator 掐断
   stream 最多让本端浪费一张自己生成的一次性 credential 和一个持久限速槽位——这正是
   “burn 不是分布式事务”的保守语义。任何 burn 前双向 commit 协议都会引入第二个信任
   锚，拒绝。
3. **`TransportLease` 落在 `internal/probeio`。** 它是 Promote 语义与 drain 见证的自然
   延伸；consumer 白名单由 architecture gate 精确列举。不放 `directconnect`（消费方不得
   自造 lease），也不放 `pkg/transport`（不得把权限泛化给 legacy 路径）。FINISH 顺序沿用
   现有契约：durable FINISH 先于 attempt 释放，handoff 成功与否都不例外。
4. **Gate A 仅 test consumer。** WireGuard memory-TUN 是第二个权限升级，留 Gate C；一次
   评审只开一个权限。
5. **2 STUN target 与 8/7 ceiling 合理**，仍受 24 小时 2,048 packet 持久预算约束；第三方
   observation service 的 operator permission 记入现场授权实例的私有记录，不进入 artifact
   或仓库——按 §5 原文执行。
6. **是：永久阻断自动 fallback。** `mapping_not_directly_usable` 是本 attempt 的干净终局。
   即使 Gate B 将来被接受，endpoint-dependent 求解也必须是显式新 attempt、新 credential、
   新签发授权实例；任何同 attempt 内升级、自动重试或“顺手换策略”都是被拒绝的捷径。
7. **拆分维持三 gate，实现粒度再细分。** Gate A 一个实现 PR（memory + netns 证据同批）；
   Gate B 先独立设计 ADR、后独立实现 PR，两步都需评审；Gate C 至少拆 SSH assembly 与
   产品入口/campaign 两个 PR。

同时明确一个预期事实：§2.2 的脱敏观测显示当前两侧环境均为 endpoint-dependent mapping，
因此在 Gate B 获准前，本环境的合法 N3c 结果只有有界失败；Gate A 的 nominal easy-NAT
success 须在满足容易路径条件的环境验证，不得用困难环境冒充。

## 16. Gate A 开工前规范矛盾裁决（Accepted，2026-08-27）

实现方在开工审计中发现硬矛盾并按停止条件报告：§7.2 step 3 原文要求 `Promote` 在关闭
sibling 的同时释放 attempt lease，但 consumer adopt（step 4）与 data-plane challenge
（step 6）的结果只能在其后得知，而 §15 答复 3 冻结"durable FINISH 先于 attempt 释放，
handoff 成功与否都不例外"。二者无法同时逐字满足：按原 step 3 释放后，FINISH 只能落在
释放之后；若 step 3 后进程崩溃，还会出现"单飞槽位已释放、无 FINISH 见证"的窗口。

裁决：**§15 答复 3 是承重不变量（沿自 pairing restart-safety 契约），§7.2 step 3 原文让位。**
采纳 lease-bound 修订（正文已按此更新）：

- step 3 改为 `PromoteToLease`：原子关闭 sibling、毒化旧句柄，把 fixed-target transport
  转入 `active=false` 的 `TransportLease`，governor attempt lease 保留；
- lease 仅在 consumer 成功 adopt 后转 active，challenge 通过后 direct path 才 standby；
- adopt 与 challenge 结束后，无论成败先记录 durable FINISH，再关闭并释放 attempt lease；
- 失败路径额外关闭 transport、session lease 与 OOB carrier，同一 FINISH 先行顺序；
- 成功后 `TransportLease` 独立持有 transport；旧 ProbeSocket、Controller 句柄保持毒化；
- 现有 N3b `Promote`/`PromoteTerminal` 语义与 golden 逐字节不变；`PromoteTerminal`
  "保留 attempt lease" 的先例（§2.1）正是本修订的既有形态；
- 本裁决不新增任何权限；attempt 在 FINISH 前始终占用单飞预算，不产生第二 attempt 窗口。

必过测试补两条硬要求：PromoteToLease 之后、FINISH 之前崩溃时，重启见证 attempt 仍被
占用且无泄漏 socket；FINISH 与 attempt 释放的顺序由持久 journal 断言，不得只靠内存状态。

## 17. Gate A Draft 实现证据（2026-08-27）

Gate A 已进入单独 Draft 实现阶段；协议面、成本、失败类、ownership 顺序、memory/loopback、
100 次 NAT simulation 与 required Linux netns harness 的可复核清单见
[`GATE-A-OOB-HANDOFF-EVIDENCE.md`](../GATE-A-OOB-HANDOFF-EVIDENCE.md)。该状态只表示实现可提交
独立评审，不表示 Gate A 已通过评审，更不授权 Gate B2、SSH assembly、WireGuard、产品入口
或任何现场 I/O。required CI 的 exact SHA 与实测数字必须在 Draft PR 全绿后补齐。
