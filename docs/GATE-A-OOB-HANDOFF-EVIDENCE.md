# Gate A：OOB direct handoff 实现与隔离证据

状态：**Draft implementation evidence；只覆盖 memory、literal loopback 与 required Linux
network namespace，不授权 SSH assembly、WireGuard/memory-TUN、产品入口、Gate B2 或现场 I/O。**

权限来源：[`ADR-N3C-OOB-DIRECT-HANDOFF.md`](./adr/ADR-N3C-OOB-DIRECT-HANDOFF.md)，包括
§15 的七条约束性答复和 §16 的 `PromoteToLease -> FINISH -> attempt release` 顺序裁决。

## 1. 固定协议面

Gate A 与 N3b artifact、presence 和 direct-attempt profile 严格分离：

```text
artifact_profile: winkyou-test-direct-oob-attempt/1
oob_carrier_profile: caller-provided-bounded-stream/1
direct_attempt_profile: winkyou-test-direct-oob-control/1
observation_profile: same-socket-multi-stun/1
secure_channel_profile: noise-nnpsk0-25519-chachapoly-sha256/1
runtime_fallback: disabled
```

artifact 不含 endpoint、TLS、命令、用户名、hostname、路径或环境变量。一次纯内存生成只产生
initiator、responder 和 secret-free manifest；五个 ID pairwise distinct，generation 固定为
1，时效固定为十分钟。N3b 与 Gate A parser 互相拒绝对方 artifact，结果已进入 JSON golden。

固定进度序列为：

```text
preflight -> oob_adopt -> present -> burned -> activated -> handshake -> prepare
  -> socket -> stun -> ready -> fire -> punch_sent -> punch -> verify
  -> transport_lease -> handoff -> data_plane_challenge -> terminal
```

新增稳定失败类固定为：

```text
oob_stream_invalid
oob_presence_timeout
oob_stream_closed
oob_protocol_violation
mapping_not_directly_usable
transport_lease_unavailable
transport_handoff_failed
data_plane_challenge_failed
```

每个错误只公开 `class/stage/credential_burned/retryable=false`；底层错误、endpoint、stream、
process、credential 和 secret 不进入协议结果。

## 2. OOB carrier 与资源上限

`internal/v2/oobcarrier` 只接收 caller 已建立的一个 `BoundedStream`。该包没有 `net`、
`os/exec`、SSH/Tailscale SDK、dial、listen、DNS、重连、轮询、队列或跨 attempt 复用能力。
presence 前只交换 secret-free channel ID 与固定 slot；durable burn 后才允许 ACTIVATE 和首个
Noise byte。认证成功的 direct-punch 域帧进入 OOB carrier 仍会立即终局。

| 资源 | initiator | responder |
| --- | ---: | ---: |
| heavyweight attempt / OOB stream / child process | 1 / 1 / 0 | 1 / 1 / 0 |
| UDP socket | 1 | 1 |
| STUN target / direct target | 2 / 1 | 2 / 1 |
| target / five-tuple 合计 | 3 / 3 | 3 / 3 |
| STUN outbound | 6 | 6 |
| direct outbound | 2 | 1 |
| UDP outbound hard ceiling | 8 | 7 |
| UDP PPS | 5 | 5 |
| active / drain | 13s / 2s | 13s / 2s |
| OOB application frame / bytes（每方向） | 8 / 8,256 | 8 / 8,256 |

成本不匹配在 stream ownership 与 socket I/O 前拒绝。普通 absence、timeout 和
`mapping_not_directly_usable` 是干净终局；只有 hard-cap/resource 违规进入持久 safety trip。

## 3. Same-socket observation 与 handoff

Gate A 在一个 governor-owned wildcard-ephemeral `ProbeSocket` 上串行登记两个 literal STUN
target；两次当前 generation 的 mapping 只有同时成功且得到同一个 canonical endpoint，才
允许登记一个认证 READY 中的 peer target。其他结果在 READY 前以
`mapping_not_directly_usable` 终止，direct 发射为 0，不重试、不换目标、不进入 Gate B。

双向 VERIFY 后的 ownership 顺序固定为：

```text
issue exact TransportLease (inactive)
  -> PromoteToLease closes siblings and poisons ProbeSocket/Controller
  -> consumer adopts within 1s
  -> standby
  -> bidirectional 3-packet synthetic data-plane challenge
  -> durable FINISH
  -> detach and release attempt
  -> close test transport and drain
```

`TransportLease` 绑定 peer、attempt、generation、path、target 和唯一 test consumer。consumer
拿不到 raw socket，不能换 endpoint、登记 target、打开第二个 socket或触发新 attempt。数据面
challenge 不错误计入 5 PPS 建立预算，但 transport 仍保持 one socket/one target/one owner。

## 4. 自动化证据

- framing 覆盖半 header、半 payload、粘帧、超长、EOF、parent cancel、deadline、writer
  failure、并发 backpressure 和 8 frame/8,256 byte ceiling；
- protocol 覆盖 burn 前 secure frame、authenticated direct-punch 跨 carrier、wrong role、
  generation、context、profile downgrade、认证失败、replay 与 CANCEL；
- handoff 覆盖 lease-before-Promote、peer/attempt/generation/path/target mismatch、nil lease、
  adopt timeout、旧 ProbeSocket/Controller 毒化、sibling close 和 3/3 data packet 计数；
- 持久 journal 证明 `PromoteToLease` 后、FINISH 前崩溃仍保留 `ADMIT+BURN` 与完整 packet
  charge，OS 回收 socket；重启同 credential 零 I/O 返回 `credential_used`；
- journal 顺序测试在 FINISH 已落盘时仍观测到 active heavyweight attempt，随后才 detach 与
  release；
- natsim 的 EIM×EIM fresh run 为 100/100；每轮 peak 为 4 个虚拟 PacketConn、2 个 mapping，
  direct 建立包合计 3、建立 UDP 合计 7、数据包 3/3，终局资源为 0；
- natsim 的 initiator/responder EDM 各 20 次有界终止，direct=0；mapping 中途变化不沿用旧
  READY；STUN 静默/错源/协议错及 direct 丢包/重复/乱序均不产生第二 attempt、不越界、不
  触发持久 trip；
- architecture 与 mutation gate 拒绝 product/stdio/CLI/runtime/legacy/scheduler/
  `wink-signal`/WireGuard 导入，拒绝 OOB carrier 获得 network/process SDK，拒绝第二 socket、
  第三 STUN target、legacy Promote 与未授权 TransportLease consumer；
- N3b artifact/parser、stdio、loopback carrier、成本和 golden 继续由原有回归逐字节守护。

## 5. Required Linux namespace 证明

`linux && natlab` harness 使用两个 endpoint 子进程、各自独立的真实 machine governor 与
durable ledger，并通过 inherited Unix socketpair 模拟 caller 已有 OOB 子流。UDP 只存在于
五个隔离 namespace 和 RFC 5737 TEST-NET 拓扑；public namespace 内运行两个现有
`internal/stunserver` responder。必跑场景为：

| 场景 | 必须见证 |
| --- | --- |
| EIM×EIM | STUN 2/2；direct 建立 2/1；data 3/3；OS UDP 7/6；双向 handoff 成功 |
| EDM 参与 | READY 前有界失败；direct 0；credential 已 burn、FINISH、不退款、无 trip |
| peer absence | 3 秒 presence timeout；未 burn；UDP 0 |
| post-burn crash + restart | survivor 有界 FINISH；crashed ledger 未完成 charge 保留；重启 `credential_used`、UDP delta 0 |
| handoff consumer crash | survivor 有界 FINISH；进程死亡后 transport/socket 全部回收 |

每个场景终局后必须证明 packet counter 稳定、process-owned TCP/UDP socket 为 0、namespace
process 为 0、conntrack 排水后为 0、machine lock 可重新取得，以及 netns/veth 删除后无残留。
结果和 CI artifact 会动态扫描 TEST-NET 地址、hostname、用户名、本机路径；只输出聚合计数
和稳定错误类。

缺少 root/netns 权限的本地环境明确 skip；required job 设置
`WINKYOU_GATE_A_REQUIRED=1`，任何权限或工具缺失都会失败，不能静默跳过。该 job 使用
race binary，test timeout 为 5 分钟、job timeout 为 6 分钟。

## 6. 验证结果与未证明事项

实现 SHA `ff876ca2b02adf98d80f373effd1e550a9b234c0` 的
[required Gate A netns job](https://github.com/houyuwushang/winkyou/actions/runs/33078137455/job/98537712708)
使用 race binary 在 13.70 秒内通过五个场景：

- EIM×EIM：STUN `2/2`、authenticated direct `2/1`、test data `3/3`、OS UDP
  `7/6`、OS peer-path UDP `5/4`，双向 handoff 成功；
- EDM 参与：STUN `2/2`，direct `0/0`，READY 前有界终止；
- peer absence：3 秒 presence timeout，`burned=false`、UDP `0`；
- post-burn crash/restart：journal 保留 `ADMIT+BURN` 与一个 unfinished admission，同
  credential 重启返回 `credential_used`，UDP delta `0`；
- handoff consumer crash：survivor durable FINISH，killed attempt 保留 unfinished 见证，
  OS socket 回收为 `0`。

五个场景的终局 packet counter 均保持稳定，namespace process 与 process-owned socket 均为
`0`；conntrack 清理前分别为 `6/4/0/0/6`，清理后全部为 `0`，machine lock 可重新取得，
netns/veth teardown 后无残留。Windows 本地同时覆盖 unit、loopback、纯内存 natsim、
architecture/mutation、全仓测试与受影响包 race；Linux tagged vet 与 cross-compile 也通过。
本机没有可用的 Docker/WSL Linux netns，因此上面的真实 OS 数值以 required CI 为权威证据。

本实现没有产品 consumer，没有 SSH/Tailscale assembly，没有 WireGuard、stdio/CLI/runtime
接线，也没有预测、端口窗口、birthday、Gate B2 executor、retry 或 fallback。它不证明真实
家庭路由器、CGNAT、企业网络或公网的成功率，不签发任何现场授权。
