# 受控同步直连模拟切片

- 状态：**Phase 1a simulation-only，不是生产直连实现**
- 纯状态机：`internal/v2/punchsim`
- 组合测试：`internal/v2/testpairing/direct_punch_integration_test.go`
- 测试依赖：`internal/v2/testpairing`、`internal/v2/noisecore`、`internal/probeio`、`internal/natsim`
- 安全边界：只在纯内存 NAT 模拟中运行；不接线 CLI、stdio API 或 Node Runtime；不授权真实网络探测

## 1. 这个切片证明什么

本切片把此前彼此独立的三项基础件接成一个最小闭环：

1. 每端取得一个 `connect_test` attempt 下的 `probeio.Controller`；
2. 测试夹具使用该 controller 打开的**同一个** `ProbeSocket` 建立模拟映射，并在纯内存中交换候选 endpoint；
3. 两端通过 `TestPairingChannel` 完成 `PREPARE -> READY -> FIRE`；默认明文模式仍使用空 payload；
4. `FIRE` 后，两端在一个短窗口内执行有界 `SYN / SYN_ACK / ACK` 模拟数据报交换；
5. 只有来源 endpoint 与本次 attempt、generation、角色和报文类型都匹配时，`probeio.ReceiveReply` 才把路径标记为可提升；
6. 每端仅把命中的同一个 socket `Promote` 为固定对端的 `PacketTransport`；
7. 双方完成 `VERIFY` 后才向调用方返回 transport，测试随后用它交换应用 payload。

NAT harness 使用文档保留地址。它验证 EIM × EIM 且 address+port-dependent filtering 的场景连续 100 次成功，也验证“用观察到的 endpoint 直接尝试”在 EDM × EDM 下会在固定窗口内失败。后一个结果不是对可预测端口求解的否定：预测策略尚未接入，本切片只证明基础候选复用不会无界重试或偷偷扩大资源。

### 1.1 可选 Noise 保护模式

`punchsim.Config.Secure == nil` 仍是默认值，生成并验证原有明文 sentinel。只有测试夹具显式提供 `SecureConfig` 时，才启用以下 simulation-only 路径：

1. 两端在现有控制 carrier 的 `PREPARE` opaque payload 中交换两条 48-byte NNpsk0 握手消息；
2. `READY` 携带并核对最终 32-byte handshake hash，随后把尚未使用的 Noise Split 双向密钥原子移交给有界 `PacketCipher`；
3. `FIRE` 后才发送经 AEAD 保护的打洞数据报；握手消息不走 probe socket，也不新增 UDP socket、target、packet 或 PPS 成本；
4. 按 [Noise rev34 §11.4](https://noiseprotocol.org/noise.html#out-of-order-transport-messages) 的 UDP 乱序指引发送显式 nonce，并记录成功解密的 nonce 以拒绝重放；这里进一步收紧为 `SYN=0`、`SYN_ACK=1`、`ACK=2`，每个序号在每个方向只能使用一次，重复、越界或认证失败都会终止对应方向；
5. `punchsim.Run` 在成功、失败和取消路径上都接管并关闭 `PacketCipher`，不会导出会话密钥，也不提供任意 nonce 设置接口。

没有把 Noise 握手直接放到待打洞 UDP socket 上：在 address+port-dependent filtering 下，握手发起报文可能在对端尚未向该五元组发送前被过滤，形成“必须先握手才能发 punch、又必须先 punch 才能收到握手”的循环。控制 carrier 先完成认证，再以同一受控 UDP socket执行 `FIRE`，才与当前状态机边界一致。

加密数据报固定为 56 bytes：明文 header 是 `WYNP\x01`、frame type 和 big-endian `uint64` sequence；AEAD additional data 是 `winkyou-test-punch-noise/1 || 0x00 || header`；密文内绑定原始 16-byte attempt ID、generation、发送角色和 frame type。header 的任何变化要么被固定 schema 拒绝，要么导致 AEAD 认证失败。

安全组合测试覆盖：相同 PSK 下 EIM × EIM 连续 100 次成功；一位 PSK 不一致在任何 UDP punch 前失败；安全数据报逐字节篡改不能提升；同一会话的数据报重复被拒；把上一轮完整握手和 punch 序列注入新一轮时，由新鲜 ephemeral 绑定的握手先失败。内存 ledger 只证明进程内重放语义，真实实现仍必须使用 mini-spec 要求的持久化 ledger。

## 2. 明确没有证明什么

默认模式的模拟数据报仍只是确定性 sentinel，**没有密码学认证能力**。可选 Noise 模式只提供实现与组合测试证据，不代表加密 ADR 已批准，也不能进入真实网络。pairing mini-spec 把 payload 定义为 opaque bytes；安全测试只用它承载两条固定握手消息和 handshake hash，候选 endpoint 仍仅由纯内存测试夹具注入，没有借 payload 引入候选交换或第二套信令协议。

为遵守 mini-spec 的实现门禁，`punchsim` 生产源码既不导入 `testpairing`，也不导入 `probeio` 或 `natsim`；它只定义零网络能力的状态机与窄接口。把现有 pairing 模拟器、受控 socket 和 NAT 模型连起来的代码只存在于 `internal/v2/testpairing` 下的 `_test.go`，不会进入任何命令或运行时构建。

本切片也没有：

- 实现真实 STUN candidate gathering 与 socket 保留 API；
- 批准配对加密实现，或实现身份、roster、生产 `SignalingChannel` 和 PSK 交付；
- 改动 `connect_test` 的稳定 `not_implemented` 行为；
- 接入 birthday 求解、随机端口枚举、端口扫描、Relay 或自动恢复；
- 修改路由器、端口转发、防火墙、计划任务或 daemon；
- 声称随机双 hard NAT、UDP blocked 或任意 NAT 都能直连。

`internal/architecture` 会拒绝任何生产包导入 `punchsim` 或 `testpairing`，并继续要求整个 `internal/v2` 依赖闭包不新增 raw network capability。

## 3. 固定资源上限

同步直连部分的编译期 envelope 为：

| 资源 | 上限 |
|---|---:|
| 同时持有 socket | 1（与 candidate gathering 复用，不得另开） |
| 新增 peer target | 1 |
| 新增 five-tuple | 1 |
| 出站模拟数据报 | 最多 2 |
| 入站模拟数据报 | 最多 2 |
| 出站 PPS | 最多 2 |
| 单数据报 | 最多 256 bytes |
| punch window | 最多 1 秒 |

`PunchWorstCaseCost` 只描述上表中的 punch 部分。未来完整策略必须在取得 lease **之前**，把 STUN/候选收集、控制 carrier 和 punch 的最坏成本合并；不能把同一 socket 误算成两只，也不能遗漏前序 target、packet、five-tuple 或持续时间。

可选 Noise 模式没有改变上表：握手只使用现有纯内存控制 carrier，安全 punch 仍最多出站 2 包、入站 2 包，单包 56 bytes。这个事实只说明当前测试 envelope 不变；未来真实控制 carrier 的 CPU、内存、消息数和 deadline 仍需在独立 admission 设计中计入。

## 4. 下一道门禁

下一步不是把这个模拟包接进 `wink connect-test`，而是先完成独立评审：

1. 审查 `noisecore` 与受限 `PacketCipher` 是否忠实、可维护且无易误用接口；
2. 审查固定 packet schema、控制 carrier 握手时序、重放语义和资源核算；
3. 由维护者填写 ADR 的实现选择与独立审查引用；当前提交只能附实现证据，不能自行翻转状态；
4. 另行设计生产 PSK 交付、认证信令、持久化 ledger、取消传播和真实网络 admission。

在这些门禁闭合前，`connect_test` 必须继续返回 `not_implemented`，真实联网仍需单独授权。提升后的模拟 `PacketTransport` 也没有被本模式继续封装；未来真实数据面仍由 WireGuard 负责，而不是复用一次性打洞密钥承载应用流量。
