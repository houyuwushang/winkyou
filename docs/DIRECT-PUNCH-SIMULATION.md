# 受控同步直连模拟切片

- 状态：**Phase 1a simulation-only，不是生产直连实现**
- 纯状态机：`internal/v2/punchsim`
- 组合测试：`internal/v2/testpairing/direct_punch_integration_test.go`
- 测试依赖：`internal/v2/testpairing`、`internal/probeio`、`internal/natsim`
- 安全边界：只在纯内存 NAT 模拟中运行；不接线 CLI、stdio API 或 Node Runtime；不授权真实网络探测

## 1. 这个切片证明什么

本切片把此前彼此独立的三项基础件接成一个最小闭环：

1. 每端取得一个 `connect_test` attempt 下的 `probeio.Controller`；
2. 测试夹具使用该 controller 打开的**同一个** `ProbeSocket` 建立模拟映射，并在纯内存中交换候选 endpoint；
3. 两端通过 `TestPairingChannel` 完成空 payload 的 `PREPARE -> READY -> FIRE`；
4. `FIRE` 后，两端在一个短窗口内执行有界 `SYN / SYN_ACK / ACK` 模拟数据报交换；
5. 只有来源 endpoint 与本次 attempt、generation、角色和报文类型都匹配时，`probeio.ReceiveReply` 才把路径标记为可提升；
6. 每端仅把命中的同一个 socket `Promote` 为固定对端的 `PacketTransport`；
7. 双方完成 `VERIFY` 后才向调用方返回 transport，测试随后用它交换应用 payload。

NAT harness 使用文档保留地址。它验证 EIM × EIM 且 address+port-dependent filtering 的场景连续 100 次成功，也验证“用观察到的 endpoint 直接尝试”在 EDM × EDM 下会在固定窗口内失败。后一个结果不是对可预测端口求解的否定：预测策略尚未接入，本切片只证明基础候选复用不会无界重试或偷偷扩大资源。

## 2. 明确没有证明什么

模拟数据报只是确定性 sentinel，**没有密码学认证能力**。它不能替代加密 ADR 所要求的经审查 secure channel，也不能进入真实网络。当前 pairing mini-spec 仍把 payload 定义为不可解释的 opaque bytes，因此本切片发送的所有控制 payload 都为空；候选 endpoint 只由纯内存测试夹具注入，没有借 payload 偷渡第二套协议。

为遵守 mini-spec 的实现门禁，`punchsim` 生产源码既不导入 `testpairing`，也不导入 `probeio` 或 `natsim`；它只定义零网络能力的状态机与窄接口。把现有 pairing 模拟器、受控 socket 和 NAT 模型连起来的代码只存在于 `internal/v2/testpairing` 下的 `_test.go`，不会进入任何命令或运行时构建。

本切片也没有：

- 实现真实 STUN candidate gathering 与 socket 保留 API；
- 实现配对加密、身份、roster 或生产 `SignalingChannel`；
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

## 4. 下一道门禁

下一步不是把这个模拟包接进 `wink connect-test`，而是先完成两项独立评审：

1. 为 candidate、FIRE 时序和直连验证数据报定义明确、版本化、attempt-bound 的 payload/packet schema；
2. 完成加密 ADR 的实现选择、向量、重放与负向测试，使真实 adapter 能证明 payload 和控制消息来自本次配对对端。

在这两项闭合前，`connect_test` 必须继续返回 `not_implemented`，真实联网仍需单独授权。
