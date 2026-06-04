# In-Band Peer Control

本文定义 WinkYou 已建立虚拟网之后的轻量 peer control 边界。它是当前 active 运维/开发说明的一部分，但不替代 [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md)。

## 目标

in-band peer control 的目标是让已建立数据面的两个节点，在 coordinator 暂时不可达时仍能交换最小控制信息：

- heartbeat
- path health
- endpoint update
- capability refresh
- re-ICE request

当前代码只冻结消息模型和 JSON 编解码，位于 [`pkg/peercontrol`](../pkg/peercontrol)。它还没有接入 client 网络循环，也不会在首次 bootstrap 阶段使用。

## 非目标

- 不替代首次 coordinator/rendezvous bootstrap。
- 不解决“双方都在 NAT 后面且没有任何会合点”的首次发现问题。
- 不改变 `transport.PacketTransport` 接口。
- 不把 NAT/ICE 细节重新引入 `pkg/session`。
- 不新增 QUIC/TCP/proxy 传输。

## 当前消息

所有消息使用 `version=1`，并带有：

- `type`
- `from`
- `to`
- `seq`
- `sent_at`

当前消息类型：

- `heartbeat`：上报 control/data 状态和最近 path id。
- `path_health`：上报 strategy、connection type、endpoint、last handshake、transport packet counters 和 last error。
- `endpoint_update`：通知已知 endpoint 变化。
- `capability_refresh`：刷新 strategy capability。
- `re_ice_request`：请求对端重新进行 ICE/strategy 选择。

## 预期接入方式

后续接入时应满足：

1. 只有 peer 已 bound 且数据面可用时才启动 in-band control。
2. coordinator 仍负责首次 registration、peer discovery、capability exchange 和 candidate/path bootstrap。
3. coordinator 不可用时，in-band control 可以把 control plane 标记为 degraded/disconnected，同时保持 data plane alive。
4. 收到 `re_ice_request` 后可以触发新的 strategy run，但不能跳过 resolver/capability 边界。
5. `wink doctor` 和 `wink peers` 应展示最后一次 in-band heartbeat/path health 时间。

## 验证要求

后续真实接入前至少需要：

- 单元测试覆盖消息校验和编解码。
- fake in-band transport 测试 heartbeat/path health 收发。
- coordinator 进程退出但 underlay 不断时，已 bound peer 不被移除。
- 恢复 coordinator 后，control state 能从 degraded/disconnected 回到 connected。
