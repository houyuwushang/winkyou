# In-Band Peer Control

本文定义 WinkYou 已建立虚拟网之后的轻量 peer control 边界。它是当前 active 运维/开发说明的一部分，但不替代 [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md)。

## 目标

in-band peer control 的目标是让已建立数据面的两个节点，在 coordinator 暂时不可达时仍能交换最小控制信息：

- heartbeat
- path health
- endpoint update
- capability refresh
- re-ICE request
- session signal

当前代码已经把 `heartbeat`、`path_health`、`re_ice_request` 和最小 `session_signal` 接入 client 运行时循环。`session_signal` 会短期缓存并随 in-band 周期重发，接收端按 `from/type/seq` 去重，避免 post-bound re-ICE 因单个 UDP 控制包丢失而中断。消息模型位于 [`pkg/peercontrol`](../pkg/peercontrol)，运行时发送/接收位于 `pkg/client/inband_control.go`。它不会在首次 bootstrap 阶段使用。

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
- `re_ice_request`：请求对端重新争取 protected direct。当前运行时会把它映射为 bound peer 的 protected-direct improvement 调度。
- `session_signal`：承载现有 `solver.Message` 的最小通用封装，包括 `session_envelope` 和 `strategy_message`。当已有虚拟网可用时，client 会把 session/strategy 信令同时发到 coordinator 和 in-band control；如果 coordinator 不可用但 in-band control 可用，bound 后的 improvement 仍有机会继续交换 capability、ICE offer/answer/candidate、path_commit 等消息。最近发送的 `session_signal` 会在短时间内随 heartbeat 周期重发；这是抗丢包补强，不是完整可靠传输。

## 当前接入方式

当前运行时遵循以下边界：

1. 只有 peer 已 bound 且数据面可用时才启动 in-band control。
2. coordinator 仍负责首次 registration、peer discovery、capability exchange 和 candidate/path bootstrap。
3. coordinator 不可用时，in-band control 可以把 control plane 标记为 degraded/disconnected，同时保持 data plane alive。
4. 当前 `heartbeat` / `path_health` 会更新 peer 的 in-band 时间戳和 control/data 状态。
5. 当前 `re_ice_request` 会调度已有 peer session 的 protected-direct improvement；它不跳过 resolver/capability 边界，也不把 NAT/ICE 细节放进 `pkg/session`。
6. 当前 `session_signal` 只作为已有虚拟网内的冗余/备用信令通道使用；短期重发会提高 post-bound protected-direct improvement 的成功率，但首次 bootstrap 仍需要 coordinator、bootstrap 节点、静态 endpoint、已有 overlay 或手动交换信息。
7. `wink doctor` 和 `wink peers` 展示最后一次 in-band heartbeat/path health 时间。

## 验证要求

后续继续扩展前至少需要：

- 单元测试覆盖消息校验和编解码。
- fake in-band transport 测试 heartbeat/path health 收发。
- fake runtime 测试 `re_ice_request` 会调度 protected-direct improvement。
- fake runtime 测试 coordinator 不可用时 session signal 可以通过 in-band control 发送。
- fake runtime 测试最近的 session signal 会被重发，重复序列会被去重。
- coordinator 进程退出但 underlay 不断时，已 bound peer 不被移除。
- 恢复 coordinator 后，control state 能从 degraded/disconnected 回到 connected。
