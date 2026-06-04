# 控制面断线与 P2P 保持

本文记录 2026-06-04 真实部署验证后暴露的问题和后续 TODO。它是当前 active 运维说明，不能替代 [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md) 的架构边界。

## 已验证现象

测试拓扑：

- 本机 Windows 作为 `local-a`
- `chen-win` 运行 coordinator
- `inner-gw` 作为远端 Linux 节点
- 本机只能通过 `chen-win` 跳板 SSH 到 `inner-gw`
- 两端 WinkYou 配置只启用 STUN，没有配置 TURN relay

验证结果：

- `local-a` 获得虚拟 IP `10.88.0.2`
- `inner-b` 获得虚拟 IP `10.88.0.1`
- `wink peers` 两端都显示 `State: connected`
- `Conn Type: direct`
- `ICE State: connected`
- WireGuard handshake 出现
- `10.88.0.1` 和 `10.88.0.2` 双向 ping 成功

这证明数据面没有通过 `chen-win` TURN relay 转发。但当断开本机到 `chen-win` 的 natpierce 连接后，WinkYou 连接也断开。

## 拓扑澄清

不要把两个 `10.6.22.1` 混为一个节点：

- 本机看到的 `10.6.22.1` 是本机/`chen-win` 所在的 natpierce 虚拟网关。
- `inner-gw` 的 `10.6.22.1` 是 `chen-win` 另一侧能看到的虚拟局域网节点。
- `inner-gw` 不是本机可直接访问的 `10.6.22.1`。

## 根因判断

当前问题不是 `PacketTransport` 必须通过 `chen-win` 转发，而是控制面仍持续依赖 `chen-win`：

- coordinator 部署在 `chen-win`
- 本机 coordinator URL 指向 `grpc://192.168.11.217:50051`
- `inner-gw` coordinator URL 指向 `grpc://10.6.22.4:50051`
- 两端注册、心跳、peer online 状态和 session 信令都依赖这个 coordinator

当前 client 还有一个行为风险：收到 peer offline 或 coordinator 判断 peer 不在线时，会走 `cleanupPeer`，从而清理 peer session、tunnel peer 和 endpoint。这样即使数据面已经 bound，只要控制面短暂断开，也可能被主动拆掉。

## 当前限制

没有 coordinator 时，从零建立通用 NAT 场景下的虚拟局域网不可保证。首次连接仍需要某种 bootstrap/rendezvous：

- 公网 coordinator
- 任意稳定在线的 bootstrap 节点
- 一方公网 IP 或端口映射
- 手动交换 endpoint/candidate
- 已有 overlay 网络

如果双方都在 NAT 后面，尤其是 symmetric NAT，且没有任何第三方会合点或手动配置，双方无法凭空知道对方当前公网映射地址，也无法完成 ICE candidate exchange。

## 目标方向

coordinator 应降级为 bootstrap 服务，而不是已建立数据面的持续依赖：

```text
coordinator bootstrap
  -> capability / candidate / path_commit
  -> PacketTransport bound
  -> WireGuard data plane alive
  -> coordinator outage tolerated
```

连接建立后，节点可以通过虚拟局域网内的 in-band control channel 交换后续控制信息。但这只能接管已建立路径之后的控制消息，不能替代首次 bootstrap。

## TODO

### P0: 控制面断线不拆已连接数据面

- 已 bound 且 WireGuard handshake 正常的 peer 收到 offline/update 丢失时，不要立即 `cleanupPeer`。
- 保留 tunnel peer、endpoint、PacketTransport 和 session snapshot。
- peer 状态应区分 control plane 和 data plane，例如：
  - `control_state: connected | degraded | disconnected`
  - `data_state: connecting | bound | alive | stale | failed`
- 只有数据面也超时、transport failed、用户显式 disconnect/down，才清理 tunnel peer。

### P0: 增加回归测试

- fake coordinator 发出 peer offline 后，已 connected peer 不应被 `RemovePeer`。
- coordinator heartbeat 失败时，client 进程不应主动拆除已 bound transport。
- path commit 已完成后，短时间 control outage 不应导致 `wink peers` 从 connected 直接变 disconnected。

### P1: 缓存 peer lease 和最近成功 path

本地 runtime/state 应保存：

- peer public key
- peer virtual IP
- 最近成功 strategy
- 最近成功 endpoint
- path summary
- last handshake time

这允许 coordinator 短暂不可用时继续展示状态，也为重启后的 cached path 重试打基础。

### P1: in-band control channel

已建立虚拟网后，可以在 `10.88.0.0/24` 内增加轻量 peer control channel，承载：

- peer heartbeat
- endpoint update
- re-ICE request
- capability refresh
- observation exchange
- path health report

该通道必须是后置能力：只有数据面已经可用时才能使用，不能承担首次发现和首次穿透。

### P1: 纯 NAT piercing 验证需要候选接口控制

本次 direct path 中 candidate 可能包含 Tailscale/peer-reflexive 地址或 Docker bridge host 地址。这证明没有使用 `chen-win` TURN relay，但不能证明完全不借助已有 overlay。

后续需要增加或验证：

- ICE interface include/exclude 配置
- candidate CIDR 过滤
- 排除 Tailscale、Docker bridge、VPN/TAP 等接口的测试配置
- `wink doctor` 输出 selected candidate 来源和是否来自 excluded interface

### P2: 部署建议

生产 quickstart 中 coordinator 应部署在双方都能稳定访问的公网或固定网络位置。`chen-win` 可以作为 SSH 跳板或临时测试机，但不应作为唯一控制面依赖；否则断开 natpierce 后，peer discovery、heartbeat 和 session signaling 都会失效。
