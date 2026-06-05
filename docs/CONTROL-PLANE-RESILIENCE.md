# 控制面断线与 P2P 保持

本文记录 2026-06-04 真实部署验证后暴露的问题和后续 TODO。它是当前 active 运维说明，不能替代 [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md) 的架构边界。

## 当前代码状态

已完成第一层保护：当 coordinator 或 peer update 把一个 peer 标记为 offline，但本地仍能看到该 peer 有最近的 WireGuard handshake、packet counters 且没有 transport error 时，client 不再立即执行 `cleanupPeer`，从而避免主动移除已连接的 tunnel peer。

client runtime 也已经新增基础可观测字段：

- `control_state`
- `data_state`
- `last_path_id`
- `last_path_strategy`
- `last_path_endpoint`
- `last_path_connection_type`
- `last_path_updated_at`

`wink peers` 文本输出和 JSON 输出都会带出这些字段，用于区分“coordinator/control plane 已断”和“WireGuard/data plane 仍活着”。

client 还修复了一个真实验证中暴露的恢复问题：当本端不是 deterministic initiator 时，之前 `startPeerConnect` 和 peer session retry 会直接返回，导致高 node id 一侧在远端 stale session 或远端未重新发起时长期停在 `data_state=connecting/failed`。现在 controlled side 也会启动 session 并按 `nat.retry_interval` 重试；`initiator` 仍只作为 session/strategy 角色输入，不再作为 client 层是否允许恢复连接的门槛。

这仍只是控制面韧性的早期补强，还不能说明“所有控制面故障下都一定保持连接”。仍待完成和验证：

- 扩展真实双节点环境验证，覆盖更长时间 coordinator 进程退出、heartbeat failure 和 signaling stream failure，而不是断开 natpierce/跳板网络。
- coordinator heartbeat 或 signaling stream 失败时，不主动拆除已 bound 的 data plane。
- 使用最近成功 path/cache 做恢复或重试；当前只完成状态展示和缓存。
- 已建立虚拟网后的 in-band peer control channel 运行时接入；消息模型和 JSON 编解码已冻结在 `pkg/peercontrol`。

## 已验证现象

测试拓扑：

- 本机 Windows 作为 `local-a`
- `chen-win` 运行 coordinator
- `inner-gw` 作为远端 Linux 节点
- 本机只能通过 `chen-win` 跳板 SSH 到 `inner-gw`
- 两端 WinkYou 配置只启用 STUN，没有配置 TURN relay
- 本机 Windows 的 Wintun 依赖由本地下载的 `D:\deployment\winkyou\bin\wintun.dll` 提供；正式部署文档不能假设系统已经全局安装 Wintun

验证结果：

- `local-a` 获得虚拟 IP `10.88.0.2`
- `inner-b` 获得虚拟 IP `10.88.0.1`
- `wink peers` 两端都显示 `State: connected`
- `Conn Type: direct`
- `ICE State: connected`
- WireGuard handshake 出现
- `10.88.0.1` 和 `10.88.0.2` 双向 ping 成功

这证明数据面没有通过 `chen-win` TURN relay 转发。但 `Conn Type: direct` 在 ICE 语义里只表示选中的 candidate pair 不是 TURN relay，并不自动表示该 path 独立于已有 overlay 或跳板 underlay。历史 runtime/observation 多次记录 remote candidate 为 `100.102.17.35:*`，属于 `100.64.0.0/10`，因此更准确的判断是：该 path 是 ICE direct-like path，但很可能仍依赖 natpierce/chen-win 相关 underlay。断开本机到 `chen-win` 的 natpierce 连接后，WinkYou 连接也断开，这与上述证据并不矛盾。

后续通过 SSH 密码登录 `chen-win` 后，已确认可以只停止 `wink-coordinator` 进程而不触碰 natpierce/underlay 网络。排查过程中先暴露了一个部署问题：重启本机验证版 client 后，前置数据面一度没有重新达到 bound/handshake：

- coordinator 在 `chen-win` 上运行，进程名 `wink-coordinator`。
- `local-a` 控制面在线，能看到 `inner-b`，但 runtime 显示 `control_state=connected`、`data_state=failed/connecting`、`connected_peers=0`。
- 本机 controlled-side retry 修复后，`local-a` 会重新进入 solver 并写出新的 observation，但没有收到足够的远端响应完成 direct path。
- 未加 candidate filter 时曾选中过 `100.64.0.0/10` 地址段 candidate，并出现 `transport: short packet write 0/148`；这不是纯 coordinator outage 现象，也不能作为独立 protected direct path 的证据。
- 仅在本机加 `nat.candidate_interface_include: natpierce` 和 `nat.candidate_cidr_include: 10.6.22.0/24` 会让本机过滤生效，但远端 `inner-b` 未同步配置时无法形成可用 candidate pair。
- 进一步检查发现，`chen-win` 上的 coordinator 以默认 memory store 启动；重启 coordinator 后 `ListPeers` 返回空数组，说明注册表丢失，而旧 client 只保留本地 runtime 状态，没有自动重新注册，导致看起来 control 连接还在、实际 coordinator 不知道任何 peer。

修复和部署调整后，2026-06-04 21:48 已完成基础真实 outage 验证：

- `chen-win` coordinator scheduled task 已切到 SQLite store：`--store-backend sqlite --sqlite-path coordinator.db`。
- coordinator 注册表按原身份恢复为 `inner-b=node-000001/10.88.0.1`、`local-a=node-000002/10.88.0.2`。
- 本机运行包含 coordinator NotFound 重注册修复的新验证版 client。
- 验证前 `wink peers` 显示 `inner-b` 为 `state=connected`、`data_state=alive`、WireGuard handshake 非空、transport packet counters 非零。
- `wink ping inner-b` 成功。
- 只停止 `chen-win` 上的 `wink-coordinator` 进程，保持 natpierce/underlay 不动。
- coordinator 停止 15 秒期间，`wink peers --json` 仍显示 peer connected/bound，`wink ping inner-b` 仍成功。
- verifier 随后通过 scheduled task 拉起 coordinator，重启后 `wink ping inner-b` 继续成功。

因此，基础结论是：在这次 direct path 已 bound 的真实环境中，短时间只停止 coordinator 进程不会拆掉数据面。不要把这个结论扩大为“任意控制面故障、任意时长、任意网络拓扑都能保持”。下一步仍需覆盖 heartbeat/signaling stream 长时间失败、cached path 恢复和 in-band peer control 接入。

安全验证脚本 [`scripts/verify-control-plane-outage.py`](../scripts/verify-control-plane-outage.py) 已用于上述真实 kill-coordinator 回归。该脚本会先检查本机 `wink peers --json`、`last_handshake`、transport error 和 overlay probe；默认使用 `wink ping`，也可用 `--ping-method icmp` 切回系统 ICMP。只有确认已经存在 connected/bound peer 后，才会读取环境变量里的 chen-win SSH 密码并停止远端 coordinator。当前本机 runtime 没有 bound peer 时，脚本会直接退出并拒绝触碰远端进程。

代码已补上 coordinator client 的 NotFound 恢复路径：heartbeat 发现当前 node 在 coordinator 中不存在时，会关闭旧 signal stream 并用最近一次 register 请求重新注册。这主要用于 coordinator 持久化 store 或稳定身份恢复场景。当前 chen-win 测试部署仍需要切到 `--store-backend sqlite --sqlite-path ...`，并让两端 client 都运行包含该修复的新版本后，再进行真实 outage 验证。

## 拓扑澄清

不要把两个 `10.6.22.1` 混为一个节点：

- 本机看到的 `10.6.22.1` 是本机/`chen-win` 所在的 natpierce 虚拟网关。
- `inner-gw` 的 `10.6.22.1` 是 `chen-win` 另一侧能看到的虚拟局域网节点。
- `inner-gw` 不是本机可直接访问的 `10.6.22.1`。
- `local-a` 和 `inner-gw` 不是同一个二层/三层可直达网络里的两个普通节点，而是通过 natpierce/跳板链路间接互通的两个节点。

因此，直接断开本机到 `chen-win` 的 natpierce 连接不是一个纯粹的 coordinator outage 测试。它会同时移除 coordinator 可达性、SSH 跳板可达性，并且可能移除 ICE 选中的 underlay candidate 所依赖的路径。要单独验证“coordinator 挂了以后已建立数据面是否保持”，应该保持 natpierce/underlay 网络不动，只在 `chen-win` 上停止 coordinator 进程。

## 根因判断

当前问题不是 `PacketTransport` 必须通过 `chen-win` 转发，而是控制面仍持续依赖 `chen-win`：

- coordinator 部署在 `chen-win`
- 本机 coordinator URL 指向 `grpc://192.168.11.217:50051`
- `inner-gw` coordinator URL 指向 `grpc://10.6.22.4:50051`
- 两端注册、心跳、peer online 状态和 session 信令都依赖这个 coordinator

当前 client 还有一个行为风险：收到 peer offline 或 coordinator 判断 peer 不在线时，会走 `cleanupPeer`，从而清理 peer session、tunnel peer 和 endpoint。这样即使数据面已经 bound，只要控制面短暂断开，也可能被主动拆掉。

另一个已修正的代码层风险是 path metadata 误标注：过去 `legacy_ice_udp` 只要选中的 ICE pair 不是 relay candidate，就会把 path 标记为 `protected_direct`。现在 `100.64.0.0/10`、loopback、link-local、私网等非公网 candidate 会被标记为带 `unknown` dependency 的 direct-like path，不再作为 protected direct standby 对外承诺。它仍可作为普通 standby 保留，但 `protected_direct_path_id` 不会指向这类依赖不清的 path。

## 当前限制

没有 coordinator 时，从零建立通用 NAT 场景下的虚拟局域网不可保证。首次连接仍需要某种 bootstrap/rendezvous：

- 公网 coordinator
- 任意稳定在线的 bootstrap 节点
- 一方公网 IP 或端口映射
- 手动交换 endpoint/candidate
- 已有 overlay 网络

如果双方都在 NAT 后面，尤其是 symmetric NAT，且没有任何第三方会合点或手动配置，双方无法凭空知道对方当前公网映射地址，也无法完成 ICE candidate exchange。

换句话说：

- 已建立连接之后，可以设计由虚拟局域网参与节点自行承载的 in-band signaling/control，用来保持状态、交换 health、触发 re-ICE 或刷新 capability。
- 从零启动时，如果没有 coordinator、bootstrap 节点、静态 endpoint、端口映射、已有 overlay 或手动交换信息，通用 NAT 后的双方无法可靠发现彼此并建立虚拟局域网。

## 目标方向

coordinator 应降级为 bootstrap 服务，而不是已建立数据面的持续依赖：

```text
coordinator bootstrap
  -> capability / candidate / path_commit
  -> PacketTransport bound
  -> WireGuard data plane alive
  -> coordinator outage tolerated
```

连接建立后，节点可以通过虚拟局域网内的 in-band control channel 交换后续控制信息。但这只能接管已建立路径之后的控制消息，不能替代首次 bootstrap。当前已冻结消息模型，详见 [`INBAND-PEER-CONTROL.md`](./INBAND-PEER-CONTROL.md)。

## TODO

### P0: 控制面断线不拆已连接数据面

- 状态：peer offline update 触发的误清理路径已加第一层保护；controlled side session retry 已修复；coordinator heartbeat NotFound 会触发 client 重新注册；已 bound 数据面上的短时间真实 coordinator 进程退出验证已通过；更长时间 heartbeat/signaling failure 仍需验证。
- 已 bound 且 WireGuard handshake 正常的 peer 收到 offline/update 丢失时，不要立即 `cleanupPeer`。
- 保留 tunnel peer、endpoint、PacketTransport 和 session snapshot。
- peer 状态应区分 control plane 和 data plane，例如：
  - `control_state: connected | degraded | disconnected`
  - `data_state: connecting | bound | alive | stale | failed`
- 只有数据面也超时、transport failed、用户显式 disconnect/down，才清理 tunnel peer。

### P0: 增加回归测试

- 已有 fake peer offline 回归覆盖 connected peer 不应被立即 `RemovePeer`。
- fake coordinator 发出 peer offline 后，已 connected peer 不应被 `RemovePeer`。
- coordinator heartbeat 失败时，client 进程不应主动拆除已 bound transport。
- path commit 已完成后，短时间 control outage 不应导致 `wink peers` 从 connected 直接变 disconnected。
- 真实环境验证应保持 natpierce/underlay 不断，只停止 `chen-win` 上的 coordinator 进程，再观察 `wink peers`、WireGuard handshake 和 `wink ping`；基础 15 秒 outage 已通过，后续应扩展时长和故障类型。

### P1: 缓存 peer lease 和最近成功 path

状态：基础 runtime/cache 字段已加入 `PeerStatus`、runtime JSON 和 `wink peers` 输出。后续还需要把这些缓存用于重启后的恢复或 cached path 重试。

本地 runtime/state 已开始保存：

- peer public key
- peer virtual IP
- 最近成功 strategy
- 最近成功 endpoint
- path summary
- last handshake time

这允许 coordinator 短暂不可用时继续展示状态，也为后续 cached path 重试打基础。

### P1: in-band control channel

状态：消息模型、校验和 JSON 编解码已加入 `pkg/peercontrol`；client 网络循环尚未接入。

已建立虚拟网后，可以在 `10.88.0.0/24` 内增加轻量 peer control channel，承载：

- peer heartbeat
- endpoint update
- re-ICE request
- capability refresh
- observation exchange
- path health report

该通道必须是后置能力：只有数据面已经可用时才能使用，不能承担首次发现和首次穿透。

最小实现边界：

- 不替代首次 coordinator/rendezvous bootstrap。
- 不改变 `transport.PacketTransport` 接口。
- 不把 NAT/ICE 细节塞回 `pkg/session`。
- 先承载 heartbeat/path health/capability refresh，再考虑 re-ICE 或 strategy re-selection。

### P1: 纯 NAT piercing 验证需要候选接口控制

状态：NAT/ICE 配置已支持 candidate interface include/exclude 和 candidate CIDR include/exclude；`wink doctor` 会展示过滤配置，并检查 runtime candidate 是否命中 excluded CIDR。

本次 direct path 中 candidate 可能包含 Tailscale/peer-reflexive 地址或 Docker bridge host 地址。这证明没有使用 `chen-win` TURN relay，但不能证明完全不借助已有 overlay。

当前可用配置：

```yaml
nat:
  candidate_interface_exclude:
    - tailscale0
    - docker0
  candidate_cidr_exclude:
    - 100.64.0.0/10
    - 172.16.0.0/12
```

后续仍需要真实验证：

- 排除 Tailscale、Docker bridge、VPN/TAP 等接口后的双节点 direct path。
- Windows 上按真实接口名配置，例如 `Tailscale`、`vEthernet (WSL)` 或 Docker/Wintun 对应接口。
- `wink doctor` 目前能检查 CIDR 命中；interface 名称无法从已选 candidate 字符串反推，后续如需精确说明来源，需要在 ICE gather 阶段记录 candidate/interface 映射。

### P2: 部署建议

生产 quickstart 中 coordinator 应部署在双方都能稳定访问的公网或固定网络位置，并优先使用持久化 store，例如 `--store-backend sqlite --sqlite-path /var/lib/wink/coordinator.db`。`chen-win` 可以作为 SSH 跳板或临时测试机，但不应作为唯一控制面依赖；否则断开 natpierce 后，peer discovery、heartbeat 和 session signaling 都会失效。测试环境如果使用 memory store，重启 coordinator 会丢失注册表，必须重启或升级两端 client 重新注册后才能继续建链。
