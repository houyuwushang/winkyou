# Protected Direct Multipath

本文定义从 Prompt 43 起的当前开发方向：WinkYou 需要支持质量最优 primary path，同时尽量保持 direct/P2P path 作为 protected standby。它是当前 roadmap 文档，不能替代 [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md) 的 session、solver、strategy 和 transport 边界。

## 目标

当前阶段目标不是把所有节点变成中继，也不是引入新的数据面。目标是：

```text
primary = 当前评分最优 path
direct_like = ICE/TCP 结果不是 TURN relay，但可能仍依赖 overlay/跳板 underlay
protected_direct = 没有 relay/peer/unknown dependency 的 direct/P2P standby path
failover = primary write/read error 或 health stale 后切换到 standby
```

对 tunnel 来说，仍然只看到一个 `transport.PacketTransport`。multipath 的最小实现应放在 tunnel 之上的 wrapper 中：

```text
WireGuard tunnel
  -> one PacketTransport
       -> MultipathPacketTransport
            -> child direct path
            -> child relay_only path
            -> child tcp_framed alpha path
```

这样可以保持 `transport.PacketTransport` 既有接口稳定，也避免把 NAT/ICE 细节塞回 `pkg/session`。

## 为什么仅防止控制面断线拆数据面不够

真实设备验证已经证明：只停止 coordinator 进程且 underlay 不断时，已 bound 的 direct 数据面可以继续工作。这解决的是一个较窄的问题：control-plane 进程不可用时，client 不应误删已经 alive 的 tunnel peer。

但这还不够。实际拓扑中，低延迟 path 可能依赖 coordinator、跳板机、TURN relay 或某个中间节点所在的物理链路。断开这条物理链路时，不只是 control-plane 消息消失，primary path 本身也可能失效。此时如果系统只保留一条当前最优 path，就没有可立即切换的备用路径。

因此，控制面韧性和 multipath 是两个层次：

- control-plane resilience：已经建立的数据面不应因 coordinator/broker 断线被误关。
- protected direct multipath：当前 primary 失效时，direct/P2P standby 应尽量仍可接管数据面。

## 为什么低延迟 path 可能依赖中间链路

连接求解器会选择候选 path。评分最低延迟的 path 不一定是独立的 direct path。它可能依赖：

- TURN relay 或 `relay_only` strategy。
- coordinator 所在机器同时承担的跳板或临时网络。
- 某个 bootstrap/broker 节点所在的 underlay。
- 明确配置的 TCP alpha 地址所在的单点链路。

这些 path 可以成为 primary，因为它们可能确实更快或更稳定。但它们的依赖关系必须被记录和展示，不能因为“当前更低延迟”而完全挤掉 independent direct/P2P path。

## 为什么 direct path 应保持为 protected standby

direct/P2P path 即使不是最低延迟，也有一个关键价值：它通常对 coordinator、relay 或中间节点的持续依赖更少。只要 direct path 已经建立、被 WireGuard 数据面验证过，并且没有命中 relay/peer/unknown dependency，它就应该尽量保留为 protected standby。

需要特别区分 ICE 的 `connection_type=direct` 和 WinkYou 的 `protected_direct`。前者只说明没有走 TURN relay；如果 selected candidate 命中 `100.64.0.0/10`、私网 VPN/TAP、loopback、link-local 或其他依赖不清的地址，它只能作为 direct-like path 记录，不应出现在 `protected_direct_path_id` 中。

当前 `legacy_ice_udp` 会在普通 `legacyice/direct_prefer` 后追加 `legacyice/public_direct`。`public_direct` 排除私网、`100.64.0.0/10`、loopback、link-local、benchmark/overlay 等 candidate，用来主动尝试不依赖现有 overlay 的公网 ICE direct path。它不是新的 strategy 名称，也不改变 `PacketTransport` 边界；它只是 legacy ICE strategy 内部的一个更严格执行计划。

如果 natpierce 能从 A 直接打到 C，这说明该真实网络里可能存在可用的 UDP NAT piercing 路径，但不等于 WinkYou 已经复用了同一组公网 candidate。WinkYou 的证据链必须来自 `legacyice/public_direct`：本地 `candidate_gathered` 至少保留一个公网 direct candidate，远端 `remote_candidates_filtered` 至少保留一个公网 direct candidate，并且最终 selected pair 没有 relay、peer 或 unknown dependency。否则它只能说明当前实现尚未证明独立 A-C direct path，不能说明 A-C 物理上绝对不可达。

这不要求 direct path 永远成为 primary。合理策略是：

- primary 仍由当前评分和运行质量决定。
- 没有明确 dependency 的 direct/P2P 成功 path 被标记为 `protected_direct`。
- primary 写失败、读失败或 health stale 时，优先 fail over 到 protected direct。
- 如果 direct standby 不存在，`wink doctor` 应明确说明当前路径仍依赖中间节点，direct standby unavailable。

## 非目标

本轮不做开放 peer relay，也不把所有虚拟局域网节点默认变成转发节点。

明确非目标：

- 不默认让普通 peer 转发其他 peer 的用户流量。
- 不做任意公网路由器控制。
- 不做未授权路由注入。
- 不做 QUIC、HTTP CONNECT 或 WebSocket transport strategy。
- 不做自研 Wink Protocol 数据面。
- 不改变 `transport.PacketTransport` 的既有接口签名。
- 不为了 multipath 删除或绕过 `legacy_ice_udp`、`relay_only`、`tcp_framed` 既有行为。

未来 A/B/C 间歇 bootstrap 场景中，B 可以帮助 A 和 C 轮流交换 descriptor、capability 或 candidate hint。但 B 的角色应是 bootstrap broker，不是 A-C 数据面的默认持续依赖。

## 最小实现形态

当前阶段的最小可行 multipath 设计如下：

1. `pkg/solver` 描述 path role、path dependency 和 policy。
2. 现有 strategy 在 `PathSummary` 中填充 role/dependency metadata。
3. `pkg/transport/multipath` 提供一个 `PacketTransport` wrapper，内部管理多条 child path。
4. `pkg/session` 在 policy 开启时保留多个 successful outcomes，并把它们组合成一个 multipath transport 传给 binder。
5. `pkg/client` 默认启用保守的 protected direct multipath，最多保留 primary + 一条 standby；需要旧单路径行为时可显式关闭。
6. `wink peers` 和 `wink doctor` 暴露 primary、protected direct、standby、active path 和 failover 状态。
7. runtime JSON 暴露最近 path 的 plan、role、dependency 和 child path 摘要，便于区分 direct-like 与 protected direct。

默认行为必须保持可控：

- multipath 默认开启，但保守限制为 `max_paths=2` 且 `shadow_write=false`。
- protected-direct 模式下，session 不应在第一个 direct 成功后立刻停止候选执行；它应执行预算内候选，让低延迟 relay/其他 path 和 protected direct 同时参与评分。
- legacy ICE 应把 selected pair RTT 暴露为 `rtt_ms` path metric，供 primary 选择使用。
- 显式设置 `connectivity.multipath.enabled: false` 时，session 仍按旧逻辑只绑定 selected result。
- 旧单路径 `PacketTransport` 行为不变。

## 验证方向

真实设备验证的最小目标：

1. primary 可以是 relay 或其他低延迟 path。
2. direct/P2P path 作为 protected standby 出现在 `wink peers --json`。
3. 停掉 coordinator 进程但不动 underlay 时，已 bound 数据面继续。
4. 断开 primary 所依赖的 relay/中间节点链路时，如果 protected direct 仍 alive，应自动 fail over。
5. 如果 direct standby 未建立，`wink doctor` 必须明确说明原因或至少展示 unavailable 状态。

当前真实验证拓扑命名：

- A = 本机 Windows 节点。
- B = `chen-win`，当前可作为 coordinator、跳板或间歇 bootstrap 参与者。
- C = `inner-gw`，远端 Linux 节点。

该拓扑中的关键判断是：B 可以帮助 A/C 完成 bootstrap 或临时信息交换，但 B 不应成为 A-C 用户数据面的默认持续依赖。任何验证凭据都属于本地操作秘密，不能写入仓库文档、配置示例或测试 fixture。

## 开发顺序

先实现 multipath 核心，不先扩展 peer relay 或三节点 broker：

```text
solver path policy
  -> strategy path metadata
  -> transport/multipath wrapper
  -> session retain successful paths
  -> session bind multipath transport
  -> config/client/CLI visibility
  -> failover behavior
  -> direct standby execution guarantee
```

只有 multipath wrapper、session bind、direct standby attempt 和 primary failover 稳定后，才继续推进 intermittent bootstrap broker 或 in-band control 的更大闭环。
