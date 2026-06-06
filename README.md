# WinkYou

WinkYou 是一个正在演进中的 P2P 虚拟局域网项目。当前架构定义是：

```text
WinkYou = connectivity solver + secure WireGuard data plane
```

项目不再以固定 ICE/TURN 流程作为架构中心。ICE、TURN relay、未来的 QUIC/TCP/proxy 路径都应被视为连接求解器可选择的候选路径；真正承载数据的是统一的 `transport.PacketTransport` 边界和 userspace `wireguard-go` 数据平面。

## 当前状态

当前代码已经完成 Phase 3B code health、Phase 4A `relay_only` 冻结，并进入 protected direct multipath、非 UDP PacketTransport alpha 验证和 v0.1 运维闭环。

- 活跃架构权威：[`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- v0.1 freeze gate：[`docs/V0.1-FREEZE.md`](./docs/V0.1-FREEZE.md)
- v0.2 multipath/bootstrap freeze gate：[`docs/V0.2-MULTIPATH-FREEZE.md`](./docs/V0.2-MULTIPATH-FREEZE.md)
- Protected direct multipath 目标：[`docs/MULTIPATH-PROTECTED-DIRECT.md`](./docs/MULTIPATH-PROTECTED-DIRECT.md)
- Phase 2D 已冻结：`phase2d-freeze-2026-04-24`
- Phase 3A strategy portfolio foundation 已落地
- Phase 3B code health 已完成，包括 CI 质量门、session 机械拆分、状态转换校验、resolver 统一、context 边界修复和若干小型清理
- Phase 4A 已新增 `relay_only` strategy
- `tcp_framed` 已作为 alpha strategy 加入，用来验证 framed stream 可以承载 `PacketTransport`
- 当前生产注册顺序保持兼容：`legacy_ice_udp` -> `relay_only`
- `tcp_framed` 默认禁用，只有显式 `tcp_framed.enabled: true` 且加入 `connectivity.strategy_order` 时才会注册
- `connectivity.mode: relay_only` 会把生产 strategy 顺序切到 `relay_only` -> `legacy_ice_udp`
- `connectivity.mode: auto` 下如果本机 NAT 检测为 `symmetric` 且已配置 TURN，生产 resolver 会临时把顺序调为 `relay_only` -> `legacy_ice_udp`，先用 relay 保活，再让 legacy/public-direct 继续尝试独立路径；如果没有 TURN，仍保持 `legacy_ice_udp` 优先，让 `direct_prefer/public_direct` 先尝试打洞
- 旧的 `nat.force_relay: true` 仍兼容映射到 relay-only 行为
- 旧 peer 空 capability 仍会隐式 fallback 到 `legacy_ice_udp`
- `wink doctor` 已提供 config、coordinator、STUN、TURN、本地接口、strategy、routing、tunnel、transport 的分层诊断；strategy 层会显示 production strategy order 和 `legacy_ice_udp` 内部 plan order；STUN 检查会用同一个本地 UDP socket 探测多个 public-direct STUN 来源，显示本机映射地址、提示映射是否稳定，并在可用时给出 `nat.public_endpoint_hints` 候选；`public direct evidence` 检查会读取 observation history，说明 `legacyice/public_direct` 是未尝试、无可用公网候选、候选已交换但 ICE 检查失败，还是已证明 `protected_direct`；`--route-target <ip>` 可以检查访问某个目标 IP 时当前操作系统实际选中的接口/本地地址/下一跳，并在命中 natpierce、Tailscale、Docker 等外部 overlay 接口时给出 warning
- `wink up/down/status/peers/logs` 已形成长期运行 CLI 工作流；Linux systemd 和 Windows 启动项文档已补齐
- v0.1 release workflow 已能构建 Windows client、Linux client、Linux coordinator、Linux relay 和 SHA256SUMS
- NAT/ICE 已支持 candidate interface include/exclude 和 candidate CIDR include/exclude；`legacy_ice_udp` 现在会在普通 `direct_prefer` 后追加 `public_direct` 执行计划，用来排除私网、`100.64.0.0/10`、loopback、link-local 等 overlay/依赖不清的 candidate，并默认避开 natpierce、Tailscale、Docker/vEthernet、Wintun/WinkYou 等外部 overlay/虚拟接口，再尝试独立公网 ICE direct；`wink doctor` 会展示过滤配置并检查 runtime candidate 是否命中排除 CIDR
- `auto` 模式默认启用保守 protected-direct multipath：最多保留 primary + 一条 standby，relay-only/force-relay 仍保持单路径
- 如果已 bound 的 path 不是 `protected_direct`，client 会保留现有数据面并在后台继续尝试保护直连；只有后续结果明确为 `protected_direct` 时，才会替换 tunnel peer 的 transport
- runtime/`wink peers --json` 会暴露最近 path 的 plan、role、dependency 和 child path 摘要；验证真实直连时应以 `last_path_role=protected_direct` 且 `last_path_dependencies` 为空作为证据，而不是只看 `connection_type=direct`
- `wink peers` / `wink peers --json` 会显示 `last_failover_why`，例如 `active_path_rx_silence:<path>`，用于判断断开 natpierce/relay/underlay 后是否真的触发了 multipath failover
- 真实双节点验证已证明 `legacy_ice_udp` direct path 可以建立虚拟局域网；在已 bound 数据面上只停止 chen-win 的 coordinator 进程 15 秒后，`wink ping` 仍成功，说明基础 coordinator outage 已通过。但历史 selected pair 的 remote candidate 曾为 `100.102.17.35`，属于 `100.64.0.0/10`，这只能证明没有走 TURN relay，不能证明该 path 独立于 natpierce/chen-win underlay。client 已加第一层 peer-offline 保护、controlled-side retry、coordinator NotFound 重注册，并已在 runtime/`wink peers` 中暴露 control/data 状态和最近成功 path cache；`pkg/peercontrol` 消息模型已冻结，client 已接入最小 in-band heartbeat/path_health 循环，`re_ice_request` 会触发 protected-direct improvement，`session_signal` 会在已建立虚拟网内冗余发送现有 session/strategy 信令，并会短期重发最近信令、按序列去重，后续仍需覆盖更长时间 heartbeat/signaling failure、完整 ACK/backoff 和 cached path 恢复；详见 [`docs/CONTROL-PLANE-RESILIENCE.md`](./docs/CONTROL-PLANE-RESILIENCE.md)

当文档发生冲突时，以 [`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md) 作为 session、solver、strategy 和 transport 边界的判断依据。部分历史架构文档已标记为 proposal/archive，不能覆盖 active baseline。

## 当前可运行路径

当前可部署的主路径仍是：

- Windows client 使用 TUN/Wintun
- Linux client / peer
- Linux coordinator
- coturn 作为公网部署推荐 TURN relay
- userspace `wireguard-go` 作为安全数据平面
- `PacketTransport` 负责把选中的 packet path 绑定给 tunnel
- rendezvous v2 envelope 负责 capability、observation、probe、path_commit 等 session 消息

当前真实 strategy：

- `legacy_ice_udp`：兼容现有 ICE/UDP 路径，内部支持 `direct_prefer`、`public_direct` 和 `relay_only` execution plan
- `relay_only`：第二个真实 strategy，是 `legacyice` 的 thin wrapper，强制 relay，并对外以 `relay_only` 出现在 capability、observation 和 path_commit 中
- `tcp_framed`：alpha 非 UDP strategy，使用显式可达 TCP 地址和 `transport/framedstream` 适配器，不承诺 NAT TCP 打洞

默认连接策略：

```yaml
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
  multipath:
    enabled: true
    protect_direct: true
    max_paths: 2
    shadow_write: true
    dependency_penalty: 50
    direct_protection_bonus: 100
    active_path_silence_timeout: 15s
```

如果某个 WinkYou peer 还负责转发它后面的后端网段，例如 `inner-gw` 所在的 `10.6.22.0/24` 不是一个直接注册到 coordinator 的 WinkYou 节点，而是 chen-win 后面的虚拟局域网，需要在网关 peer 上显式发布路由：

```yaml
node:
  name: chen-win
  advertise_routes:
    - "10.6.22.0/24"
```

其他 peer 从 coordinator 收到该发布后，会把 `10.6.22.0/24` 加入 chen-win 这个 peer 的 WireGuard `AllowedIPs`，并在本机加一条经由 chen-win 虚拟 IP 的系统路由。这不是默认 peer relay，也不会自动替任何 peer 转发任意网段；只有被显式配置的后端 CIDR 才会发布。网关机器本身仍必须允许 IP forwarding/转发，并放行对应防火墙规则。后端主机还必须能把 WinkYou 虚拟网段回包送回该网关；如果后端网络不能加静态回程路由，就需要在网关上做 SNAT/masquerade。

排查时，`wink peers` 的 `Routes` 行和 `wink peers --json` 的 `advertised_routes` 字段会显示远端 peer 发布的后端网段；`wink doctor` 会在 `routing` 层报告本节点正在发布的路由、已绑定 peer 的远端发布路由，并检查本机操作系统路由表是否已经把远端后端网段指向对应 peer 的 WinkYou 虚拟 IP。配置了 `node.advertise_routes` 的网关 peer 还会检查当前操作系统的 IP forwarding 状态，同时提醒检查后端回程路由或 SNAT。要确认某个具体地址当前是否仍由 natpierce/Tailscale 等外部 overlay 承载，可以运行 `wink --config <config.yaml> doctor --route-target 10.6.22.1`；如果输出接口是 `natpierce`，这只能证明 natpierce overlay 能到达该地址，不能证明 WinkYou 已经独立承载这条路。

默认 `auto` 模式会启用 protected-direct multipath：最多保留 primary + 一条 standby，并默认开启 shadow write，让 standby path 也持续收到数据包，从而维持 NAT/relay 状态。session 会执行预算内候选，而不是在第一个 direct 成功后立刻停止；跨 strategy 场景下也会在 `max_paths` 预算内继续给后续候选一次机会，直到能组成 primary + protected direct standby 或没有剩余候选。legacy ICE 会把 selected pair 的 RTT 写入 path metrics，让低延迟 relay/其他 path 和高延迟 direct 能参与同一轮评分。默认 scoring 会惩罚 relay/依赖路径，并对 `unknown` 依赖加倍惩罚，同时给真正的 `protected_direct` 加保护分。这样当 `legacyice/direct_prefer` 选中了低延迟但依赖不清的 path，而 `legacyice/public_direct` 或后续 direct path 也成功时，client 会把它们组合成一个 `multipath` transport 绑定给 WireGuard；如果没有 RTT 证据，依赖不清的 direct-like path 不应仅因为看起来是 direct 就压过明确可用的 relay。

如果启动时 NAT detection 得到 `symmetric` 且配置了 TURN，`auto` 模式会把 production strategy 顺序临时调成 `relay_only`、`legacy_ice_udp`。这不会设置 `nat.force_relay`，也不会禁用 `legacyice/public_direct`；它只是避免在 endpoint-dependent 映射环境下先把用户流量绑到高失败概率 direct path，后续仍会继续尝试 protected-direct improvement。如果没有 TURN，`relay_only` 本身不可用，生产顺序会保持 `legacy_ice_udp` 在前，继续优先尝试 `direct_prefer/public_direct`。

在没有 TURN 且没有显式 `connectivity.mode: relay_only` / `nat.force_relay: true` 时，`legacy_ice_udp` 内部也不会把 `legacyice/relay_only` plan 插到 `public_direct` 前面；历史 relay success 只会在 relay 真的可用时影响排序。这避免无 TURN 环境先等待一个必然不可用的 relay plan，给 direct/public-direct 打洞留下完整预算。

如果初始绑定只拿到了 relay 或依赖不清的 direct-like path，client 不会把它当作最终状态停止。它会在保持现有 WireGuard 数据面的同时继续调度 protected-direct improvement；尝试失败时关闭临时 transport 并保留旧 path，尝试成功且 path summary 明确为 `protected_direct` 时再替换 tunnel peer 的 transport。需要回退到旧单路径行为时，可以显式设置 `connectivity.multipath.enabled: false`。

显式验证 `tcp_framed` alpha 路径时，需要同时启用 strategy 和配置可达 TCP 地址：

```yaml
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
    - tcp_framed

tcp_framed:
  enabled: true
  listen_addr: "0.0.0.0:0"
  advertise_addr: "203.0.113.10:39000"
  dial_timeout: 5s
```

显式验证 relay-only 路径时，优先使用连接策略入口：

```yaml
connectivity:
  mode: relay_only
  strategy_order:
    - relay_only
    - legacy_ice_udp
  multipath:
    enabled: false
    protect_direct: true
    max_paths: 2
    shadow_write: false

nat:
  turn_servers:
    - url: turn:your-turn.example.com:3478?transport=udp
      username: winkdemo
      password: winkdemo-pass
```

旧配置仍兼容：

```yaml
nat:
  force_relay: true
  turn_servers:
    - url: turn:your-turn.example.com:3478?transport=udp
      username: winkdemo
      password: winkdemo-pass
```

在 relay-only 模式下，如果双方都支持 `relay_only`，生产 resolver 会优先选择 `relay_only`。如果远端是旧 peer 且没有上报 capability，仍会 fallback 到 `legacy_ice_udp`，但 legacy ICE agent 会继续使用 relay-only candidate gathering。

注意：`connectivity.mode: relay_only` 和旧的 `nat.force_relay: true` 是单路径 relay 验证/保底模式，会关闭 protected-direct multipath。要同时保持“relay 或低延迟路径作为 primary + direct/P2P standby”，使用 `connectivity.mode: auto`，并把 `connectivity.strategy_order` 配成 `relay_only`、`legacy_ice_udp`。`wink doctor` 会在 multipath 已开启但 relay-only policy 实际导致单路径时给出 warning。

验证纯 NAT piercing 时，可以排除已有 overlay 或本地虚拟网卡：

```yaml
nat:
  candidate_interface_exclude:
    - tailscale0
    - docker0
  candidate_cidr_exclude:
    - 100.64.0.0/10
    - 172.16.0.0/12
```

Windows 接口名应使用系统实际接口名称，例如 `Tailscale`、`vEthernet (WSL)` 或 Docker/Wintun 对应名称。`wink doctor` 会展示当前过滤配置，并在 runtime candidate 命中排除 CIDR 时报告失败。

`legacyice/public_direct` 默认还会自动跳过 natpierce、Tailscale、Docker、Wintun/WinkYou 等疑似 overlay/虚拟接口，避免把已有外部通道误判成 WinkYou 自己的 protected direct。需要复现“natpierce 能通”的同类路径时，可以显式配置 `nat.candidate_interface_include` 把具体接口加入本轮测试；显式 `candidate_interface_exclude` 仍然优先。这个开关只表示你允许 WinkYou 在该接口上采集候选，不等于已经证明断开 natpierce 后仍可独立保活；若要把非公网地址当作 protected-direct 证据，还必须配合已验证的 `nat.direct_trusted_cidrs`。

同理，`nat.candidate_cidr_include` 现在会让 `legacyice/public_direct` 接受该 CIDR 内的 host/peer-reflexive 候选参与连接尝试，适合受控复现 natpierce 或路由器日志中看到的非公网 underlay。它也允许该 CIDR 内的非公网 `public_endpoint_hints` 和启动时 STUN 观测生成的 runtime endpoint hints 参与尝试，并会与 mapped hint 的本地 base `/32` 合并使用，因此公网 endpoint hint、runtime hint 和受控 underlay CIDR 可以在同一轮 public-direct 尝试中共存。它不会自动把路径标为 `protected_direct`；未进入 `nat.direct_trusted_cidrs` 的非公网候选仍会在 path summary 中保留 dependency。

如果两端有可确认的公网 1:1 映射或固定 UDP 端口映射，可以把公网候选提示交给 ICE agent，减少只依赖默认 STUN 采集的误判：

```yaml
nat:
  candidate_port_min: 40000
  candidate_port_max: 40100
  nat1to1_candidate_type: srflx
  nat1to1_ips:
    - "203.0.113.10/192.168.0.10"
  public_endpoint_hints:
    - "117.48.146.2:41000/192.168.1.20:40000"
  # 默认开启。启动时 STUN 观测到的公网 endpoint 会自动合入
  # legacyice/public_direct 的 public_endpoint_hints。
  auto_public_endpoint_hints: true
  # 默认 2。围绕每个 public endpoint hint 的公网端口追加 ±N 的小窗口候选，
  # 用于复现 natpierce/路由器日志里看到的可预测端口漂移。
  public_endpoint_hint_port_window: 2
  # 仅在确认该非公网 CIDR 是独立可达 underlay 时配置。
  # direct_trusted_cidrs:
  #   - "100.64.0.0/10"
```

`nat1to1_ips` 使用 Pion ICE 的 `external/local` 语义，适合公网 IP 映射和本地 ICE 端口范围稳定的场景。`public_endpoint_hints` 直接表达本机已知的公网 UDP `ip:port`，也可以写成 `公网ip:公网端口/本地ip:本地端口` 绑定到具体本地 UDP base；它只会作为 `legacyice/public_direct` 额外 srflx 候选发布。当 mapped hint 带本地 base 时，`legacyice/public_direct` 会把本次 ICE agent 限制到这些本地 IP；如果只有一个唯一的本地 base 端口，也会精确绑定该端口；如果有多个本地 base 端口，会拆成多个 `public_direct` hint plan，并分别绑定对应端口，避免把已经观测到的多个 UDP 映射混到同一个 ICE socket 里碰运气。`public_endpoint_hint_port_window` 默认是 `2`；`public_direct` 会围绕每个公网 hint 追加相邻公网端口候选，例如 `41000` 和窗口 `2` 会尝试 `41000,40999,41001,40998,41002`。该配置适合拿 natpierce 或路由器日志里的公网端点和可预测端口漂移做验证。普通家宽或运营商 NAT 如果每个 UDP socket 都分配不可预测公网端口，仍应依赖 STUN/peer-reflexive learning，或走 TURN/relay fallback。

`auto_public_endpoint_hints` 默认开启：启动时 NAT detection 会把运行时观测到的公网 endpoint hint 与手工 `public_endpoint_hints` 合并后交给 `legacyice/public_direct`。该检测使用与 public-direct/doctor 一致的 STUN 来源：显式 `nat.stun_servers`，以及 UDP TURN URL 派生出的同 host/port STUN binding 入口，所以只配置 coturn 的自托管部署也能生成 runtime hint。如果检测结果是 `nat_type=symmetric`，这些 endpoint-dependent 映射仍只是 best-effort 候选：同一 UDP socket 到 STUN 服务器的端口不一定等于到 peer 的端口。默认的小窗口端口试探会让 WinkYou 更接近 natpierce 这类持续 punch 行为，但仍必须继续看 `legacyice/public_direct` 是否学到 `peer_reflexive_pair` / `public_direct_learned_pair`，以及最终 path 是否是 `protected_direct`。需要保守排查时，可以显式设为 `auto_public_endpoint_hints: false` 或把 `public_endpoint_hint_port_window` 设为 `0`。

当本轮 `legacyice/public_direct` 已经带有手工或运行时 endpoint hint 时，legacy ICE 会把 `public_direct` 排到普通 `direct_prefer` 前面，让 hint 对应的公网 UDP 打洞先拿到执行窗口；如果历史 observation 显示 relay 更可靠，仍可以先用 relay 保活，但 `public_direct` 会排在 `direct_prefer` 前继续争取 protected-direct standby。

多个 mapped hint 本地端口会拆成多个 public-direct hint 尝试；这些尝试共享 `legacyice/public_direct` 信令家族，并由 session 在同一候选窗口内并发启动，避免像串行重试那样错过短暂 NAT 映射窗口。base `public_direct` 信令会广播给同 family hint executor，精确 `public_direct_hint_N` 信令优先送到对应 executor；任一 hint 成功后会取消同 family 慢 hint 并进入 bind，全部失败时仍继续后续 `relay_only` fallback，避免“多试几个打洞端口”反而跳过保底 relay。

如果另一个打洞工具已经证明某个非公网地址段确实是两端可达的 underlay，例如受控测试中的运营商 CGNAT 段，可以显式配置 `nat.direct_trusted_cidrs`。该字段会让 `legacyice/direct_prefer` 和 `legacyice/public_direct` 在 path dependency 判定中信任这些 CIDR，并让 `public_direct` 接受这些 CIDR 内的候选、手工 mapped hint，以及启动时 STUN 观测生成的 runtime endpoint hint。旧的 `nat.public_direct_trusted_cidrs` 仍兼容，并会与 `direct_trusted_cidrs` 合并使用。默认仍拒绝 `100.64.0.0/10`、私网、loopback、link-local 和 benchmark/overlay 地址。不要把 natpierce、Tailscale、Docker 或其他虚拟 overlay 的接口网段随意加入 trusted CIDR，否则会把依赖不清的 path 误标成 protected direct；只有在你确认该 CIDR 是 WinkYou 自己可直接打到的 underlay，而不是外部 overlay 提供的虚拟路由时才应配置。`wink doctor` 会检查 `direct_trusted_cidrs` 是否命中本机上疑似 natpierce、Tailscale、Docker、Wintun 或 WinkYou 的虚拟接口，并给出 warning。

当 `legacyice/public_direct` 的 STUN gather 超时但本地 UDP candidate 已经建立时，NAT 层会返回已知本地候选，让上层继续追加 `public_endpoint_hints` 并尽快交换候选开始打洞。这不会把私网 host candidate 当作公网候选发布；最终信令里能否出现可用候选，仍由 `public_direct` 的公网过滤规则决定。

如果本轮已经有手工或运行时 `public_endpoint_hints`，`public_direct` 会使用较短的 gather deadline，先拿到本地 socket 并尽快把 hint 发给对端；没有 hint 时仍使用正常 gather timeout 等待 STUN/server-reflexive candidate。

用于排查真实 NAT piercing 时，legacy ICE 会把候选采集和过滤结果写入 observation history。客户端运行状态文件同目录下会生成 `<runtime-state-base>.observations.jsonl`，其中：

- `candidate_gathered`：本端 gather 后准备发布的 candidate 统计。
- `remote_candidates_filtered`：收到远端 offer/answer/candidate 后的过滤统计。
- `candidate_total`、`candidate_kept`、`candidate_rejected`、`candidate_reject_reasons` 可用于判断是没有采到公网候选、候选被 `public_direct` 规则过滤，还是候选保留下来后 ICE 连通检查失败。`candidate_kept_samples` 会保留少量候选样本；带 local base 的 hint 会显示为 `srflx:公网ip:端口<-本地ip:端口`，便于和 natpierce 或路由器日志对比。
- `candidate_failed`：`public_direct` 失败时会附带最近一次 `last_local_candidate_*` / `last_remote_candidate_*` 摘要、`public_endpoint_hint_count` 和 `ice_state`，便于直接判断是本端没有发布有效候选、远端候选被过滤，还是 ICE checks 已经进入 checking 但没选中路径。

`wink doctor` 也会对 public-direct 的有效 STUN 来源做 binding probe：包括 `nat.stun_servers`，以及从 UDP TURN URL 派生出的同 host/port STUN binding URL。该检查会复用同一个本地 UDP socket 探测多个来源，并输出 `nat_type` 和每个来源看到的 mapped endpoint；如果显示 `nat_type=symmetric`，说明同一 socket 到不同 STUN 目的地的公网映射不一致，`public_direct` 可能需要稳定 `public_endpoint_hints`、更强 rendezvous/punch 机制，或继续使用 TURN/`relay_only` fallback。自托管场景中，只配置 coturn 也能用同一个 UDP 入口检查 srflx 映射，但 `public_direct` 不会使用 TURN relay candidate。如果 STUN probe 已经失败，`legacyice/public_direct` 很可能无法采集到 server-reflexive candidate。如果 doctor 显示 `candidate_kept=0`，则按本端 gather 或远端过滤结果继续排查。此时应先换成两端都可达的 STUN/UDP TURN 服务、检查 UDP 出站和防火墙，或改用 TURN/`relay_only`。

从当前版本起，`legacy_ice_udp` 在没有 endpoint hint 时默认会按顺序尝试：

1. `legacyice/direct_prefer`：保留 ICE 默认行为，可能选中 NAT/overlay/100.64 direct-like path。
2. `legacyice/public_direct`：只采集 host/server-reflexive direct candidate，跳过 TURN/relay 采集；UDP TURN URL 会被当作同 host/port 的 STUN binding URL 使用，以便只配置 coturn 的自托管部署也能采集 srflx candidate。信令里只发布公网 direct 候选，并过滤远端私网、`100.64.0.0/10`、loopback、link-local、benchmark/overlay 等 candidate。该 plan 默认不在 natpierce、Tailscale、Docker/vEthernet、Wintun/WinkYou 等疑似外部 overlay/虚拟接口上 gather candidate，避免把外部 overlay 路径误证明为 WinkYou 自己的 protected direct。该 plan 会使用更积极的 ICE check interval、按 `nat.connect_timeout` 放大的 binding request 预算，以及更短的 srflx/prflx 接受等待，在同一个 public-direct socket 上持续打洞，以更接近 natpierce 这类持续 punch 的行为；session 的 candidate execution budget 会按每个 plan 的 execution timeout 和候选数量扩展，避免 `direct_prefer` 耗时后跳过 `public_direct` 或后续 relay fallback；当 ICE 过程中收到远端 STUN Binding Request 并形成公网 peer-reflexive 候选对时，public_direct 只会在本地为公网或 RFC1918 NAT base、远端为公网时切换到该候选对，不会因本地或远端 `100.64.0.0/10`、overlay、relay、loopback、link-local 或 benchmark 地址触发切换。
3. `legacyice/relay_only`：强制 TURN relay fallback。

如果 `nat.auto_public_endpoint_hints` 或手工 `nat.public_endpoint_hints` 为本轮提供了公网 endpoint hint，`public_direct` 会排到 `direct_prefer` 前面，避免普通 direct-like ICE 先耗尽候选执行窗口。这样 WinkYou 会主动尝试类似 natpierce 能打通的公网 UDP NAT piercing 路径；如果 natpierce 在同一对设备间已经能直接打通，本项目不应把 WinkYou 的失败解释为“物理不可达”，而应继续看公网候选是否采集、是否被过滤、ICE 检查是否超时以及 selected pair 是否仍落在 overlay/100.64 路径上。但如果双方 NAT 类型、运营商映射或防火墙不允许，`public_direct` 仍会失败并继续走后续 fallback。
历史 observation 如果显示 direct 失败且 relay 成功，legacy ICE 可以把 relay 排到更前面作为 primary 候选，但不会再因为普通 `direct_prefer` 失败而完全剪掉 `public_direct`。这保证 relay/overlay 能先保活的同时，仍给独立公网 direct standby 留一次执行机会。
当 overlay/100.64 direct-like path 和 `public_direct` 都成功且基础分相同，solver 会优先选择无显式依赖的 protected direct，避免继续被先出现的 overlay path 抢占。
`public_direct` 的 protected direct 判定只允许本地 RFC1918 host candidate 在匹配本次已发布公网 STUN/srflx candidate 的 related/base 地址时作为 NAT base；远端 candidate 仍必须是公网，且本地或远端 `100.64.0.0/10`、loopback、link-local、198.18/15 等地址仍会被视为依赖不清。
真实排查时，`wink doctor` 的 `public direct evidence` 会显示 `remote_candidate_kind`、`peer_reflexive_pair` 和 `public_direct_learned_pair`。其中 `remote_candidate_kind=prflx` 或 `public_direct_learned_pair=true` 表示 ICE 过程中确实学到了 peer-reflexive 候选对，更接近 natpierce 这类运行中打洞成功的证据；但仍需同时满足 `path_role=protected_direct` 且没有 `path_dependencies`，才算证明了独立公网 direct standby。

尚未完成：

- no-admin mode
- proxy/userspace-only 产品路径
- QUIC datagram、HTTP CONNECT、WebSocket 等真实 transport strategy
- 自研 Wink Protocol 数据平面
- `tcp_framed` 仍是 alpha，不做 NAT TCP 打洞承诺
- 高级 learning/scoring 闭环
- protected direct multipath：v0.2 freeze gate 已定义；代码已支持初始多路径绑定和 bound 后 protected-direct improvement，后续重点是真实设备报告、保护直连成功后的 failover 边界收敛，见 [`docs/V0.2-MULTIPATH-FREEZE.md`](./docs/V0.2-MULTIPATH-FREEZE.md)
- coordinator 断线后保持已 bound 数据面的完整控制面韧性：基础 kill-coordinator 验证已通过；peer-offline 误清理、controlled-side retry、coordinator NotFound 重注册和 runtime control/data/path cache 已先修；更长时间 heartbeat/signaling failure、cached path 恢复仍待完成
- 已建立虚拟网后的 in-band peer control channel 已接入最小 heartbeat/path_health、re-ICE request、session_signal 运行时循环，以及 session_signal 短期重发/去重；后续仍需更长时间真实设备验证、ACK/backoff 和恢复策略收敛
- 真实环境下 `legacyice/public_direct` 排除 Tailscale、Docker bridge、其他 VPN/TAP 后的双端公网 NAT piercing 验证
- GUI、移动端、原生 Windows service

## 架构边界

- `pkg/session` 负责 session 生命周期、状态机、capability 交换、rendezvous envelope、probe/observation 消息和 binder 协调；不要把 NAT/ICE 细节重新引入这里。
- `pkg/solver` 保持 strategy-agnostic，只处理通用 `Strategy`、`Plan`、`Result`、observation 和 plan ordering/refinement 输入。
- `pkg/transport` 提供稳定的 `PacketTransport` 边界；当前不要把它改成新的 V2 接口。
- `pkg/tunnel` 使用 `wireguard-go` 和 `PacketTransport` 消费 packet 数据，不拥有路径求解逻辑。
- strategy 专属逻辑放在 `pkg/solver/strategy/*` 或 client 组装边界中。

## 目录导览

- [`pkg/session`](./pkg/session)：session lifecycle、state machine、strategy selection、planning、probe、observation、envelope 和 binder 协调
- [`pkg/client`](./pkg/client)：客户端 engine、生产 resolver 组装、peer session 和运行时状态
- [`pkg/solver`](./pkg/solver)：连接求解器核心抽象
- [`pkg/solver/strategy/legacyice`](./pkg/solver/strategy/legacyice)：当前 ICE/UDP 兼容 strategy
- [`pkg/solver/strategy/relayonly`](./pkg/solver/strategy/relayonly)：relay-only strategy
- [`pkg/transport`](./pkg/transport)：packet transport 抽象及适配器
- [`pkg/tunnel`](./pkg/tunnel)：userspace WireGuard 数据平面和 per-peer transport bind
- [`pkg/rendezvous`](./pkg/rendezvous)：coordinator-backed rendezvous 通道与 v2 envelope 类型
- [`pkg/probe`](./pkg/probe)：probe model/lab
- [`deploy/quickstart`](./deploy/quickstart)：快速部署素材
- [`deploy/coturn`](./deploy/coturn)：TURN relay 部署素材
- [`docs/SELFHOST-QUICKSTART.md`](./docs/SELFHOST-QUICKSTART.md)：自托管快速部署
- [`docs/LONG-RUNNING-CLIENT.md`](./docs/LONG-RUNNING-CLIENT.md)：长期运行客户端、日志和 service/startup 工作流
- [`docs/CONTROL-PLANE-RESILIENCE.md`](./docs/CONTROL-PLANE-RESILIENCE.md)：真实部署中暴露的控制面断线、P2P 保持和候选接口过滤 TODO
- [`docs/MULTIPATH-PROTECTED-DIRECT.md`](./docs/MULTIPATH-PROTECTED-DIRECT.md)：protected direct multipath 当前阶段目标
- [`docs/INBAND-PEER-CONTROL.md`](./docs/INBAND-PEER-CONTROL.md)：已建立数据面后的 peer control 消息模型和边界
- [`docs/TROUBLESHOOTING.md`](./docs/TROUBLESHOOTING.md)：分层排障指南
- [`docs/RELEASE.md`](./docs/RELEASE.md)：release 构建、校验和发布流程
- [`docs/V0.1-FREEZE.md`](./docs/V0.1-FREEZE.md)：v0.1 Alpha freeze gate 与验收边界
- [`docs/V0.2-MULTIPATH-FREEZE.md`](./docs/V0.2-MULTIPATH-FREEZE.md)：v0.2 multipath/bootstrap freeze gate
- [`docs/README.md`](./docs/README.md)：文档分级索引

## 常用命令

客户端运维入口：

```bash
wink --config <config.yaml> up
wink --config <config.yaml> down
wink --config <config.yaml> status
wink --config <config.yaml> peers
wink --config <config.yaml> logs
wink --config <config.yaml> doctor
```

开发和回归入口：

```bash
go fmt ./...
go vet ./...
go test ./... -count=1
go test -race ./pkg/session ./pkg/client ./pkg/solver/... -count=1
```

Makefile 中也提供了等价入口：

```bash
make check
make test-race
make test-phase2d
make test-phase3a
make test-phase4a
make build-all
```

Windows 本机跑 race test 需要可用的 cgo/GCC 环境。可以使用 MSYS2、MinGW-w64、w64devkit 或等价工具链，并在当前 shell 中临时启用：

```powershell
$env:PATH='<gcc-bin-dir>;' + $env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
go test -race ./pkg/session ./pkg/client ./pkg/solver/... -count=1
```

## 构建

```bash
make build-wink
make build-wink-coordinator
make build-wink-relay
make build-all
```

跨平台构建入口：

```bash
make build-windows-client
make build-linux-client
make build-linux-coordinator
make build-linux-relay
```

构建产物输出到 `bin/`。根目录下的 `wink.exe`、`netprobe.exe`、`e2e.test` 当前不应作为源码树的一部分跟踪。

## Relay 握手排障

当预期走 relay 时，先使用 `wink peers` 或 `wink peers --json`。CLI 会展示从 ICE 选择、transport attach 到 WireGuard handshake 的链路状态。

示例：

```text
Peer 1
  Name:        beta
  Node ID:     node-000002
  Virtual IP:  10.77.0.2
  Public Key:  BRWDltpykmj7xkz5mscwH82XtleebmfOtYvvaIxIRVQ=
  State:       connected
  Endpoint:    127.0.0.1:65042
  Conn Type:   relay
  ICE State:   connected
  Local Cand:  relay:127.0.0.1:65040
  Remote Cand: relay:127.0.0.1:65042
  Tx:          1.2 KiB
  Rx:          304 B
  Xport Tx:    13 pkts / 1.2 KiB
  Xport Rx:    4 pkts / 304 B
  Xport Err:   -
  Handshake:   2026-04-22T16:04:34Z
  Last Seen:   2026-04-22T16:04:34Z
```

排查顺序：

- `ICE State` 不是 `connected` 或 `completed`：问题仍在 ICE/TURN 或 candidate exchange。
- `Local Cand` / `Remote Cand` 未出现 `relay`：没有选中 relay path，或 relay candidate 没有成功 gather。
- candidate 显示 relay，但 `Xport Tx` / `Xport Rx` 始终为 `0`：ICE transport 已选中，但 `PacketTransport` 未 attach 或未保持存活。
- `Xport Tx` / `Xport Rx` 增长且 `Xport Err` 非空：transport/bind 读写失败。
- `Xport Tx` / `Xport Rx` 增长但 `Handshake` 仍为 `-`：relay packet 在流动，但 WireGuard 握手没有完成。
- `Handshake` 非 `-` 但业务流量失败：检查 `AllowedIPs`、路由、防火墙和 MTU。

## 文档定位

- Active baseline：[`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- 文档索引：[`docs/README.md`](./docs/README.md)
- Phase 2D freeze gate：[`docs/PHASE2D-FREEZE.md`](./docs/PHASE2D-FREEZE.md)
- Phase 3A entry：[`docs/PHASE3A-STRATEGY-PORTFOLIO.md`](./docs/PHASE3A-STRATEGY-PORTFOLIO.md)
- Phase 3B+ working plan：[`implementation_plan.md`](./implementation_plan.md)
- legacy execution baseline notice：[`docs/EXECUTION-BASELINE.md`](./docs/EXECUTION-BASELINE.md)

历史 ICE/TURN-centric baseline 保留在 tag `legacy-ice-turn-baseline-2026-04-15`，仅用于回溯和 rollback 分析。当前代码应按 connectivity solver baseline 评估。
