# WinkYou 排障指南

本文按连接链路分层排查。当前可用命令主要是 `wink status`、`wink peers`、`wink logs`、`wink doctor`、client 日志、coordinator 日志和 coturn 日志。

## 1. Config

检查配置是否能加载：

```bash
wink --config node-a.yaml status
```

常见问题：

- `invalid coordinator.url`：确认使用 `grpc://host:50051`
- `invalid connectivity.strategy_order`：只使用当前实现的 strategy 名称，例如 `legacy_ice_udp`、`relay_only`、`tcp_framed`
- `connectivity.multipath.max_paths must be greater than zero`：默认 multipath 已启用，因此 `max_paths` 必须至少为 `1`；真实 protected direct 验证建议使用 `2`
- WireGuard 私钥错误：重新运行 `wink genkey`，把 private key 写入 `wireguard.private_key`

## 2. Coordinator

服务器侧：

```bash
docker compose --env-file deploy/quickstart/.env -f deploy/quickstart/docker-compose.yml logs coordinator
```

client 侧：

```bash
wink --config node-a.yaml status
```

常见问题：

- 连接失败：确认 TCP `50051` 已开放
- auth 失败：确认 client 的 `coordinator.auth_key` 和 `WINK_AUTH_KEY` 一致
- 看不到 peer：两台 client 必须连接同一个 coordinator，且 `wink up` 进程仍在运行
- 已经 `State: connected` 后断开 coordinator 所在网络，peer 随后断开：先确认你断开的是否只是 coordinator 进程，而不是 natpierce/跳板/underlay 网络。当前 client 已有第一层 peer-offline 保护和 bound 后 protected-direct improvement，但如果已选 path 本身依赖 natpierce，断开 natpierce 仍会拆掉实际数据路径。详见 [`CONTROL-PLANE-RESILIENCE.md`](./CONTROL-PLANE-RESILIENCE.md)。

部署建议：

- coordinator 应部署在双方都能稳定访问的位置，例如公网服务器或固定内网节点。
- 不要把唯一 coordinator 放在临时跳板链路后面；否则断开跳板/natpierce 后，心跳、peer discovery 和 session signaling 都会失效。
- 已建立数据面未来应能容忍 coordinator 短暂不可达。当前已修 peer offline update 导致的第一层误清理风险，并支持 bound 后继续尝试 protected direct；但 heartbeat/signaling failure 的长时间验证和 cached path 恢复仍需继续收敛。
- 如果要单独验证 coordinator outage，不要断开 natpierce/跳板网络；应保持 underlay 不动，只停止 coordinator 进程，再观察 `wink peers`、WireGuard handshake 和双向 ping。断开 natpierce 会同时改变控制面和可能的数据面候选路径，不能单独证明 coordinator 问题。

## 3. STUN/TURN

服务器侧：

```bash
docker compose --env-file deploy/quickstart/.env -f deploy/quickstart/docker-compose.yml logs coturn
```

防火墙必须允许：

```text
UDP 3478
UDP 49152-65535
```

常见问题：

- `Conn Type: relay` 但没有 WireGuard handshake：通常是 relay 端口范围没放通
- TURN 认证失败：确认 `nat.turn_servers.username/password` 和 compose `.env` 一致
- coturn external-ip 错误：确认 `WINK_PUBLIC_IP` 是服务器公网 IPv4，不是内网地址

## 4. TUN/Wintun

Windows：

- 用管理员权限运行终端
- 确认 Wintun/TUN backend 可用
- 如果是手动下载的 Wintun，建议把 `wintun.dll` 放在 `wink.exe` 同目录或部署脚本明确复制到运行目录；本地验证环境曾使用 `D:\deployment\winkyou\bin\wintun.dll`
- 如果创建接口失败，先重启终端或系统，再确认安全软件没有拦截虚拟网卡

Linux：

```bash
ls -l /dev/net/tun
sudo modprobe tun
```

如果非 root 运行，需要给二进制配置网络 capability，或先用 root 验证 quickstart。

## 5. WireGuard Handshake

查看 peer：

```bash
wink --config node-a.yaml peers
```

关注字段：

```text
State
Conn Type
Endpoint
Handshake
Xport Tx / Xport Rx
Xport Err
```

判断：

- `Handshake: -` 且 `Conn Type: relay`：优先排查 coturn relay 端口范围
- `Xport Tx` 增长但 `Xport Rx` 不增长：对端 client 可能未运行或 relay 回包失败
- `State: connected` 但 ping 不通：检查双方虚拟 IP、系统防火墙和 ICMP 策略
- 如果 `State: connected` 且 `Conn Type: direct`，但候选地址显示为 `100.64.0.0/10`、Tailscale、Docker bridge、其他 VPN/TAP 地址，这只能证明当前 path 不是 TURN relay；不能证明完全不借助已有 overlay。当前代码会把这类 direct-like path 标为带 dependency 的普通路径，不再把它暴露为 `protected_direct_path_id`。纯 NAT piercing 验证应优先查看 `legacyice/public_direct` 是否成功；它会排除私网、`100.64.0.0/10`、loopback、link-local、benchmark/overlay 等 candidate。如果该 plan 失败，说明当前环境下 WinkYou 尚未证明独立公网 direct path。
- 真实 protected direct 的证据应来自 `wink peers --json`：`last_path_role` 为 `protected_direct`、`last_path_dependencies` 为空；如果启用了 multipath，还应看到非空 `protected_direct_path_id`。如果 `last_path_dependencies` 包含 `unknown:remote_cgnat_or_overlay_candidate` 或类似值，说明当前 path 仍可能依赖 natpierce、VPN/TAP 或跳板 underlay。
- 如果当前已经 connected/bound，但没有 `protected_direct_path_id`，新版 client 会保留现有 path 并在后台继续尝试 protected direct。尝试失败只会关闭临时 transport，不应打断原 path；只有后续结果明确为 `protected_direct` 时才会替换 tunnel peer transport。
当前可用过滤配置：

```yaml
nat:
  candidate_interface_exclude:
    - tailscale0
    - docker0
  candidate_cidr_exclude:
    - 100.64.0.0/10
    - 172.16.0.0/12
```

Windows 需要按真实接口名配置，例如 `Tailscale`、`vEthernet (WSL)` 或 Docker/Wintun 对应接口。过滤后重新启动两端 `wink up`，再用 `wink peers` 和 `wink doctor` 检查 selected candidate。

如果 natpierce 或路由器日志能证明两端存在稳定公网映射，可以显式配置 ICE 公网候选提示：

```yaml
nat:
  candidate_port_min: 40000
  candidate_port_max: 40100
  nat1to1_candidate_type: srflx
  nat1to1_ips:
    - "203.0.113.10/192.168.0.10"
  public_endpoint_hints:
    - "117.48.146.2:41000/192.168.1.20:40000"
```

这只适用于公网 IP/端口映射相对可预测的场景。`nat1to1_ips` 表示公网 IP 映射，`public_endpoint_hints` 表示本机已知的公网 UDP `ip:port`，也可以写成 `公网ip:公网端口/本地ip:本地端口` 绑定到具体本地 UDP base；它只会作为 `legacyice/public_direct` 的额外 srflx 候选发布。当 mapped hint 带本地 base 时，`legacyice/public_direct` 会让本次 ICE agent 只在这些本地 IP 上 gather；如果只有一个唯一的本地 base 端口，会在该本地 `ip:port` 上使用固定 UDP mux，让 host candidate 和 STUN/server-reflexive candidate 共用同一个 socket，从而让公网 hint 指向 WinkYou 实际用于打洞的 socket。若运营商 NAT 会为每个 UDP socket 动态改写端口，过期的 `public_endpoint_hints` 不能保证复现 natpierce 的成功路径；默认配置 `nat.public_endpoint_hint_port_window: 2` 会围绕已观测端口追加小窗口候选，生产启动检测到 symmetric NAT，或 NAT 类型因只有一个 STUN 来源成功而仍为 `unknown` 但本轮已有 endpoint hint 时，会把有效窗口提高到 `16`，再查看 `legacyice/public_direct` 是否采集到了 server-reflexive/peer-reflexive candidate，或使用 TURN/`relay_only` fallback。

如果 natpierce 或路由器日志证明两端使用的是一个非公网但确实可达的 underlay 地址段，可以在两端显式加入 `nat.direct_trusted_cidrs`，例如 `100.64.0.0/10`。这会让 `legacyice/direct_prefer` 和 `legacyice/public_direct` 在 path dependency 判定中信任该 CIDR；`public_direct` 也会接受该 CIDR 内的候选、手工 mapped hint、启动 STUN 观测生成的 runtime endpoint hint，并允许 ICE 过程中学到的 peer-reflexive pair 切换到该地址段。旧的 `nat.public_direct_trusted_cidrs` 仍兼容，并会与 `direct_trusted_cidrs` 合并使用。不要把虚拟 overlay、Tailscale、Docker、Wintun peer 网段或只是“看起来能 ping”的跳板地址加入 trusted CIDR；否则 `protected_direct` 证据会失真。默认配置仍会拒绝这些地址段。`wink doctor` 会检查 `direct_trusted_cidrs` 是否命中本机疑似虚拟/overlay 接口；如果看到 `nat/direct trusted cidrs` warning，先移除该 trust 配置或改成真实 underlay CIDR。

如果要用 WinkYou 受控复现 natpierce 已证明可达的同一接口，除了 `direct_trusted_cidrs` 之外，还可能需要显式配置 `nat.candidate_interface_include`。`legacyice/public_direct` 默认会自动排除 natpierce、Tailscale、Docker、Wintun/WinkYou 等疑似 overlay/虚拟接口；显式 include 会覆盖这层自动排除，但 `candidate_interface_exclude` 仍然优先。这只能说明 WinkYou 被允许在该接口上尝试候选，不能证明断开 natpierce 后数据面仍独立可用。

如果已知可达的是一个非公网网段，但你还不确定它是否可以作为独立 protected-direct 证据，可以先把该网段放进 `nat.candidate_cidr_include`。这会让 `legacyice/public_direct` 接受该 CIDR 内的 host/peer-reflexive 候选参与 ICE checks；如果同时存在 mapped `public_endpoint_hints`，hint 的本地 base `/32` 会和这个 include 列表合并，不会覆盖你显式加入的 underlay CIDR。你也可以把已观测到的非公网 `public_endpoint_hints` 与对应 CIDR include 一起用于受控复现。最终 path summary 仍会保留 private/CGN/overlay dependency。只有把同一 CIDR 放进 `nat.direct_trusted_cidrs`，才会把该依赖清掉。

先运行 `wink --config <config.yaml> doctor` 看 `stun` 检查。doctor 和生产启动时的 runtime endpoint hint 检测都会使用 public-direct 的有效 STUN 来源：显式 `nat.stun_servers`，以及从 UDP TURN URL 派生出的同 host/port STUN binding URL。doctor 会复用同一个本地 UDP socket 探测多个来源，并输出 `nat_type` 与每个 mapped endpoint。如果显示 `nat_type=symmetric`，说明同一 socket 到不同 STUN 目的地的公网映射不一致；如果只有一个来源成功而显示 `nat_type=unknown`，只能说明证据不足以证明映射稳定。`legacyice/public_direct` 可能需要稳定 `public_endpoint_hints`、更强 rendezvous/punch 机制，或继续使用 TURN/`relay_only` fallback。生产 `auto` 模式在检测到本机 `nat_type=symmetric` 且配置了 TURN 后会优先尝试 `relay_only` 保活，再保留 `legacy_ice_udp`/`public_direct` 作为后续 fallback/improvement；这不会等同于 `nat.force_relay=true`。如果没有 TURN，`relay_only` 不是有效保底路径，生产顺序会保持 `legacy_ice_udp` 优先，继续先尝试 direct/public-direct 打洞。如果 STUN probe 失败，说明当前 STUN/UDP TURN 入口没能返回公网映射地址，`legacyice/public_direct` 大概率没有足够的公网候选可用。此时优先换成两端都可访问的 STUN/UDP TURN 服务，确认 UDP 出站没有被拦截；如果无法保证公网 UDP NAT piercing，就使用 TURN/`relay_only` 作为保活路径。

当 STUN 映射看起来稳定时，doctor 会在 suggestion 中给出 `nat.public_endpoint_hints=[...]` 候选；如果能推断本机真实出口地址，会写成 `公网ip:公网端口/本地ip:本地端口`。如果显示 `nat_type=symmetric`，doctor 会把这些端点标成 `public_endpoint_hint_candidates` 供对比 natpierce；默认配置会把它们作为 best-effort 候选交给 `legacyice/public_direct`，但不能把它们视为已证明稳定。实际使用前，应确认该公网端点和 natpierce 或路由器日志里的可用路径一致，并且本地 base IP 是物理/underlay 出口而不是 natpierce、Tailscale、Docker 或 Wintun 虚拟接口。

生产 client 默认会自动复用 STUN 观测并尝试很小的端口漂移窗口：

```yaml
nat:
  auto_public_endpoint_hints: true
  public_endpoint_hint_port_window: 2
```

如果 doctor 显示 `nat_type=symmetric`，或只有一个 STUN 来源成功导致 `nat_type=unknown`，这些映射仍只是 best-effort：这不是说 natpierce 的直连不可能，而是说明 WinkYou 不能把“到 STUN 服务器的映射”直接当成“到 inner-gw peer 的映射”。生产配置会在有 endpoint hint 时自动扩大有效端口窗口，覆盖更多可预测端口漂移；这种情况继续看 `legacyice/public_direct` 是否学到 `peer_reflexive_pair` / `public_direct_learned_pair`，或手工配置已确认稳定的 natpierce/路由器端点。需要保守复现时，可以设为 `auto_public_endpoint_hints: false` 或 `public_endpoint_hint_port_window: 0`。

无 TURN 的 `auto` 模式还会禁用 `legacy_ice_udp` 内部的 `legacyice/relay_only` plan。这样即使 observation history 里有旧的 relay success，当前会话也不会先等待不可用的 relay plan，而是把预算留给 `direct_prefer` 和 `public_direct`。显式 `connectivity.mode: relay_only` 或 `nat.force_relay: true` 仍会保留 relay-only 行为，用于检查 TURN 配置或强制 relay。

`wink doctor` 的 `strategy/legacy plans` 检查会直接显示当前 legacy 内部执行顺序。无 TURN auto 模式如果没有 endpoint hint，应看到 `legacyice/direct_prefer -> legacyice/public_direct (relay plan disabled: no TURN configured)`；如果启动时 STUN 或手工配置提供了 `public_endpoint_hints`，应看到 `legacyice/public_direct -> legacyice/direct_prefer`。如果看到 `legacyice/relay_only` 排在里面，说明当前配置已经启用了 TURN 或显式 relay-only/force-relay。

`wink doctor` 还会检查 mapped `public_endpoint_hints` 的本地 base IP 是否存在于本机接口上。如果这里出现 `public endpoint hint local base` warning，说明 hint 的本地部分很可能写成了虚拟局域网 peer 地址、旧地址或另一台机器的地址；`legacyice/public_direct` 会按这个 base 限制本地 gather，因此必须改成本机真实出口网卡 IP。

没有 endpoint hint 时，默认 `legacy_ice_udp` 内部执行顺序为：

```text
legacyice/direct_prefer -> legacyice/public_direct -> legacyice/relay_only
```

`direct_prefer` 可能选中 natpierce、Tailscale、Docker bridge 或其他 overlay candidate；`public_direct` 会跳过 TURN/relay candidate gathering，只采 host/server-reflexive direct candidate，才是用于验证双方是否能通过公网 UDP NAT piercing 形成独立 direct path 的 plan。为避免把外部 overlay 误证明成 WinkYou 自己的 protected direct，`public_direct` 默认会排除 natpierce、Tailscale、ZeroTier、Docker/vEthernet、Wintun/WinkYou 等疑似 overlay/虚拟接口；显式 `nat.candidate_interface_include` 可以把指定接口纳入受控测试。`public_direct` 会用更短 ICE check interval、按 `nat.connect_timeout` 放大的 binding request 预算、更短 srflx/prflx 接受等待，并确保 ICE failed-check timeout 不短于 `nat.connect_timeout`，在同一 public-direct socket 上持续打洞到连接超时；session 的 candidate execution budget 会按每个候选的 execution timeout 扩展，避免前面的 plan 耗时后跳过 `public_direct` 或 relay fallback。如果仍失败，优先比较两端 STUN 映射、候选过滤和 natpierce 实际使用的公网端点。

当 `nat.auto_public_endpoint_hints` 或手工 `nat.public_endpoint_hints` 为本轮提供了公网 endpoint hint，legacy ICE 会优先执行 `legacyice/public_direct`。这是为了把 natpierce/路由器日志或 STUN 观测到的 UDP 映射尽早用于双方打洞；如果先跑普通 `direct_prefer`，映射可能在 `public_direct` 开始前已经过期。当前 client 会在创建 peer session 前，以及 relay/依赖路径已 bound 后发起 protected-direct improvement 前，用短超时刷新 runtime STUN endpoint hint；刷新失败时保留旧 hint，不会因为一次 STUN 失败把已有线索清空。

如果 public-direct STUN gather 超时，但 Pion agent 已经准备好本地 UDP candidate，WinkYou 会继续返回这批本地候选，让 `public_endpoint_hints` 能尽快追加进 offer/answer 并开始 ICE checks。这个行为只解决“慢 STUN 卡住候选交换”的问题；如果 hint 过期、两端 NAT 映射和 natpierce 使用的 socket/端口行为不一致，或远端公网候选被过滤，仍会失败并进入后续 fallback。若 hint 已写成 `公网ip:公网端口/本地ip:本地端口` 且本轮只有一个本地 base 端口，WinkYou 会让 host 和 srflx candidate 共用固定 UDP mux；如果仍失败，问题更可能在对端端点、端口漂移窗口、防火墙或 NAT 对 peer 目的地的映射差异。

如果本轮已经有手工或运行时 `public_endpoint_hints`，`public_direct` 会用较短的 gather deadline 尽快进入候选交换，`candidate_gathered` details 会出现 `public_endpoint_hint_fast_gather=true` 和 `gather_timeout_ms=1000`。如果没有这些字段，说明本轮并没有带 endpoint hint，或者二进制不是最新版本。

如果 observation history 中已有 direct 失败和 relay 成功，legacy ICE 可以把 `relay_only` 排到前面，但 `public_direct` 不应仅因为 `direct_prefer` 失败而被剪掉。排障时如果只看到 `legacyice/relay_only`，没有看到 `legacyice/public_direct` 的 `candidate_planned` 或 `candidate_started`，应检查当前二进制是否为最新版本，或是否处于显式 `connectivity.mode: relay_only` / `nat.force_relay: true`。

当前 session 会按 strategy message 顶层 `plan_id` 缓存未来 plan 的消息。如果两端推进速度不一致，`legacyice/public_direct` 的 offer/answer 不应再被仍在执行 `legacyice/direct_prefer` 的 executor 吞掉。若仍看不到 `public_direct` 的 candidate 事件，优先确认两端二进制都已更新。

如果 natpierce 能从本机直达 `inner-gw`，但 WinkYou 不能建立 `protected_direct`，不要先判断为“物理不可达”。先运行：

```powershell
wink --config <config.yaml> doctor
```

查看 `public direct evidence` 检查。它会读取 observation history，直接提示 `legacyice/public_direct` 是没有记录、远端候选为 0、本端候选为 0、ICE 检查失败，还是已经选中/提交了 protected direct。若 ICE 检查失败但本端和远端都保留了 public-direct 候选，doctor 会把 `local_gather(...)` 和 `remote_filter(...)` 候选数量/样本合并到失败消息里，便于和 natpierce 实际公网端点对比。客户端运行状态文件同目录下也会有 `<runtime-state-base>.observations.jsonl`，需要手工核对时可在 Windows 上用：

```powershell
Get-Content <runtime-state-base>.observations.jsonl |
  Select-String 'candidate_gathered|remote_candidates_filtered|candidate_failed'
```

重点看 `PlanID=legacyice/public_direct` 或 details 中 `mode=public_direct` 的记录：

- `candidate_gathered` 的 `candidate_total>0` 但 `candidate_kept=0`：本端 gather 到的 direct candidate 全部被 public-direct 规则排除，常见原因是只采到了私网、`100.64.0.0/10` 或 overlay candidate。该 plan 会失败并继续后续 fallback。
- `remote_candidates_filtered` 的 `candidate_kept=0`：远端发来的候选没有可用于独立公网 direct 的地址，本端不会把它交给 ICE agent。该 plan 会记录 `candidate_failed`，但不应把整个 peer session 直接打失败。
- `candidate_kept_samples` 和 `candidate_rejected_samples`：少量候选样本。用这些字段直接对比 natpierce 日志里的公网 endpoint；带 local base 的 hint 会显示为 `srflx:公网ip:端口<-本地ip:端口`。如果 WinkYou 只看到 `host:100.64...` 或私网样本，说明它还没有采到同级别的公网 srflx/prflx 候选。
- `public_endpoint_hint_count` 和 `public_endpoint_hint_port_window`：只会出现在带 `public_endpoint_hints` 的本地 `candidate_gathered` observation 中。看到这些字段才能确认本轮 `legacyice/public_direct` 确实带着 endpoint hint 和端口窗口参与了 ICE 检查；如果配置里开了窗口但 observation 没有这些字段，优先确认两端二进制和实际使用的 config。
- doctor 的 `candidate filters` 会显示静态配置的 `public_endpoint_hint_port_window`。如果当前 STUN probe 判定为 symmetric NAT，或 NAT 类型无法分类但本轮能生成 endpoint hint，还会额外显示 `effective_public_endpoint_hint_port_window=16` 和 `effective_window_reason=symmetric_nat_endpoint_hints` / `unclassified_nat_endpoint_hints`，表示生产策略会使用放宽后的有效端口窗口。
- `candidate_signaled`：`public_direct` 在 offer/answer 后额外发送的有界 candidate 信令。重点看 `candidate_sent`、`candidate_total`、`candidate_round` / `candidate_rounds` 和 `candidate_capped`；如果完全没有该事件，优先确认两端二进制是否包含候选信令重发补强。
- 如果 `candidate` 信令先于 offer/answer 到达，当前 legacy ICE 会把有效候选暂存到 remote credentials 到达后再合并使用；因此后续 answer/offer 里候选被 public-direct 规则过滤为空，不一定会丢掉前面已经收到的有效公网 candidate。若仍失败，继续看 `candidate_failed` 里的本端/远端候选摘要和 ICE 状态。
- `candidate_failed` 中的 `last_local_candidate_*` / `last_remote_candidate_*`：这是失败事件携带的最近一次候选摘要。如果 `last_local_candidate_kept=0`，优先查本端 STUN、hint、CIDR 过滤和本地 base；如果 `last_remote_candidate_kept=0`，优先查对端是否发布了公网/受信 underlay 候选，或本端是否缺少对应 `nat.direct_trusted_cidrs`。
- 两边 `candidate_kept>0` 但随后 `candidate_failed`：候选已经交换，问题更可能在 UDP 映射不稳定、防火墙、端口范围、STUN/TURN 配置或 NAT 行为与 natpierce 使用的 socket/映射不一致。
- `candidate_reject_reasons` 中出现 `*_cgnat_or_overlay_candidate`：当前路径仍可能依赖 natpierce、VPN/TAP 或类似 underlay，不能作为 `protected_direct` 证据。
- 成功记录中 `remote_candidate_kind=prflx` 或 `public_direct_learned_pair=true`：说明 ICE 过程中通过对端 STUN Binding Request 学到了 peer-reflexive 候选对，更接近 natpierce 这类运行中打洞成功的证据。仍需同时确认 `path_role=protected_direct` 且 `path_dependencies` 为空。
- 如果 selected pair 的本地地址是 `100.64.0.0/10`、198.18/15、loopback、link-local 或 overlay/VPN 地址，即使远端是公网，也不会触发 `public_direct` 的 protected-direct 切换；应检查 mapped hint 的本地 base IP 是否写到真实出口网卡，而不是 natpierce/Tailscale/Docker 等虚拟接口。

本机能 ping `10.6.22.1` 时，还要先看 Windows 路由表。如果 `10.6.22.0/24` 当前挂在 `natpierce` 接口上，这只能证明 natpierce 的虚拟路由可达，不证明 WinkYou 已经建立了独立 direct path：

```powershell
Get-NetRoute -DestinationPrefix 10.6.22.0/24
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like '*natpierce*'
```

如果 `inner-gw` 本身不是 WinkYou peer，而是 chen-win 后面的后端网段，那么 WinkYou 之前只知道 chen-win 的 peer `/32`，不会自动知道 `10.6.22.0/24` 应该经由 chen-win 转发。natpierce 能通，可能是因为它本身已经发布/安装了这条虚拟路由。对应的 WinkYou 配置应放在网关 peer 上：

```yaml
node:
  name: chen-win
  advertise_routes:
    - "10.6.22.0/24"
```

重新启动网关 peer 后，其他 peer 应在 `wink peers --json` 里看到该 peer 的 `advertised_routes` 包含 `10.6.22.0/24`。绑定成功后，本机会把这条网段加入该 peer 的 WireGuard `AllowedIPs`，并添加经由该 peer 虚拟 IP 的系统路由。Windows TUN 会用低 route/interface metric 安装 WinkYou 后端路由，减少同前缀 natpierce/Tailscale 路由抢占；但如果系统里已有更具体的 `10.6.22.1/32` host route，它仍会优先于 `10.6.22.0/24`，需要清理该 stale overlay route，或让网关 peer 发布同样具体的 WinkYou route。网关 peer 仍必须在操作系统层开启 IP forwarding/转发，并允许防火墙通过该后端网段；否则路由会存在，但包仍可能在 chen-win 或 inner-gw 侧被丢弃。后端主机也必须知道如何回到 WinkYou 虚拟网段；如果 inner-gw 不能配置静态回程路由，就需要在 chen-win 上做 SNAT/masquerade，让后端看到的源地址变成 chen-win 在后端网段里的地址。

普通 `wink peers` 文本输出也会显示 `Routes` 行；`wink doctor` 的 `routing` 层会分别报告本节点 `node.advertise_routes` 正在发布的路由、当前操作系统 IP forwarding 状态、后端回程路由/SNAT 风险、运行时从远端 peer 收到的后端路由，以及本机操作系统路由表是否已经把这些远端后端网段指向对应 peer 的 WinkYou 虚拟 IP。如果 `routing/peer advertised routes` 只提示未绑定或没有运行时状态，先把对应 gateway peer 连到 `connected/bound`，再检查 Windows 路由表和 WireGuard `AllowedIPs`。如果 `routing/os route table` 失败，说明路由没有安装、下一跳错误或残留了旧路由，先重连 gateway peer 并清理 stale route；如果 `routing/ip forwarding` 失败，先在 gateway peer 上开启系统转发和防火墙放行；如果 `routing/backend return path` 提醒未验证，继续检查 inner-gw 的回程路由或 chen-win 上的 SNAT，否则 `inner-gw` 后端网段仍然不会通。

如果某个地址看起来“能直连”，但怀疑它实际仍走 natpierce、Tailscale、Docker 或其他外部 overlay，运行：

```powershell
wink --config <config.yaml> doctor --route-target 10.6.22.1
```

`routing/target route` 会显示当前操作系统访问该目标 IP 选中的接口、本地地址和下一跳。如果接口是 `natpierce`，只能说明 natpierce overlay 正在承载这条路；要证明 WinkYou 独立承载，需要看到该目标网段作为远端 peer 的 `advertised_routes` 被安装到 WinkYou peer 虚拟 IP，或者看到 `legacyice/public_direct` 的 `protected_direct` observation。

要验证 WinkYou 自己的路径，应以 `wink peers --json` 的 `last_path_role=protected_direct`、空 `last_path_dependencies`、非空 `protected_direct_path_id`，以及对应 observation 里的 `legacyice/public_direct` 成功记录为准。

## 6. Strategy Selection

默认策略：

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

默认 multipath scoring 会对 relay/依赖路径扣分，对 `unknown` 依赖加倍扣分，并给真正的 `protected_direct` 加保护分。结果是：低 RTT relay 仍可成为 primary；但没有 RTT 证据时，`100.64.0.0/10`、VPN/TAP、natpierce 等依赖不清的 direct-like path 不应仅因为 `Conn Type: direct` 就压过明确的 relay fallback。
`wink peers` 和 `wink peers --json` 会显示 `last_failover_why`。如果看到 `active_path_rx_silence:<path>`，说明 multipath 因 active path 长时间没有收到包而切到了 standby；如果没有该字段，说明尚未触发 failover，或当前版本/运行时状态还没有记录原因。

强制验证 relay：

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
```

`connectivity.mode: relay_only` 和 `nat.force_relay: true` 会让生产路径保持单路径 relay 语义，即使配置里写了 `connectivity.multipath.enabled: true`，client 也不会同时保留 direct standby。要验证“relay primary + direct/P2P standby”，保持 `connectivity.mode: auto`，只把 `connectivity.strategy_order` 调成 `relay_only`、`legacy_ice_udp`，并确认 `connectivity.multipath.enabled: true`。`wink doctor` 的 `multipath/policy` 检查会提示 relay-only policy 导致的单路径状态。

如果 `wink peers --json` 只有一条 path，但本轮明明还有后续 strategy 可用，先确认两端二进制已包含 protected-direct 调度修复：session 应在 `connectivity.multipath.max_paths` 预算未填满时继续执行后续 strategy，而不是在第一条 protected/direct outcome 成功后立刻停止。仍只有单路径时，再看 observation 中是否有后续 strategy 的 `candidate_planned` / `strategy_failed`，用于区分“没有执行”与“执行后失败”。

`tcp_framed` 仍是 alpha，仅用于显式可达 TCP 地址测试：

```yaml
connectivity:
  strategy_order:
    - tcp_framed
    - legacy_ice_udp
    - relay_only

tcp_framed:
  enabled: true
  listen_addr: "0.0.0.0:0"
  advertise_addr: "203.0.113.10:39000"
  dial_timeout: 5s
```

`tcp_framed` 不做 TCP NAT 打洞；`advertise_addr` 必须能被对端直接访问。

## 7. Tunnel / Transport

如果 `wink peers` 中有 `Xport Err`：

- `context deadline exceeded`：选中 path 可能不可达或 relay 端口被挡
- `connection refused`：TCP framed 对端地址没有监听
- `destination buffer too small`：packet/frame 尺寸配置异常，保留日志后再排查

如果 transport 已经绑定但业务不通：

1. 先用 relay-only 配置排除 direct NAT 问题。
2. 再检查系统防火墙是否阻止虚拟网卡流量。
3. 最后查看 coordinator/coturn/client 三侧日志的时间线是否一致。
