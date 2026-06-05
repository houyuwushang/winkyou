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

这只适用于公网 IP/端口映射稳定的场景。`nat1to1_ips` 表示公网 IP 映射，`public_endpoint_hints` 表示本机已知的公网 UDP `ip:port`，也可以写成 `公网ip:公网端口/本地ip:本地端口` 绑定到具体本地 UDP base；它只会作为 `legacyice/public_direct` 的额外 srflx 候选发布。若运营商 NAT 会为每个 UDP socket 动态改写端口，过期的 `public_endpoint_hints` 不能保证复现 natpierce 的成功路径；应查看 `legacyice/public_direct` 是否采集到了 server-reflexive candidate，或使用 TURN/`relay_only` fallback。

先运行 `wink --config <config.yaml> doctor` 看 `stun` 检查。该检查会使用 public-direct 的有效 STUN 来源：显式 `nat.stun_servers`，以及从 UDP TURN URL 派生出的同 host/port STUN binding URL。如果 STUN probe 失败，说明当前 STUN/UDP TURN 入口没能返回公网映射地址，`legacyice/public_direct` 大概率没有足够的公网候选可用。此时优先换成两端都可访问的 STUN/UDP TURN 服务，确认 UDP 出站没有被拦截；如果无法保证公网 UDP NAT piercing，就使用 TURN/`relay_only` 作为保活路径。

默认 `legacy_ice_udp` 内部执行顺序为：

```text
legacyice/direct_prefer -> legacyice/public_direct -> legacyice/relay_only
```

`direct_prefer` 可能选中 natpierce、Tailscale、Docker bridge 或其他 overlay candidate；`public_direct` 会跳过 TURN/relay candidate gathering，只采 host/server-reflexive direct candidate，才是用于验证双方是否能通过公网 UDP NAT piercing 形成独立 direct path 的 plan。`public_direct` 会用更短 ICE check interval、按 `nat.connect_timeout` 放大的 binding request 预算、更短 srflx/prflx 接受等待，并确保 ICE failed-check timeout 不短于 `nat.connect_timeout`，在同一 public-direct socket 上持续打洞到连接超时；session 的 candidate execution budget 会按每个候选的 execution timeout 扩展，避免前面的 plan 耗时后跳过 `public_direct` 或 relay fallback。如果仍失败，优先比较两端 STUN 映射、候选过滤和 natpierce 实际使用的公网端点。

如果 public-direct STUN gather 超时，但 Pion agent 已经准备好本地 UDP candidate，WinkYou 会继续返回这批本地候选，让 `public_endpoint_hints` 能尽快追加进 offer/answer 并开始 ICE checks。这个行为只解决“慢 STUN 卡住候选交换”的问题；如果 hint 过期、两端 NAT 映射和 natpierce 使用的 socket 不一致，或远端公网候选被过滤，仍会失败并进入后续 fallback。

如果 observation history 中已有 direct 失败和 relay 成功，legacy ICE 可以把 `relay_only` 排到前面，但 `public_direct` 不应仅因为 `direct_prefer` 失败而被剪掉。排障时如果只看到 `legacyice/relay_only`，没有看到 `legacyice/public_direct` 的 `candidate_planned` 或 `candidate_started`，应检查当前二进制是否为最新版本，或是否处于显式 `connectivity.mode: relay_only` / `nat.force_relay: true`。

当前 session 会按 strategy message 顶层 `plan_id` 缓存未来 plan 的消息。如果两端推进速度不一致，`legacyice/public_direct` 的 offer/answer 不应再被仍在执行 `legacyice/direct_prefer` 的 executor 吞掉。若仍看不到 `public_direct` 的 candidate 事件，优先确认两端二进制都已更新。

如果 natpierce 能从本机直达 `inner-gw`，但 WinkYou 不能建立 `protected_direct`，不要先判断为“物理不可达”。先运行：

```powershell
wink --config <config.yaml> doctor
```

查看 `public direct evidence` 检查。它会读取 observation history，直接提示 `legacyice/public_direct` 是没有记录、远端候选为 0、本端候选为 0、ICE 检查失败，还是已经选中/提交了 protected direct。客户端运行状态文件同目录下也会有 `<runtime-state-base>.observations.jsonl`，需要手工核对时可在 Windows 上用：

```powershell
Get-Content <runtime-state-base>.observations.jsonl |
  Select-String 'candidate_gathered|remote_candidates_filtered|candidate_failed'
```

重点看 `PlanID=legacyice/public_direct` 或 details 中 `mode=public_direct` 的记录：

- `candidate_gathered` 的 `candidate_total>0` 但 `candidate_kept=0`：本端 gather 到的 direct candidate 全部被 public-direct 规则排除，常见原因是只采到了私网、`100.64.0.0/10` 或 overlay candidate。该 plan 会失败并继续后续 fallback。
- `remote_candidates_filtered` 的 `candidate_kept=0`：远端发来的候选没有可用于独立公网 direct 的地址，本端不会把它交给 ICE agent。该 plan 会记录 `candidate_failed`，但不应把整个 peer session 直接打失败。
- `candidate_kept_samples` 和 `candidate_rejected_samples`：少量候选样本。用这些字段直接对比 natpierce 日志里的公网 endpoint；带 local base 的 hint 会显示为 `srflx:公网ip:端口<-本地ip:端口`。如果 WinkYou 只看到 `host:100.64...` 或私网样本，说明它还没有采到同级别的公网 srflx/prflx 候选。
- 两边 `candidate_kept>0` 但随后 `candidate_failed`：候选已经交换，问题更可能在 UDP 映射不稳定、防火墙、端口范围、STUN/TURN 配置或 NAT 行为与 natpierce 使用的 socket/映射不一致。
- `candidate_reject_reasons` 中出现 `*_cgnat_or_overlay_candidate`：当前路径仍可能依赖 natpierce、VPN/TAP 或类似 underlay，不能作为 `protected_direct` 证据。
- 成功记录中 `remote_candidate_kind=prflx` 或 `public_direct_learned_pair=true`：说明 ICE 过程中通过对端 STUN Binding Request 学到了 peer-reflexive 候选对，更接近 natpierce 这类运行中打洞成功的证据。仍需同时确认 `path_role=protected_direct` 且 `path_dependencies` 为空。

本机能 ping `10.6.22.1` 时，还要先看 Windows 路由表。如果 `10.6.22.0/24` 当前挂在 `natpierce` 接口上，这只能证明 natpierce 的虚拟路由可达，不证明 WinkYou 已经建立了独立 direct path：

```powershell
Get-NetRoute -DestinationPrefix 10.6.22.0/24
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like '*natpierce*'
```

要验证 WinkYou 自己的路径，应以 `wink peers --json` 的 `last_path_role=protected_direct`、空 `last_path_dependencies`、非空 `protected_direct_path_id`，以及对应 observation 里的 `legacyice/public_direct` 成功记录为准。

## 6. Strategy Selection

默认策略：

```yaml
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
```

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
