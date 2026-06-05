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
- 已经 `State: connected` 后断开 coordinator 所在网络，peer 随后断开：这是当前控制面韧性缺口。现有 client 可能把 peer offline/control-plane loss 转成 `cleanupPeer`，从而拆掉已 bound 的 tunnel peer。详见 [`CONTROL-PLANE-RESILIENCE.md`](./CONTROL-PLANE-RESILIENCE.md)。

部署建议：

- coordinator 应部署在双方都能稳定访问的位置，例如公网服务器或固定内网节点。
- 不要把唯一 coordinator 放在临时跳板链路后面；否则断开跳板/natpierce 后，心跳、peer discovery 和 session signaling 都会失效。
- 已建立数据面未来应能容忍 coordinator 短暂不可达。当前已修 peer offline update 导致的第一层误清理风险，但 heartbeat/signaling failure、runtime control/data 状态和真实 coordinator outage 验证仍是 TODO。
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
```

这只适用于公网 IP/端口映射稳定的场景。若运营商 NAT 会为每个 UDP socket 动态改写端口，`nat1to1_ips` 不能保证复现 natpierce 的成功路径；应查看 `legacyice/public_direct` 是否采集到了 server-reflexive candidate，或使用 TURN/`relay_only` fallback。

默认 `legacy_ice_udp` 内部执行顺序为：

```text
legacyice/direct_prefer -> legacyice/public_direct -> legacyice/relay_only
```

`direct_prefer` 可能选中 natpierce、Tailscale、Docker bridge 或其他 overlay candidate；`public_direct` 才是用于验证双方是否能通过公网 UDP NAT piercing 形成独立 direct path 的 plan。

如果 observation history 中已有 direct 失败和 relay 成功，legacy ICE 可以把 `relay_only` 排到前面，但 `public_direct` 不应仅因为 `direct_prefer` 失败而被剪掉。排障时如果只看到 `legacyice/relay_only`，没有看到 `legacyice/public_direct` 的 `candidate_planned` 或 `candidate_started`，应检查当前二进制是否为最新版本，或是否处于显式 `connectivity.mode: relay_only` / `nat.force_relay: true`。

如果 natpierce 能从本机直达 `inner-gw`，但 WinkYou 不能建立 `protected_direct`，不要先判断为“物理不可达”。先查看 observation history。客户端运行状态文件同目录下会有 `<runtime-state-base>.observations.jsonl`，可在 Windows 上先用：

```powershell
Get-Content <runtime-state-base>.observations.jsonl |
  Select-String 'candidate_gathered|remote_candidates_filtered|candidate_failed'
```

重点看 `PlanID=legacyice/public_direct` 或 details 中 `mode=public_direct` 的记录：

- `candidate_gathered` 的 `candidate_total>0` 但 `candidate_kept=0`：本端 gather 到的 candidate 全部被 public-direct 规则排除，常见原因是只采到了私网、`100.64.0.0/10`、overlay 或 relay candidate。该 plan 会失败并继续后续 fallback。
- `remote_candidates_filtered` 的 `candidate_kept=0`：远端发来的候选没有可用于独立公网 direct 的地址，本端不会把它交给 ICE agent。该 plan 会记录 `candidate_failed`，但不应把整个 peer session 直接打失败。
- 两边 `candidate_kept>0` 但随后 `candidate_failed`：候选已经交换，问题更可能在 UDP 映射不稳定、防火墙、端口范围、STUN/TURN 配置或 NAT 行为与 natpierce 使用的 socket/映射不一致。
- `candidate_reject_reasons` 中出现 `*_cgnat_or_overlay_candidate`：当前路径仍可能依赖 natpierce、VPN/TAP 或类似 underlay，不能作为 `protected_direct` 证据。

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
