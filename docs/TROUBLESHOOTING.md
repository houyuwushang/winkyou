# WinkYou 排障指南

本文按连接链路分层排查。当前可用命令主要是 `wink status`、`wink peers`、client 日志、coordinator 日志和 coturn 日志；专用 `wink doctor` 会在后续阶段补齐。

## 1. Config

检查配置是否能加载：

```bash
wink --config node-a.yaml status
```

常见问题：

- `invalid coordinator.url`：确认使用 `grpc://host:50051`
- `invalid connectivity.strategy_order`：只使用当前实现的 strategy 名称，例如 `legacy_ice_udp`、`relay_only`、`tcp_framed`
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
