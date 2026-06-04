# WinkYou 自托管 Quickstart

本文给出一条从零跑通的最小路径：一台 Linux 公网服务器运行 coordinator + coturn，两台 client 加入同一个虚拟网络，并分别验证 direct path 与 relay path。

快速验证时可以直接以前台方式运行 `wink up` 并保持终端打开。长期运行请使用 [`LONG-RUNNING-CLIENT.md`](./LONG-RUNNING-CLIENT.md) 中的 systemd、Windows Task Scheduler 或 NSSM 工作流。

## 1. 前置条件

Linux 服务器：

- 一台有公网 IPv4 的 Linux 主机
- 已安装 Docker 和 Docker Compose 插件
- 防火墙允许：
  - TCP `50051`：coordinator gRPC
  - UDP `3478`：TURN/STUN 入口
  - UDP `49152-65535`：coturn relay 端口范围

Windows client：

- 以管理员权限运行 PowerShell 或终端
- TUN/Wintun 可用
- 已构建或下载 `wink.exe`

Linux client：

- 需要 `/dev/net/tun`
- 需要 root 权限，或给二进制配置等价的网络 capability
- 已构建或下载 `wink`

## 2. 启动 coordinator + coturn

在 Linux 公网服务器上克隆仓库后：

```bash
cd winkyou
cp deploy/quickstart/.env.example deploy/quickstart/.env
```

编辑 `deploy/quickstart/.env`：

```dotenv
WINK_PUBLIC_IP=203.0.113.10
WINK_AUTH_KEY=wink-demo-key
WINK_TURN_USER=winkdemo
WINK_TURN_PASSWORD=winkdemo-pass
```

`WINK_PUBLIC_IP` 必须替换为服务器公网 IPv4。示例凭据只用于测试环境，真实部署时请修改。

启动：

```bash
docker compose --env-file deploy/quickstart/.env -f deploy/quickstart/docker-compose.yml up -d --build
```

查看状态：

```bash
docker compose --env-file deploy/quickstart/.env -f deploy/quickstart/docker-compose.yml ps
docker compose --env-file deploy/quickstart/.env -f deploy/quickstart/docker-compose.yml logs -f coordinator coturn
```

## 3. 准备两个 client 配置

把 `<HOST>` 替换为 coordinator/TURN 服务器公网地址。

节点 A：

```bash
sed 's/<HOST>/203.0.113.10/g' deploy/quickstart/config.node-a.yaml > node-a.yaml
```

节点 B：

```bash
sed 's/<HOST>/203.0.113.10/g' deploy/quickstart/config.node-b.yaml > node-b.yaml
```

Windows PowerShell 等价写法：

```powershell
(Get-Content deploy\quickstart\config.node-a.yaml -Raw).Replace("<HOST>", "203.0.113.10") | Set-Content -Encoding utf8 node-a.yaml
```

示例配置内的 WireGuard 私钥是 demo key。真实部署请在每台 client 上运行：

```bash
wink genkey
```

然后把输出写入各自配置的 `wireguard.private_key`。

## 4. 启动两个 client

节点 A：

```bash
wink --config node-a.yaml up
```

节点 B：

```bash
wink --config node-b.yaml up
```

保持两个终端运行。另开终端查看状态：

```bash
wink --config node-a.yaml status
wink --config node-a.yaml peers
wink --config node-a.yaml doctor
```

看到 peer 后，记录对端 `Virtual IP`，尝试 ping：

```bash
ping <peer-virtual-ip>
```

## 5. 验证 direct path

默认配置使用：

```yaml
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
```

如果两台 client 所在网络允许直连，`wink peers` 应显示：

```text
Conn Type:  direct
Handshake:  <timestamp>
```

如果当前网络不能直连，auto 模式可能自然选择 relay。这不是失败；请继续执行 relay-only 验证。

## 6. 验证 relay_only path

生成 relay-only 配置：

```bash
sed 's/<HOST>/203.0.113.10/g' deploy/quickstart/config.node-a.relay-only.yaml > node-a.relay.yaml
sed 's/<HOST>/203.0.113.10/g' deploy/quickstart/config.node-b.relay-only.yaml > node-b.relay.yaml
```

分别重启两个 client：

```bash
wink --config node-a.relay.yaml up
wink --config node-b.relay.yaml up
```

检查：

```bash
wink --config node-a.relay.yaml peers
```

预期：

```text
Conn Type:  relay
Handshake:  <timestamp>
```

如果 `Conn Type` 是 relay 但没有 handshake，优先检查 coturn relay 端口范围 `49152-65535/udp` 是否开放。

## 7. 常用文件

- Compose：[`../deploy/quickstart/docker-compose.yml`](../deploy/quickstart/docker-compose.yml)
- 节点 A：[`../deploy/quickstart/config.node-a.yaml`](../deploy/quickstart/config.node-a.yaml)
- 节点 B：[`../deploy/quickstart/config.node-b.yaml`](../deploy/quickstart/config.node-b.yaml)
- relay-only 节点 A：[`../deploy/quickstart/config.node-a.relay-only.yaml`](../deploy/quickstart/config.node-a.relay-only.yaml)
- relay-only 节点 B：[`../deploy/quickstart/config.node-b.relay-only.yaml`](../deploy/quickstart/config.node-b.relay-only.yaml)
- coturn 单独部署说明：[`../deploy/coturn/README.md`](../deploy/coturn/README.md)
- 长期运行说明：[`LONG-RUNNING-CLIENT.md`](./LONG-RUNNING-CLIENT.md)

## 8. 安全提醒

- 不要在公网复用 demo TURN 凭据。
- 不要在多个真实节点复用 demo WireGuard 私钥。
- coordinator 的 `WINK_AUTH_KEY` 应改成随机长字符串。
- coturn 的公网端口范围必须和防火墙一致。
