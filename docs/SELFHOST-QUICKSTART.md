# WinkYou 自托管 Quickstart

本文给出一条从零跑通的最小路径：一台 Linux 公网服务器运行 coordinator + coturn，两台 client 加入同一个虚拟网络，并分别验证 direct path 与 relay path。

这是默认 `legacy` 模式的 quickstart，不是 Slice 4.5 `autonomous_mesh` 指南。默认关闭的自治图模式不启动这里的 coordinator/WireGuard client 生命周期；它的类型化配置、独立状态文件冒烟和 graceful `wink down` 见 [`LONG-RUNNING-CLIENT.md`](./LONG-RUNNING-CLIENT.md)。该自治 CLI adapter 尚未现场部署，不能用本 quickstart 的验收结果替代。

快速验证时可以直接以前台方式运行 `wink up` 并保持终端打开。长期运行请使用 [`LONG-RUNNING-CLIENT.md`](./LONG-RUNNING-CLIENT.md) 中的 systemd、Windows Task Scheduler 或 NSSM 工作流。

## 1. 前置条件

Linux 服务器：

- 一台有公网 IPv4 的 Linux 主机
- 已安装 Docker 和 Docker Compose 插件
- 防火墙允许：
  - TCP `50051`：coordinator gRPC over TLS
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

远程 coordinator 强制使用 TLS 和部署级共享密钥。先在 Linux 公网服务器上克隆仓库，并生成一张测试证书。下面示例使用公网 IP `203.0.113.10`，因此证书必须包含同一个 IP SAN：

```bash
cd winkyou
mkdir -p deploy/quickstart/tls
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
  -keyout deploy/quickstart/tls/coordinator.key \
  -out deploy/quickstart/tls/coordinator.crt \
  -subj "/CN=winkyou-coordinator" \
  -addext "subjectAltName=IP:203.0.113.10"
chmod 600 deploy/quickstart/tls/coordinator.key
openssl rand -hex 32
```

如果 client 使用 DNS 名称连接，请改用 `subjectAltName=DNS:coord.example.com`，并在后续配置里使用同一个名称。最后一条命令的输出是新的 `WINK_AUTH_KEY`，不要提交到仓库。

复制环境模板：

```bash
cp deploy/quickstart/.env.example deploy/quickstart/.env
```

编辑 `deploy/quickstart/.env`：

```dotenv
WINK_PUBLIC_IP=203.0.113.10
WINK_COORD_TLS_CERT=/absolute/path/to/winkyou/deploy/quickstart/tls/coordinator.crt
WINK_COORD_TLS_KEY=/absolute/path/to/winkyou/deploy/quickstart/tls/coordinator.key
WINK_AUTH_KEY=<PASTE_OPENSSL_RANDOM_OUTPUT>
WINK_TURN_USER=winkdemo
WINK_TURN_PASSWORD=winkdemo-pass
```

`WINK_PUBLIC_IP`、TLS 文件绝对路径和共享密钥都必须替换。仓库已忽略 `deploy/quickstart/.env` 与 `deploy/quickstart/tls/`，但仍应把私钥权限限制为 coordinator 运行用户可读。

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

把 coordinator 公共证书 `coordinator.crt` 安全复制到两台 client；只复制证书，不复制 `coordinator.key`。然后把三个占位符替换为服务器地址、同一部署共享密钥和 client 本地的证书路径。

节点 A：

```bash
export WINK_COORD_HOST=203.0.113.10
export WINK_COORD_AUTH_KEY='<PASTE_THE_SAME_RANDOM_KEY>'
export WINK_COORD_CA_FILE=/etc/winkyou/coordinator.crt
sed \
  -e "s|<HOST>|${WINK_COORD_HOST}|g" \
  -e "s|<COORDINATOR_AUTH_KEY>|${WINK_COORD_AUTH_KEY}|g" \
  -e "s|<COORDINATOR_CA_FILE>|${WINK_COORD_CA_FILE}|g" \
  deploy/quickstart/config.node-a.yaml > node-a.yaml
chmod 600 node-a.yaml
```

节点 B：

```bash
sed \
  -e "s|<HOST>|${WINK_COORD_HOST}|g" \
  -e "s|<COORDINATOR_AUTH_KEY>|${WINK_COORD_AUTH_KEY}|g" \
  -e "s|<COORDINATOR_CA_FILE>|${WINK_COORD_CA_FILE}|g" \
  deploy/quickstart/config.node-b.yaml > node-b.yaml
chmod 600 node-b.yaml
```

Windows PowerShell 等价写法：

```powershell
$authKey = "<PASTE_THE_SAME_RANDOM_KEY>"
$caFile = "C:\ProgramData\WinkYou\coordinator.crt"
$content = Get-Content deploy\quickstart\config.node-a.yaml -Raw
$content = $content.Replace("<HOST>", "203.0.113.10")
$content = $content.Replace("<COORDINATOR_AUTH_KEY>", $authKey)
$content = $content.Replace("<COORDINATOR_CA_FILE>", $caFile)
$content | Set-Content -Encoding utf8 node-a.yaml
```

也可以使用模板脚本：

```powershell
deploy\quickstart\windows-run.ps1 `
  -HostAddress 203.0.113.10 `
  -CoordinatorCAFile C:\ProgramData\WinkYou\coordinator.crt `
  -CoordinatorAuthKey "<PASTE_THE_SAME_RANDOM_KEY>"
```

远程地址必须使用 `grpcs://`。`grpc://` 和无 scheme 的明文地址只允许数值 loopback（`127.0.0.0/8` 或 `::1`），用于同机开发；`localhost` 也不会被当作“显式 loopback”，以避免名称解析把 bearer credential 发到非本机地址。

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
sed -e "s|<HOST>|${WINK_COORD_HOST}|g" -e "s|<COORDINATOR_AUTH_KEY>|${WINK_COORD_AUTH_KEY}|g" -e "s|<COORDINATOR_CA_FILE>|${WINK_COORD_CA_FILE}|g" deploy/quickstart/config.node-a.relay-only.yaml > node-a.relay.yaml
sed -e "s|<HOST>|${WINK_COORD_HOST}|g" -e "s|<COORDINATOR_AUTH_KEY>|${WINK_COORD_AUTH_KEY}|g" -e "s|<COORDINATOR_CA_FILE>|${WINK_COORD_CA_FILE}|g" deploy/quickstart/config.node-b.relay-only.yaml > node-b.relay.yaml
chmod 600 node-a.relay.yaml node-b.relay.yaml
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
- coordinator 的 `WINK_AUTH_KEY` 必须是随机长字符串，并应像 bearer token 一样保护和轮换；它会授权全部 coordinator unary/stream RPC。
- 共享密钥只标识“这个部署的成员”，不提供每节点身份隔离。任何持有者都能以已注册 node ID 绑定或替换 signaling session；per-node Ed25519 身份属于后续 Phase 2，不能把本 quickstart 描述成零信任。
- 不要在真实部署设置 `coordinator.tls.insecure_skip_verify: true`。自签名证书应通过 `coordinator.tls.ca_file` 显式信任。
- 只有公共证书可以复制给 client；coordinator TLS 私钥必须留在服务器。
- coturn 的公网端口范围必须和防火墙一致。
