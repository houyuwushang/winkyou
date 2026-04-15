# WinkYou

当前可部署的快速路径是：`Windows client + Linux coordinator + coturn relay + Linux peer`。  
`docs/EXECUTION-BASELINE.md` 仍然是最高优先级执行基线；本 README 只描述这条已经可以真实部署、真实复现的路径。

## 当前支持矩阵

| 角色 / 平台 | 状态 | 说明 |
| --- | --- | --- |
| Windows client | 支持 | `netif.backend: tun`，使用 Wintun，要求管理员权限 |
| Linux client | 支持 | TUN + 进程内 `wireguard-go` |
| Linux coordinator | 支持 | gRPC 控制面 |
| coturn relay | 支持 | 生产级 TURN relay（推荐） |
| embedded wink-relay | 实验性 | 开发/测试用，不推荐公网部署 |
| macOS client | 实验性 | 已修复 TUN 包头写入 bug，但部署验证仍应谨慎 |
| `userspace` / `proxy` / no-admin 模式 | 未完成 | 当前会明确报错，不再伪装成已完成 |

当前数据面不再依赖系统 `wg` 命令。WireGuard 数据面已经改为进程内 `wireguard-go`。  
Windows 侧需要 Wintun，推荐两种准备方式：

1. 推荐路径 A：先安装官方 WireGuard for Windows。
2. 推荐路径 B：把 `wintun.dll` 放到 `wink.exe` 同目录。

## 5 分钟快速部署

下面这条 quickstart 只覆盖一个明确场景：

- Windows 本地客户端
- Linux coordinator
- coturn relay (生产推荐)
- Linux peer

文中统一把 Linux 主机对外可访问的 IPv4 地址写成 `<HOST>`。  
`deploy/quickstart/windows-client.yaml` 和 `deploy/quickstart/linux-peer.yaml` 里已经内置了静态 auth key、TURN 用户名密码和示例私钥，可以直接替换 `<HOST>` 后启动。

### 1. 环境前提

- Windows client：Windows 10/11，必须以管理员权限运行 `wink.exe up`。
- Windows client：必须满足下面二选一。
  - 已安装官方 WireGuard for Windows。
  - `wintun.dll` 已放到 `wink.exe` 同目录。
- Linux coordinator / relay / peer：建议 Ubuntu 22.04+ 或同类发行版。
- Linux peer：需要 root 权限创建 TUN。
- 网络端口：
  - coordinator：TCP `50051`
  - coturn relay：UDP `3478` (TURN signaling)
  - coturn relay：UDP `49152-65535` (relay data ports，**必须开放**，否则 relay 模式下 WireGuard 握手会失败)
- 本轮不包含 `userspace` / `proxy` / no-admin 模式。

### 2. 构建命令

Linux 构建：

```bash
mkdir -p bin
GOOS=linux GOARCH=amd64 go build -o bin/wink ./cmd/wink
GOOS=linux GOARCH=amd64 go build -o bin/wink-coordinator ./cmd/wink-coordinator
GOOS=linux GOARCH=amd64 go build -o bin/wink-relay ./cmd/wink-relay
```

Windows 构建：

```powershell
New-Item -ItemType Directory -Force bin | Out-Null
$env:GOOS = "windows"
$env:GOARCH = "amd64"
go build -o bin/wink.exe ./cmd/wink
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
```

如果你使用 GNU Make，也可以直接执行：

```bash
make build-deploy-preview
```

### 3. 启动 Linux coordinator

先在 Linux 主机上设置共享注册密钥，然后启动 coordinator：

```bash
export WINK_AUTH_KEY=wink-demo-key
bash deploy/quickstart/start-coordinator.sh
```

等价的显式命令是：

```bash
./bin/wink-coordinator \
  --listen :50051 \
  --network-cidr 10.42.0.0/24 \
  --lease-ttl 30s \
  --auth-key wink-demo-key \
  --store-backend memory
```

### 4. 启动 coturn relay (推荐)

**推荐使用 coturn** 作为生产 TURN relay。coturn 是经过实战验证的 TURN 服务器，被广泛部署。

#### 使用 Docker 部署 coturn

```bash
cd deploy/coturn
export EXTERNAL_IP=<HOST>
bash start-coturn.sh
```

或手动部署：

```bash
cd deploy/coturn
sed -i 's/<EXTERNAL_IP>/<HOST>/g' turnserver.conf
docker-compose up -d
```

**关键防火墙规则**：

```bash
# TURN signaling
sudo ufw allow 3478/udp

# Relay data ports (必须开放)
sudo ufw allow 49152:65535/udp
```

详细配置和故障排查见 `deploy/coturn/README.md`。

#### 或使用 embedded wink-relay (实验性)

embedded `wink-relay` 仍保留在仓库中用于开发和测试，但**不推荐用于公网生产部署**。

如果你仍想使用它：

```bash
export WINK_RELAY_IP=<HOST>
export WINK_TURN_USERS=winkdemo:winkdemo-pass
bash deploy/quickstart/start-relay.sh
```

等价的显式命令：

```bash
./bin/wink-relay \
  --external-ip <HOST> \
  --listen <HOST>:3478 \
  --realm winkyou \
  --users winkdemo:winkdemo-pass \
  --min-port 49152 \
  --max-port 65535
```

**注意**：
- 如果 `--listen` 是 wildcard (如 `:3478` 或 `0.0.0.0:3478`) 且设置了 `--external-ip`，必须显式传 `--allow-wildcard-listen`，否则会 fail-fast
- 必须设置 `--min-port` 和 `--max-port` 以分配 relay 端口范围
- 确保防火墙开放了 relay 端口范围

### 5. 准备 Windows client 配置

模板文件已经在仓库里：

- `deploy/quickstart/windows-client.yaml`

把其中的 `<HOST>` 替换成 coordinator / relay 所在 Linux 主机地址。示例：

```powershell
$cfg = (Get-Content .\deploy\quickstart\windows-client.yaml -Raw).Replace("<HOST>", "203.0.113.10")
$cfgPath = "$env:TEMP\wink-windows-client.yaml"
[System.IO.File]::WriteAllText($cfgPath, $cfg, [System.Text.UTF8Encoding]::new($false))
```

也可以直接用脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\quickstart\windows-run.ps1 -HostAddress 203.0.113.10
```

说明：

- `netif.backend: tun` 是当前 Windows 的真实可用路径。
- `wireguard.listen_port: 0` 表示让系统分配 UDP 端口，由 ICE/NAT 协商后对外公布。

### 6. 准备 Linux peer 配置

模板文件：

- `deploy/quickstart/linux-peer.yaml`

在 Linux 上把 `<HOST>` 替换掉：

```bash
sed 's/<HOST>/203.0.113.10/g' deploy/quickstart/linux-peer.yaml > /tmp/wink-linux-peer.yaml
```

### 7. 启动 Linux peer 和 Windows client

Linux peer：

```bash
sudo ./bin/wink --config /tmp/wink-linux-peer.yaml up
```

Windows client：

```powershell
.\bin\wink.exe --config $cfgPath up
```

如果没有管理员权限，Windows 侧现在会直接给出明确错误，而不会再偷偷降级到未完成 backend。

### 8. 验证命令

先看 peer 列表：

Linux：

```bash
./bin/wink --config /tmp/wink-linux-peer.yaml peers
```

Windows：

```powershell
.\bin\wink.exe --config $cfgPath peers
```

输出里重点看这几项：

- `State: connected`
- `Conn Type: direct` 或 `Conn Type: relay`
- `Endpoint:` 有真实地址

再做 request/response 连通性验证：

Linux：

```bash
./bin/wink --config /tmp/wink-linux-peer.yaml ping <Windows 节点的 Node ID 或 Virtual IP>
```

Windows：

```powershell
.\bin\wink.exe --config $cfgPath ping <Linux 节点的 Node ID 或 Virtual IP>
```

如果 `peers` 里显示 `Conn Type: direct`，说明当前走直连。  
如果显示 `Conn Type: relay`，说明当前回退到了 TURN relay。

### 9. 常见故障排查

#### Windows 客户端问题

- 提示 `Wintun is unavailable`：
  - 先安装官方 WireGuard for Windows。
  - 或把 `wintun.dll` 放到 `wink.exe` 同目录。
- 提示需要 `Administrator privileges`：
  - 用管理员 PowerShell 或管理员 CMD 重新运行 `wink.exe up`。

#### 连接问题

- `peers` 长时间停在 `connecting`：
  - 确认 Linux coordinator 的 TCP `50051` 可达。
  - 确认 relay 的 UDP `3478` 可达。
  - 确认 relay 主机额外放行了 UDP `49152-65535` 端口范围。
  - 确认 `coordinator.auth_key` 与 coordinator 启动参数一致。
  - 确认 Windows 防火墙 / Linux 防火墙没有拦截 `wink.exe` 或 UDP。

#### Relay 特定问题

**症状**: `Conn Type: relay` 但 `Last Handshake: never`

这说明 ICE 已经选中了 relay candidate，但 WireGuard 握手失败。

**诊断步骤**：

1. **检查 relay 端口范围是否开放**：
   ```bash
   sudo ufw status | grep 49152:65535
   ```
   如果没有，添加规则：
   ```bash
   sudo ufw allow 49152:65535/udp
   ```

2. **查看 ICE 状态** (需要 verbose 模式或 runtime state)：
   ```bash
   ./bin/wink --config /tmp/wink-linux-peer.yaml peers --json | jq '.[] | {node_id, ice_state, local_candidate, remote_candidate}'
   ```
   
   如果 `ice_state: "connected"` 且 candidate 包含 `relay:`，说明 ICE 层成功，问题在 WireGuard 层。

3. **coturn 日志检查**：
   ```bash
   docker-compose -f deploy/coturn/docker-compose.yml logs coturn | grep -i allocation
   ```
   应该看到成功的 allocation 记录。

4. **embedded wink-relay 日志检查**：
   如果使用 `wink-relay`，检查是否有 `CreatePermission-request ... no allocation found` 错误。
   这通常意味着 relay 绑定地址配置错误。

**常见原因**：
- 防火墙只开放了 3478/udp，没有开放 relay 端口范围
- coturn `external-ip` 配置错误
- wink-relay 使用了 wildcard listen 但没有正确的 external-ip

#### 其他问题

- 想用 `userspace` / `proxy` / no-admin：
  - 当前未完成，这一轮没有承诺该路径。
- 想安装系统 `wg`：
  - 不需要。当前数据面已经是进程内 `wireguard-go`。

### 10. 清理 / 停止

Windows client：

```powershell
.\bin\wink.exe --config $cfgPath down
```

Linux peer：

```bash
./bin/wink --config /tmp/wink-linux-peer.yaml down
```

Linux coordinator / relay：

- 前台运行时直接 `Ctrl+C`
- 或由你自己的进程管理器停止

## 当前范围说明

- 这条 README quickstart 只承诺 `Windows client + Linux coordinator + coturn relay + Linux peer`。
- **推荐使用 coturn** 作为生产 relay。embedded `wink-relay` 保留用于开发/测试，但不推荐公网部署。
- `memory backend` 仍然保留，但只用于测试。
- `userspace` / `proxy` / no-admin 模式当前没有完成，不应作为生产路径使用。
- macOS 目前只标记为实验性，不在本 quickstart 承诺范围内。

## 为什么默认 relay 改用 coturn

embedded `wink-relay` 仍在仓库中，但有以下限制：

1. **生产验证不足**：未经过大规模公网部署验证
2. **配置复杂**：wildcard listen + external-ip 的组合容易出错
3. **调试困难**：allocation 失败时诊断信息不如 coturn 清晰

coturn 是成熟的 TURN 服务器，被 WebRTC、Jitsi 等项目广泛使用。切换到 coturn 作为默认路径可以：

- 降低部署失败率
- 提供更好的故障排查体验
- 让 `wink-relay` 专注于开发/测试场景

如果你在开发环境中需要快速启动 relay，`wink-relay` 仍然可用。但对于面向用户的部署，强烈建议使用 coturn。

## 其他文档

- 部署入口：[`README.md`](./README.md)
- 文档索引：[`docs/README.md`](./docs/README.md)
- 执行基线：[`docs/EXECUTION-BASELINE.md`](./docs/EXECUTION-BASELINE.md)
- 今日部署疑点与专家问题：[`docs/DEPLOYMENT-QUESTIONS-2026-04-15.md`](./docs/DEPLOYMENT-QUESTIONS-2026-04-15.md)
