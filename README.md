# WinkYou

当前可部署的快速路径是：`Windows client + Linux coordinator + Linux relay + Linux peer`。  
`docs/EXECUTION-BASELINE.md` 仍然是最高优先级执行基线；本 README 只描述这条已经可以真实部署、真实复现的路径。

## 当前支持矩阵

| 角色 / 平台 | 状态 | 说明 |
| --- | --- | --- |
| Windows client | 支持 | `netif.backend: tun`，使用 Wintun，要求管理员权限 |
| Linux client | 支持 | TUN + 进程内 `wireguard-go` |
| Linux coordinator | 支持 | gRPC 控制面 |
| Linux relay | 支持 | TURN relay |
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
- Linux relay
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
  - relay：UDP `3478`
  - TURN relay 数据端口：还需要放行一段高位 UDP 端口范围；如果只开放 `3478/udp`，可能会出现 `Conn Type: relay` 但数据面握手仍然失败
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

### 4. 启动 Linux relay

把 `WINK_RELAY_IP` 设成客户端真正会访问到的公网 IP 或内网可达 IP，然后启动 TURN relay：

```bash
export WINK_RELAY_IP=<HOST>
export WINK_TURN_USERS=winkdemo:winkdemo-pass
bash deploy/quickstart/start-relay.sh
```

`deploy/quickstart/start-relay.sh` 默认会把 TURN listener 绑定到 `${WINK_RELAY_IP}:3478`，避免公网部署时继续落到 `0.0.0.0:3478` 这种难排查状态。

等价的显式命令是：

```bash
./bin/wink-relay \
  --listen <HOST>:3478 \
  --realm winkyou \
  --users winkdemo:winkdemo-pass \
  --relay-ip <HOST>
```

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

- 提示 `Wintun is unavailable`：
  - 先安装官方 WireGuard for Windows。
  - 或把 `wintun.dll` 放到 `wink.exe` 同目录。
- 提示需要 `Administrator privileges`：
  - 用管理员 PowerShell 或管理员 CMD 重新运行 `wink.exe up`。
- `peers` 长时间停在 `connecting`：
  - 确认 Linux coordinator 的 TCP `50051` 可达。
  - 确认 Linux relay 的 UDP `3478` 可达。
  - 确认 relay 主机额外放行了一段高位 UDP 端口范围，而不是只开放 `3478/udp`。
  - 确认 `coordinator.auth_key` 与 coordinator 启动参数一致。
  - 确认 Windows 防火墙 / Linux 防火墙没有拦截 `wink.exe` 或 UDP。
  - 如果内置 `wink-relay` 日志里持续出现 `CreatePermission-request ... no allocation found`，先检查 `--listen` 是否绑定到了真实接口 IP；若问题仍在，可先切到 `coturn` 做部署验证。
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

- 这条 README quickstart 只承诺 `Windows client + Linux coordinator + Linux relay + Linux peer`。
- `memory backend` 仍然保留，但只用于测试。
- `userspace` / `proxy` / no-admin 模式当前没有完成，不应作为生产路径使用。
- macOS 目前只标记为实验性，不在本 quickstart 承诺范围内。

## 其他文档

- 部署入口：[`README.md`](./README.md)
- 文档索引：[`docs/README.md`](./docs/README.md)
- 执行基线：[`docs/EXECUTION-BASELINE.md`](./docs/EXECUTION-BASELINE.md)
- 今日部署疑点与专家问题：[`docs/DEPLOYMENT-QUESTIONS-2026-04-15.md`](./docs/DEPLOYMENT-QUESTIONS-2026-04-15.md)
