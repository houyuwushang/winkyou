# WinkYou 长期运行客户端

本文说明当前可用的长期运行方式。现阶段不引入新的 service 框架；`wink up` 仍是前台 client 进程，Linux 交给 systemd 管理，Windows 先使用管理员启动项、Task Scheduler 或 NSSM 管理。

源码现在包含两个显式运行模式：默认的 `legacy` coordinator/WireGuard engine，以及默认关闭的 `autonomous_mesh` graph engine。只有配置 `autonomous_mesh.enabled: true` 才会选择后者。该 Slice 4.5 接入已通过全量测试、目标 race、全量 vet 和隔离本机 CLI 生命周期验收；它尚未滚动部署到现有现场节点，也未完成 systemd、Task Scheduler、NSSM 或整机重启验收。不要因为本节存在就替换当前运行中的实验进程。

## CLI 工作流

常用命令：

```bash
wink --config <config.yaml> up
wink --config <config.yaml> down
wink --config <config.yaml> status
wink --config <config.yaml> peers
wink --config <config.yaml> logs
wink --config <config.yaml> doctor
```

`wink up` 会保持运行并持续刷新 runtime state。`status`、`peers`、`doctor` 读取同一份 runtime state。autonomous runtime 会把随机 instance ID、进程启动身份、随机 shutdown token 和实际 loopback control endpoint 写入权限收紧且原子替换的状态文件；稳定的 `.runtime.json.lock` sidecar 在整个进程生命周期持有 OS 文件锁，阻止同一路径双重启动，进程异常退出时由操作系统释放。`status --json` 会删除 token 后再输出。

`wink down` 对 autonomous runtime 先核对 runtime state 中的 PID、进程启动身份和 instance ID，再发送带 token 的 loopback `POST /v1/shutdown`，等待运行时关闭 listener、TCP facade、地址别名并删除自己的状态文件。优雅停止失败时命令返回错误且保留状态，便于排查；即使显式传入 `wink down --force`，受管 autonomous runtime 也不会退回裸 PID 强杀。没有 managed control endpoint 的 legacy runtime 只能使用兼容 PID 停止路径；现在必须显式传入 `--force`，终止失败或无法确认退出时会保留状态并返回错误。

如果配置文件和状态文件需要分开存放，使用全局 `--state`：

```bash
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json up
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json status
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json down
```

默认状态路径仍保持兼容：不传 `--state` 时，runtime state 放在 config 同目录，文件名为 `<config-base>.runtime.json`。

## Autonomous mesh 配置

下面的值只演示结构；`.invalid` 域名、ULA、节点名和端口不是现场部署信息：

```yaml
node:
  name: demo-a

nat:
  stun_servers:
    - stun:stun.example.invalid:3478

autonomous_mesh:
  enabled: true
  node_id: demo-a
  virtual_ip: fd7a:115c:a1e0::a
  listen: 0.0.0.0:32100
  control_listen: 127.0.0.1:32110

  bootstrap_peers:
    - node_id: demo-b
      address: mesh-b.example.invalid:32100

  maintain_peers:
    - demo-b
  recovery_card: ./demo-a-recovery.json
  recovery_debounce: 500ms
  self_bootstrap_secret_file: ./mesh.secret

  tcp_target: 127.0.0.1:8022
  tcp_forwards:
    - listen: 127.0.0.1:22022
      remote_id: demo-b
  virtual_tcp_forwards:
    - listen: "[fd7a:115c:a1e0::b]:22"
      remote_id: demo-b
```

字段边界：

- `node_id` 是稳定 mesh 身份；`node.name` 只是显示名。
- `virtual_ip` 当前必须显式填写 numeric IPv6 ULA。它是成员记录和 selected-port facade 使用的节点地址，不表示已经存在透明系统 L3。
- `listen` 是可选 bootstrap stream listener，可设为 `off`；`bootstrap_peers` 是类型化初始 seed，不是永久数据 relay。
- `maintain_peers` 应在成对节点上对称声明。配置了 `recovery_card` 时至少要有一个 maintained peer；secret 文件是可选的当前可信节点认证输入。
- `recovery_debounce` 控制拓扑收敛后启动直连边修复前的等待时间，默认 `250ms`；现场迁移可显式填写 `500ms` 以保持原实验进程的行为。
- `control_listen` 在 enabled 模式下必填且必须是 loopback。`127.0.0.1:0` 适合本地冒烟，由 runtime state 记录实际端口；长期服务应使用经过冲突检查的固定 loopback 端口。
- `tcp_target` 和普通 `tcp_forwards` 必须使用 loopback；`virtual_tcp_forwards` 必须使用远端成员的 ULA。三类字段仍是 fixed-target/selected-port 用户态 facade。
- autonomous engine 复用 `nat.stun_servers`，但不会构造 legacy coordinator client、netif/Wintun 或 WireGuard tunnel。旧字段仍被加载以保持配置兼容，不应把它们的存在误认为本次 autonomous runtime 已使用。

这一步没有任意 TCP/UDP/ICMP、透明 L3、子网发布或出口节点能力。Slice 5 的 WinkYou-owned packet ingress/egress backend 仍是后续工作。

## 不影响现场进程的本机验收

先创建独立配置 `demo-autonomous.yaml`：

```yaml
node:
  name: demo-a

autonomous_mesh:
  enabled: true
  node_id: demo-a
  virtual_ip: fd7a:115c:a1e0::a
  listen: off
  control_listen: 127.0.0.1:0
```

使用一个新的状态路径；不要复用现场 config、state、recovery card 或端口。终端一保持前台运行：

```bash
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json up
```

终端二验收：

```bash
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json status
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json status --json
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json peers
go run ./cmd/wink --config ./demo-autonomous.yaml --state ./demo-autonomous.runtime.json down
```

应看到：

- `Mode: autonomous_mesh`、`Backend: userspace-mesh`；
- `Infra Coord: not started`，并显示实际 loopback control 地址；
- 单节点 `peers` 为空是正常结果；
- `status --json` 不含 `shutdown_token`；
- `down` 输出 `gracefully stopped`，状态文件随后消失。

2026-07-19 已按该配置完成实际本机冒烟：动态 control 端口成功发布，第二个 `up` 以非零退出码被 sidecar 锁拒绝，`status`/`peers` 正常，JSON 不含 token，认证 `down` 后临时进程和 state 均消失；`.lock` 文件保留是正确行为，既有现场进程未被停止。

源码回归命令：

```bash
go test ./... -count=1
go test -race ./pkg/config ./pkg/meshruntime ./pkg/processidentity ./pkg/client ./cmd/wink/cmd -count=1
go vet ./...
```

## 路径约定

普通用户运行：

- Linux config：`~/.wink/config.yaml`
- Linux runtime state：`~/.wink/config.runtime.json`
- Windows config：`%APPDATA%\wink\config.yaml`
- Windows runtime state：`%APPDATA%\wink\config.runtime.json`

系统服务运行：

- Linux config：`/etc/wink/config.yaml`
- Linux runtime state：`/var/lib/wink/wink.runtime.json`
- Linux log：`/var/log/wink/wink.log`

Windows 启动项运行：

- Windows config：`%APPDATA%\wink\config.yaml`
- Windows runtime state：`%APPDATA%\wink\wink.runtime.json`
- Windows log：`%APPDATA%\wink\wink.log`

## 文件日志

配置文件中启用：

```yaml
log:
  level: info
  format: text
  output: file
  file: /var/log/wink/wink.log
```

Windows 示例：

```yaml
log:
  level: info
  format: text
  output: file
  file: C:\Users\<you>\AppData\Roaming\wink\wink.log
```

查看最近日志：

```bash
wink --config /etc/wink/config.yaml logs --tail 200
wink logs --path /var/log/wink/wink.log --tail 50
```

日志轮转建议：

- Linux：用系统 `logrotate` 管理 `/var/log/wink/*.log`。
- Windows：先使用 NSSM 或 Task Scheduler 的进程管理能力；文件轮转可交给外部脚本定期归档。

## Linux systemd

仓库提供示例 unit：

```text
deploy/systemd/wink.service
```

安装示例：

```bash
sudo useradd --system --home /var/lib/wink --shell /usr/sbin/nologin wink || true
sudo install -d -o wink -g wink -m 0750 /var/lib/wink
sudo install -d -o wink -g wink -m 0750 /var/log/wink
sudo install -d -o root -g wink -m 0750 /etc/wink
sudo install -m 0755 bin/wink /usr/local/bin/wink
sudo install -m 0644 deploy/systemd/wink.service /etc/systemd/system/wink.service
sudo install -o root -g wink -m 0640 config.yaml /etc/wink/config.yaml
```

服务配置建议使用文件日志：

```yaml
log:
  level: info
  format: text
  output: file
  file: /var/log/wink/wink.log
```

启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wink
sudo systemctl status wink
```

示例 unit 的 `ExecStop` 带 `--force`，用于兼容默认 legacy PID 停止路径；若配置启用了 managed autonomous runtime，该参数不会绕过进程身份、instance ID 或 shutdown token 校验，仍只执行认证优雅停止。

排查：

```bash
journalctl -u wink -f
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json status
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json peers
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json logs --tail 200
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json doctor
```

TUN/WireGuard userspace 后端通常需要 `/dev/net/tun` 和 `CAP_NET_ADMIN`。示例 unit 已设置 `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`；如果发行版或安全策略仍阻止创建 TUN，请先用 `wink doctor` 检查本地接口层。纯 autonomous graph/loopback TCP 模式本身不创建 legacy TUN/WireGuard，但 advertised subnet、出口节点和未来系统 packet backend 会重新引入相应系统权限。当前 unit 尚未作为 autonomous OS-autostart 现场结果验收。

## Windows 启动项

Windows legacy Wintun/TUN 和 autonomous `virtual_tcp_forwards` 的临时 ULA alias 都需要相应管理员权限；不配置 virtual facade 的 autonomous graph/loopback TCP 模式不因自身而要求 Wintun。当前建议两种进程托管方式，但启用 autonomous 自动启动前仍应先完成上面的独立状态文件冒烟：

### Task Scheduler

以管理员 PowerShell 执行：

```powershell
$WinkExe = "C:\Program Files\WinkYou\wink.exe"
$Config = "$env:APPDATA\wink\config.yaml"
$State = "$env:APPDATA\wink\wink.runtime.json"
$Args = "--config `"$Config`" --state `"$State`" up"

$Action = New-ScheduledTaskAction -Execute $WinkExe -Argument $Args
$Trigger = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
Register-ScheduledTask -TaskName "WinkYou" -Action $Action -Trigger $Trigger -Principal $Principal -Description "Start WinkYou client at logon"
```

配置文件建议：

```yaml
log:
  level: info
  format: text
  output: file
  file: C:\Users\<you>\AppData\Roaming\wink\wink.log
```

查看：

```powershell
wink --config "$env:APPDATA\wink\config.yaml" --state "$env:APPDATA\wink\wink.runtime.json" status
wink --config "$env:APPDATA\wink\config.yaml" --state "$env:APPDATA\wink\wink.runtime.json" peers
wink --config "$env:APPDATA\wink\config.yaml" --state "$env:APPDATA\wink\wink.runtime.json" logs --tail 200
```

停止：

```powershell
wink --config "$env:APPDATA\wink\config.yaml" --state "$env:APPDATA\wink\wink.runtime.json" down --force
Unregister-ScheduledTask -TaskName "WinkYou" -Confirm:$false
```

### NSSM

如果偏好 Windows service 管理器，可用 NSSM 包装前台命令：

```powershell
nssm install WinkYou "C:\Program Files\WinkYou\wink.exe" "--config `"$env:APPDATA\wink\config.yaml`" --state `"$env:APPDATA\wink\wink.runtime.json`" up"
nssm set WinkYou AppDirectory "C:\Program Files\WinkYou"
nssm set WinkYou AppStdout "$env:APPDATA\wink\wink.stdout.log"
nssm set WinkYou AppStderr "$env:APPDATA\wink\wink.stderr.log"
nssm start WinkYou
```

如果使用 NSSM，仍建议在 WinkYou 配置里启用 `log.output: file`，这样 `wink logs` 能直接读取项目日志。
