# WinkYou 长期运行客户端

本文说明当前可用的长期运行方式。现阶段不引入新的 service 框架；`wink up` 仍是前台 client 进程，Linux 交给 systemd 管理，Windows 先使用管理员启动项、Task Scheduler 或 NSSM 管理。

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

`wink up` 会保持运行并持续刷新 runtime state。`wink down` 会尝试结束对应 PID 并清理 runtime state。`status`、`peers`、`doctor` 读取同一份 runtime state。

如果配置文件和状态文件需要分开存放，使用全局 `--state`：

```bash
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json up
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json status
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json down
```

默认状态路径仍保持兼容：不传 `--state` 时，runtime state 放在 config 同目录，文件名为 `<config-base>.runtime.json`。

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

排查：

```bash
journalctl -u wink -f
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json status
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json peers
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json logs --tail 200
wink --config /etc/wink/config.yaml --state /var/lib/wink/wink.runtime.json doctor
```

TUN/WireGuard userspace 后端通常需要 `/dev/net/tun` 和 `CAP_NET_ADMIN`。示例 unit 已设置 `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`；如果发行版或安全策略仍阻止创建 TUN，请先用 `wink doctor` 检查本地接口层。

## Windows 启动项

Windows 需要管理员权限才能稳定使用 Wintun/TUN。当前建议两种方式：

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
wink --config "$env:APPDATA\wink\config.yaml" --state "$env:APPDATA\wink\wink.runtime.json" down
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
