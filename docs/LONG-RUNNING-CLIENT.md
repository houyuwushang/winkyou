# WinkYou 长期运行客户端

> **2026-07-22 暂停告警：** 本文的通用托管方法不构成重新启用 `autonomous_mesh` cached self-bootstrap 的授权。后续现场构建在失联恢复时引发严重 UDP 五元组/出口会话风暴；该方向短期暂停，`WinkYou-A` 计划任务必须保持禁用，stop marker 必须保留。legacy 模式与自治恢复应分开评估。详见 [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)。

本文说明当前可用的长期运行方式。现阶段不引入新的 service 框架；`wink up` 仍是前台 client 进程，Linux 交给 systemd 管理，Windows 先使用管理员启动项、Task Scheduler 或 NSSM 管理。

源码现在包含两个显式运行模式：默认的 `legacy` coordinator/WireGuard engine，以及默认关闭的 `autonomous_mesh` graph engine。只有配置 `autonomous_mesh.enabled: true` 才会选择后者。该 Slice 4.5 接入已通过全量测试、目标 race、全量 vet、隔离本机 CLI 生命周期，以及 2026-07-19 的 C -> B -> A 三节点 `wink up` 滚动现场验收。三个节点均以 zero seed、无基础设施 coordinator、每节点两条一跳 `protected_direct` packet edge 运行。2026-07-20 先证明新 A generation 可接管硬崩溃遗留的 ULA alias，随后完成 A-only Task Scheduler + child-supervisor 现场迁入：强杀 Wink child 后自动重建 runtime 和直连三角，并通过保持与业务探针。详细边界见 [`SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md`](./SLICE-4.5-FIELD-ROLLOUT-2026-07-19.md)、[`VIRTUAL-TCP-ALIAS-CRASH-RECOVERY-2026-07-20.md`](./VIRTUAL-TCP-ALIAS-CRASH-RECOVERY-2026-07-20.md) 和 [`WINDOWS-SUPERVISOR-FIELD-2026-07-20.md`](./WINDOWS-SUPERVISOR-FIELD-2026-07-20.md)。systemd、A 整机重启、B/C 托管、三节点同时冷启动和公网 IP 变化仍未完成现场验收。

A 的四个 SSH facade 都返回了完整的预期 stdout 或状态 JSON。最初的独立探针在输出留证后立即终止本地 ssh，因此本身不能证明 client-side close；随后 120 秒 output-aware monitor 给每个客户端 500ms 收尾窗口，44 个 SSH 承载的 status/ping/hostname 探针全部自然返回 exit code `0`，同时 Win32-OpenSSH 仍打印 `close - IO is still pending on closed socket`。该字符串应作为客户端关闭警告单独留证，不能单凭它认定 WinkYou stream/FIN 失败；历史 M8 第 627 条真正不退出仍是独立回归测试项。

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

Windows managed autonomous `wink up` 的 `virtual_tcp_forwards` 还使用第二套、独立于 runtime lock 的机器级 alias ownership：每个 ULA 在 `%ProgramData%\WinkYou\system-ingress-ipalias` 下有 durable marker 和永不删除的 lock sidecar。marker 绑定由清理后的绝对 state 路径加 node ID 派生的稳定 scope、完整 virtual-forward 映射集指纹、PID/进程启动身份/instance、随机 token，以及 Windows 地址行创建时间戳。进程崩溃后，只有 scope 和映射集相同、旧进程已死、地址仍为 loopback ActiveStore `/128` 且 `SkipAsSource=true`、地址行未被替换时，新进程才会原位接管。marker 缺失、映射变化、旧进程仍活着或地址行无法验证都会 fail closed，绝不会把未知地址当成自己的地址删除。旧版本留下的 markerless alias 需要先由运维确认并做一次清理。

异常退出时，操作系统会释放 `.runtime.json.lock` 和 alias byte-range locks，但 ActiveStore alias、旧 runtime state 和 ownership marker 会保留；WinkYou 不会在进程死亡后自己拉起自己，必须由外部 supervisor 使用相同 state 路径、node ID 和 virtual-forward 映射集重新启动。地址已经因整机重启而消失但 marker 仍匹配时，源码允许重新创建；该分支有单元测试，但整机重启尚未完成现场验收。

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

Windows legacy Wintun/TUN 和 autonomous `virtual_tcp_forwards` 的临时 ULA alias 都需要相应管理员权限；不配置 virtual facade 的 autonomous graph/loopback TCP 模式不因自身而要求 Wintun。源码现在提供一个 Task Scheduler 安装器和一个小型 PowerShell child supervisor。2026-07-20 已在 A 上完成真实进程强杀验收：任务中的 supervisor 保持运行，在约 5 秒后拉起新 Wink child，强杀后约 9.1 秒内观测到新 runtime state，约 91 秒观测到直连三角恢复并继续保持。整机重启、B/C 等价托管、三节点同时冷启动和公网 IP 变化仍未验收；现场细节见 [`WINDOWS-SUPERVISOR-FIELD-2026-07-20.md`](./WINDOWS-SUPERVISOR-FIELD-2026-07-20.md)。

### Task Scheduler

先运行不修改系统的自测：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-wink-supervised-task.ps1 -SelfTest
```

再以管理员 PowerShell 安装。先把二进制和 supervisor 复制到管理员保护的稳定目录，把配置和状态目录放到受保护的 ProgramData 子目录；不要让 `SYSTEM` 启动项直接执行普通用户可修改的 checkout 文件。下面使用 SID，避免 Windows 显示语言影响 `icacls`：

```powershell
$InstallDir = "C:\Program Files\WinkYou"
$DataDir = "C:\ProgramData\WinkYou"
New-Item -ItemType Directory -Path $InstallDir, $DataDir -Force
icacls $InstallDir /setowner "*S-1-5-32-544"
if ($LASTEXITCODE -ne 0) { throw "failed to set owner on $InstallDir" }
icacls $DataDir /setowner "*S-1-5-32-544"
if ($LASTEXITCODE -ne 0) { throw "failed to set owner on $DataDir" }
icacls $InstallDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX"
if ($LASTEXITCODE -ne 0) { throw "failed to protect $InstallDir" }
icacls $DataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"
if ($LASTEXITCODE -ne 0) { throw "failed to protect $DataDir" }
Copy-Item ".\path\to\wink.exe" "$InstallDir\wink.exe"
Copy-Item ".\scripts\run-wink-supervisor.ps1" "$InstallDir\run-wink-supervisor.ps1"
Copy-Item ".\path\to\config.yaml" "$DataDir\config.yaml"
```

安装器会检查 `wink.exe`、supervisor 和配置文件自身及直接父目录，working directory、state/log/stop/lock 目录，以及已经存在的运行时文件的 owner 和 ACL。默认只信任 `SYSTEM`、内置 `Administrators` 与 `TrustedInstaller` 作为 owner 或可写主体；普通 `Users` 的只读/执行权限可以保留，任何其他主体的写权限或不可解析的可写 ACE 都会拒绝创建 `SYSTEM` 任务。这也防止普通用户预建 stop/lock 或读取 shutdown token。`-AllowUnsafeSystemPaths` 只用于所有本机账号都可信的隔离开发机，或由操作者另行审计过的自定义 ACL，不是默认生产安装方式。所有路径都会规范化成绝对路径；运行配置中的日志、recovery card、secret 等路径也应使用绝对路径，因为任务运行身份是 `SYSTEM`：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\install-wink-supervised-task.ps1 `
  -TaskName "WinkYou-A" `
  -WinkExe "C:\Program Files\WinkYou\wink.exe" `
  -Config "C:\ProgramData\WinkYou\config.yaml" `
  -State "C:\ProgramData\WinkYou\wink.runtime.json" `
  -WorkingDirectory "C:\Program Files\WinkYou" `
  -SupervisorScript "C:\Program Files\WinkYou\run-wink-supervisor.ps1" `
  -StartNow
```

任务 action 不是直接运行 `wink.exe`，而是用 Windows PowerShell 启动 [`run-wink-supervisor.ps1`](../scripts/run-wink-supervisor.ps1)。Task Scheduler 负责 `AtStartup`、`SYSTEM`/最高权限、`MultipleInstances=IgnoreNew` 和无限执行时长；supervisor 等待 Wink child，异常退出后按 `5s -> 10s -> ... -> 60s` 有界退避重启，连续稳定运行五分钟后重置失败计数。独立的 `.supervisor.lock` 还会拒绝手工启动的第二个 supervisor，runtime lock 则继续拒绝第二个 Wink runtime。正常 `wink down` 让 child 返回 `0`，supervisor 也返回 `0`，不会重启。

现场先尝试了让 Task Scheduler 直接运行 Wink，并设置原生 `RestartOnFailure`。强杀 action 后任务记录 `0xFFFFFFFF` 并变成 Ready，但三分钟内没有重启，因此该路径在当前 Windows 主机上明确不作为产品承诺。安装器仍配置少量外层失败重试，但它只是未验收的 best-effort 设置，不能作为 supervisor 自身恢复承诺；真正通过验收的是存活 supervisor 对 Wink child 的秒级重启。

如果旧的前台 `wink up` 还在运行，不要直接加 `-StartNow`：先完成一次正常 `wink down`，再启动任务。安装器会根据 runtime state 拒绝明显仍存活的 PID，`wink up` 自身的 runtime lock 继续作为权威的并发保护。

安装器默认也不会覆盖任何同名任务。只有旧任务可识别为 WinkYou 管理的 supervisor、已经按下文流程停到非 Running 状态，并且显式传入 `-Force` 时才允许重装；无关同名任务和仍在运行的旧 supervisor 都会被拒绝。

配置文件建议：

```yaml
log:
  level: info
  format: text
  output: file
  file: C:\ProgramData\WinkYou\wink.log
```

查看和 `down` 应在管理员 PowerShell 中使用已安装二进制的绝对路径，避免误用 checkout 中的另一个版本：

```powershell
Get-ScheduledTask -TaskName "WinkYou-A"
Get-ScheduledTaskInfo -TaskName "WinkYou-A"
Test-Path "C:\ProgramData\WinkYou\wink.runtime.json.supervisor.stop"
Get-Content "C:\ProgramData\WinkYou\wink.runtime.json.supervisor.log" -Tail 50
$Wink = "C:\Program Files\WinkYou\wink.exe"
& $Wink --config "C:\ProgramData\WinkYou\config.yaml" --state "C:\ProgramData\WinkYou\wink.runtime.json" status
& $Wink --config "C:\ProgramData\WinkYou\config.yaml" --state "C:\ProgramData\WinkYou\wink.runtime.json" peers
& $Wink --config "C:\ProgramData\WinkYou\config.yaml" --state "C:\ProgramData\WinkYou\wink.runtime.json" logs --tail 200
```

临时停止时先禁用任务并写入 stop marker，再在有界循环中使用认证的 graceful down。supervisor 在退避、启动前和 child 运行期间都会观察 marker；循环允许第一次 `down` 恰好命中旧 state。只有任务不再 Running 且 runtime state 中没有仍存活的 PID 才算停稳；超时要保留 marker 并排查，不能直接注销任务：

```powershell
$Task = "WinkYou-A"
$Wink = "C:\Program Files\WinkYou\wink.exe"
$Config = "C:\ProgramData\WinkYou\config.yaml"
$State = "C:\ProgramData\WinkYou\wink.runtime.json"
$StopFile = $State + ".supervisor.stop"
Disable-ScheduledTask -TaskName $Task
New-Item -ItemType File -Path $StopFile -Force
$Deadline = (Get-Date).AddSeconds(90)
do {
  & $Wink --config $Config --state $State down 2>$null
  $RuntimeAlive = Test-Path $State
  if ($RuntimeAlive) {
    try {
      $Runtime = Get-Content $State -Raw | ConvertFrom-Json
      $RuntimeProcess = Get-Process -Id ([int]$Runtime.pid) -ErrorAction SilentlyContinue
      $RuntimeAlive = $null -ne $RuntimeProcess -and
        $RuntimeProcess.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -eq
          [string]$Runtime.process_start_id
    } catch { $RuntimeAlive = $true }
  }
  $TaskRunning = (Get-ScheduledTask -TaskName $Task).State -eq "Running"
  if (-not $TaskRunning -and -not $RuntimeAlive) { break }
  Start-Sleep -Seconds 1
} while ((Get-Date) -lt $Deadline)
if ($TaskRunning -or $RuntimeAlive) {
  throw "WinkYou did not stop within 90 seconds; keep $StopFile and inspect the supervisor log"
}
```

恢复时必须先确认旧 task action 已经退出，然后先删除 marker、再启用并显式启动任务。即使 `StartWhenAvailable` 在 Enable 时已经触发，task 的 `IgnoreNew` 和 supervisor lock 也只会保留一个实例：

```powershell
$Task = "WinkYou-A"
$StopFile = "C:\ProgramData\WinkYou\wink.runtime.json.supervisor.stop"
if ((Get-ScheduledTask -TaskName $Task).State -eq "Running") {
  throw "the old supervisor is still running"
}
Remove-Item $StopFile -Force -ErrorAction SilentlyContinue
Enable-ScheduledTask -TaskName $Task
Start-ScheduledTask -TaskName $Task
```

永久移除是另一条流程：先完成上面的受控停止，并要求 runtime state 已由 graceful down 删除；如果 state 仍在，说明可能留下可恢复的 crash residue，应先恢复一次、等待新 generation 接管，再重新执行受控停止，不能直接注销：

```powershell
$Task = "WinkYou-A"
$State = "C:\ProgramData\WinkYou\wink.runtime.json"
if ((Get-ScheduledTask -TaskName $Task).State -eq "Running") { throw "task is still running" }
if (Test-Path $State) { throw "runtime state remains; recover once and stop gracefully before uninstall" }
Unregister-ScheduledTask -TaskName $Task -Confirm:$false
Remove-Item ($State + ".supervisor.stop"), ($State + ".supervisor.lock") -Force -ErrorAction SilentlyContinue
```

### NSSM

如果偏好 Windows service 管理器，可用 NSSM 包装前台命令：

```powershell
nssm install WinkYou "C:\Program Files\WinkYou\wink.exe" "--config `"C:\ProgramData\WinkYou\config.yaml`" --state `"C:\ProgramData\WinkYou\wink.runtime.json`" up"
nssm set WinkYou AppDirectory "C:\Program Files\WinkYou"
nssm set WinkYou AppStdout "C:\ProgramData\WinkYou\wink.stdout.log"
nssm set WinkYou AppStderr "C:\ProgramData\WinkYou\wink.stderr.log"
nssm start WinkYou
```

如果使用 NSSM，仍建议在 WinkYou 配置里启用 `log.output: file`，这样 `wink logs` 能直接读取项目日志。
