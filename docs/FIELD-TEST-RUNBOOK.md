# WinkYou 首次真实网络 STUN 观测 Runbook

状态：**待维护者具名授权执行**。本文只定义一次有界、可停止、可脱敏的现场实验；合入文档
不等于授权部署、开放防火墙或向公网发包。执行前必须选定具体服务器、执行人、时间窗和
回滚人，并确认 `wink-stund` 与主动 `diagnose` 来自已经评审的同一发布基线。

本实验只验证：不同接入网络能否向维护者控制的 response-only STUN 目标完成有界 Binding
观测；获得独立授权时，还可比较同一服务器 IP 的两个端口在单 socket 短时间窗中的映射
证据。它不运行 birthday punch、自动恢复、ICE、TURN、端口扫描或 daemon 化客户端。

## 1. 数据与网络红线

- 仓库、Issue、PR 和公开聊天中永不写入真实服务器 IP、家庭公网 IP、蜂窝出口 IP、
  hostname、SSID、设备名、账户名或私有拓扑。
- 本文所有地址都使用 TEST-NET 占位符，例如 `203.0.113.10`；实际值只能放在操作者本机、
  仓库外且访问受限的临时记录中。
- `wink diagnose --active-stun ... --json` 的本地输出是 `redaction: partial`，会包含完整
  target 与 mapped endpoint，不能原样提交。公开记录只能使用 strict-redacted 导出，或
  按本文模板人工抄录 `/24`、`/48` 与端口行为分类。
- 基础可达性窗口只开放一个 UDP 端口、只使用一个目标；映射行为窗口必须另行具名授权，
  且只允许同一服务器 IP 上明确列出的两个 UDP 端口。两种窗口都不得扩大为扫描或自动循环。
- `WinkYou-A`、cached self-bootstrap 与 autonomous birthday recovery 必须继续 Disabled。

## 2. 前置检查

### 2.1 服务器

- 一台维护者控制、允许丢弃重建的 Linux 服务器；不与生产业务共用变更窗口。
- 可用的普通 SSH 管理路径和独立于 `wink-stund` 的紧急停止路径。
- 主机防火墙与云厂商安全组均可查看和撤销。
- systemd 可用；若临时使用 nohup，也必须记录精确 PID 和日志路径。
- 服务器时间已同步，磁盘空间和日志轮转正常。

### 2.2 客户端

- Windows 或 Linux 上的 `wink` 包含显式 `--active-stun` 支持。
- 优先准备机器级安全 namespace，并确认没有 safety trip：

```powershell
wink setup-machine-scope --check --json
wink safety status --json
```

若安装机器 scope 不可行，只能在操作者再次明确知情时使用较低权限、非机器级声明：

```powershell
wink diagnose --governor-scope=user-acknowledged --active-stun=203.0.113.10:3478 --json
```

地址是占位符，不能直接运行。authority 被其他进程占用或 safety trip 生效时应停止排查，
不得通过提高上限或绕过 lock 继续。

### 2.3 执行记录

开始前在仓库外创建私有实验记录，至少写明：

- 经授权的操作者和回滚人；
- 服务器资产的内部引用，而非把真实地址复制到仓库；
- 计划开始/结束时间；
- 使用的两个精确 Git SHA；
- UDP 端口（基础窗口一个；映射窗口恰好两个）、全局 PPS 配置和防火墙规则变更单；
- 独立 kill switch：停止 service 加撤销 UDP 入站规则。

## 3. 构建与传输

从干净、已评审的 checkout 交叉编译，不在仓库中保存服务器地址：

```powershell
$env:GOOS = "linux"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -o .\dist\wink-stund-linux-amd64 ./cmd/wink-stund
Get-FileHash .\dist\wink-stund-linux-amd64 -Algorithm SHA256
```

把显示的哈希写入私有实验记录，再传到服务器临时目录：

```powershell
scp .\dist\wink-stund-linux-amd64 <SERVER_USER>@<SERVER_HOST>:/tmp/wink-stund
```

`<SERVER_USER>` 与 `<SERVER_HOST>` 必须只在命令行本地替换，不能把替换后的命令提交。
服务器上复核 SHA-256 后安装：

```bash
sha256sum /tmp/wink-stund
sudo install -o root -g root -m 0755 /tmp/wink-stund /usr/local/bin/wink-stund
/usr/local/bin/wink-stund --version
```

如果目标不是 Linux amd64，应明确改变 `GOARCH` 并重新记录哈希，不能复用未经验证的产物。

## 4. 启动服务

### 4.1 systemd（推荐）

创建不可登录用户：

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin winkyou-stun
```

将真实监听值只写入服务器本地 `/etc/winkyou/wink-stund.env`。下面仍是 TEST-NET 占位：

```text
STUN_LISTEN=203.0.113.10:3478
STUN_MAX_PPS=20
```

首次现场窗口建议把全局值从编译上限 200 主动降到 20。创建
`/etc/systemd/system/wink-stund.service`：

```ini
[Unit]
Description=WinkYou response-only STUN field target
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=winkyou-stun
Group=winkyou-stun
EnvironmentFile=/etc/winkyou/wink-stund.env
ExecStart=/usr/local/bin/wink-stund --listen ${STUN_LISTEN} --max-pps ${STUN_MAX_PPS}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wink-stund
sudo systemctl status --no-pager wink-stund
sudo ss -lunp | grep ':3478'
sudo journalctl -u wink-stund --since '5 minutes ago' --no-pager
```

若监听 `0.0.0.0` 或 `::`，启动 JSON 必须明确出现
`"wildcard_listen":true` 与 `"exposure":"all_interfaces"`。

### 4.2 nohup（仅短时备用）

```bash
nohup /usr/local/bin/wink-stund --listen 203.0.113.10:3478 --max-pps 20 \
  >/dev/null 2>/tmp/wink-stund.jsonl &
echo $! >/tmp/wink-stund.pid
```

这里的地址仍是 TEST-NET 占位。必须确认 PID 只属于该二进制；停止时先发 `TERM`，不得用
模糊的进程名批量终止其他服务。

### 4.3 双端口 systemd template（仅映射行为窗口）

只有第 7 节的映射行为窗口获得独立授权后，才使用两个实例。真实监听地址仍只写入服务器
本地文件；仓库中的模板固定使用同一个 TEST-NET IP 的两个端口：

```bash
sudo install -d -o root -g root -m 0755 /etc/winkyou
sudo tee /etc/winkyou/wink-stund-3478.env >/dev/null <<'EOF'
STUN_LISTEN=203.0.113.10:3478
STUN_MAX_PPS=20
EOF
sudo tee /etc/winkyou/wink-stund-3479.env >/dev/null <<'EOF'
STUN_LISTEN=203.0.113.10:3479
STUN_MAX_PPS=20
EOF
```

创建 `/etc/systemd/system/wink-stund@.service`：

```ini
[Unit]
Description=WinkYou response-only STUN field target on UDP %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=winkyou-stun
Group=winkyou-stun
EnvironmentFile=/etc/winkyou/wink-stund-%i.env
ExecStart=/usr/local/bin/wink-stund --listen ${STUN_LISTEN} --max-pps ${STUN_MAX_PPS}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wink-stund@3478.service wink-stund@3479.service
sudo systemctl status --no-pager wink-stund@3478.service wink-stund@3479.service
sudo ss -lunp | grep -E ':(3478|3479)\b'
```

两个实例必须来自同一已复核 SHA，并分别保持编译期限速、每源限速与默认不记录客户端 IP。
不得通过端口范围或动态实例列表扩大目标集合。

## 5. 放行 UDP：两层都要检查

只选择服务器实际使用的一种主机防火墙。示例端口为 UDP 3478：

```bash
# UFW 示例
sudo ufw allow 3478/udp

# 或 firewalld 示例，不要与上面的命令重复执行
sudo firewall-cmd --permanent --add-port=3478/udp
sudo firewall-cmd --reload
```

然后在云厂商安全组增加同一个 UDP 端口的入站规则。家庭 Wi-Fi 与蜂窝热点出口不同，若
测试窗口必须临时允许任意来源，应只开放这个 UDP 端口、保留全局/每源限速，并在结束时
立即撤销。不得顺带开放 TCP、端口范围或管理端口。

映射行为窗口需要分别放行 UDP 3478 与 3479；必须使用两条精确端口规则，不能改成
`3478:3479` 以外的范围。窗口结束时两条规则都要逐条撤销并复核。

`nc -zvu 203.0.113.10 3478` 只能证明本机命令能够发送一个 UDP datagram；UDP 没有连接
握手，它不能证明防火墙已放行，也不能证明 STUN 应答正确。真正自检必须使用下一节的
`wink diagnose`，并同时观察服务器聚合计数是否增加。

## 6. 基础单目标实测矩阵

每次运行前确认 stderr 出现主动观测隐私提示。相邻运行间隔至少 10 秒，避免把短时间重试
误当作独立样本。原始 JSON 只保存在仓库外的私有临时目录。

| 场景 | 网络切换确认 | 执行次数 | 可能观察到的结果 | 禁止推断 |
|---|---|---:|---|---|
| 家庭宽带 Wi-Fi | 关闭蜂窝数据或确认路由确实走 Wi-Fi | ≥3 | 成功；mapped port 可能 preserved 或 translated；短窗内可能稳定 | 单目标结果不能证明 EIM |
| 手机热点/蜂窝 CGNAT | 客户端只连接热点并确认原 Wi-Fi 已断开 | ≥3 | 成功或有界 timeout；可能 translated；可能存在多层 NAT 或 UDP 限制 | mapped 地址不能证明具体 CGNAT 层数 |

每次只运行一个显式目标：

```powershell
wink diagnose --active-stun=203.0.113.10:3478 --json
```

若只能使用用户级 scope：

```powershell
wink diagnose --governor-scope=user-acknowledged --active-stun=203.0.113.10:3478 --json
```

对每种网络重复 3 次并记录实际开始时间。不要写脚本无限循环；出现资源错误、异常日志增长、
safety trip 或服务器响应计数超出人工运行规模时立即停止 service 并撤销入站规则。

## 7. 映射行为判定（独立授权的双端口窗口）

先完成第 6 节的单目标可达性验证；只有维护者重新确认双端口服务器、客户端、网络和时间
窗后，才进入本节。两个 `wink-stund` 实例必须位于同一个服务器 IP、使用不同端口，例如
占位符 `203.0.113.10:3478` 与 `203.0.113.10:3479`。客户端必须用一条命令显式列出两者：

```powershell
wink diagnose --map-behavior `
  --active-stun=203.0.113.10:3478 `
  --active-stun=203.0.113.10:3479 `
  --json
```

若只能使用用户级 scope，仍需同时显式知情：

```powershell
wink diagnose --governor-scope=user-acknowledged --map-behavior `
  --active-stun=203.0.113.10:3478 `
  --active-stun=203.0.113.10:3479 `
  --json
```

同一网络手工执行 3 次，相邻运行至少间隔 10 秒；不得写无限循环。每次命令内部只建立一个
governed socket，并按 3478、3479 顺序串行观测。三个 behavior 的证据边界如下：

| behavior | 本次短窗能说明什么 | 仍不能说明什么 |
|---|---|---|
| `consistent_same_address` | 同一服务器 IP 的不同端口观察到完全一致的 mapped endpoint；与 EIM 一致 | 不能排除 ADM，不能视为永久 NAT 类型 |
| `port_dependent` | 同一服务器 IP 的不同端口观察到不同 mapped endpoint；存在端口依赖证据 | 不能推断其他时间、网络或服务器地址上的行为 |
| `inconclusive` | 成功目标不足两个或证据不满足同地址多端口比较 | 不能据此选择 birthday punch 或其他激进策略 |

使用同一 IP 时，结果必须同时出现 `address_comparison_unavailable`。这是强制限制标记，
表示缺少第二个服务器 IP，无法区分 EIM 与 ADM；它不是第四种 behavior。若标记缺失、两个
目标没有共享同一本地 endpoint、出现 safety trip，或任一实例计数超过人工规模，应立即
停止两个 service、撤销两个 UDP 入站规则，并回到 loopback/netns 复现。

## 8. 单目标端口分配画像（独立授权）

本节与第 7 节回答不同问题：第 7 节用**一个 socket 对两个目标端口**比较映射行为；本节用
**多个同时保持打开的 socket 对同一个目标端口**观察 NAT 分配的 mapped-port 序列。完成
基础单目标可达性并取得本节的具名授权后，只需保持一个 `wink-stund` 实例和一个精确 UDP
入站规则，不得为画像增加端口范围。

先用最小 K=3 做一次人工运行：

```powershell
wink diagnose --port-allocation=3 `
  --active-stun=203.0.113.10:3478 `
  --json
```

机器级 scope 的资源状态正常时，可在另一个间隔至少 10 秒的窗口使用默认 K=5：

```powershell
wink diagnose --port-allocation `
  --active-stun=203.0.113.10:3478 `
  --json
```

当前 user-acknowledged 编译期硬上限只能容纳 K=3；K=4 至 8 会在开 socket 前因 socket 或
总时长预算被拒绝，不能通过改配置抬高。每条命令内部先打开全部 K 个 governed socket，
再严格串行交换，并在整轮结束后统一关闭。任何 socket 失败都保留为单独结果；不得为了
凑足成功数自动追加 socket 或循环重试。

结果必须同时阅读 `behavior`、`deltas` 和三个 limitation：

- `sequential_uniform`：本窗口的环形增量相同，包括一次 `65535 -> 1` 回绕；
- `monotonic_nonuniform`：严格前进但增量不完全相同；
- `apparently_random`：存在反向/重复或增量离散度超过保守阈值；
- `insufficient_data`：成功数少于 3；
- `single_time_window`、`single_target`、`small_sample_not_permanent_nat_label` 永远保留。

同一网络最多手工执行 3 轮，相邻至少 10 秒。原始 JSON 中 local/mapped endpoint 与端口只
能留在仓库外私有记录。公开摘要可以保留有符号 `deltas` 和 behavior，但必须清除所有原始
local/mapped port，并保留 limitation；这些小样本不能直接转化为 birthday-punch 预测窗口。

## 9. 脱敏记录模板

当前 CLI 主动模式的 `--json` 是本地原始证据，不是可公开报告；stdio
`export_redacted_report` 仍采集被动报告，不能自动携带这次 CLI-only active 结果。除非以后
提供并评审了 active strict-export 命令，否则只能把允许字段人工转录到下表，再由第二人
检查原始地址和端口均未出现。

```markdown
## STUN field observation (redacted)

- client build SHA: <PUBLIC_COMMIT_SHA>
- responder build SHA: <PUBLIC_COMMIT_SHA>
- window UTC: 2026-08-18T00:00:00Z .. 2026-08-18T00:05:00Z
- network class: home_wifi | mobile_hotspot
- trials: 3

| trial | result class | mapping behavior | mapping limitation | target prefix | mapped prefix | port behavior | transmissions | duration bucket |
|---:|---|---|---|---|---|---|---:|---|
| 1 | success | consistent_same_address | address_comparison_unavailable | 203.0.113.0/24 | 198.51.100.0/24 | preserved | 1 | <1s |
| 2 | timeout | inconclusive | address_comparison_unavailable | 203.0.113.0/24 | — | unknown | 3 | 3–4s |
| 3 | protocol_error | not_requested | not_requested | 203.0.113.0/24 | — | unknown | 1 | <1s |

- responder aggregate delta: received=<COUNT>, responded=<COUNT>
- notes: <NO ISP, SSID, HOSTNAME, DEVICE NAME, FULL IP, OR PORT>
```

模板地址全部是 TEST-NET 合成材料，不能用来声称真实结果。IPv4 只允许 `/24`，IPv6 只
允许 `/48`；不得记录 mapped port 数值，只记录 `preserved`、`translated` 或 `unknown`。
原始 JSON 在脱敏核对完成后按维护者的数据保留政策处理，绝不移动进 Git 工作树。

## 10. 故障排查

| 客户端结果/现象 | 先检查 | 可能原因 | 下一步 |
|---|---|---|---|
| `timeout` | service、`ss -lunp`、主机防火墙、云安全组、聚合 received | 入站未到、回程被拦、家庭/蜂窝 UDP 受限、全局限速 | 不增加重试；分层检查规则和服务器计数 |
| `invalid ... literal IP:port` | 命令中的括号、端口和 hostname | 使用了 DNS 名、IPv6 未加 `[]`、端口为 0 | 改为经授权的字面量地址，不加入 DNS fallback |
| `blocked` / authority unavailable | setup check、owner PID、safety status | machine scope 未安装、锁被占用、safety trip | 停止实验；按现有安全文档处理，不能绕过 |
| `protocol_error` | 客户端与 responder SHA、服务器 dropped 分类 | 版本不一致、中间设备改写、目标不是 `wink-stund` | 保留本地原始证据，不公开 IP；回到 loopback/netns 复现 |
| 服务器 received 增加但 responded 不增 | dropped 聚合分类 | 错 cookie/类型/长度、required 属性、源/全局限速 | 不开启报文日志；用离线测试包复现 |
| 服务器完全无计数 | 两层防火墙与监听地址 | 安全组、主机规则、错误网卡绑定、上游 UDP 阻断 | 先修路径，不提高 PPS、不开放端口范围 |
| 家庭成功、热点超时 | 重复 3 次并确认网络切换 | 蜂窝 CGNAT/运营商策略可能限制 UDP | 记录为有界失败；不能直接命名 NAT 类型 |
| mapping 为 `inconclusive` | 两实例状态、逐目标结果、同一本地 endpoint | 一个目标超时/协议错误，或目标没有形成同地址多端口证据 | 保留部分结果，不增加重试、不自动切换打洞策略 |
| 缺少 `address_comparison_unavailable` | 两个目标是否确为同一服务器 IP | 客户端/报告版本不匹配或目标配置错误 | 停止公开记录，回到同 SHA 的 loopback 集成测试 |
| allocation 为 `insufficient_data` | 逐 socket 错误、成功数、server aggregate | 某些 Binding exchange 超时或协议失败 | 保留失败，不追加 socket、不提高 K 或重传上限 |
| allocation 预算拒绝 | K、governor scope、fresh-idle snapshot | user-acknowledged 上限不足或 authority 已被占用 | machine scope 就绪后重开新窗口，不能降低门禁或抬高硬上限 |

## 11. 结束与泄漏检查

实验窗口结束或触发 kill switch 时：

1. 立即停止 responder；
2. 撤销云安全组 UDP 入站规则；
3. 撤销主机防火墙规则；
4. 验证没有监听、进程或自动重启；
5. 只保留经复核的脱敏摘要。

```bash
sudo systemctl disable --now wink-stund
sudo ss -lunp | grep ':3478' || true
pgrep -a -x wink-stund || true

# 按实际使用的防火墙二选一
sudo ufw delete allow 3478/udp
# 或
sudo firewall-cmd --permanent --remove-port=3478/udp
sudo firewall-cmd --reload
```

若启用了双端口 template，还必须逐项停止并撤销第二个端口：

```bash
sudo systemctl disable --now wink-stund@3478.service wink-stund@3479.service
sudo ss -lunp | grep -E ':(3478|3479)\b' || true

# 按实际使用的防火墙二选一，并对两个端口逐条撤销
sudo ufw delete allow 3478/udp
sudo ufw delete allow 3479/udp
# 或
sudo firewall-cmd --permanent --remove-port=3478/udp
sudo firewall-cmd --permanent --remove-port=3479/udp
sudo firewall-cmd --reload
```

若使用 nohup，只能读取 `/tmp/wink-stund.pid`、核验该 PID 的可执行文件确为
`/usr/local/bin/wink-stund` 后发送 `TERM`。不得使用 `pkill -f wink`。

## 12. 完成判据与已知限制

一次现场窗口只有同时满足以下条件才算记录完成：

- 家庭 Wi-Fi 与手机热点各有 3 个有界结果，成功和失败都可以作为证据；
- 基础单目标命令最多发送 3 次；双端口 mapping 命令每目标最多 3 次、总计最多 6 次；
  allocation 命令最多 K 个 socket、每 socket 3 次、总计最多 `3K` 次；服务端未出现超
  编译上限的响应行为；
- 结束后无 `wink-stund` 进程、UDP listener、残留安全组/防火墙规则；
- 公开材料通过第二人隐私检查，只包含前缀和分类；
- 没有触发或恢复任何 autonomous recovery 路径。

默认 `diagnose --active-stun` 仍为每个 target 创建独立 socket，不同 target 的 mapped port
不能用于映射行为判断。只有显式 `--map-behavior` 才提供“单 socket、同地址多端口”的
有限证据；它仍不是完整 RFC 4787 分类。区分 ADM 需要第二个服务器 IP 和新的部署/隐私/
资源评审，不能从本双端口模板自行扩展。任何结果都不能自动恢复 birthday punch。

显式 `--port-allocation` 只提供“同一目标、同一时间窗、K 个同时存活 socket”的端口序列。
即使多轮都为 `sequential_uniform`，也不能证明下一次分配、另一个目标或另一个接入网络仍
使用同一步长，更不能绕过单独的打洞设计评审与 live-network 授权。
