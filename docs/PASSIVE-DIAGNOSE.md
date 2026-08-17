# Phase 1a diagnose（默认被动，可显式启用 STUN 观测）

`wink diagnose` 是 v2 计划的首次运行入口。默认行为仍是零发包的被动诊断；它与旧版
`wink doctor` 分离，后者的 coordinator、STUN 与可选 TCP 检查可能产生主动网络活动。

```powershell
wink diagnose
wink diagnose --json
```

不带 `--active-stun` 时，命令不要求配置文件或已安装的机器 scope，也不会打开 socket。
scope 缺失或不安全会进入报告，而不会丢弃其他本地证据。只要能生成报告，命令就成功
退出；`active_probe` 小节继续 fail-closed。现有默认 JSON 字段和文本结尾保持不变。

受限的便携用户可以显式证明独立、额度更低的 per-user authority：

```powershell
wink diagnose --governor-scope=user-acknowledged
wink diagnose --governor-scope=user-acknowledged --json
```

该本地参数是 user-acknowledged scope 的唯一激活路径。它不能来自配置、环境变量、持久化
状态、JSON-RPC、coordinator 或 peer 输入，也不会被记住为默认值。使用时会向 stderr
打印“非机器级安全”的警告。

## 被动证据

当前报告包含：

- build and operating-system identity;
- canonical selected namespace validation and, in explicit user mode, the
  separate machine namespace state;
- actual OS lock state plus best-effort owner PID, instance, build, and scope;
- safety-trip state (machine-persistent for machine scope; subject to the
  documented OS-user runtime lifecycle for explicit user scope);
- configuration presence and validation state, without configuration values;
- local interface names, flags, MTU, and address classes, without IP or MAC
  addresses; and
- the IPv4 default-route interface, without the gateway address.

Windows 通过有界的 `Get-NetRoute` 子进程读取默认路由，Linux 从 `/proc/net/route`
读取；两者都不会修改路由。锁检查只会短暂取得并释放空闲 OS 锁以证明其可用，不会创建
instance ID 或改写 owner metadata。

显式 user 模式是上述只读属性的例外：打印警告后，它可以创建受保护的 canonical
per-user 文件、取得锁、写入诊断 owner metadata 并释放。这仍只是本地文件系统安全设置，
不会启动网络活动。报告会记录取得/释放结果、编译期 allowlist 与硬上限，并说明该
authority 既非机器级，也不是持久默认值。参见
[`USER-ACKNOWLEDGED-SCOPE.md`](./USER-ACKNOWLEDGED-SCOPE.md)。

## 默认主动探测边界

不带 `--active-stun` 时始终报告：

```text
active_probe.state = active_probe_blocked
network_activity_started = false
```

reason 与 action 会区分机器 scope 缺失/不安全、已有 owner、safety trip、无效配置和
`passive_only` 边界。缺失 scope 会返回可复制的修复命令：

```text
wink setup-machine-scope
```

不存在静默的 per-user 或 per-directory fallback。显式 `user-acknowledged` 基础已经
存在；在默认被动路径中，成功的 scope 证明仍以 `user_acknowledged_passive_only` 结束，
不安全或被占用的 scope 报告为 `user_acknowledged_scope_unavailable`。它不会自动转入
STUN、connect-test、恢复或其他网络行为。

## 显式主动 STUN 模式

只有调用方逐个给出字面量 `IP:port` 时才启用 STUN Binding 观测；不接受 DNS 名称，
最多三个目标，目标按给定顺序串行执行：

```powershell
wink diagnose --active-stun=127.0.0.1:3478
wink diagnose --active-stun=192.0.2.10:3478 --active-stun=198.51.100.20:3478 --json
```

上例仅使用 loopback 与文档专用 TEST-NET 地址，不代表可用公共服务。项目不内置公共
STUN 地址，也不会替用户选择目标。真实公网目标的首次运行仍需维护者具名授权，本批次
没有执行此类运行。

主动路径有三项必须同时成立：

- CLI 存在显式 `--active-stun`，且所有目标在任何网络 I/O 前完成字面量和数量校验；
- 取得机器级 governor lock，或用户同时显式选择 `--governor-scope=user-acknowledged`；
- 在开 socket 前验证 `N × WorstCaseCost`，随后每个目标各自取得 AttemptLease，经
  `probeio` 与 `stunobserve.Client` 串行执行。

每个目标最坏占用 1 socket、1 target、1 five-tuple、2 packets/s、最多 3 个包和 4 秒；
三个目标的整次命令预检为 3 sockets、3 targets、3 five-tuples、6 packets/s、9 个包和
12 秒。目标仍是串行执行，汇总值用于先验拒绝而不是放大瞬时发包能力。任一 authority、
safety trip 或总预算问题都会 fail-closed；预算拒绝发生在 socket 创建之前。

启用时 stderr 会先明确提示：目标会观察到本机源 IP 与观测时间信息。报告中的每条结果
只说明该次 `time_window_only` 时间窗，包含映射地址或稳定错误类、耗时、发送次数和端口
保持/转换行为；它不是永久 NAT 标签。调用方可以完全不使用此参数，且 stdio JSON-RPC
的 `diagnose` 方法仍只走被动路径。

## 隐私状态

schema 为 `winkyou.diagnose/v1alpha1`，本地输出声明 `redaction: partial`。原始接口地址、
MAC、网关地址和配置值仍被省略；显式主动模式的本地 `--json` 会保留完整目标与映射地址，
因此发布前必须审阅。`export_redacted_report` 的 strict 形式会移除完整 STUN endpoint：
IPv4 只保留 `/24`、IPv6 只保留 `/48`，并保留 `preserved` / `translated` 端口行为分类，
不保留完整映射地址或映射端口。
