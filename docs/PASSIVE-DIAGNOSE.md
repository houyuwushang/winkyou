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

默认多目标语义保持不变：每个 `--active-stun` 目标各自取得 attempt、建立独立 socket，
所以不同目标的 mapped endpoint 不能用于映射行为比较。只有同时显式给出
`--map-behavior` 与 2 至 3 个目标时，才切换为一个 attempt、一个 governed socket、按
输入顺序串行交换：

```powershell
wink diagnose --map-behavior `
  --active-stun=203.0.113.10:3478 `
  --active-stun=203.0.113.10:3479 `
  --json
```

mapping 模式不接受单个目标，也不在同一个 socket 中混用 IPv4 与 IPv6 目标。所有目标
仍须是去重后的字面量 unicast `IP:port`，并在被动采集、authority 获取和网络 I/O 前完成
CLI 校验。地址仍是 TEST-NET 占位符，不能直接当作可用服务运行。

端口分配画像使用相反的受控形状：恰好一个目标、3 至 8 个同时保持打开的 governed
socket，并按 socket 顺序串行交换。flag 没有显式值时 K 默认为 5：

```powershell
wink diagnose --port-allocation=3 --active-stun=203.0.113.10:3478 --json
wink diagnose --port-allocation --active-stun=203.0.113.10:3478 --json
```

`--port-allocation` 与 `--map-behavior` 互斥。所有 socket 都保持打开到整轮结束，避免关闭
前一个 socket 后 NAT 复用端口污染序列；任一 exchange 失败仍保留并继续后续 socket。

主动路径有三项必须同时成立：

- CLI 存在显式 `--active-stun`，且所有目标在任何网络 I/O 前完成字面量和数量校验；
- 取得机器级 governor lock，或用户同时显式选择 `--governor-scope=user-acknowledged`；
- 默认模式在开 socket 前验证 `N × WorstCaseCost`，随后每个目标各自取得 AttemptLease，
  经 `probeio` 与 `stunobserve.Client` 串行执行；mapping 模式改为一次验证完整的
  `MappingWorstCaseCost(N)`，只取得一个 AttemptLease 并调用 `MappingClient`；端口分配
  模式验证 `AllocationWorstCaseCost(K)`，同样只取得一个 AttemptLease 并调用
  `AllocationClient`。

每个目标最坏占用 1 socket、1 target、1 five-tuple、2 packets/s、最多 3 个包和 4 秒；
三个目标的整次命令预检为 3 sockets、3 targets、3 five-tuples、6 packets/s、9 个包和
12 秒。目标仍是串行执行，汇总值用于先验拒绝而不是放大瞬时发包能力。任一 authority、
safety trip 或总预算问题都会 fail-closed；预算拒绝发生在 socket 创建之前。

mapping 模式的 2/3 目标成本分别为：1 socket、2/3 targets、2/3 five-tuples、3/4
packets/s、6/9 个包和 8/12 秒。`N+1` PPS 是滑动一秒窗口的最坏预留：某目标可能在
第二次发送后立即成功，余下目标随后各完成第一次发送；目标本身仍严格串行。

allocation 模式声明 K sockets、1 unique target、K five-tuples、`K+1` packets/s、最多
`3K` 个包和 `4K` 秒。机器 scope 支持 K=3..8；当前 user-acknowledged 硬上限只能容纳
K=3，其他 K 在开 socket 前 fail-closed，不能通过运行时配置抬高。

启用时 stderr 会先明确提示：目标会观察到本机源 IP 与观测时间信息。报告中的每条结果
只说明该次 `time_window_only` 时间窗，包含映射地址或稳定错误类、耗时、发送次数和端口
保持/转换行为；它不是永久 NAT 标签。调用方可以完全不使用此参数，且 stdio JSON-RPC
的 `diagnose` 方法仍只走被动路径。

mapping JSON 位于 `active_stun.mapping_behavior`，把 `behavior`、`evidence_scope`、
`limitations`、成功目标数和逐目标结果放在同一个对象中。当前 behavior 只有
`consistent_same_address`、`port_dependent`、`inconclusive`；同一服务器 IP 的多端口
比较必须同时保留 `address_comparison_unavailable`，因为它不能排除 ADM，也不等于完整
RFC 4787 分类。该字段不会进入 stdio v1；stdio 对 `map_behavior` 参数继续返回
`invalid_params`。

allocation JSON 位于 `active_stun.port_allocation`，把 `behavior`、`evidence_scope`、
三个强制 limitation、成功/总 socket 数、有符号相邻 `deltas` 和逐 socket 结果放在一个
对象中。四个 behavior 是 `sequential_uniform`、`monotonic_nonuniform`、
`apparently_random`、`insufficient_data`；它们只描述单目标、单时间窗、最多 8 个样本，
不会自动改变连接策略。stdio v1 对 `port_allocation` 参数同样返回 `invalid_params`。

## 隐私状态

schema 为 `winkyou.diagnose/v1alpha1`，本地输出声明 `redaction: partial`。原始接口地址、
MAC、网关地址和配置值仍被省略；显式主动模式的本地 `--json` 会保留完整目标与映射地址，
因此发布前必须审阅。`export_redacted_report` 的 strict 形式会移除完整 STUN endpoint：
IPv4 只保留 `/24`、IPv6 只保留 `/48`，并保留 `preserved` / `translated` 端口行为分类，
不保留完整映射地址或映射端口。mapping report 的 behavior、evidence scope 与 limitation
原样保留，嵌套的逐目标 endpoint 继续应用相同 `/24`、`/48` 规则。
allocation strict redaction 对 local、target、mapped endpoint 采用同一前缀规则并清除所有
原始端口；classification、limitations 与端口差值序列保留，且返回值拥有独立切片。
