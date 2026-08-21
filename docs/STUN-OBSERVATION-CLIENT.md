# STUN Binding 观测客户端（Phase 1a loopback 切片）

## 状态与用途

`internal/stunobserve` 实现 RFC 8489 的最小 Binding 客户端子集，用于在一个
短时间窗口内陈述“该 socket 对该 STUN 目标观察到了什么”。它不推断或持久化 NAT
类型。单目标 `Client` 已由显式主动 diagnose 使用；`MappingClient` 只接入同样显式的
`--map-behavior` CLI；`AllocationClient` 只接入 `--port-allocation`。三者都不进入 stdio
API、连接策略或 daemon。

客户端和生产 adapter 的默认值仍只允许 loopback。显式 `AllowNonLoopback` 与
`AllowedTargetScopeUnicast` 只放开字面 unicast endpoint，并把本地绑定限制为未指定
地址的临时端口；它们本身不构成 live-network 授权。本文中的 `127.0.0.1` 仅表示
本机测试应答器；真实 STUN 目标仍属于调用入口的单独授权边界。

## 协议范围

客户端只发送无属性的 Binding Request，并只接受对应事务的 Binding Success
Response。它校验 magic cookie、事务 ID、响应源、消息长度和属性四字节填充，优先
使用 `XOR-MAPPED-ADDRESS`，缺失时回退到 `MAPPED-ADDRESS`。未知
comprehension-optional 属性被忽略；未知 comprehension-required 属性被拒绝。

MESSAGE-INTEGRITY、认证、Binding Error、TURN、ICE 以及其他 STUN 方法均不在本
切片内。客户端不依赖 Pion STUN，也不能取得 `net.PacketConn`、`*net.UDPConn`、
文件描述符或其他原始网络能力。

## 最坏成本契约

每个 `Client` 只能执行一次观测，并在返回前关闭整个 probeio controller：

| 资源 | 编译期声明 |
| --- | ---: |
| socket | 1 |
| target | 1 |
| 新五元组 | 1 |
| 每秒发送包数 | 2 |
| 总发送包数 | 3 |
| 最大持续时间 | 4 秒 |
| heavyweight | false |

重传 RTO 从 500 ms 开始并按 `500 ms -> 1 s -> 2 s` 递增；最多发送三次。构造
客户端前会核验 `AttemptLease` 已覆盖 `WorstCaseCost()`，不足时直接返回
`ErrInsufficientBudget`，不会尝试开 socket 或发送；若运行期预算拒绝被表达为观测
结果，则使用稳定错误类 `budget_rejected`。

`MappingClient` 在同一个 attempt 和同一个 governed socket 上，按给定顺序串行观测
2 至 3 个不同 endpoint。所有 endpoint 会在第一次发送前完成校验和 target/five-tuple
登记；一个目标超时或返回协议错误不会抹掉此前结果，也不会阻止下一个目标。它的聚合
成本由 `MappingWorstCaseCost(N)` 在构造前验证：

| 目标数 | socket | target / 新五元组 | 每秒发送包数 | 总发送包数 | 最大持续时间 |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2 | 1 | 2 | 3 | 6 | 8 秒 |
| 3 | 1 | 3 | 4 | 9 | 12 秒 |

每秒发送上限不是简单沿用单目标的 2：前一个目标可能在第二次发送后立即成功，剩余目标
随即各发送第一次请求，因此滑动一秒窗口的最坏值为 `N+1`。这只是预留上限，不改变
目标间“严格串行、无并发”的执行语义。

`AllocationClient` 对一个目标预先打开 K 个 governed socket（`3 <= K <= 8`），逐个登记
同一目标，再串行执行 K 次 Binding exchange。所有 socket 必须保持打开到整轮结束后才
统一关闭：如果前一个 socket 提前关闭，NAT 可能立即复用其映射端口，所得序列就不再能
说明“同时存活的多个本地 socket”对应的端口分配行为。单次 exchange 的协议错误或超时会
保留在对应结果中，并继续后续 socket；socket 创建、登记或清理失败仍按 attempt 级错误
fail-closed。

构造前由 `AllocationWorstCaseCost(K)` 验证完整预算：

| K | socket | unique target | 新五元组 | 每秒发送包数 | 总发送包数 | 最大持续时间 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3 | 3 | 1 | 3 | 4 | 9 | 12 秒 |
| 5（CLI 默认） | 5 | 1 | 5 | 6 | 15 | 20 秒 |
| 8 | 8 | 1 | 8 | 9 | 24 | 32 秒 |

K 个目标首次发送可能都落入同一个滑动一秒窗口；一次重传之后还可能立即开始后续首次
发送，因此 PPS 预留为 `K+1`，不是把 K 个 socket 并发发送。默认值 5 超过当前
user-acknowledged scope 的 socket/时长硬上限，会在开 socket 前拒绝；该 scope 只有 K=3
可能通过编译期预算，且仍需显式知情选择。

## 单地址多端口映射证据

`ClassifyMapping` 是不进行 I/O 的纯函数，只对“同一服务器地址、不同 UDP 端口”形成的
短时间窗口证据分类：

| behavior | 含义 | 不得推导出的结论 |
| --- | --- | --- |
| `consistent_same_address` | 至少两个成功目标位于同一 IP 的不同端口，且所有成功结果的 mapped endpoint 完全一致；该证据与 EIM 一致 | 不能排除 ADM；需要第二个服务器 IP 才能比较地址依赖性 |
| `port_dependent` | 同一 IP 的不同目标端口得到不同 mapped endpoint；观测到端口依赖 | 不是节点的永久 NAT 标签，也不代表所有网络路径都相同 |
| `inconclusive` | 成功目标少于两个，或现有结果不能形成同地址多端口比较 | 不能据此选择激进打洞策略 |

当本次配置的目标全部属于同一个 IP 时，分类必须同时保留限制标记
`address_comparison_unavailable`。这个标记不是第四种 mapping behavior；它明确说明
当前证据无法区分 EIM 与 ADM。完整 RFC 4787 分类仍需要第二个服务器地址、独立评审的
测试设计和新的现场授权。

## 单目标多 socket 端口分配证据

`ClassifyAllocation` 是纯函数，只使用成功结果按观测时间排序后的 mapped port，并保留
相邻端口的**有符号原始差值**供人工复核。分类范围固定为
`single_target_multiple_sockets`：

| behavior | 本次样本的含义 | 不能推出的结论 |
| --- | --- | --- |
| `sequential_uniform` | 至少 3 个成功样本的正向环形增量完全相等；允许一次 `65535 -> 1` 回绕 | 不保证下一次或另一个目标仍保持该步长 |
| `monotonic_nonuniform` | 至多一次回绕、严格前进，但增量不相等且离散度未超过保守阈值 | 不能直接据此选择预测窗口 |
| `apparently_random` | 出现重复/多次反向变化，或归一化增量的变异系数大于 0.5 | “apparently” 只描述小样本，不能证明真正随机 |
| `insufficient_data` | 成功 socket 少于 3 | 失败样本仍保留，但不能分类端口分配 |

回绕计算使用端口环 `1..65535`；报告中的 `deltas` 保持普通有符号差值，因此回绕会显示为
一个大的负数，而不会被隐藏。每个结果强制携带 `single_time_window`、`single_target`、
`small_sample_not_permanent_nat_label` 三个限制。K 最大只有 8，这些枚举都不是永久 NAT
标签、端口预测保证或自动启用 birthday punch 的依据。

## diagnose 接线边界

`wink diagnose --map-behavior` 必须与 2 至 3 个去重后的字面量
`--active-stun=IP:port` 同用，并要求所有目标属于同一个地址族。该模式仍先验证 safety
trip、fresh-idle authority 与完整 `MappingWorstCaseCost(N)`，随后只取得一个 attempt、
打开一个 socket 并串行观测。省略 `--map-behavior` 时，现有“每目标独立 attempt 与
socket”的主动 STUN 行为不变；完全省略 `--active-stun` 时仍是零网络活动的被动诊断。

报告把行为、证据范围、限制标记和逐目标结果放在
`active_stun.mapping_behavior` 下。strict redaction 保留行为与限制标记，但完整 target、
mapped address 和端口会被移除，只留下 IPv4 `/24` 或 IPv6 `/48`。stdio v1 不接受
`map_behavior` 参数，也不会从被动 diagnose 结果中产生该字段。

`wink diagnose --port-allocation[=K]` 要求恰好一个 `--active-stun=IP:port`，K 为 3 至 8；
省略 flag 的值时使用 5。它与 `--map-behavior` 互斥，并沿用同一 disclosure、safety trip、
fresh-idle authority、machine/user-acknowledged 与预算先验门禁。报告位于
`active_stun.port_allocation`，包含分类、证据范围、限制、成功数、有符号增量和逐 socket
结果。strict redaction 清除 local、target、mapped 的完整 endpoint 与原始端口，只保留
地址 `/24` 或 `/48` 前缀，同时保留分类与增量。端口差值本身不作为节点身份信息，但公开
材料仍必须连同证据限制一起审阅。stdio v1 拒绝 `port_allocation` 参数，且其被动报告不会
产生该字段。

## 输出语义

结果是 `solver.Observation`：包含观测开始/结束时间、STUN 目标、本地受控 socket、
发送次数、映射地址或稳定错误类。当前稳定错误类包括 `timeout`、
`protocol_error`、`source_mismatch`、`cancelled`、`budget_rejected`、
`invalid_target` 和 `io_error`。`observation_scope=time_window_only` 明确禁止把单次
结果解释为节点身份上的永久 NAT 标签。
