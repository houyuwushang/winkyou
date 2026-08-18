# STUN Binding 观测客户端（Phase 1a loopback 切片）

## 状态与用途

`internal/stunobserve` 实现 RFC 8489 的最小 Binding 客户端子集，用于在一个
短时间窗口内陈述“该 socket 对该 STUN 目标观察到了什么”。它不推断或持久化 NAT
类型，也没有接入 `diagnose`、stdio API、连接策略或 daemon。

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

## 输出语义

结果是 `solver.Observation`：包含观测开始/结束时间、STUN 目标、本地受控 socket、
发送次数、映射地址或稳定错误类。当前稳定错误类包括 `timeout`、
`protocol_error`、`source_mismatch`、`cancelled`、`budget_rejected`、
`invalid_target` 和 `io_error`。`observation_scope=time_window_only` 明确禁止把单次
结果解释为节点身份上的永久 NAT 标签。
