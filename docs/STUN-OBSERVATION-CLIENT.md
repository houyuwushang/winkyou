# STUN Binding 观测客户端（Phase 1a loopback 切片）

## 状态与用途

`internal/stunobserve` 实现 RFC 8489 的最小 Binding 客户端子集，用于在一个
短时间窗口内陈述“该 socket 对该 STUN 目标观察到了什么”。它不推断或持久化 NAT
类型，也没有接入 `diagnose`、stdio API、连接策略或 daemon。

Phase 1a 的生产 adapter 仍只允许 loopback。本文中的 `127.0.0.1` 仅表示本机测试
应答器；真实 STUN 目标、公共域名以及非 loopback 地址仍属于单独的 live-network
授权边界。

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

## 输出语义

结果是 `solver.Observation`：包含观测开始/结束时间、STUN 目标、本地受控 socket、
发送次数、映射地址或稳定错误类。当前稳定错误类包括 `timeout`、
`protocol_error`、`source_mismatch`、`cancelled`、`budget_rejected`、
`invalid_target` 和 `io_error`。`observation_scope=time_window_only` 明确禁止把单次
结果解释为节点身份上的永久 NAT 标签。
