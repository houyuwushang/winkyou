# 2026-07-22 cached self-bootstrap UDP 会话风暴

## 状态与决策

- 严重级别：P0，可能耗尽终端和出口 NAT/防火墙资源。
- 受影响构建：现场 A 节点使用的 `880936b` 构建。
- 当前决定：**cached self-bootstrap / autonomous birthday recovery 短期暂停**。不安排修复、现场实验或重新部署，仅保留代码、日志和本记录供以后重新立项。
- 当前运行状态：Windows 计划任务 `\WinkYou-A` 已禁用，supervisor stop marker 已保留，相关进程和现场监听已停止。不得只删除 marker、手动启动 child 或重新启用任务。
- 安全结论：当前实现为 **NO-GO**，不得在办公网、生产网或未经独立出口限流的公网运行。

这里的“暂停”不是否定 P2P 直连结果。历史实验已经证明 birthday punch 可以建立真实公网直连；本事故证明的是：把高成本概率打洞直接接入长期自动重连生命周期，在没有节点级资源预算、退避和熔断时不具备产品运行安全性。

## 事故现象

2026-07-22，A 节点的长期托管构建在 peer 失联后持续执行 cached self-bootstrap。公司网络侧报告约 40 万会话/并发状态，现场网络受到影响。A 本机曾观察到 128 到 256 个 UDP socket、异常 CPU/线程/句柄压力和 `WSAENOBUFS`（系统缓冲区或队列不足）。

“40 万会话”不是指 A 本机同时持有 40 万个 socket。更可能的含义是出口设备在统计窗口内观察到或保留了大量不同 UDP 五元组/conntrack 状态。出口设备的准确口径尚未取得，因此不能把 40 万精确表述为某一时刻的本机活跃连接数。

以后若要完成数字核账，需要网络侧提供：指标名称、累计或瞬时口径、统计时间窗、UDP idle timeout、源 IP 过滤条件以及去重键。

## 为什么数字会接近 40 万

现场构建的重型 fallback 参数为：

| 参数 | 数值 |
|---|---:|
| 本地 UDP socket | 128 |
| 每个 socket、每轮新随机目标端口 | 48 |
| round delay | 300 ms |
| 19.5 秒内的轮数 | 65 |

每轮最多制造的全新目标组合为：

```text
128 sockets × 48 fresh random ports = 6,144
```

对应的新目标尝试速率为：

```text
6,144 ÷ 0.3 s = 20,480 attempts/s
```

持续 19.5 秒即为：

```text
6,144 × 65 = 399,360
```

这与网络侧报告的“约 40 万”高度吻合。它是机制解释，不是对网络设备统计口径的反向证明。随机端口碰撞会令唯一五元组略少，固定/预测目标和其他流量又会增加实际发包与状态；上游设备还可能在本地 socket 关闭后继续按 UDP idle timeout 保留状态。

一次实际 punch 可用时间约为 `45 s attempt window - 8 s HELLO timeout ≈ 37 s`，约 124 轮。仅一个 peer 的 fresh-random 尝试上界已接近：

```text
128 × 48 × 124 = 761,856
```

如果两个失联 peer 的重型窗口重叠约 25 秒，则简单估算可超过：

```text
2 × 128 × 48 × (25 ÷ 0.3) ≈ 1,024,000
```

## 代码根因

问题不是一个永久不释放 40 万 socket 的传统泄漏，而是长期生命周期内缺少总预算的高基数 UDP 探测：

1. `pkg/bootstrap/selfhosted/engine.go` 的默认现场参数使用 45 秒窗口、1 分钟周期、128 sockets、48 birthday targets 和 300 ms round delay。
2. `pkg/nat/puncher/puncher.go` 为每个 socket 启动 sender，并在**每一轮**为该 socket 重新生成 48 个随机远端端口。目标集合没有按 attempt 预生成并复用，因此持续产生新五元组。
3. `880936b` 增加了 `punchDeadlineMisses` 路径：preserving/sequential 候选一次 deadline miss 后，从低成本预测升级为完整 `cached_predictive_birthday_fallback`。失败因此会提高后续成本，而不是降低速率。
4. 每个 maintained peer 有独立循环；self-bootstrap 和 recovery 之间没有共享的节点级 single-flight、packets-per-second 或 new-tuples budget。多个 peer 可以重叠执行重型 punch。
5. 失败调度会轮换候选，但没有足够的指数退避和长期冷却，形成“约每分钟运行一个长窗口”的持续负载。
6. UDP 写错误被逐包忽略。出现 `WSAENOBUFS` 时，本轮不会立刻全局停止并进入本地资源冷却。
7. `PacketNeighbor` 的 keepalive 一次写失败就可能关闭原本健康的邻居，触发更多恢复任务。
8. punch packet nonce 每包调用 OS CSPRNG，进一步放大高包率下的 CPU 和线程/系统调用压力。

可能出现的正反馈为：

```text
一个 peer 失联
  -> 对该 peer 启动重型 birthday fallback
  -> 本机/出口资源趋于耗尽并出现 WSAENOBUFS
  -> 健康邻居因单次 keepalive 写失败被关闭
  -> 同时对更多 peer 启动重型 fallback
  -> 新五元组、CPU 和队列压力继续上升
```

## 为什么原测试没有拦住

现有测试主要验证状态机、候选调度和 punch 成败，并通过 mock/injected punch 避开真实流量。部分单元测试还明确断言 128 sockets、48 birthday targets 的 fallback 配置，因此这不是测试无法观察到的偶发竞态，而是缺少资源安全不变量。

缺失的门禁包括：

- 单次 attempt 最大包数和最大新五元组数；
- 节点级最大 packets/s 和最大并发重型 punch 数；
- 多 peer 同时失联的长期 fake-clock 仿真；
- `WSAENOBUFS`/临时写失败的 fail-closed 与健康边保护；
- Windows 真实网络栈、出口 conntrack/session 和 24 小时不可达场景验收。

## 若未来重新立项，最低修复门禁

短期不执行以下工作；本节仅用于防止未来在没有边界的情况下直接恢复：

1. 默认关闭自动重型 birthday fallback，并增加编译期硬上限，不能只依赖配置。
2. self-bootstrap、recovery 和全部 peer 共享一个节点级 single-flight；同一节点同时最多一个重型 attempt。
3. 以预算驱动算法：限制 packets/s、new tuples/attempt、packets/attempt、socket 数、目标数和持续时间。
4. 每次 attempt 预生成有限目标集合并复用；禁止每个 socket 每 300 ms 生成一批全新随机端口。
5. 失败使用指数退避和 jitter；资源错误触发立即取消与长冷却，不能持续每分钟高占空比运行。
6. 健康邻居不得因一次临时 `WSAENOBUFS` 被拆除；使用有限重试、连续错误阈值并区分本地资源错误。
7. 增加独立于主进程和 supervisor 的流量熔断/一键关闭保险，但不能用 watchdog 代替算法硬预算。
8. 在隔离网络使用可观测出口进行多 peer、长时间、故障注入验收；先冻结二进制 SHA-256，再做 monitor-only canary，最后才允许受控 trip-mode canary。

一个保守的重新起步参考值是 8 sockets、8 个预生成目标、1 秒一轮、5 秒 attempt、节点级并发 1、失败后至少冷却 5 分钟，并设置 `max_new_tuples_per_attempt <= 512`。这些数值只是隔离实验起点，不能直接视为生产安全值。

## 重新开启的行政门禁

必须同时满足以下条件，才允许讨论移除暂停状态：

- 有明确负责人和独立评审人；
- 上述代码级预算、退避、熔断和回归测试全部完成；
- 隔离环境能同时核对终端指标和出口 session/conntrack；
- 形成书面测试计划、停止阈值和回滚命令；
- 明确得到目标网络所有者允许；
- 不直接复用 `880936b` 现场二进制；
- 两人复核后才允许删除 stop marker、启用计划任务和启动新构建。

在这些条件满足前，历史“直连成功”“三角恢复成功”或“长连接保持成功”均不能作为重新启用 cached self-bootstrap 的依据。
