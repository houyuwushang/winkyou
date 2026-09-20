# 回环 attempt 两阶段终止

Status: Draft implementation design (2026-09-20)。维护者已授权方案 2 的设计与实现；具体实现仍须独立复审，
不得据此合并、推进 Gate C1c 或运行现场网络。

## 1. 问题与裁决

#111 的 caller-cancel 反例不是第二个 duration 超限：AcquireAttempt 的 ctx watcher
立即 Close，pairing drain 却在 FINISH fsync 后才 Complete。即使预先撤销全部 socket，
10s FINISH 仍会超过原 2s cancellation drain，持久记录 cancellation_timeout。
旧反例日志 SHA-256：
`6d8b12ac1277236a74d639f140198d1f30154fb3425e23e03399a1966930bf2a`。

仅添加 pre-finish hook 不能解决这个所有权冲突。采用 governor 显式选择的两阶段生命周期，
不在 carrier 隐藏使用 detached context，不加大网络排水门，不修改 Gate B/C 的完成阶段。

## 2. 状态、时间与权限

```text
Active -> Stopping (立即撤销新网络权限)
       -> NetworkDrained (原 2s，真实 probeio drain)
       -> Finalizing (单个 durable FINISH，独立 15s)
       -> Done (FINISH 成功后释放 attempt)
```

- 新的 AcquireLoopbackAttempt 在取得 lease 前固定此模式；普通 AcquireAttempt 行为不变。
  仅 phase1 machine/connect-test 与 loopbackcarrier 可选择，不提供运行时配置开关。
- 原 15s attempt、2s terminal margin、2s cancellation drain、3 packets/3 PPS 与 admission
  全额计费不变。新增 LoopbackFinalizationTimeout=15s 只约束记账结果等待：依据已观测
  10s 磁盘停顿给出 50% 余量，不允许网络继续运行，也不增加任何 socket/packet 额度。
- pairing gate 的 drain 在此模式单独归类为记账见证。全部普通 RegisterDrain 仍是网络/
  worker 排空见证；调用者不能自行把普通 drain 改成记账类。
- 第一个终局选择启动停止 attempt；权限撤销的线性化点是 governor 关闭 Stopping，
  此后零新 Open/Write/Register。已经准入的在途操作仍须在原 2s 内真实排空，
  不把 caller 调用 cancel 的墙钟时刻或内部终局选举当成物理排空见证。单次 pre-finish hook 撤销
  probe controller，任何 FINISH 都须在网络排水的成功或超限判决之后。hook 错误加入返回值，
  不跳过 FINISH。注册与 controller 发布的竞态由终局 slot 关闭，不能漏掉后来构造的 controller。
- 网络排水超限仍持久 cancellation_timeout；记账超限为 terminal_finalization_timeout，
  写入失败为 terminal_finalization_failed。不得用后两者伪造网络 trip 或成功结果。
  这些是内部错误身份，不增加或改写 stdio v1/v2 schema，既有 adapter 仍负责脱敏。
- probeio 的同步操作 guard 使用 governor 的 ProbeRevocation 信号：新模式返回 Stopping，
  普通 lease 返回原 Done。未改变 Done 的物理/记账含义，也不依赖 watcher 何时获得调度。
  此只读接口仅 probeio 的精确 adapter 消费，调用者不能注入或替换该信号。

## 3. 磁盘阻塞、占用与关闭

- governor 持有唯一终局管理者、唯一 FINISH writer、原 attempt 预留与 OS owner。
  收尾期间拒绝新 peer/attempt；无退款、重试、后台恢复或第二个 writer。
- 15s 限制的是向等待者发布收尾判决，不声称 Go 能中止卡在内核中的 fsync。
  超时后 writer 仍明确归属原 governor；不能释放锁、启动新 attempt 或报告物理排空。
- FINISH 写失败或超时在该 governor 生命周期内锁存记账故障。迟到的成功不能清除此判决。
  Snapshot 不等待 writer 持有的 owner mutex；机器元数据在创建时取不可变副本。
- Governor.Close 在 writer/网络 worker 未真正退出时返回有类型的故障并保留 owner，
  不无限等待，也不把错误返回当成释放锁。Snapshot.Closed 沿用原有 closing-or-closed
  口径，不能用它推导 owner 已释放。worker 实际退出后可再次 Close，才释放 owner。
  该进程内仍不允许新 admission；重新取得 owner 必须经过原有 ledger 检查。
- 完整 FINISH 之前进程崩溃仍是 BURN 无 FINISH；沿用原未完成记账/不退款规则。
  半写或无法确认的记录仍 ledger_indeterminate；不新增修复或自动重启机制。
- 这里不能保证任意内核/硬件故障下 syscall 必然退出。必要时由进程退出释放 OS 资源；
  不新增 child、信号处理器、主机服务或自动 kill。外部调用者须检查 Close 的错误。

## 4. 隔离与验收

只允许 loopbackcarrier 注册 pre-finish hook、选择新 lifecycle；architecture 精确锁定
调用点，包含方法值绕过的负向用例。probeio RevokeForTerminal 实现保持不变。
共享 probeio 仅增加上述操作拒绝信号选择，普通 attempt 获得同一条原 Done channel；
新模式在该 signal 已关闭、socket 尚未物理 Close 时，Open/Write/Register 必须全部拒绝。
Gate A/B/C、handoff、默认缺席测试、冻结数字、配置和工作流均不修改。

验收包括：原 R1/R2；R3 first-emission expiry +2.5s FINISH；R4 caller cancel +10s FINISH；
网络真实排水失败仍 trip；FINISH 挂起/错误的独立故障与持锁；晚返回不能重新打开 admission；
并发 Close/Finish、hook 一次性、注册竞态、进程崩溃 BURN 恢复、不退款与跨模式隔离。
变异须拒绝 FINISH 先于 revoke、跳过网络 drain、提前释放 lease、越权消费者和计费减少。

验证仍按 #111 批次要求：压力至少50、无压力至少100、focused race20、受影响包 race20、
C1b memory 首跑、全仓 #116 分区、独立 relay race20、vet、Linux tagged vet、普通构建符号检查。
所有首次 RED 保留；未完成的验证不得预填 PASS。证据随实现追加。
