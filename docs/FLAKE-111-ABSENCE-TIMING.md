# #111 absent-peer 计时与 Fatal 清理

Status: Draft，**仅 Fatal 清理已修；15s 计时根因未闭合，断言未放宽**。基线 `fde8dfa`。

## 提示词假设核对

`loopbackcarrier_integration_test.go` 在 namespace、端点和 bundle 准备完成后才开始计时，
测量只包住 `loopbackcarrier.Connect`。本用例也没有 child bundle 启动。因此不能把
Connect 超时解释成夹具开销，更不能直接删掉 elapsed 断言。

现行 carrier 没有返回失败 attempt 的 monotonic start/FINISH/release 时间；Governor
AttemptLease 也不保存创建时刻。本 PR 只使用现有 journal hook 读取真实 monotonic 时钟，
不替换 clock/write/sync、不改生产 API。BURN append→FINISH sync 是生命周期**下界**，
不是精确的 AcquireAttempt→FINISH；不能用下界小于 15s 证明真实生命周期小于 15s。

## 首次证据（2026-09-08）

压力 helper 为 28 个逻辑核 ×2 =56 busy goroutines，每 65,536 次纯整数运算 Gosched。
首轮 GOMAXPROCS=2，50/50 通过，总计 672.339s。第二轮 GOMAXPROCS=28，46 次通过后
第 47 次 RED（fail-fast；未把后续未跑的 3 次算成通过），总计 648.600s。
第二轮后段另有 relay 压力与一份 `go test ./...` 并行，属于明确记录的复合 CPU 负载，
不是专用空闲机器测试。原始本地输出保留在仓库外，只提交以下脱敏数字。

| 第 47 次 RED 的分段 | 实测 |
| --- | --- |
| fixture（计时区间外） | 1,212 ms |
| Connect 总时长 | **15,039.3481 ms** |
| Connect start→BURN append hook | 298 ms |
| BURN append→sync | 50 ms |
| BURN append→FINISH sync hook | **14,631 ms** |
| FINISH append→sync | 318 ms |
| FINISH sync 后到返回附近 | 约108 ms；该首次版本取 log 前读数，非独立 release timestamp |

最后一项现已改为固定在 `start + elapsed` 读数处计算，避免把观察器读取/日志调度额外
计入尾段；不改变 elapsed 的测量或原 `<15s` 断言。该日志不是逐 syscall 的 emission witness。

**结论不能越过证据**：超限发生在 Connect 内；不能认定是 fixture；也不能仅凭 14,631ms
下界就认定 attempt 本体没超时。没有证据显示真实网络持续发包；测试始终仅 loopback。
在精确 witness 或计时口径经裁决前，原 AttemptDuration=15s、terminalDrainMargin=2s、
deadline 错误类型、ledger admission/failure 与 safety-clear 断言全部保留。

## 唯一已修问题：Fatal 清理

把 governor Close 注册到 `t.Cleanup`，即使在 elapsed 断言处 Fatal 也释放 owner。
收尾再取得/释放同一 namespace 的 OS owner，证明锁可重取，不修复或重建 journal/trip 文件。
原正常路径的 ledger/safety/socket 可复用检查仍原样执行。

新增真实子进程确定性 RED/GREEN：子测试在正常 Close 前故意 Fatal；旧顺序变异的
同进程见证为 `lock_reacquired=false`，Cleanup 顺序为 true，子进程退出后为零残留。
父测试验证两个子进程都完成预定 Fatal，不能把启动失败冒充 mutation 命中。
`go test -race ./internal/governor -run '^TestAbsentPeerFatalCleanupWitness$' -count=20 -timeout=3m`
通过（32.510s）。这是 cleanup 的确定性回归，不是 15s flake 已修复的证明。

## 最小续行提案（未授权、未实现）

先允许独立审查的只读 witness，精确记录 AcquireAttempt、durable FINISH 与释放三个
monotonic 点（失败结果同样可读，不能只返回成功 Result）。据此判断生产阶段是否超过
合同，以及 FINISH 后的 controller/attempt/peer 排水是否属于原 15s 口径。
若需更改计时合同或生产路径，先交维护者裁决，不能在测试中把 BURN 时间冒充 start。

production delta=0。不推进 Gate/C1c，不改变任何预算、golden 或 live 权限。
100 次无压力及 50 次修复后全绿的完整验收**未闭合**，不能从首轮绿样本拼接为已完成。
