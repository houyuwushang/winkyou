# #97 relay 启动停滞阶段证据

Status: Draft，已复现并细化定位，已实现测试执行分区，等待完整验收与独立复审。
基线 `fde8dfa`；production delta=0；不宣称修复任意负载下的产品选路行为。

## 本批做了什么

在既有真实 loopback relay 测试添加只读阶段采样和 opt-in CPU helper，并将该用例
迁入独立 required CI 分区；不改变
30s transport 断言、capability 2s、RunTimeout 25s、2/4/8/10s 退避、#94 ready/route
两道防线或生产代码。快照使用原锁，退出 join observer；日志仅固定测试 side、相对时间、
阶段、是否收到 capability、策略/协商/重试/binding 标志，无 endpoint/key/PID/path。
采样是 50ms 尽力观察，不是每个状态 transition 的精确时间；短暂状态可能未采到。

## 保留的首次 RED

1. 本批基线全仓测试先命中同名用例：33.52s；一侧 executing/legacy_ice_udp/negotiated=false/
   capability 缺失，另一侧 executing/relay_only/negotiated=true；handshake/transport 均零。
2. 第一份 opt-in 压力矩阵：28 logical CPUs、56 busy goroutines、GOMAXPROCS=2，
   每 65,536 次整数运算 Gosched。17 PASS 后第18次在 beta 注册时触发独立的 200ms RPC
   fixture timeout，fail-fast；不能把它算作目标 transport-stall 签名，也不能算50次全绿。
3. 全仓复合压力（GOMAXPROCS=28、同一56-worker helper，并行另一份 #111 压力与 relay
   重复测试）复现**目标 transport 超时**，用例50.56s，pkg/client80.073s。其余包通过。
   原始日志保存在仓库外，以下仅脱敏阶段数字。

| 相对采样时间 | side | 状态 / 事实 |
| --- | --- | --- |
| 6,080ms | 2 | capability_exchange，capability=false |
| 7,621ms | 1 | capability_exchange，capability=false |
| 11,072ms | 1 | capability=true |
| 12,371ms | 2 | selecting，capability **仍 false** |
| 15,171ms | 1 | selecting，capability=true |
| 16,021ms | 2 | capability 迟到，变为 true |
| 23,971ms | 2 | planning，legacy_ice_udp，negotiated=false |
| 25,172–25,871ms | 1 | probing→planning，relay_only，negotiated=true |
| 27,571ms | 2 | executing，仍 legacy_ice_udp |
| 27,971–29,371ms | 2 | 旧 session 消失，随后新 capability_exchange，capability=false |
| 31,521–35,472ms | 1 | executing，relay_only；后续 observation 到达 |
| 38,771ms | 1 | session 消失；随后 transport 30s 断言失败 |

这不是“已经绑定成功、只是测试还没看到”的 RED；在测试截止前没有 binding 见证。
`waitForRemoteCapability` 在 timer 到期时返回当时的远端 snapshot；`resolveStrategyCandidates`
把该值交给 resolver。后来 `CapabilityExchangeAt` 变为非零，不会自动更新已经取得的
策略选择。时间线和这条源码路径一致，但**不证明历史所有 #97 RED 都只有这一根因**，
也没有证实第三个消息丢失竞态。后续 session 消失还受到 fixture liveness/更新路径影响。

## 防止错误的“修复”

只在 Connect 外多等30秒不能倒转已经发生的异侧策略选择。也不能把 capability 非零
当作“双方本次选择已经协商一致”，更不能强行在测试中写入 capability 或重开 attempt。
本 PR 因而保留原断言，而非把更宽的聚合墙钟伪装成分阶段 readiness。

为了不让注册200ms的另一个失败淹没目标，第二个诊断配置将**人工压力的启动点**移到
两端 Start 返回之后（生产调用顺序与默认测试完全不变）。这只是区分注册与 transport
负载的实验变量，不是 timeout 修复；第一份 RED 不删。该配置在56个 busy workers、
GOMAXPROCS=28 下 **50/50 PASS，671.104s**；无人工压力的 focused race **20/20 PASS，
254.989s**。后者部分时间与其他宿主验证重叠，不冒充独占机器的性能基准。

## 已实现的独立 CI 分区

任务明确允许独立 CI 分区。全仓普通测试（Linux/Windows）与 Linux core race 只以完整、
锚定的测试名排除本用例；排除的执行全部迁移，不减少次数。现有 Linux relay job 保留
原3次 smoke，追加迁入的普通1次和 race1次；新 Windows required job 承接普通1次。
这些步骤没有条件执行、advisory 或 continue-on-error。其他 Gate A/B/C job 不变。

| 平台 / 覆盖 | 分区前 | 分区后 |
| --- | --- | --- |
| Linux 普通 | full suite 1 + smoke 3 | 独立 relay job 1 + 3 |
| Linux race | core race 1 | 独立 relay job 1 |
| Windows 普通 | full suite 1 | 独立 Windows relay job 1 |

`internal/architecture/relay_ci_partition_test.go` 检查平台、命令、精确排除、次数和强制执行；
变异自检覆盖遗漏 Windows、减少 smoke、丢失 race、扩大 skip、全仓重复执行和降级可选。
分区及既有 C1b 分区门禁20轮通过，相关 vet 与 `git diff --check` 通过。100次无人工压力
重复及最终 CI 结果记录于 PR，不把尚未结束的检查标绿。

分区证明的是固定功能回归与全仓包级争用分离，不是任意主机负载下的可靠性保证。
若要求负载下已到达 capability 后仍能可靠共同选路，需要单独审查生产侧 late-capability、
attempt 归属和双边选择同步；本 PR 不增加重试、扩预算或改变 fallback。
未增加 sleep、未减 count、未降级 required、未 rerun 掩盖失败。只读 observer 与压力 worker
均在返回/Fatal 时退出；完整验收仍待最终结果与独立复审。
