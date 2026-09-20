# ADR：loopback 缺席路径的生命周期见证与 FINISH/drain 余量

Status: **Draft，测量证据；未修改生产余量**（2026-09-09）。Refs #111。
当前 O2 实施裁决见 §9；上述 Draft 状态与下列旧基线属于 §1–§8 的历史测量记录。
基线 `214ff2d`；#115 分支未修改。2026-09-09维护者明确允许本PR修改旧墙钟断言
所在测试文件，具体范围见§7。

## 1. 问题与禁止推断

[#115](https://github.com/houyuwushang/winkyou/pull/115)保留的 RED 是
Connect 15,039.3481ms、BURN append→FINISH sync 14,631ms；夹具1,212ms在计时区间外。
旧断言 Fatal 早于 persistent trip 复检，因而当时是否 latch **仍未知**。
新实验不能把这个未知值倒填为 clear，不能删旧 RED，也不能把 journal 下界冒充完整生命周期。

约束仍为 [取消排水契约](../CANCELLATION-DRAIN-CONTRACT.md)、
[配对重启安全契约](../PAIRING-RESTART-SAFETY-CONTRACT.md)及
[Gate A ADR](ADR-N3C-OOB-DIRECT-HANDOFF.md)。Gate A 的13s/2s、8/7包、5PPS
不是 loopback carrier 的包预算；本任务的 loopback 仍为15s、3包、3PPS、2s余量。

## 2. 起点必须区分

源码 `internal/v2/loopbackcarrier/carrier.go` 与 `internal/probeio/probeio.go` 显示：

1. AcquireAttempt 先登记实际 lease；之后才执行 durable BURN / Consume。
2. admittedCarrier.run 在这些操作之后创建13s context。
3. probeio.New 再建立 startedAt；发送侧 duration 检查基于这个时刻。
4. watchLifecycle 创建独立15s timer；实际 armed 时刻还可能稍晚。
5. 缺席 ReceiveReply 返回后写 FINISH，controller.Close 触发停止/排水，再返回 Connect。

因此提示词括号中的“AcquireAttempt→probeio 停止就是 tripwire 看到的区间”不准确。
本报告同时记录 owner 与 controller 两个起点，既不偷换起点，也不借此扩大15s。
对本批样本，两段均严格小于15s；这不自行裁决全部产品 duration 的统一起算语义。

13s nominal deadline 与 `presence_read_return` 也分开：后者是 ReceiveReply 返回的观察
时间，包括 reader 调度/排水延迟，不能声称精确捕获 Go runtime 关闭 context channel
的那个 CPU 指令。返回的错误类别另行核对。所有差值保留 Go monotonic 部分。

## 3. 只读测量方法

首个提交 `7294b4e` 只有三个 loopback 测试/模板文件。使用 Go test overlay，在临时测试
二进制中对真实源码插入时间记录；移除全部插入后必须恢复原源码字节（仅CRLF归一化）。
不复制实现逻辑、不替换 clock/timer/fsync、不新增生产 hook/API，不编辑或覆盖 #115 的文件。

真实 governor、OS owner、durable ledger 与字面 loopback UDP 原样运行；BURN/FINISH/latch
观察使用既有 test hooks，返回结果不变。所有 observer 只记录时间到内存，不在路径上写日志。
记录 AcquireAttempt、nominal deadline/read return、FINISH append/sync、probeio workers
停止、timer stop、controller.Close 返回、Connect 返回；返后重新取得 owner 并复检持久 trip。
只输出合成 sample 序号、单调差值、clear/latch 布尔；原始本机日志不进入仓库。

这是一份**被只读观测的真实实现**实验，有少量观察开销；不是原历史 RED 的无扰动追踪。
每个样本新临时 namespace，不重置生产 ledger，不复用 credential，不增加真实探测权限。

## 4. Windows 压力首轮实测

Go1.26.5、28 logical CPUs、GOMAXPROCS=28、56 busy goroutines；每65,536次整数运算
Gosched，退出 join。50个独立样本全部完成，682.135s；没有同时启动另一份本地 Go 压力/
全仓任务。相比 #115 历史复合压力，负载组成不同，不能互相抵消 RED。

| 指标 | p95 | 最大值 |
| --- | ---: | ---: |
| AcquireAttempt→probeio timer stop | 13,870.5531ms | 14,215.8496ms |
| probeio startedAt→timer stop | 13,816.4597ms | 14,175.7123ms |
| nominal deadline→cancel observation | 19.3022ms | 58.9942ms |
| FINISH append→sync | 803.7522ms | 1,169.2784ms |
| FINISH sync→controller.Close 返回 | 5.5056ms | 12.0237ms |
| Connect 墙钟（只记录） | 13,870.5531ms | 14,215.8496ms |

50/50：persistent latch hook=未触发，内存/重新打开 namespace 后均 clear；
一个已计费 admission + 一个失败 FINISH，peer/attempt/reservation=0，loopback 端口可重新绑定，
人工压力 worker 返回后为零。每个 interval 的原始单调纳秒保存在仓库外。

### 4.1 修正读取见证后的无人工压力与 race

无人工 CPU 压力100个独立样本全部完成，1,365.923s，100/100 clear、零 latch。
不与另一份全仓/压力任务并跑；采样期间有一次0.765s的观察器静态负面对照编译，
不能把“无人工压力”扩大解释成操作系统绝无其他工作。

| 指标 | p95 | 最大值 |
| --- | ---: | ---: |
| AcquireAttempt→probeio timer stop | 14,162.1575ms | 14,496.1624ms |
| probeio startedAt→timer stop | 14,124.2007ms | 14,467.3687ms |
| nominal deadline→Read 返回 | 0.9101ms | 15.6309ms |
| FINISH append→sync | 1,122.9385ms | 1,465.8334ms |
| FINISH sync→controller.Close 返回 | 1.4950ms | 94.7321ms |
| Connect 墙钟（只记录） | 14,162.1575ms | 14,496.1624ms |

随后外层与真实 governor 临时二进制均启用 race，`-count=20`、每轮一个独立样本，
377.831s，20/20 clear、零 latch；AcquireAttempt→stop最大14,475.8196ms，
probeio startedAt→stop最大14,429.9201ms。所有样本都核对 FINISH、持久 clear、
资源清空与端口可重新绑定，不只核对错误字符串。三个批次合计170个完整样本，
不把首次无压力运行的5 PASS + 1观察器 RED混进这三个完整批次。

## 5. 本批采用的分支与剩余边界

采用提示词的“未观察到 latch”分支：**不改生产代码**，不把2s改成3s，不改15s、3包/3PPS。
理由是压力50、无人工压力100及race20都没有观察到支持生产时限修正的 latch，
而非声称任意负载下绝不可能 latch。
FINISH写入失败/普通过期/资源清理的语义均不改。

只在新增的 loopback 见证测试中断言两个起点→timer stop均 `<15s`、FINISH-before-stop、
排水/返回顺序与持久 clear；Connect 总墙钟只记录。负面对照包含缺点、FINISH晚于停止、
恰好15s/超过15s拒绝，以及模拟16s返回但真实生命周期未超限可以通过。
不通过宽化阈值或“任意错误都过”修测试。

原 `internal/governor/loopbackcarrier_integration_test.go` 的墙钟断言也属于 #115 修改过的
文件。首轮交付遵守原禁令而未替换它；该范围冲突现由维护者明确授权解除，
不是通过删除历史RED或放宽生产时限解除。

## 6. 验证命令与状态

使用当前 shell 设置下列 opt-in 变量（不提交机器值或路径）：

```powershell
$env:WINKYOU_ABSENCE_WITNESS='1'
$env:WINKYOU_ABSENCE_WITNESS_RUNS='50'
$env:WINKYOU_FLAKE_111_CPU_STRESS='1'
$env:GOMAXPROCS=[string][Environment]::ProcessorCount
go test ./internal/v2/loopbackcarrier -run '^TestAbsenceLifecycleWitness$' -count=1 -v -timeout=35m
```

压力50已通过。首轮无人工压力100在第6次因**观察器缺点**停止：5 PASS + 1 RED，
85.980s。旧观察器只有 ctx.Err()!=nil 才记录；已有 probeio.contextErrorForIO 明确允许
OS deadline先返回、ctx.Err仍nil。原日志未走到最终错误打印，不能逆推那个样本的完整
产品状态。现在对 Read 返回无条件记录，并单独核对真实错误类；补旧条件的负面对照。
这是 test-only 见证修正，不改生产时钟/错误归因；旧 RED 留存。
压力表来自旧名 presence_cancel_observed 的50个完整样本，不能和缺点样本混为全绿。

修正见证后的无人工压力100、真实见证 race×20均已通过，详见§4.1；
无压力运行在新 shell 不设置 CPU_STRESS，RUNS=100；race 设置
WINKYOU_ABSENCE_WITNESS_RACE=1、RUNS=1，并用 `go test -race ... -count=20`，
使外层与临时 governor 测试二进制都启用 race。

测试实现 `bf6ce58` 的本地完整验证：

- `go vet ./...`：PASS。
- `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -json`：
  PASS，88个有测试包、11个无测试包；governor 322.201s，client 29.890s。
- `go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=1 -v`：
  PASS，14.011s。沿用 #116 已有分区，保留原测试与时限，不减少其平台/次数。
- `go test ./internal/architecture -count=1 -v`：PASS，11.020s，包含既有变异检查。
- `git diff --check`、新增文件隐私扫描、本文3个相对文件链接：PASS。

同一 `bf6ce58` 的首轮远端CI是52 SUCCESS / 3 FAILURE / 1 CANCELLED，**不是全绿**：
两平台 real WireGuard liveness失败、Windows model/owner达到既有20min作业上限，
下游required聚合门失败。链接与脱敏见证见本PR描述。未修改这些路径或重跑刷绿，
不能拿本地PASS抵消远端RED。本次后续提交只补齐测量表和证据，生产代码仍为零改动。

保持 Draft，不合并，不以本次采样自动关闭 #111；#115 的复跑/合并顺序由维护者后续办理。

## 7. 默认回归接线授权（2026-09-09）

维护者接受S3设计并另外明确“允许”本PR修改旧墙钟断言所在测试文件。
仅解除该文件范围限制；#115分支、既有RED记录、生产15s/2s/3包/3PPS均不修改。

默认 `TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip` 将调用本PR既有
只读overlay见证：一次运行一个真实缺席场景，保留原测试名，不能以opt-in未设置而skip。
子测试移除源码插入必须恢复原实现；父测试验证实际完成的唯一样本，不能把空输出、
被skip、零样本或缺失持久/生命周期见证当作通过。race运行须传到真实governor子二进制。
原精确DeadlineExceeded、一个admission/失败FINISH、重开后clear、端口/资源排空
均由同一真实worker检查；Connect总墙钟仅诊断，两个起点→timer stop仍必须严格小于15s。

该默认入口会多一层测试编译/启动成本，属于test-only开销，不计为探测生命周期，
也不引入生产observer/API或任何额外网络权限。后续复审#115时须明确处理重叠的测试接线，
不能把此PR的合入当作已复跑/合并#115。接线后的验证结果另行追加，不冒用旧170样本
证明尚未完成的新入口测试。

### 7.1 默认入口接线的实际验证

`0faab17` 先提交永久 RED：AST 门禁要求默认测试实际委托 `runObservedAbsenceLifecycle(t)`，
空函数、skip、条件绕过均不能通过。旧实现实测 RED（0.439s），日志保留。
`10a5f14` 完成接线；生产代码仍零改动。父级还拒绝空/重复报告、缺项、latch、
错误类型不符、恰好15s与超过15s；合法生命周期但16s Connect返回的合成对照可以通过。

新入口普通1次 PASS（18.222s，含编译/启动）；父级与真实 governor worker 均启用 race，
默认缺席测试及报告负面测试 `-race -count=20` PASS（455.491s）。20个实际缺席样本均
clear、无 latch、FINISH与资源/端口清空通过。AcquireAttempt→stop 最大14,450.3317ms
（p95 14,297.5540ms）；probeio→stop 最大14,413.3655ms（p95 14,251.9250ms）；
FINISH sync最大1,412.0603ms；sync→drain最大1.5514ms。
这是新默认入口的独立20次证据；§4的压力50/无压力100保持原批次，不冒充本次重新测量。

同一 `10a5f14`：`go vet ./...` PASS；全仓沿用§6的 #116精确分区，88个有测试包通过
（governor236.172s、client18.934s），独立 relay PASS10.599s，architecture/mutation
PASS9.552s。未修改工作流、原预算、#115分支或其他flake。最终远端检查另在PR描述登记，
历史首轮RED不删除，未自动关闭#111。

### 7.2 最低工具链 CI 复现与修正

`ec105d3` 的首次 CI 暴露本地验证遗漏：仓库与 CI 使用 Go1.23.1，先前本机默认是1.26.5。
1.23.1 的 vet 子进程不能打开 overlay 新增、物理路径不存在的两个测试文件，默认入口在
约2–3s构建阶段失败，并未运行到13s缺席场景；不能归为持久 trip 或用重跑消除。
同版本本地已复现 `vet: open ...: file not found`。

`cb8f2bd` 改为向两个**已存在的测试文件的临时overlay**追加import/见证声明，原文件不落写。
删除两处插入仍须恢复原测试字节；三个生产文件的可逆只读插入也保持不变。
未关闭vet、未升级go.mod/CI、未改timer或fsync；父级增加只含固定阶段的失败诊断。

Go1.23.1：默认入口普通1次PASS20.680s；父/worker真实race×20 PASS437.878s，
20/20 clear、无latch、资源清空。AcquireAttempt→stop最大13,030.2842ms，
probeio→stop最大13,026.5639ms，FINISH sync最大24.2431ms。这里是工具链兼容验证，
采样中有其他小型测试编译，不作不同工具链的独占性能比较。
同一实现 `go vet ./...` PASS；原全仓分区88个有测试包PASS（governor139.194s、
client2.689s、architecture17.233s）；独立relay PASS7.709s。旧RED仍保留，
新head远端结果单独记录，不把本地PASS写成CI全绿。

## 8. 默认接线裁决 A 与 #115 合流（2026-09-10）

Refs #111 #115。维护者在 #123 复审选择 A，随后明确同意本节的证据分层修订。
§1–§7 及所有历史 RED 原文保留；**本节取代 §7 的默认 overlay 接线规则**，
不追溯改变旧批次结论，也不修改生产实现、15s / 2s / 3 包 / 3PPS。

### 8.1 约束核对与本次裁决

默认缺席测试属于 `governor_test`。Go 1.23.1 与本机 Go 1.26.5 的独立零网络
编译对照均证实：依赖包的 `*_export_test.go` 不会暴露给这个测试包；仅包自身的
external test 能访问该包的测试导出。实际 `probeio` 也没有保存 timer stop 时间，
`loopbackcarrier.Connect` 内部的 controller 不会交给调用者。单加测试 getter 无法
使这些时间点变成默认测试可读，不能据此偷偷添加生产 hook、clock、unsafe/linkname，
或仍在默认路径编译 overlay。

维护者因此批准：**生产 delta=0；默认测试在进程内验证终局、账本与排水；精确
双起点计时继续由显式 opt-in overlay 证明。** 这是一项明确的验收口径调整，
不是声称默认测试仍然测得内部 timer stop。journal 区间始终只是生命周期下界。

| 证据 | 默认进程内回归 | opt-in `TestAbsenceLifecycleWitness` |
| --- | --- | --- |
| 真实 carrier / governor / durable journal / loopback UDP | 保留 | 保留 |
| 精确 `DeadlineExceeded`、一个 admission + 一个失败 FINISH | 保留 | 保留 |
| 重开 owner 后 safety clear、资源归零、端口可重绑 | 保留 | 保留 |
| journal append/sync 顺序与只读时间点 | 保留；仅诊断，不代替起点 | 保留 |
| AcquireAttempt / probeio startedAt → timer stop 严格 `<15s` | 不声称有此见证 | 原精确断言与边界负例保留 |
| Connect 总墙钟 | 只记录 | 只记录 |
| `go test -overlay` / 额外编译 | 无 | 仅显式启用时存在 |

默认入口去掉 shell-out 和 stdout 文本验收。原因包括工具链/编译耦合、§7.2 已有
Go 1.23 vet RED，以及每次全仓多一轮编译。opt-in 路径继续使用原来的可逆只读
插入和同一真实实现，不复制算法、不替换 fsync；未启用时明确 skip。

### 8.2 实现与回归要求

等价迁入 #115 的 `closeAbsentPeerGovernor`（提前注册 `t.Cleanup`）、
`ObserveCarrierAbsenceJournal`（仅 governor 测试二进制可见）和 opt-in
`startAbsenceCPUPressure`，不修改 #115 分支。

默认场景在断言之前先收集返回错误、journal 顺序、内存资源、关闭/重开 owner、
持久 ledger / unfinished occupancy 与端口重绑结果。不能因早期断言 Fatal 跳过
持久安全复检；失败仍由同一进程的结构化断言拒绝。负面对照分别破坏错误类、
见证完整性/顺序、admission/FINISH、safety clear 与资源排水；合法但较晚的 Connect
返回不得重新触发旧的墙钟门。静态接线门另拒绝 skip、空实现、条件绕过、恢复
shell-out 或把墙钟重新当作内部资源时长。

新默认入口必须重新完成 focused race×20、人工 CPU 压力至少50（fail-fast）、
无人工压力至少100、Go1.23.1与本机工具链各一次；另跑全仓 #116 分区、独立 relay、
vet / architecture 和 opt-in 精确见证。§4 / §7 的旧数字不冒充这批新结果。
本节实现与验证完成后在 PR 描述登记当前 SHA、首次 RED（如有）和实际通过数；
是否关闭 #111 仍留给独立复审，保持 Draft，不合并，不启动阶段3或现场操作。

### 8.3 本轮首次回归

先加入新的默认进程内接线门，再运行 Go1.23.1：
`go test ./internal/v2/loopbackcarrier -run '^TestAbsenceDefaultRegressionRequiresInProcessWitness$' -count=1`
在旧的默认 shell-out 实现上按预期 RED（0.527s）。它拒绝的是旧接线，不是生产 trip；
本轮后续 GREEN 与压力/无压力结果另行登记，不删除这个先红证据。

首次 GREEN 验证还出现一项见证测试自身的 RED（0.100s）：源码变异替换误命中同文件
另一个测试的 ledger 调用。替换范围改为默认缺席函数自身，并拒绝未实际替换的变异；
没有修改生产。修正后静态套件0.352s、结构化负例0.398s通过。

### 8.4 新默认入口实测（实现 `336ea4d`）

全部 socket 来自原 literal-loopback 夹具。默认进程内路径不编译 overlay，压力组与
无人工压力组串行，不并行运行另一组重测试；只进行轻量日志/源码/PR元数据核对。

| 验证 | 本轮结果 |
| --- | --- |
| Go1.23.1 默认入口 + Fatal cleanup 负例，`-count=1` | PASS13.322s；实际默认13.04s |
| Go1.26.5 默认入口，`-count=1` | PASS14.508s；实际默认14.16s |
| Go1.23.1 focused race×20 | governor266.602s、source2.875s；7个非opt-in入口各20/20 |
| Go1.23.1 默认入口 CPU压力 + race×50，fail-fast | PASS917.019s；50/50 |
| Go1.23.1 默认入口无人工压力 + race×100，fail-fast | PASS1,303.921s；100/100 |

focused命令：

```powershell
$env:GOTOOLCHAIN = 'go1.23.1'
go test -race ./internal/governor ./internal/v2/loopbackcarrier -run '^Test(LoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip|AbsentPeer|Absence)' -count=20 -failfast -timeout=12m -json
```

37类结构化负例每类20/20；源码接线的10种变异、原插入恢复与读取归因门各20/20。
未显式启用时的20次opt-in skip不冒充精确观测执行。默认20个样本持久clear，40次
owner清理成功；Connect最大13,019.7082ms（只诊断），FINISH sync最大12.2631ms。

压力命令：

```powershell
$env:GOTOOLCHAIN = 'go1.23.1'
$env:WINKYOU_FLAKE_111_CPU_STRESS = '1'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=50 -failfast -timeout=25m -json
```

实际28核、GOMAXPROCS28、56个busy worker；50组全部join、100次owner清理成功。
50个样本均精确DeadlineExceeded、内存/重开持久safety clear、一次admission与失败FINISH、
账本sequence/records均3、未完成占用/资源归零、端口可重绑；未观测到持久trip。
fixture最大10,061.6966ms、FINISH sync最大26.6684ms。压力返回时间的例外见下一节，
本表PASS只代表§8.1裁决后的默认终局/账本/排水门，不代表全部内部计时达标。

无人工压力命令（在压力组完全退出后执行）：

```powershell
$env:GOTOOLCHAIN = 'go1.23.1'
$env:WINKYOU_FLAKE_111_CPU_STRESS = '0'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=100 -failfast -timeout=40m -json
```

100/100精确错误/持久clear/计费与失败FINISH/排水通过，200次owner清理成功，
人工压力worker启动数0。Connect最大13,018.3405ms、journal区间最大13,013.9079ms、
FINISH sync最大8.4089ms，fixture最大20.4325ms；这些仍是各自观测区间，
不写成100次内部timer-stop观测。三个默认批次共170个新样本，不含§4/§7的旧批次。

另单独显式执行原精确观测：

```powershell
$env:GOTOOLCHAIN = 'go1.23.1'
$env:WINKYOU_ABSENCE_WITNESS = '1'
$env:WINKYOU_ABSENCE_WITNESS_RUNS = '1'
$env:WINKYOU_ABSENCE_WITNESS_RACE = '1'
go test -race ./internal/v2/loopbackcarrier -run '^TestAbsenceLifecycleWitness$' -count=1 -v -timeout=5m
```

PASS24.184s；真实parent/worker均race。该独立样本AcquireAttempt→timer stop
13,007.9391ms、probeio startedAt→timer stop13,003.7547ms，均严格小于15s；
持久clear、latch观察为false。此单样本不替代压力组或历史任何一次RED。

### 8.5 压力计时异常与证据边界

压力50样本中有3次Connect返回达到/超过15s，全部保留：

| 样本 | Connect总墙钟ms | journal观测区间ms | FINISH sync→Connect返回ms |
| --- | ---: | ---: | ---: |
| 8 | 26,086.9300 | 13,040.8758 | 3,020.2485 |
| 13 | 16,868.7260 | 16,502.8135 | 0.0000 |
| 37 | 25,027.9820 | 15,000.9601 | 1.8687 |

三次持久安全复检及计费/排水均通过，旧默认断言报告PASS；复审确认这不构成产品余量证明。
这些样本**没有内部timer-stop见证，不能声称双起点严格小于15s**；尤其journal
区间较长不能被隐去，也不等于probeio startedAt→timer stop。具体延迟位置、调度与
内部timer先后仍未确定，不把猜测写成根因。将这些实测限制一并交给独立复审；本轮
不新增生产观测hook、不调整预算或余量，也不以正常opt-in单样本抵销它们。

#### 8.5.1 复审 must-fix：25s caller 的竞争终止者（2026-09-10）

依据 [复审意见](https://github.com/houyuwushang/winkyou/pull/123#issuecomment-5618712598)。
§8.4 的全部170个默认样本都使用25s caller context。`AcquireAttempt` 的独立
ctx watcher 可以先关闭 lease，从而停止 probeio 的15s timer。`DeadlineExceeded`
本身甚至 FINISH reason=`expired` 都不能区分13s carrier deadline与25s caller deadline。
**25s 批次中 caller deadline 是可能的终止者，故该批次不能证明产品余量。**
旧批次保留为历史终局/账本/排水记录，不抵销 #111，也不计入本轮60s验收数。

以下为旧压力批次中全部 Connect≥15s 样本的原始测量行，按样本8、13、37排列。
只去掉 Go 测试文件/行号前缀；六个原始纳秒字段未取整、未重算或省略：

```text
ABSENCE_IN_PROCESS fixture_ns=10030357700 connect_ns=26086930000 journal_lower_bound_ns=13040875800 burn_sync_ns=13487400 finish_sync_ns=13748600 after_finish_ns=3020248500
ABSENCE_IN_PROCESS fixture_ns=420042300 connect_ns=16868726000 journal_lower_bound_ns=16502813500 burn_sync_ns=1892800 finish_sync_ns=21826300 after_finish_ns=0
ABSENCE_IN_PROCESS fixture_ns=10061696600 connect_ns=25027982000 journal_lower_bound_ns=15000960100 burn_sync_ns=14270900 finish_sync_ns=13441300 after_finish_ns=1868700
```

用 `pre_BURN = connect_ns - journal_lower_bound_ns - after_finish_ns` 得到
8/13/37分别为10,025.8057 / 365.9125 / 10,025.1532ms。这里的 BURN 边界是
**append后、sync前的既有hook**，不是 AcquireAttempt 或 probeio 的起点。

复审样本37推导（相对 Connect 开始；caller context稍早创建，故以下25s仅是近似）：

- BURN append在10.0251532s，FINISH synced在25.0261133s，Connect返回在25.0279820s。
- 设 `X = BURN append → carrier run/probeio起点`，包含 BURN fsync、提交后的
  校验/Consume等未分段区间。`burn_sync_ns=14270900` 只测得其中14.2709ms，
  **不能把 X 等同于 burn_sync_ns**；run与probeio起点另有微小差值 ε。
- carrier run deadline约为23.0251532s+X；probeio tripwire约为25.0251532s+X+ε；
  产品正常 lease.Close不早于25.0261133s（必须先完成持久FINISH）。
- caller watcher约在25.000s已经可以关闭lease，比tripwire早约25.1532ms+X+ε。
  因而“clear且返回expired”与caller抢先停止timer完全相容，不能证明产品自行清理有余量。
  样本13的较长journal区间也不能单凭短BURN fsync解释；未观测区间不能猜成fsync或调度。

本轮默认ctx固定为独立的 `60*time.Second` 字面量；静态门拒绝25s、从生产
`AttemptDuration` 派生或使用未冻结变量的替代。它只是防挂死兜底，远大于15s+2s；
另断言返回时caller未取消且尚未到其deadline，避免60s兜底再次被算作产品超时。
既有journal afterSync观察同时记录真实FINISH的`record.Reason`，要求
`PairingTerminalExpired`；Cancelled/CarrierError/缺失reason均由负向变异拒绝。
这些改动只在测试中，生产/配置/工作流delta=0。

#### 8.5.2 60s caller 的重新测量（实现 `144fed3`）

本轮只运行现有 literal-loopback 夹具，不并行另一组重测试。固定Go1.23.1、
GOMAXPROCS=28；压力组沿用28核×2=56个worker、每次yield前65,536次计算，
`-race -failfast` 不变。runner watchdog与每次60s caller兜底、生产15s/2s不是同一上限。

```powershell
$env:GOTOOLCHAIN = 'go1.23.1'
$env:GOMAXPROCS = '28'
$env:WINKYOU_FLAKE_111_CPU_STRESS = '1'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=50 -failfast -timeout=55m -json
```

首跑压力50/50 PASS704.416s，50次FINISH reason=`expired`、caller未到期、
内存/持久safety clear，100次owner锁清理成功，50组压力worker全部join。
Connect最大13,996.5556ms、journal下界最大13,539.6647ms、BURN sync最大40.4039ms、
FINISH sync最大54.3295ms、FINISH sync后最大16.3399ms；fixture最大659.6698ms，
pre-BURN最大452.3781ms。Connect≥15s样本为0，因此本批没有相应原始异常行。
本批没有复现 #111 RED，也没有复现旧约10,025ms间隙；这不关闭旧反例或证明其根因。

压力组完全退出后，同一实现、同一工具链/GOMAXPROCS，仅关闭人工压力：

```powershell
$env:WINKYOU_FLAKE_111_CPU_STRESS = '0'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=100 -failfast -timeout=40m -json
```

首跑100/100 PASS1,306.388s；100次expired/caller未到期/内存与持久clear，
200次owner锁清理成功，人工压力worker启动数0。Connect最大13,030.2753ms，
journal下界最大13,026.4015ms，BURN sync最大7.0231ms，FINISH sync最大13.4289ms，
FINISH sync后最大2.1802ms；fixture最大54.7556ms、pre-BURN最大5.7594ms。
Connect≥15s样本及生产RED均为0。上述两个批次没有启用runtime trace或overlay；
trace定位与精确内部计时不得借用这些数字冒充已完成。

之后独立运行focused回归：

```powershell
go test -race ./internal/governor ./internal/v2/loopbackcarrier -run '^Test(LoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip|AbsentPeer|Absence)' -count=20 -failfast -timeout=25m -json
```

首跑PASS：governor265.010s、loopbackcarrier3.575s，7个非opt-in顶层入口各20/20。
44类结构化负例（含FINISH Cancelled/CarrierError与caller兜底失效）各20/20；
14种源码变异均拒绝，Fatal-safe cleanup与原overlay可逆性门均通过。
默认缺席20/20 expired/caller未到期/内存与持久clear，40次owner清理成功；
Connect最大13,026.3276ms、journal下界最大13,019.6473ms、BURN sync最大5.7745ms、
FINISH sync最大7.9588ms、FINISH sync后最大4.2258ms，fixture最大23.0072ms、
pre-BURN最大10.1762ms；Connect≥15s与生产RED均0。
20次未启用opt-in的skip不算精确计时执行。本轮170个默认新样本与§8.4旧170个严格分开。

#### 8.5.3 仅测试侧 runtime trace 定位

额外诊断不计入上述170个未插桩验收样本。以相同Go1.23.1、GOMAXPROCS28、
56个CPU worker、`-race -failfast` 分组采样，每组10次，最多5组；所有文件留在仓库外。
测试函数标记namespace准备、已导出的governor获取步骤与Connect；既有journal
afterAppend observer仅增加固定 `burn_appended` trace标记，不新增生产hook/clock/延迟。

```powershell
$env:WINKYOU_FLAKE_111_CPU_STRESS = '1'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=10 -failfast -timeout=12m -trace='<PRIVATE_TRACE_FILE>' -json
go tool trace -d=1 '<PRIVATE_TRACE_FILE>'
```

原始trace含运行时源码路径，禁止作为公开artifact上传。只导出固定阶段、纳秒区间与
函数名，按测试goroutine重建Running/Runnable/Syscall状态，检查状态连续及区间闭合。
首个全量文本展开因吞吐过低主动停止；原始trace未丢失，改为仓库外原生流式解码。
解析器用独立PowerShell解析器及纯合成10s syscall输入交叉验证，合成结果不是产品证据。

前两组（`5b235cd`）的可见最长pre-BURN分别约377ms与382ms，较长syscall位于
`Commit → Admit → readValidatedPairingLedgerSnapshot → os.Open → CreateFile`：
组1样本4为370,041,056ns，组1样本2为358,870,049ns，组2样本8为366,317,944ns。
这些是新样本的函数级观察，**不能当作旧样本8/37的10,025ms根因**；也不据此归咎于
磁盘、杀毒、文件系统过滤器或调度。`GetConsoleMode`另有短记录，不是这三条最长调用。

组1样本6还暴露测试标记边界限制：原始pre-BURN=714,853,100ns，而标记内区间仅
7,758,665ns，标记启动开销落在旧stopwatch内，不能把差额认作产品Connect耗时。
`aad8149`将trace region开始移到stopwatch之前；前两组保留原貌，从第三组使用修正边界。
上述170个未插桩样本使用`144fed3`，没有这个标记开销。

五组采样及解码全部完成；全部50次expired/caller未到期/内存与持久clear、
100次owner锁清理、50组压力worker join均通过，无生产RED。首跑记录如下；
表中runner秒数采用JSON package pass事件，第二组包输出行159.617s与该事件159.618s
相差1ms，二者不混用：

| trace组 | 实现 | 通过数 | package pass秒 | 最大Connect ms | 最大原始pre-BURN ms |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | `5b235cd` | 10/10 | 149.213 | 13,880.0386 | 714.8531（含标记启动开销） |
| 2 | `5b235cd` | 10/10 | 159.618 | 14,119.8715 | 381.6808（同一旧标记边界） |
| 3 | `aad8149` | 10/10 | 147.310 | 13,878.9572 | 441.7146 |
| 4 | `aad8149` | 10/10 | 154.410 | 17,004.1671 | 3,941.9277 |
| 5 | `aad8149` | 10/10 | 170.145 | 14,390.6380 | 362.1128 |

第四组样本4是50个诊断样本中唯一的Connect≥15s记录，六字段原始行如下：

```text
ABSENCE_IN_PROCESS fixture_ns=387327500 connect_ns=17004167100 journal_lower_bound_ns=13061239800 burn_sync_ns=10513900 finish_sync_ns=20109100 after_finish_ns=999600
```

它的pre-BURN=3,941.9277ms，FINISH=`expired`，caller未到期，内存/持久safety clear，
账本与排水通过。Connect超过15s并不等于probeio从其自身起点超时；但仍须完整保留，
不可用该样本PASS替代内部timer-stop见证或旧10s间隙定位。

对应trace标记内pre-BURN为3,944,139,951ns（标记在stopwatch之前），其中
Runnable共3,902,573,914ns，最长连续Runnable区间3,902,309,382ns；Syscall共
35,334,940ns、Running共6,157,592ns、Waiting共73,505ns。这是测试goroutine
已可运行但尚未再次获调度的区间，**不是3.9s fsync或3.9s文件打开**。
不能把唤醒方的`gcBgMarkWorker`栈当作产品调用栈或据此指定旧样本根因。
另第三组样本4的438,384,292ns、第五组样本3的356,313,963ns确在上述
journal读取的`CreateFile`调用内；它们与长Runnable区间是不同观测。

第四组完整时序复核：该长Runnable之前的Waiting为73,505ns，但该转换没有产品调用栈；
其唤醒事件附带的是另一个goroutine的`gcBgMarkWorker`栈。逐段纳秒相加严格等于
3,944,139,951ns，状态区间本身成立；**不能从缺失的目标调用栈补造“卡在某个产品步骤”**。

#### 8.5.4 按复审停止条件暂停：旧10,025ms间隙未定位

**第5项仍未闭合。** 旧样本8/37只有六个聚合时间字段，没有runtime trace；
50个额外trace样本没有复现约10,025ms的pre-BURN间隙。新样本同时显示较短文件打开
延迟与一次3.902s Runnable等待，不能把任何一种观察倒推为旧两例的同源根因。
目前许可的测试侧采样不足以指定旧间隙落在哪一步，也不能断言加生产hook就必然能定位。

遵守本次任务的停止条款：不新增生产hook，不猜根因，不改15s/2s/包数/PPS/limits，
不扩大采样到现场或主机配置。本轮170个未插桩新样本与50个trace样本都没有出现
`memory_safety_not_clear` / `persistent_safety_not_clear`；这只是本轮未复现，
**#111仍未关闭，不能把生产缺陷改写成已修复。** 所有原始日志和trace在仓库外完整保留。

当前仅完成第1–4项及第5项的有界取证，**不进入第6项**：本轮最终全仓vet、
architecture、#116全仓分区、独立relay race×20尚未执行，不能借用下面§8.6的旧SHA结果。
改动只保存在#123原分支本地；未推送、没有本轮CI首跑，rerun=0，PR仍Draft且未合并。
后续需维护者裁决是否接受“旧间隙暂未定位”的证据缺口，或另行规定有界测试侧取证方案；
这不是自行放宽must-fix。#124/阶段3与其他PR保持未触碰。

#### 8.5.5 维护者裁决：保留定位缺口后继续验证（2026-09-11）

维护者在收到§8.5.4停止报告后，明确允许保留“旧间隙未定位”的结论，
继续第6项验证与推送。§8.5.4保留为当时的停止记录；本裁决只解除该继续工作前置，
不把定位项记为已完成，也不认定旧反例的根因或生产余量已经获得证明。

继续范围仍仅为#123原分支的测试与ADR：执行全仓vet、architecture、#116全仓分区
及独立relay race×20，记录首跑结果后推送并停下等复审。#111保持未关闭；不增加生产
hook、不调整15s/2s/limits、不触碰#124或阶段3，不进行现场网络或主机配置操作。
PR保持Draft、不合并；远端CI首跑单列，rerun仍禁止。本次验证见§8.7，不能借用§8.6。

### 8.6 旧提交9c0610d的全仓与交付核对（历史记录）

Go1.23.1，无人工压力，在上述三组重复测试结束后执行：

- `go vet ./...`：PASS。
- `go test ./internal/architecture -count=1 -v`：PASS9.376s，含现有变异门。
- `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -json`：
  按#116原分区，88个有测试包PASS、11个无测试包、0FAIL；governor95.553s、
  architecture11.671s、client1.170s。
- `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=1 -v`：
  实际独立relay1/1 PASS7.36s，package9.386s，observer worker归零。
- §1–§7原文前缀一致、三个相对链接有效、`git diff --check`与新增内容隐私扫描通过。
  原#115三个辅助文件等价迁入，原精确worker/template字节不变；生产/配置/工作流delta=0。
- 已运行的相关测试进程归零，原停用任务仍Disabled；无现场网络或主机配置操作。

本轮提交仅追加到#123原分支，保留RED与旧提交历史。远端首跑CI结果在PR描述单列，
本地PASS不写成远端全绿。保持Draft、不合并；阶段2推送后停下等复审，阶段3不启动。

### 8.7 裁决后第6项的最终本地验证（2026-09-11）

按§8.5.5继续，不再扩大定位采样。以下均为本次首跑，测试代码与`aad8149`一致，
后续仅追加ADR。固定Go1.23.1、GOMAXPROCS=28；关闭人工压力与精确overlay，
各组重测试串行执行，原始日志在仓库外独立保存，不覆盖§8.5或§8.6的旧批次。

```powershell
$env:GOTOOLCHAIN = 'go1.23.1'
$env:GOMAXPROCS = '28'
$env:WINKYOU_FLAKE_111_CPU_STRESS = '0'
$env:WINKYOU_ABSENCE_WITNESS = '0'
go test -race ./internal/governor ./internal/v2/loopbackcarrier -run '^Test(LoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip|AbsentPeer|Absence)' -count=20 -failfast -timeout=25m -json
go vet ./...
go test ./internal/architecture -count=1 -json
go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -json
go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast -timeout=15m -json
```

- 最终测试代码focused race×20 PASS：governor266.097s、loopbackcarrier3.569s，
  7个非opt-in顶层入口各20/20；44类结构化变异各20/20，14种源码变异每轮均拒绝。
  20次真实缺席均为FINISH=`expired`、caller未到期、内存与重开持久safety clear；
  40次owner清理通过，人工压力worker启动数0。未启用的opt-in仍不算精确内部计时证明。
- 这20次Connect最大13,016.7417ms、journal下界最大13,012.2418ms，BURN sync最大
  2.2633ms、FINISH sync最大6.8305ms、FINISH sync后最大4.5259ms；fixture最大
  26.6667ms、pre-BURN最大5.0869ms。Connect≥15s及生产RED均0。
  这些是独立的最终重验证样本，不重复计入§8.5.2的170次或§8.5.3的50次。
- `go vet ./...` PASS；独立architecture PASS10.886s，含既有变异门。
- #116全仓分区：88个有测试包PASS、11个无测试包、0FAIL；governor110.990s、
  architecture14.227s、client1.389s。该次默认缺席Connect13,016.0436ms，
  FINISH=`expired`、caller未到期、两级safety clear、资源/账本占用归零、端口可重绑。
- 独立relay race×20：20/20 PASS，package153.430s，单次最大7.660s；
  20次`observer_workers=0`见证，未遗漏全仓唯一精确排除的用例。
- 10个PR文件均为测试/ADR；生产/配置/工作流delta=0，原精确worker/template、
  压力helper及ADR§1–§7均未改。相对链接3/3有效、`git diff --check`及新增内容
  隐私扫描PASS；相关测试/产品进程检查为0，原停用任务仍Disabled。

本地首跑全部通过不等于远端CI全绿，也不关闭#111或补造旧间隙根因。
提交与推送仅沿用#123原分支，保持Draft；本head远端CI首跑在PR描述独立记录，
不manual rerun、不合并。推送后停止实现并等待复审，#124/阶段3继续冻结。

## 9. O2 裁决与设计（2026-09-14）

本节依据维护者本批明确选择 O2 的实施指令。问题背景见
[#111 既有记录](https://github.com/houyuwushang/winkyou/issues/111#issuecomment-5630029119)；
该旧评论仍列待选方案，不能冒称它已经包含本次裁决。基线 `2864a18`。
本节授权独立 Draft 实现与隔离测试，不授权合并、现场 I/O、主机配置或后续现场窗口。
§1–§8 的原始 RED、未定位结论和旧批次数字保持原貌，不重写为本次证据。

### 9.1 修复目标与取舍

`admittedCarrier.run` 的缺席终局原先先写 durable FINISH，再调用 controller.Close，
使 FINISH append/fsync 仍位于 probeio 的 15s duration 绊线内。O2 将这条终局路径改为
**撤销探测权限 → durable FINISH → 关闭 attempt lease**。

```text
旧 run 终局：13s 自有 deadline → FINISH append/sync → Controller.Close → 停止 probeio
新 run 终局：13s 自有 deadline → RevokeForTerminal → FINISH append/sync → Controller.Close
                                 │                    │                     │
                                 │                    配对 drain Complete   释放 attempt
                                 probeio 句柄/worker 排空、timer 停止、自己的 drain Complete
                                 attempt 与配对 drain 此时仍保留
```

不选 O1：增加固定余量仍把磁盘等待放在活动探测绊线内。
[#124 的 trace 证据](ADR-STRATEGY-SELECTION-CONVERGENCE.md#11113-已证实的阻塞链)
已在普通 runtime 快照路径观测到约 10s 的 MoveFileEx 系统调用；这不是对本路径 FINISH
fsync 或 §8.5 旧缺失 trace 样本的归因，但足以说明额外 2s 不是这种等待的可靠上界。
不选 O3：本次明确决定移除 run 终局上可避免的持久化/探测计时耦合，不仅记录风险。
FINISH 仍同步落盘，不改成后台队列、不跳过 fsync、不退款。

### 9.2 显式终局撤销能力

新增 `probeio.Controller.RevokeForTerminal()`，唯一生产调用点是
`internal/v2/loopbackcarrier/carrier.go` 的 `admittedCarrier.run` 终局 defer。

- 复用既有 stopLocal 的撤销/排水语义：拒绝新操作、取消本地 context、关闭全部未移交
  probe socket，并等待已接纳的 I/O 与 pending open。之后 Open/Write/Register 均拒绝，
  有效参数下归为 `ErrLeaseClosed`；不能复活旧 handle、换 endpoint 或重新 Promote。
- 复用既有 handoff 完成通知唤醒 duration watcher。这里不移交 datagram、不创建
  PacketTransport、不把失败标成 promoted，只复用“保留 attempt，但探测权限已经结束”
  的计时器脱离语义。watchLifecycle 正常退出，不因随后 FINISH 慢而触发 duration trip。
- 返回前确认 watcher 已退出，并幂等完成 probeio 自己的 drain；不能只拿 watchDone
  当作 Complete 已发生的证明，因为现有 watcher 先关闭 watchDone 再调用 Complete。
- 不调用 AttemptLease.Close，不完成 pairing gate 的 drain。后者仍由既有 finish() 负责。
  API 幂等；它返回的错误 join 进 carrier 错误，不得导致 FINISH 被跳过。
- 沿用 reviewed Datagram 的 Close/解除 I/O 契约，不新增任意第三方 factory 或强制终止
  不合作内核调用的承诺。逻辑 revoked 与物理排空不能混为一谈。

run 的 defer 无论成功还是失败，都先调用此幂等 API（controller 存在时），再调用
authorization.Finish(reason)，最后调用 controller.Close。已完成的 terminal promotion
不会被重复移交；其短命 transport 仍按原路径关闭。本 API 不返回任何数据面能力。

### 9.3 两个 drain 与计费不变量

正常终局下，最终 Controller.Close 之前 probeio 与 pairing gate 的 drain 均已完成，
AttemptLease.Close 应立即收束。若仍有未完成 drain，既有
`CancellationDrainTimeout` 与持久 `cancellation_timeout` 语义不变，不能吞掉第二道绊线。

冻结值全部不变：`AttemptDuration=15s`、`terminalDrainMargin=2s`、
`MaxAttemptDuration`、machine cancellation drain 2s、3 packets / 3 PPS。
2s terminal margin 用于 run 退出到撤销，不再要求覆盖其后的 FINISH 磁盘等待。
admission 仍全额计入 15s envelope；24h packet 与 admission 计数不因早撤销而减少。
这不是向 Gate B/C 引入新的完成阶段：§19.9、handoff 实现、golden 与预算保持字节不变。

### 9.4 崩溃窗口

- revoke 前崩溃：沿用原 governor/OS 与未完成 admission 恢复；不新增恢复代码。
- revoke 完成、FINISH 写入前崩溃：OS socket 已排空，journal 有 BURN 无 FINISH。
  既有 unfinished charge 保留，重启不能重用该 credential 或获得退款。
- FINISH 写入/sync 期间崩溃：仍按已有持久 journal 校验/恢复处理，不能凭进程内标志
  补造 FINISH。任何不确定状态仍 fail-closed。
- FINISH 成功后、最终 Close 前崩溃：持久终局已可见；不新增补发、重试或自动恢复。

测试只核对这些现有行为，使用新临时 namespace 与合成 credential，绝不 reset ledger。

### 9.5 红回归、变异与验收

先在 governor 的既有 FINISH `afterAppendBeforeSync` test hook 注入：

| 回归 | 延迟 | 旧 run 终局预期 | 修复后预期 |
| --- | ---: | --- | --- |
| R1 | 2.5s | memory_safety_not_clear，持久 hard_limit_exceeded | clear、FINISH=expired、资源归零、端口可重绑 |
| R2 | 10s | 同上 | 同上 |

Connect 墙钟预计约 13s 加注入延迟，只记录分段数据，不把它重新作为 probe 资源上限。
原默认缺席回归及其 AST 接线门保持原样，调用方仍为独立 60s 兜底。
新变异必须拒绝 FINISH 先于 revoke、revoke 后仍能发送、提前关闭 attempt、计费减少、
白名单外引用该 API；错误传播与幂等完成另有测试。崩溃窗口通过真实 journal 与 OS 见证，
不把内存状态或强制退出本身冒充持久/物理排水证据。

Go1.23.1 首跑验收依次记录：R1/R2 RED→GREEN；#123 同 profile 的压力至少50
（GOMAXPROCS 与 2×CPU busy worker、race、fail-fast）、无压力至少100、focused race×20；
probeio/governor/loopbackcarrier/architecture race×20；C1b memory pipeline 本机首跑；
#116 全仓分区与独立 relay race×20；vet 与 Linux CGO=0、natlab/c1bproof tagged vet。
普通 cmd/wink 构建产物留仓库外，go tool nm 须为零 natlab/c1bproof 符号。
远端首轮 CI 单列，不 rerun 求绿；每步独立提交，未执行项不预填 PASS。

### 9.6 单独登记的提前 FINISH 路径

源码核对另发现共享 pairing gate 的 BeforeFirstEmission/CheckActive 可以在 validate 失败时
先调用内部 finish，再向 carrier 返回错误；watchInvalidation 也可独立选择终局。
仅重排 run 的 defer 不能证明这些更早的 FINISH 也先撤销了 probeio。
已在 [#111 补充记录](https://github.com/houyuwushang/winkyou/issues/111#issuecomment-5660948336)
登记。当前是源码可达性结论，不伪称已对这条支路取得动态 latch 复现。

按本批不扩改共享生产范围的纪律，本 PR 不顺手修改该授权层。R1/R2 只证明本次指定的
run-owned 缺席终局；这一残留不隐去，当前保留 Refs #111，不贸然声明全部失败路径或
整个 issue 已闭合。是否扩展该顺序覆盖由维护者/独立复审另行处理。

### 9.7 实施前 R1/R2 首跑 RED

在 docs 提交 `09d0aa2` 上仅新增测试，生产代码仍为基线。Go1.23.1、Windows、
GOMAXPROCS=28、CGO=1，无人工压力；两个子例在同一进程串行运行，不 fail-fast、不 rerun：

```text
go test -race ./internal/governor -run '^TestLoopbackCarrierSlowFinishRevokesBeforeDurableIO$' -count=1 -timeout=3m -v
```

| 首跑 | 实际 FINISH hook 延迟 | Connect | memory / persisted | FINISH | 24h admission / packets | 未完成 / 活动 attempt | 端口重绑 |
| --- | ---: | ---: | --- | --- | --- | --- | --- |
| R1 | 2,500.2886ms | 15,506.3473ms | tripped / hard_limit_exceeded | expired | 1 / 3 | 0 / 0 | PASS |
| R2 | 10,000.3356ms | 23,005.1182ms | tripped / hard_limit_exceeded | expired | 1 / 3 | 0 / 0 | PASS |

两个 hook 均只执行一次；两例都产生 `memory_safety_not_clear`、`owner_reopen_failed`、
`persistent_safety_not_clear`，后两项来自带原持久 trip 的 owner 重开拒绝，未清除 trip 或 ledger。
package 首跑 FAIL39.575s；两个 port-rebind 子例 PASS、peer/reservation 归零、清理后 owner lock
可重取。该 RED 是实际 duration trip，不是编译失败或夹具提前取消。
原始日志保存在仓库外，SHA-256：
`e85b4b81f0ba98673aacc3005cd6d8568912945c73e136391a507363f4d5e412`。
尚未运行修复后 GREEN；后续结果另列，不能覆盖本表。

### 9.8 O2 实现与定向首跑

`ea6b696` 只新增 `internal/probeio/terminal_revoke.go` 并修改 loopback run 的终局 defer 与
一段说明注释；生产净变更为 31 行新增、4 行删除。既有 probeio.go、Gate A/B/C 实现、所有冻结
常量与 golden 均未改动。`1e517c0` 另行加入所有权、顺序、崩溃与调用者门测试。

| 首跑 | 实际 FINISH hook 延迟 | Connect | memory / persisted | FINISH | admission / packets | 资源 / 未完成 / 重绑 |
| --- | ---: | ---: | --- | --- | --- | --- |
| R1 GREEN | 2,500.2569ms | 15,508.4195ms | clear / clear | expired | 1 / 3 | 0 / 0 / PASS |
| R2 GREEN | 10,000.1137ms | 23,008.0858ms | clear / clear | expired | 1 / 3 | 0 / 0 / PASS |

与 §9.7 完全相同的命令和延迟注入；两个 FINISH hook 均执行一次。package PASS39.933s，
外层命令46,712ms；原始日志 SHA-256：
`15b72a32cba1a5134109ba620fe88fa05bb13772a2100866b52cffaf724886e7`。
这里大于15s的 Connect 墙钟包含已撤销后的持久 I/O，不是把探测窗口延长到了23s。

定向测试首跑另证：

- `go test -race ./internal/probeio ./internal/v2/loopbackcarrier -run '^TestTerminalRevoke' -count=1 -timeout=2m -v`：
  probeio PASS1.915s，loopbackcarrier PASS1.654s。两个 probe datagram 全关；撤销后的
  Open/Register/Read/Write 拒绝；pending open 与在途 read/write 排空；16 个并发重复调用幂等；
  probeio drain 完成但另一个 owner 的 drain、attempt 与原 request 仍保留。FINISH 内进行 OS 端口
  重绑见证，撤销/FINISH/Close 三种错误都保留，FINISH 恰好调用一次。
- `go test ./internal/architecture -run '^TestTerminalRevoke' -count=1 -v`：PASS0.867s；
  21 个越权引用形态、8 个顺序/排水变异、7 个成本降低变异全部被拒。
  原默认 observation 门另外继续检查 admission/24h packet 不退款。
- `go test -race ./internal/governor -run '^TestLoopbackTerminalRevokeCrash' -count=1 -timeout=3m -v`：
  PASS2.076s。实际 run 在 FINISH 首字节写入前被 test-only ledger seam 暂停，子进程活着时端口
  已可重绑；kill 后 journal 仍只有 INITIALIZE+BURN，未完成 admission=1、packets=3。
  同材料重启失败，独立 UDP 接收见证零发射，端口与 owner lock 可重取、safety clear。
- `go test -race ./internal/governor -run '^TestLoopbackTerminalRevokeRetainsSecondDrainTripwire$' -count=1 -timeout=2m -v`：
  PASS3.893s。所有 drain 完成时 Close 在本机时钟精度内立即返回、safety clear；故意留下另一 owner
  的 drain 时 Close2,007.9645ms 返回，原 `cancellation_timeout` 持久 trip 可重开验证，资源归零。
  这是第二道绊线的负向控制，不是正常缺席批次的生产 RED，也未降低2s门槛。

新增崩溃与第二道绊线夹具各有一次编译前检查失败（辅助函数返回值个数、现有常量名引用错误）；
均只修新测试，原始日志单独保留。这两次不是动态 RED，也未计入上述编译通过后的首跑。
其余完整验收批次尚未完成，不预填全绿。

### 9.9 旧 opt-in 精确计时模板的范围限制

另见 [#111 测试兼容性记录](https://github.com/houyuwushang/winkyou/issues/111#issuecomment-5661368752)：
`absence_worker_test.go.txt` 的旧 `absenceLifetimeInvariant` 要求 FINISH sync 先于 probeio worker/
timer 停止，且把 `finish_after_stop` 设为负向控制；这正是 O2 要改变的先后关系。
本批按约束保留原默认缺席测试、AST、overlay 与 template 字节不变，未运行的旧 opt-in 不计为
O2 的 PASS，也不据此宣称精确双起点旧测量已迁移。当前是源码兼容性发现，不是已复现的新动态
latch；该模板的单独迁移需后续确认。默认真实 journal 回归和本批 R1/R2、撤销、崩溃见证独立有效。

### 9.10 原默认缺席回归：压力首批

Go1.23.1、Windows、GOMAXPROCS=28、56 个 busy worker（2×28 CPU），保持原 helper、
60s caller guard、所有终局断言与 fail-fast。该批次在 `1e517c0` 上运行，期间只追加文档：

```powershell
$env:WINKYOU_FLAKE_111_CPU_STRESS = '1'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=50 -failfast -timeout=30m -json
```

首跑50/50 PASS，package802.894s、外层807,274ms；50 个 FINISH=expired，50 个双层 safety clear，
50 次压力 worker_remaining=0；FAIL、memory_safety_not_clear、persistent_safety_not_clear 均0。
日志 SHA-256：`44b4018e052ef51b14a04a1a6a6c4cda8a2f528099665183e7926f2e64ce1532`。
Connect 最大23,119.9938ms，FINISH sync 最大36.7789ms，fixture 最大10,075.8071ms。

4 个 Connect≥15s 的原始计时行如下，样本序号为本批独立计数，不沿用 §8 的历史序号：

```text
sample=10
ABSENCE_IN_PROCESS fixture_ns=376425800 connect_ns=21272820500 journal_lower_bound_ns=13479090400 burn_sync_ns=10201000 finish_sync_ns=19977700 after_finish_ns=0
sample=17
ABSENCE_IN_PROCESS fixture_ns=10075807100 connect_ns=23119993800 journal_lower_bound_ns=13058696500 burn_sync_ns=14536200 finish_sync_ns=23057600 after_finish_ns=14441500
sample=18
ABSENCE_IN_PROCESS fixture_ns=381187600 connect_ns=18755118400 journal_lower_bound_ns=13362208500 burn_sync_ns=2112500 finish_sync_ns=1999500 after_finish_ns=502900
sample=25
ABSENCE_IN_PROCESS fixture_ns=10056326300 connect_ns=17958584800 journal_lower_bound_ns=13033751700 burn_sync_ns=573000 finish_sync_ns=20802000 after_finish_ns=1004300
```

这些墙钟样本不能反推内部 timer 的停止时刻，也不是新的 FINISH fsync 根因定位。
O2 的慢 FINISH 顺序证明来自 §9.7–§9.8 的同故障 RED→GREEN、FINISH 内重绑与 drain 见证。
本表不替代后续无压力100、focused20、四包race20或远端 CI，尚未执行/完成者另列。

### 9.11 原默认缺席回归：无压力首批

保持 Go1.23.1、Windows、GOMAXPROCS=28，关闭人工压力与旧 opt-in observer：

```powershell
$env:WINKYOU_FLAKE_111_CPU_STRESS = '0'
$env:WINKYOU_ABSENCE_WITNESS = '0'
go test -race ./internal/governor -run '^TestLoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip$' -count=100 -failfast -timeout=45m -json
```

首跑100/100 PASS，package1304.494s、外层1,308,872ms；100 个 FINISH=expired，100 个双层
safety clear，FAIL=0。Connect 最大13,025.785ms、FINISH sync 最大5.8863ms、fixture最大
29.7236ms；Connect≥15s 样本为0。原始日志 SHA-256：
`bbfba34234cf2c0d2771bde53162e0abd132c93908beae6dca06cd66479733e7`。
没有缩短任何产品或测试内 deadline，没有减少次数，也没有把这100次当作压力样本重复记账。

### 9.12 原 focused race×20 首批

同一 Go1.23.1/Windows/GOMAXPROCS=28、无人工压力：

```text
go test -race ./internal/governor ./internal/v2/loopbackcarrier -run '^Test(LoopbackCarrierAbsentPeerExpiresCleanlyWithoutSafetyTrip|AbsentPeer|Absence)' -count=20 -failfast -timeout=25m -json
```

governor PASS268.300s，loopbackcarrier PASS3.594s，外层276,117ms；7 个非 opt-in 顶层入口
各20/20，20次缺席 FINISH=expired，FAIL=0。包含原观察/计费负向控制、默认回归接线 AST、
overlay/template 插入后可还原的原门禁，文件本身未修改。
`TestAbsenceLifecycleWitness` 沿用原 opt-in 条件，20次均未启用；这20个既有 skip 不算 PASS，
也不是为 O2 新加 skip，其语义限制已在 §9.9 单独披露。
原始日志 SHA-256：`703d5e76e2e738bf6c7c1db2bdf25ad74a81563602771fc29b0df8d36f6612c3`。

### 9.13 四个受影响包的完整 race×20 首批

沿用 Go1.23.1/Windows/GOMAXPROCS=28，无人工压力，按包串行：

```text
go test -race -p=1 ./internal/probeio ./internal/governor ./internal/v2/loopbackcarrier ./internal/architecture -count=20 -failfast -timeout=90m -json
```

| 包 | 首跑 | package 耗时 |
| --- | --- | ---: |
| probeio | PASS，完整20轮 | 142.634s |
| governor | PASS，完整20轮 | 1925.999s |
| loopbackcarrier | PASS，完整20轮 | 34.038s |
| architecture | PASS，完整20轮 | 850.782s |

总命令2,966,104ms，FAIL=0；没有命中其他需登记的实际失败签名。R1/R2 各20次 clear/expired，
新子进程崩溃/重启见证20次、第二道绊线正负控制各20次；全部句柄撤销、在途 I/O 排空、
FINISH 内重绑与错误保留、调用边界与变异门也各20轮。原 handoff/完成阶段测试和 golden 未改。
日志 SHA-256：`ea3a98861e815f9b472d9984833369c14d621eb20b540051f9dc64014035246a`。

本批另外保留13个原有条件入口的 skip（每个20次）：pairing gate 的 parent-witness crash、
safety-trip emission boundary、32进程同 credential 竞争、1000次同 bundle 重启、fresh-credential
restart windows、emit-before-burn witness mutation；hard-NAT 的32进程竞争、1000次重启及
FreshTopology100；旧 loopback 两进程成功、message-one crash、pre-Promote crash；以及旧
opt-in 精确缺席 observer。它们没有新增 skip、没有被算作 PASS，也不能借本次替代其独立 CI 门。
本批新增的真实子进程 revoke/FINISH 崩溃回归则未跳过，已经在 race 下实际跑满20次。

### 9.14 C1b memory pipeline 与独立校准

首次宽选择器 `^TestGateC1bMemory` 在 GOMAXPROCS=28 下误选了仅允许 GOMAXPROCS=4 的
`TestGateC1bMemoryFixtureFresh100Schedules` 校准入口；它在采样前拒绝运行，package FAIL1.133s，
原文为 `Fresh100 fixture calibration requires CI-equivalent GOMAXPROCS=4`。
这是验证命令的前置配置错误，不是 #133 的候选耗尽复现，也没有运行到实际 pipeline。
该首跑 RED 完整保留，SHA-256：
`06cc8ef79cd16b2a7ab3ff45348fb6f84c6eacba6b9026a31b69fa7194ca85f5`。
已在 [#133 验证配置记录](https://github.com/houyuwushang/winkyou/issues/133#issuecomment-5662482727)
登记；未修改仓库窗口、测试、工作流，也没有覆盖原日志或重跑该错误配置。

之后按各入口原有前置分区：普通 pipeline 使用 GOMAXPROCS=28；Fresh100 校准单独使用4；
原独立压力校准单独使用2并启用其压力开关。各自保存新的首次执行结果，不冒充宽选择器首跑全绿。
普通 pipeline 保持 Go1.23.1、Windows、race，启用 `WINKYOU_GATE_C1B_REPEAT_REQUIRED=1`：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1b(Memory(ProductPipelineReachesPostOOBEcho|SlowDurableFinishReachesPostOOBEcho|FixtureSessionWindows|SlowResponderDurableFinishReachesPostOOBEcho|CancellationAfterDurableFinish|ProductPipelineFresh100|CLIAndClaimedChildPipeline|CLIEvidenceDriftAndExhaustionAreOneShot)|GateBProductHandoffRetainsOwnershipUntilFinish)$' -count=1 -failfast -timeout=30m -json
```

九个顶层入口首跑全部 PASS，无 FAIL/skip，package193.898s、外层200,898ms。
Fresh100 实际100个 fresh namespace、3种确定性 schedule、residue=0，wall154,413ms；
另覆盖 handoff 持有到 FINISH、慢 FINISH、取消、CLI/claimed-child 组合及证据漂移/候选耗尽一次性终局。
日志 SHA-256：`abadef7083d71e820e1c9413eb8b19bec728c22fec5184c20523c7af457a9b7f`。
Fresh100 独立校准首次正确配置执行（GOMAXPROCS=4、内部2个 busy worker）：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryFixtureFresh100Schedules$' -count=1 -failfast -timeout=15m -json
```

| profile | 完成场景 / endpoint | p50 | p95 | max | 原 candidate 窗口 | p95 < 80% |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| predictive | 34 / 68 | 502.9541ms | 505.5464ms | 524.2687ms | 1000ms | PASS |
| asymmetric | 33 / 66 | 454.8016ms | 462.4929ms | 475.2712ms | 1500ms | PASS |
| hard-16k | 33 / 66 | 911.1974ms | 989.9197ms | 1010.9043ms | 4000ms | PASS |

100个 fresh namespace 全部完成，无 FAIL/skip；package164.932s、外层169,919ms。
SHA-256：`9040d6cbef9e19577c29a6e5d7427e16ae7fb1e13767797167feeb60f19cbc05`。
未修改 #133/#119 的窗口或夹具，不把本批的有限测量当作其全部环境已消除 flake 的证明。

原独立校准另按 GOMAXPROCS=2、`WINKYOU_FLAKE_119_STRESS=1` 首次执行：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryFixtureStressSchedules$' -count=1 -failfast -timeout=5m -json
```

PASS10.528s，外层16,189ms，无 FAIL；SHA-256：
`da3acefaacd8afaa643c6fcb2b0ffa8db7b561cd184163552ad7e17fca3ae395`。
以上校准的运行器超时不改变任何产品/夹具冻结数字。剩余全仓验收单独记录。

### 9.15 静态检查与全仓分区首跑

继续按 Go1.23.1、Windows、GOMAXPROCS=28 串行执行；没有 source/workflow 变更或 CI rerun：

| 命令 | 首跑结果 | 外层耗时 | 原始日志 SHA-256 |
| --- | --- | ---: | --- |
| `go vet ./...` | PASS，无诊断输出 | 14,209ms | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `go test ./internal/architecture -count=1 -json` | PASS9.228s | 12,095ms | `1b9158ce0df6e86fd6c558f16dfeaa70100f6c7e857d807e050a13964780660f` |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -json` | PASS，88个有测试包、11个无测试包 | 193,097ms | `9bbe7b98b4a70c5b377b55a37c578e66532930524cf3501a923a2f1c78681292` |
| `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast -timeout=15m -json` | PASS20/20，package164.705s | 173,701ms | `e9bb85064946eac83a297621c3571119d8bd3e8427f003e89801832e36135b47` |
| `GOOS=linux CGO_ENABLED=0 go vet -tags=natlab,c1bproof ./...` | PASS，无诊断输出；未运行 Linux 二进制 | 15,451ms | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

全仓按 #116 原分区只把 relay 用例移到独立 race×20 批次，并非删除验收。1814个顶层测试 PASS，
0个失败；14个原有 opt-in/平台入口 skip 未计入 PASS：artifact symlink、旧缺席精确 observer、
hard-NAT1000重启及 FreshTopology100、TUN backend、两个 relay 诊断、两个旧 ICE/relay 条件测试、
session 诊断阻塞、legacyICE 诊断取消、Docker smoke、两个 Windows 特权转发测试。
未新增跳过条件，也未把本机跳过当作 required CI 已通过。

生产范围核验仍严格只有两个文件：terminal_revoke.go 为24行新增，carrier.go 为7行新增/4行删除。
既有 probeio.go、Gate A/B/C、默认缺席测试及 overlay/template、配置、工作流均零差异。
新增行身份/密钥/个人路径扫描零命中，13个相对文件链接全部存在，`git diff --check` 无错误。
远端 CI 与其尚未运行的门禁另列，不预填 PASS。

普通 `cmd/wink` 无标签构建留仓库外，仅运行编译器和 `go tool nm`，从未执行该二进制。
build/nm 均退出0，5,442ms；natlab/c1bproof 符号命中0。
构建产物 SHA-256：`25419f3c6680d4b9f4526e3761b746d3556e81a3a6725c5c13787b0a832b2e7f`；
原始 nm 输出 SHA-256：`7a6ce5c19cbc28b4f0d0cd551f87862f271ca4802f19fdca5eb0fbe2daa94f27`。
本地必跑动态批次均通过，但 §9.6/§9.9 的单独范围限制与 §9.14 的首次命令配置 RED 均保留。
本 PR 使用 Refs #111，等待独立复审，不合并、不推进现场权限。

### 9.16 caller cancellation 与两阶段终止裁决（2026-09-20）

共享 gate 的提前 FINISH 不能仅靠 run defer 撤销；caller cancellation 还会先启动 governor
的 2s drain，等待 pairing FINISH，导致已排空网络仍报 cancellation_timeout。
维护者已选择方案 2，契约见[回环两阶段终止 ADR](ADR-LOOPBACK-TWO-PHASE-TERMINATION.md)。
网络门不变，独立有界记账阶段由 governor 持有；磁盘超时不退款、不释放未排空 owner，
也不等同于网络安全 clear。先前 RED 与范围限制保留，后续实测另列。
