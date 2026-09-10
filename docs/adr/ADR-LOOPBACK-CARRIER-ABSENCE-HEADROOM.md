# ADR：loopback 缺席路径的生命周期见证与 FINISH/drain 余量

Status: **Draft，测量证据；未修改生产余量**（2026-09-09）。Refs #111。
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

### 8.6 本轮全仓与交付核对

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
