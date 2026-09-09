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
