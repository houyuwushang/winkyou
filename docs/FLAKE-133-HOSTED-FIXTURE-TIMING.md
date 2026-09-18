# #133：托管夹具计时与校准证据

## 1. 范围与测量前置裁决

基线 `97c3750`。维护者在 2026-09-18 同意先补成功/失败采集，取得托管 CI
首跑样本后再校准。此阶段不改生产代码、任何窗口、测试命令、count 或 job timeout。
Refs #133；采集成功不等于四种历史失败已修复。

历史采集的 64 个 job 中，最近首跑 Windows/Linux 各 30 个：59 个成功 job 没有
`MEMORY_PHASE`，1 个失败 job 有 46 行。另补 4 个历史 job。两个 predictive 失败
没有阶段行；hard-16k 没有 winner；asymmetric slow-FINISH 没有 finish_recorded
通知。不得把缺失值写成零或把失败终局时长当作成功完成时间。
详见 [测量前置核查](https://github.com/houyuwushang/winkyou/issues/133#issuecomment-5724640608)。

## 2. 只读计时契约

- 唯一采集位置是既有 C1b/liveness memory 公共夹具；复用已有 progress witness，
  不新增产品 hook，不改回调返回值、网络能力、调度、预算或已有失败日志。
- 环境变量 `WINKYOU_FIXTURE_TIMING_DIR` 显式启用；未设置不写文件。
  每次 invocation 在测试 cleanup 阶段写一个独立、排他创建的 JSON 文件。
  文件不使用测试名、PID、设备身份、目录、地址、密钥或命令作为内容。
  磁盘写入在夹具已有清理之后，不放入 candidate/FINISH 的关键路径。
- 成功和失败都写；写入失败使测试失败，只输出稳定说明、不输出路径。
  文件值仅为整数及整数数组。重复次数和双端不能合并去重；每文件代表一次双端运行。
- schema=1；profile=0/1/2 对应 predictive/asymmetric/hard-16k。
  scenario=0 普通、1 CLI、2 initiator slow-FINISH、3 responder slow-FINISH、
  4 cancel-after-FINISH、5 evidence-drift、6 candidate-exhaustion、7 liveness。
  `failed` 是整个子测试结果（0/1），不是协议预期失败的分类。
- `stages_ns` 为双端各 23 槽，顺序锁定为现有 `ProductProgressSequence`；
  相对于 witness 创建时刻的单调纳秒，未见事件记 `-1`，真实零时刻保留为 0。
  `candidate_budget_ns` / `active_budget_ns` 是原值的只读拷贝；
  `finish_delay_ns` 只记录既有 3500ms 注入量，不调节它。
- candidate→winner、winner→finish_recorded 按同一端相减，缺任一端点即缺失。
  preflight→finish_recorded 是 **active 建立耗时的保守上界**（含 reservation 前置），
  ssh_spawn→finish_recorded 是下界，不冒充 active 定时器的精确起点。
  不把 terminal/liveness 会话结束当作建立完成；FINISH 通知缺失也不等于 journal 未写入。
- 脚本对完整样本按 profile/scenario/failed/side 分组，nearest-rank p50/p95/max；
  缺失/截断单独计数。校准前仍需检查 profile/窗口覆盖，不以无样本的分位数推导地板。

## 3. CI 与隐私

相关 memory、owner、idle/blackholes/nonproof job 使用各自 runner 临时目录。
追加 `always()` 的验证/摘要与 artifact 上传，测试命令原样保留。
上传仅包括通过严格 schema 校验的数字文件和数字摘要，不包含原始 job 日志。
禁止未知字段、字符串值、非法 profile/槽数、除 -1 缺失标记外的负时间、
混入其他文件或符号链接。
采集脚本与测试均使用标准库，不新增依赖；GitHub 下载模式只读 API。
job 已有预算不变，首跑单列上传开销及 80% 预算判定；超线只登记，不抬预算。

## 4. 验证计划与结果

1. 源码契约先 RED：旧夹具没有无条件 cleanup 采集。
2. GREEN 与变异：失败专属采集、槽位漂移、丢失值转零、隐私字段、缺 artifact、
   减少 count/改变命令均拒绝；并发写不覆盖既有样本。
3. Go 1.23.1：聚焦 race×20、Fresh100 100 个新 namespace、受影响包、architecture、
   vet、全仓 #116 分区与独立 relay race×20；原始首次 RED 保留在仓库外。
4. 托管首跑保留每个 profile 的完整与截断数，不 rerun 求绿。
   数据到齐前不提交校准数字，不声称 Closes #133。

### 4.1 本地首跑（Go 1.23.1、Windows）

| 批次 | 实测结果 |
| --- | --- |
| 旧实现新增捕获契约 | RED，0.448s；旧实现缺少成功路径的无条件 cleanup 捕获 |
| 首个修复后契约 | GREEN，0.147s |
| 最终新增契约与变异 race×20 | PASS，4.049s；包括立即注册、成功/失败采集、原 CI 命令与上传范围 |
| 数字脚本离线负面矩阵 | 11 项 PASS；隐私字段、重复键、截断、顺序、类型、archive 路径及只读 API |
| 真实 memory 路径 race×20 | PASS，包内 547.804s / 外部 558319ms；220 次双端运行 |
| required Fresh100，GOMAXPROCS=4 + 两个忙线程，race | PASS，100/100，200 端点；外部 173333ms |
| 整包架构 race×20，20m 测试进程总时限 | **RED，1200.275s**，总时限超时；未完成，不用其他结果替代 |
| 普通完整架构检查 | PASS，外部 13273ms，与上行分开记账 |
| go vet ./... | PASS，外部 24196ms |
| 全仓 #116 首跑 | RED，外部 209074ms；新增采集步骤与既有 C1b CI 精确白名单不一致 |
| 白名单修正后 CI 契约 race×20 | PASS，65.188s；原九条 proof 命令与既有预算原样，另验采集不可绕过 |
| 修正后的全仓 #116 分区 | PASS，外部 204386ms；与上述首次 RED 分开保留 |
| 独立 relay race×20 | PASS，包内 165.504s / 外部 190829ms |
| Linux 交叉 tagged vet（natlab,c1bproof） | PASS，外部 32422ms |

整包架构超时时位于既有 `TestSelectionConvergenceDetectsBypassMutations` 的
`selectionBoundaryViolations` / `go/parser` 扫描，当前测试已运行 12s。
没有断言失败行，但不能因此称该批通过；不修改 selection 代码，不重跑这批求绿。
首次日志 SHA-256 为 `a106d01d933fa192e3c0759bf06b90d8a495cf494372b834a35ab42cbbb2897c`，
原日志保留在仓库外。[登记记录](https://github.com/houyuwushang/winkyou/issues/133#issuecomment-5725076451)。

全仓首次 RED 是本次新增采集的契约接线遗漏，不归因于既有 flake：
`TestGateC1bMemoryCIContract` 与其 mutations 要求原环境和步骤精确相等，
没有包含新增采集。修正只在原清单后允许一个固定 `always()` 验证/上传步骤与一个目录变量；
原 proof 命令、顺序、count、超时、预算公式均未改变。原有减次数/删步骤变异仍对准 proof，
另加删采集、成功专属采集、绕过校验上传、提前采集等变异。
首次日志 SHA-256 为 `8793b72a5e06bd1a8c81916e22433a3ee38ae64219af6d36af6f32b6b4748078`，
修复后的全仓批次使用另一份日志，不覆盖首次 RED。

220 个真实夹具样本通过提取校验：440 个端点、22 个分组；80 个缺失 winner 的
端点来自预期 evidence-drift/exhaustion 场景，保留为截断而非零耗时。
Fresh100 的 100 个文件、200 个端点全部通过校验，没有缺失 winner。
以下仅证明采集能够记录分布，**不是 hosted 校准输入**：

| profile | 端点样本数 | candidate→winner p95 最大值（两侧取较大，ns） | max（ns） |
| --- | ---: | ---: | ---: |
| predictive | 68 | 504408000 | 504503100 |
| asymmetric | 66 | 459920200 | 481962200 |
| hard-16k | 66 | 1095258900 | 1142852800 |

本地批次未命中新的 #101/#125/#132/#133/#139 签名；整包架构 race×20 仍为上述未完成状态。
生产 Go、配置、依赖改动均为 0。尚无托管采样数据，不生成新地板/校准快照。
测量阶段保持 Draft/Refs #133；A 的完整校准及 B/C/D 均未完成。

主要验证命令（各批独立日志，失败后未原样 rerun）：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1b(FixtureTimingFiles|MemoryFixtureSessionWindows|MemoryProductPipelineReachesPostOOBEcho|MemoryCLIAndClaimedChildPipeline|MemorySlowDurableFinishReachesPostOOBEcho|MemoryCLIEvidenceDriftAndExhaustionAreOneShot)$' -count=20 -failfast -timeout=25m
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryFixtureFresh100Schedules$' -count=1 -v -failfast -timeout=12m
go test -race ./internal/architecture -run '^TestGateC1bFixtureTiming' -count=20 -failfast
go test -race ./internal/architecture -count=20 -failfast -timeout=20m
go test ./internal/architecture -count=1
go test -race ./test/natlab -run 'Test(GateC1bMemoryCIContract|SessionLivenessCI)' -count=20 -failfast
go vet ./...
go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'
go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast -timeout=15m
go vet -tags=natlab,c1bproof ./...
python -B scripts/test_ci_fixture_timing.py
```

第二条启用 `WINKYOU_GATE_C1B_REPEAT_REQUIRED=1`；本地 Go 批次使用 `GOMAXPROCS=4`。
带 `-tags=natlab,c1bproof` 的 vet 命令使用 `GOOS=linux CGO_ENABLED=0`。仅夹具采样批次设置
`WINKYOU_FIXTURE_TIMING_DIR`，指向仓库外的独立目录，不随文档发布具体路径。
