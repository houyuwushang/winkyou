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
禁止未知字段、字符串值、非法 profile/槽数/负时间、混入其他文件或符号链接。
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

当前：测量阶段设计已记录，红回归及采集实现待验证。
