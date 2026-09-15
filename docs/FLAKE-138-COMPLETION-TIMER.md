# #138：完成阶段夹具的独立定时器竞争

## 范围与已知签名

状态：本地首跑验收完成，等待独立复审；远端 CI 首跑另列于 PR。基线 `2864a18`，
仅测试与证据文档；不改产品、配置、工作流或冻结数字。

[原始 issue #138](https://github.com/houyuwushang/winkyou/issues/138) 记录了 Windows required
memory job 的首跑失败：

```text
TestConsumerFinishedCompletionAfterChallengeDeadline/received
fixture did not cross only the original challenge deadline exactly once
```

历史失败与本批压力结果分别保存，不能用一次通过证明该竞争不存在，也不重跑 CI 求绿。

## 根因与修复契约

`waitCompletionBoundary(deadline.Add(...))` 创建独立于 context 的定时器。
它先唤醒并不证明 context 自身的定时器回调已经完成；随后断言 `challengeCtx.Err()`
等于 `DeadlineExceeded`，把两个独立定时器的调度顺序当成了契约。

需要断言 context 已到期的夹具改为观察它自己的 `Done()`，等待受原有 8s 测试 context
兜底约束，再检查原来的错误身份。原有真实 3s challenge deadline、absolute envelope、
`finishCalls == 1`、精确 3/3 packet 计数与关闭/排水见证不变。

按基线文件的五处调用逐一处理：

| 基线位置 | 调用用途 | 处理 |
| --- | --- | --- |
| `wireguard_completion_phase_test.go:40` | FINISH 回调等待后断言 challenge context 到期 | 等待 `challengeCtx.Done()`，保留准确错误断言 |
| `wireguard_completion_phase_test.go:132` | responder FINISHED 写入前等待，随后断言 context 已到期 | 同上 |
| `wireguard_completion_phase_test.go:154` | 延迟合成 FINISHED 到达的绝对时刻，不断言 context 状态 | 保留，并说明不推断 context 到期 |
| `wireguard_completion_phase_test.go:172` | 在标称边界之后调用已通过 challenge 的 completion admission，不断言 context 状态 | 保留，并说明不推断 context 到期 |
| `wireguard_completion_phase_test.go:253` | detach 屏障等待后断言 challenge context 到期 | 等待 `challengeCtx.Done()`，保留准确错误断言 |

## 红回归与源码门

1. 旧测试使用 Go 1.23.1、`GOMAXPROCS=2`、同进程两个 busy goroutine、`-race -count=200`
   首跑尝试复现。额外压力夹具通过仓库外 Go build overlay 注入，不进入提交；记录两个 worker 的启动与退出。
   失败为零时明确写零，不伪造动态 RED。
2. 新增 AST 契约：完成阶段测试不得在等待“context deadline + margin”的独立定时器之后，
   把同一 context 的 `Err()` 当作已经到期的证明。覆盖 deadline 变量、到达时间别名、直接调用与回调内等待。
   旧文件必须被拒绝；无 context 错误断言的绝对到达时间测试允许保留。
3. 合成源码变异证明该门能拒绝旧模式，不靠日志关键字、注释或行号做匹配。

## 验证计划

全部保持真实窗口与原 count，不启动任何现场网络或主机配置操作。

- 旧文件压力首跑：目标测试 `-race -count=200`，记录失败次数与原始日志哈希。
- AST 旧代码 RED、修复后 GREEN、合成变异自检。
- 与 CI 相同的完成阶段选择器：
  `go test -race ./internal/probeio -run '^Test(ConsumerFinished.*(Completion|ConfirmationAfterChallengeDeadline|DetachAfterChallengeDeadline)|WireGuardCompletion)' -count=20`。
- 相同压力配置下，完成阶段选择器 `-race -count=200`。
- `go vet ./...`、`go test ./internal/architecture`、全仓 #116 分区及独立 relay race×20。
- `git diff --check`、隐私扫描、生产/配置/工作流 delta=0 与提交身份核对。
- 单次推送 Draft PR，完整记录首轮 CI；不合并，不覆盖首轮 RED。

## 本批实测

### 压力夹具建立记录

首次尝试把 TestMain 放入一个不存在于工作树的新 overlay 文件。Go list 能发现它，
但默认 vet 报该文件不存在，命令以 build failed 结束，任何测试都未执行。
这不是 #138 的动态 RED；原始日志保留，SHA-256：
`de9fb266d873f1eb06c5754e79ce1527317526f63c3577ca369e59c4b1fa540b`。

随后只修正仓库外压力夹具的装载方式：overlay 已有的完成阶段测试文件，保留所有原测试，
附加两个 busy worker 的 TestMain。没有关闭 vet，没有修改工作树中的被测文件。
有效压力批次首行必须见证 `gomaxprocs=2 busy_workers=2`，结束须有 `busy_workers=0 drained=true`。
夹具建立失败日志与有效批次日志分别保存，不覆盖、不混作红绿结果。

### 旧代码压力与确定性红回归

| 首跑 | 测试结果 | 外层命令结果 |
| --- | --- | --- |
| 旧完成阶段目标，GOMAXPROCS=2、两个 busy worker、race×200 | 200/200 轮、400/400 子用例 PASS，动态失败 0；包耗时 644.218s；worker 排空 | exit 0，994.074s |
| 新 AST 门扫描未修改的旧文件 | RED，准确命中基线第 40、132、253 行；包耗时 0.755s | exit 1，299.321s |

有效压力日志 SHA-256：`e7cee62895e28db688052a160288b722074cbc3ee91a7e3bcc31de979bb01518`。
AST RED 日志 SHA-256：`24d7efcbbadb594309e0f1788467cd032c38de495d83c801a859d5a8fd6bff2e`。

两条命令在测试进程退出后仍有较长的外层 Go 收尾耗时；只读核对时测试子进程已经消失，
外层 Go 尚在，最终均自行退出。没有强杀、重跑或改缓存配置。该耗时原因尚未精确定位，
不把它归为产品失败，也不从总墙钟反推 challenge 的时间余量。

### 修复后首跑

修复只改变三处完成阶段测试的等待依据，并将 responder 的“非 nil 错误”检查收紧为
准确的 `DeadlineExceeded`；没有把任意取消误判为成功跨过原始 deadline。
两处不读取 context 错误状态的绝对时刻等待保留，并补上用途注释。

| 批次 | 首跑结果 |
| --- | --- |
| AST 实际文件门与 18 个合成正负/作用域用例 | PASS，0.226s；旧代码的三处 RED 变 GREEN |
| 完整 CI 完成阶段选择器，race×20 | PASS，91.797s；命令 exit 0，外层 96.249s |
| 完整选择器，GOMAXPROCS=2、两个 busy worker、race×200 | PASS，12 个测试组各 200 轮，失败 0、race 报告 0；包耗时 3247.154s，命令 exit 0，外层 3251.175s；worker 排空 |
| `go vet ./...` | PASS，exit 0，19.073s，无诊断输出 |
| `go test ./internal/architecture -count=1 -v` | PASS，9.737s；命令 exit 0，外层 12.508s |
| 全仓 #116 分区，`-count=1` | PASS，88 个有测试的包、11 个无测试文件的包，失败 0；命令 exit 0，161.430s |
| 独立 relay，race×20、fail-fast | PASS，20/20，164.669s；命令 exit 0，外层 185.270s |

AST GREEN 日志 SHA-256：`c98410b38324423f730f7e2bec24c2ec10b3d6499639fd05f944bb5ba79c46fb`。
race×20 日志 SHA-256：`25f9963d278ef718e3245986a24ddf5936d4db277dc0fff392c29fbcc62d89bf`。
完整压力×200 日志 SHA-256：`b5c92478c513ecba062b2db9922c70902b4c4591527a9069f8503687e2f40c2b`。
完整 architecture 日志 SHA-256：`9d954abf70c82dad9e1c3b4fa7be717be97272abfc77893300ec72dca550e76c`。
全仓分区日志 SHA-256：`8cef76cc35c2e0d37aa5fa7a6fb863335f591af6e7512600e5bced114059fd1a`。
独立 relay 日志 SHA-256：`ef13bf89434ac81477294bce42dcaffc8e4a0c50fb53eac15e633ef18e99275d`。

全仓命令为 `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -timeout=20m -v`。
relay 依 #116 单独执行 race×20，不在分区中重复执行。全仓输出含基线已有的 13 条 SKIP：
两条 required-job 专用高重复证明、一条 Windows symlink 条件、三条 opt-in 诊断、
两条 Windows alias 特权测试、两条外部 TURN 依赖、两条历史诊断 characterization 和一条 Docker 外部夹具。
没有新增 skip、降低 count 或改工作流；这些未启用的条件测试不计为本机通过，required job 的结果另列于 PR。

完整选择器压力×200 的外层测试 runner 单独给足累计等待时间，不改变任何单个测试的
3s challenge / 8s guard / absolute envelope，也不改变 CI 的原有分组与 12m runner。

独立 relay 命令为 `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -timeout=10m -v -failfast`。
本地有效测试首跑均未命中其他已登记签名；没有重跑测试求绿。旧代码动态复现为零，
确定性 RED→GREEN 依据是 AST 原文件回归，二者没有混写。

### 范围与发布核对

`git diff --check` 通过。相对基线只改本证据文档、completion timer AST 测试和
`wireguard_completion_phase_test.go`；生产、配置、工作流 delta 均为零。
完成阶段生产行为、三报文计数、冻结 deadline/absolute envelope 不变。

仓库外增量隐私检查最初因盘符正则缺少词边界，误把 issue 的 HTTPS 链接当成本机路径。
补充两个盘符正例和一个 HTTPS 反例后，3/3 控制例通过，增量扫描为零命中；
没有删除链接或修改产品内容来绕过扫描。该检查夹具误报与真实隐私泄漏分开记录。
提交身份逐项核对为维护者本人，无协作署名尾注；原始证据只留仓库外。
不合并，不启动现场网络、计划任务或主机配置操作。远端首跑在 PR 中记录，未执行的验证不计为通过。
