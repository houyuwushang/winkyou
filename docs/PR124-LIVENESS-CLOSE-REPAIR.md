# PR #124：liveness CLOSE 完成见证修复

2026-09-12，维护者在诊断后授权修复；沿用原 Draft PR，不合并、不运行现场 I/O。
约束：[session liveness ADR §8](./adr/ADR-N3C-SESSION-LIVENESS.md#8-结果取消与兼容)。

## 原始 RED 与归因边界

[Windows idle 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34685361094/job/103531312495)
的 predictive 在约 225s 返回 `session_liveness_timeout`：PING=10、PONG=9、proof=8、
pending expired=2、inner injected=19；另两 profile 通过。全部 58 checks 中 56 成功，
实际失败及其 required 聚合共 2 项失败，run_attempt=1，未 rerun。

已确认 `bestEffortClose` 把任意 `ActiveWrites` 增量当成本次 CLOSE 完成。纯内存反例中，
无关 data / empty keepalive / rekey 都使 `CloseWritten=1`，但 CLOSE inner 注入为 0。
完整真实 WG + governor + memory NAT 组合中，暂缓 CLOSE inner 注入至多 250ms，并插入
一次无关 active write，CLOSE 在 25.127ms 被过早关闭撤销；对端重现 225s 及上述全部核心计数。
这证明缺陷足以造成该签名，**原 CI 没有逐 CLOSE 轨迹，仍不声称复原其唯一历史原因**。

| 私有原始证据（只公布摘要和 SHA-256） | SHA-256 |
| --- | --- |
| 首次 CI RED | `eff278f881117639c6eaf13cd976f3cb662186bacaf52f9bdf58ab9819cfba36` |
| 三类无关 write 反例 RED | `d767e2b6a848709c0e98de0f25e34b424ce26d094b7daaac1597189a35cf16d0` |
| 完整组合受控 interleaving RED | `b2c647bf23bd938d57067e66961ac013a1c0914d815c9bf3609dd3ecf7dcd749` |
| 原 180s observer-only 三 profile PASS（不能抵销 RED） | `45b6eaf6fec632babec65deb4a6d7007a078d22ce37caea9e730d9f247cfc8a5` |

## 修复契约

- 同一个 teardown intent 的 admission 与完整 inner 注入分开记数。`InjectPacket` 只是
  内层队列接纳，不是 WireGuard 加密或 outer UDP write completion，不得换名后继续冒充。
- liveness 路径不再由 aggregate `ActiveWrites` 推断 CLOSE；没有逐 CLOSE outer 见证，
  `Echo.CloseWritten` 保守为 0，本地取消使用已有 `canceled`，不再报
  `authenticated_close_sent`。接收方经原 WYCE parser 认证后仍可报 `authenticated_close`。
  新增的可选计数只在 liveness witness 内，旧无 policy 路径、原 parser/wire/error golden 不变。
- 只尝试一次，沿用从 intent admission 起的原 1s 出站窗，给异步 WG 发送机会；计数不提前
  截断该窗。许可/absolute/revocation 优先，不能从 inner 注入成功起重新计时。没有新 timer、
  ACK、重传、target、socket 或授权；1s 到期后仅原 2s drain。写硬故障仍保留 terminal/trip。
- 健康 idle 必须在取消**之前**读双端当前许可与 proof/rekey 见证，两端都满足完整 180s
  健康期后才由 fixture 显式取消两端。取消后必须干净排水，不接受提前发生的 timeout。
- teardown 单独验证：真实 WG 下 CLOSE 交付；无关 write + 暂缓 inner 注入不得提前关停；
  丢失 CLOSE 时对端保持原许可到期并干净结束，不退款/重试/持久 trip，不要求 best-effort 必达。

K=20s、R=5s、M=2/3、L=45/65s、write=1s、drain=2s、原 absolute ceiling 与所有建立预算不变。
普通 observation 修复的历史 RED/证据继续保留；不顺手处理其他 flake。

## 本地首跑（Go 1.23.1 / Windows amd64 / race）

受测实现：`50170b470c0d11f4c2da28f6c307757915004fae`。全部独立、串行执行，不与其他本地
重测试并行；不加压力 worker，不把这些测试叫作现场 OS 证明。原始日志留在仓库外。

| 验收 | 原样结果 |
| --- | --- |
| 旧实现新增回归 | 3/3 预期 RED；注入 receipt 缺失，writer error / short write 还被报告成 `canceled` / nil。提交 `f8a8306` 保留。 |
| 原 worker 排水 + 初版 close 回归 race×20 | PASS，package 4.241s。 |
| close 完整单元矩阵 race×20 | PASS，package 2.819s；注入成功、写错误、短写、卡住四路，另有 lease/absolute 已过期零 admission。 |
| 完整 WG CLOSE 反例 race×20 | 三类各 20/20，合计 60；package 181.631s，runner 189.821s。每例无关 write=1、CLOSE inner=1、outer claim=0、对端 authenticated CLOSE read=1；原计费/owner/排水断言保留。 |
| required idle + teardown | PASS，package 193.799s，runner 198.302s；三个 180s profile、三个交付反例、一份 CLOSE 丢失。 |
| 六种黑洞 | 6/6 PASS，package 87.692s，runner 92.741s；M=2/3 × 双向/两种单向。 |
| 无 proof 的持续流量 | 4/4 PASS，runner 270.856s；两种单向业务和垃圾各 64 批；控制例实测握手 2/2、empty keepalive 2/1，均未续租、残留为零。 |
| 受影响包整包 race×20 | 全 PASS：gatecorchestrator 4.935s、config 5.136s、tunnel 5.382s、probeio 138.449s；runner 142.585s。 |
| 真实 owner / 业务共存 / fresh 生命周期 race×20 | 三组各 20/20 PASS，runner 678.010s；原正常拒绝、硬违规、owner 丢失、持久化、排水断言保留。 |
| 全架构 race×20 首批 | **未完成，进程超时 RED**；本地 runner 误设 6m，在第 9 轮执行 AST mutation 扫描时被 `testing` 终止；package 360.440s。没有独立测试断言失败或 data race 报告，不算 20 轮通过。 |
| 全架构 race×20 完整新批 | **PASS**；109 个顶层门各 20 次，合计 2180，package 843.668s / runner 847.107s；同一实现和全测试集，18m 仅为本地批次上限。 |
| 全仓 #116 精确分区 | PASS：88 个测试包、11 个无测试包、0 失败；runner 134.532s。只隔离原单个 relay 测试，另做独立 race×20。 |
| 独立 relay race×20 | 20/20 PASS；package 142.325s / runner 148.744s，最长单例 7.14s，20 个 observer 全部 join。 |
| vet / Linux 隔离构建 | `go vet ./...` exit=0（6.016s）；`GOOS=linux CGO_ENABLED=0 go vet -tags=natlab,c1bproof ./...` exit=0。两者 stdout 为空，不伪造日志哈希；cross-vet 不冒充 Linux OS 实测。 |
| 跨语言向量 / 隐私 / 相对链接 | Python 独立验证 4 个 WYCL 向量；原 testdata tree 完全相同。新增文本 0 真实身份/地址/本机路径；9 个相对链接均存在。 |

空闲期是 **取消前** 的独立快照，不能用 teardown 等待把短样本凑够 180s：

| profile | 双端当前许可 | 取消前 elapsed | 双端有效 proof | 双端 rekey 计数 |
| --- | --- | --- | --- | --- |
| predictive | 有效 / 有效 | 180000ms | 8 / 8 | 1 / 1 |
| asymmetric | 有效 / 有效 | 180000ms | 8 / 8 | 1 / 1 |
| hard-16k | 有效 / 有效 | 180000ms | 8 / 8 | 1 / 1 |

此后双端显式取消；终局 elapsed 181014–181039ms，原 1s 出站机会与 drain 内完成。
另一个独立场景确实丢掉 1 份 CLOSE，对端以 `liveness_timeout` 结束；取消后 64003ms 排水完成，
内存 NAT 的连接/映射/队列及 governor 资源原断言通过，safety trip clear。
该例日志的 `retry=0` 仅指 WinkYou/CLOSE 不重试；WireGuard 本身仍有已计费的自动握手
（此例为 10 次），受原 active permit 和控制 cap 约束，不声称 WG 内部没有 timer 流量。

黑洞最晚新发射分别为故障后 36.215s（M=2）/56.919s（M=3），双端排水至多
40.004s/60.006s；低于原 45/47s 与 65/67s 界，不据此缩短或增加配置。

| 本地首跑日志 | SHA-256 |
| --- | --- |
| 新增旧实现 RED | `fa28c3f6ff6271124add99480e03ae7923113ed7ed9b520e866c64579bed93b8` |
| close 单元完整矩阵 | `282e13df438d71702094fe85e9c7e01fee211d370a09d934bc4f2713d0785448` |
| 完整 WG CLOSE race×20 | `dc5050552cdcc6a8c68fabc81b537ce70b05e46c81ae9fe01cd81398b80999c2` |
| 180s idle 与 teardown | `d5d0a92610bc3d6d4026710693238dc748add8751b45e4d413c249acbcc5d23d` |
| 六种黑洞 | `a33035e7c2a6efbe5784852508ba5b9e3e7d72f8a0e5086dfa138d03b0801234` |
| 无 proof 的持续流量 | `dfd73edb7715c2dae2d7ef11330622bafca685b99f2a52ed864cfd9e38984483` |
| 受影响包 race×20 | `0abe737999e67719b575ab7f32319696815e9dd825875a15fc7a77d2f6937b1f` |
| owner / 业务 / fresh race×20 | `0d8558f8345714de1a3a79962c27ae12e3ef15dca88088df0b11319be2568192` |
| 全架构首批进程超时 RED | `7a0c707971191f83275365fc65cbb1860559ec7ec508492911ba6f9e8beaf0c9` |
| 全架构完整新批 PASS | `da99fd49808cf65cab86571c1f2e82b072f58a59f5a1a34db94455872e311b76` |
| 全仓 #116 | `2ab70637ca3d7d220f89256b24193cea2b6e087fe2648a1ac093576c7c483eef` |
| 独立 relay race×20 | `a82b827e1761b573689f9cc88f2c067ead227eb6a6b4761ae4f87d304cbe9041` |

全架构首批完成的 8 轮间隔为 41.963、42.274、42.107、42.064、41.674、42.215、41.559、
42.361s。只修正仓库外本地批量测试进程上限：ceil(20 × 42.362 × 1.25 / 60)=18min；
同一实现、完整测试集、`-race -count=20 -failfast` 均不变，从新批次完整重做 20 轮，不把旧批
8 轮拼入通过数。首批日志与失败记录保留，不改产品/单例/CI deadline，也不是 GitHub rerun。

本地上述门已完成；全架构首批超时与完整新批 PASS 分开保留。新 head 的首次 CI 链接、
逐项结果及最终 SHA 另记在 [PR #124](https://github.com/houyuwushang/winkyou/pull/124) 说明，
不把旧 head CI 算作新 head，也不 manual rerun。本文是本地证据截止记录，不代替远端 CI。
没有修改配置、workflow、probeio、旧 WYCE/session parser、governor limits/永久缺席回归；
没有部署、任务变更、真实 LAN/公网流量或合并。保持 Draft，等待独立复审。

主要命令（所有 Go 命令使用 `GOTOOLCHAIN=go1.23.1`；原始 runner 参数与退出码同时保留）：

```powershell
go test -race ./internal/v2/gatecorchestrator -run '^TestLivenessClose' -count=20 -failfast
go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLiveness(CloseCompletion|IdleHealthRequiresPreCancelWitness)$' -count=20 -failfast
# 三个 required 长窗口命令分别启用原 WINKYOU_LIVENESS_*_REQUIRED=1
go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessMemoryIdle180Required$' -count=1 -timeout=6m
go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessMemoryBlackholesRequired$' -count=1 -timeout=4m
go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLivenessOneWayTrafficCannotReplaceProofRequired$' -count=1 -timeout=6m
go test -race ./internal/probeio ./internal/v2/gatecorchestrator ./pkg/config ./pkg/tunnel -count=20 -failfast -timeout=15m
go test -race -tags=c1bproof ./internal/governor -run '^TestSessionLiveness(OwnerTripCasesAreDistinct|BusinessCoexistsWithTap|MemoryFreshComposition)$' -count=20 -failfast -timeout=20m
go test -race ./internal/architecture -count=20 -failfast -timeout=18m
go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'
go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast
go vet ./...
python internal/v2/gatecorchestrator/testdata/liveness_reference.py
git diff --check
```
