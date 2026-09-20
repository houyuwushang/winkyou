# #111 两阶段终止实现证据

Status: 本地验收完成，Draft；CI 首跑状态在 PR 单列。尚不构成合并或现场授权。
基线 `97c375003bc4410bb6f8e491209e9ba08aa3a872`；
设计见[两阶段终止 ADR](adr/ADR-LOOPBACK-TWO-PHASE-TERMINATION.md)。

## 1. 原始失败与修正口径

原 coupling 反例见 #111：提前 RevokeForTerminal 并完成真实端口 rebind，随后 caller cancel
与 10s FINISH 延迟，仍持久 cancellation_timeout。该签名不能改称 hard_limit_exceeded。

首次新增回归于修改生产代码前执行，Go 1.23.1 / Windows / race / count=1：

| 场景 | elapsed | FINISH | 内存 / 持久 trip | 端口可重绑 | admission / packets |
| --- | ---: | --- | --- | --- | --- |
| carrier deadline 前首字节检查 +2.5s FINISH | 15.5122587s | expired | hard_limit_exceeded / 同左 | 是 | 1 / 3 |
| R4 caller cancel +10s FINISH | 10.0215193s | cancelled | cancellation_timeout / 同左 | 是 | 1 / 3 |

首跑 exit=1，package26.575s，日志 SHA-256：
`d519dadc5f342a63f188c0f0eedcc2dfb11a916f8b3523c1fbcb4702770a294c`。
最初把第一行命名为 R3，但它实际覆盖 carrier deadline，不是 credential expiry；保留为额外
回归，不替代 R3。R4 原断言还假定 validate 比 watcher 先运行，随后已按两种合法拒绝顺序
修正；未改变 FINISH reason、安全状态、资源或计费断言。首次失败未覆盖、未删除。

真正的 R3 是 `TestLoopbackPreFinishCredentialExpiry`：caller 保持60s有效；仅通过既有
线程安全测试时钟推进 credential expiry；真实 controller 在13s附近进入过期检查，FINISH
注入2.5s。断言必须包含 ErrPairingCredentialExpired 且 caller 仍有效。基线 source overlay
只用于复现旧实现，不改 worktree，不作正常验收替代；实际结果如下。

实际 R3 的基线运行已复现：elapsed=15503278700ns，FINISH 延迟=2500456000ns，调用1次；
credential_expired=true、caller_clear=true、FINISH=expired；内存与持久状态均为
hard_limit_exceeded；attempt/peer/reservation 全0、port_rebound=true、1 admission/3 packets。
exit=1，package15.873s；日志 SHA-256：
`ff00d56115a93fe12d0387c7ab4a2244012097a173d7d60675d23e6d440863b6`。
overlay 中四个生产文件的 `git hash-object --path` 均与基线 Git blob 精确相等；
只把本 PR 新增的生命周期文件/相应新单元文件替换为空同包文件，以恢复旧实现。

工具前置失败同样保留：首次 overlay 调用尚未运行测试即被 vet 阻断。随后 compile-only
诊断显示测试二进制可构建，但 vet 仍读到工作树的新增方法/导入，而非完整旧源码替换。
该诊断 exit=1，日志 SHA-256：
`6c5b598d4bb03b145d006c4f52884b781c1b3985fab736974e55bfd563ad69c8`。
因此仅上述旧源码 runtime RED 使用 `-vet=off`；它不是验收命令，也不替代已通过的完整
`go vet ./...` 与 Linux tagged vet。最初 PowerShell 的原生错误中止及空输出文件未覆盖。

## 2. 中间版本结果（不能冒充最终 SHA 验收）

第一版相同 deadline / R4 用例均转绿，elapsed15.5087682s / 10.0082836s，
内存与持久 safety=clear，FINISH expired/cancelled，资源归零，1 admission /3 packets，
端口可重绑。两阶段单元首跑18.812s、兼容性首跑 loopback3.155s / governor5.966s、
architecture17.202s，均 PASS。之后补强了“hook 已报错而 FINISH 超时”的错误保留，以及
独立同步 ProbeRevocation 信号，故这些结果仅为实施过程证据。

| 批次 | 编译时 checkpoint | 结果 | package / 外层 | 原始日志 SHA-256 |
| --- | --- | --- | --- | --- |
| 压力50，race，fail-fast | 397afe1 | 50/50 PASS | 690.968s /698819.6648ms | c5c9a4ecdc3f8d87986c59cd89b2b87f8547d10b049ec15f1a2b31b53cbd4c96 |
| 无压力100，race，fail-fast | 73ca560 | 100/100 PASS | 1305.833s /1318038.636ms | 2cb6ea8792b2a12780746af3bb567d6c8db53277e6d0e920f973b3c1b601dc77 |
| focused race20 | b5037e8（最终生产代码） | 20/20 PASS | 262.727s /277668.031ms | 6862675cb99697e0ca5975e49b9a12bb9f29caf673ee86292bc64450a9f46cbe |

三批均使用 GOMAXPROCS=28；压力批为56个 busy worker，无压力批不启用负载开关。
压力50的 connect p50=13058737300ns、p95=13374245900ns、max=13572226500ns，
connect>=15s 的样本为0，所有资源/端口/持久状态检查通过。
前两批须在最终生产代码上补跑，不用中间 PASS 充作最终结果。

## 3. 最终验收与隔离

最终生产代码的受影响包批次已经完整退出，exit=0；没有失败事件：

| 包 | 参数 | 实际结果 |
| --- | --- | --- |
| internal/probeio | -race -count=20 -failfast | PASS 143.247s |
| internal/v2/loopbackcarrier | -race -count=20 -failfast | PASS 36.314s |
| internal/architecture | -race -count=20 -failfast | PASS 2071.650s |
| internal/governor | -race -count=20 -failfast | PASS 3226.057s |

命令：`go test -race ./internal/probeio ./internal/governor ./internal/v2/loopbackcarrier
./internal/architecture -count=20 -failfast -timeout=120m -json`。
外层3237072.2745ms；日志 SHA-256：
`d7f2cb2346a1a82aeb648e7c9cfb7fa35c1c0b0a341a6f49c0d6fa5a178e8dbd`。
实际 credential expiry 回归20/20；2.5s/10s FINISH 与独立网络/记账故障测试均保留真实等待。
未修改的 `TestLoopbackTerminalRevokeCrashRetainsBurnAndRestartEmitsZero` 同批20/20通过：
真实子进程在 pre-FINISH 边界被终止，端口事先可重绑，journal仍2条，unfinished admission=1 /
packets=3，同 artifact 重启发射0，进程残留0，owner lock可重取，safety=clear。

| 其他首跑 | 结果 | 外层耗时 | 原始日志 SHA-256 |
| --- | --- | ---: | --- |
| C1b memory 相关，race，repeat required | PASS；Fresh100=100/100，package204.560s | 227069.8084ms | 9acd1de7805618639da2bd94b7572e5ff32b5006a00d95dfb65619fda6f1a356 |
| go vet ./... | PASS | 26770.4483ms | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| go test ./...，#116 分区（relay 独立验证） | PASS | 275989.3446ms | 07b28c997d2a6b0ecefb025d901f6bdd39abae53b677896a76e0aaf739c14f63 |
| 独立 relay，race20，fail-fast | PASS | 175791.5791ms | 45af1c6bbbea3e646182306f03e2415deb604dbad49a3a3b6db15edb7f616ccb |
| Linux / CGO_ENABLED=0，natlab,c1bproof vet | PASS | 26232.0015ms | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 |
| 普通构建 + nm（不执行二进制） | PASS；natlab/c1bproof 符号0 | 5412.504ms +1404.4708ms | nm: b488159b5ed2d09a4340d79d81ffd388b4beec29ed7e454acfae296ae959b374 |

撤销 guard 运行时变异：仅把 `c.probeRevoked` 改回 `c.lease.Done()`，exit=1，package0.791s。
测试同时抓到 revoked send reached datagram、revoked registration accepted、revoked open reached factory；
未启用真实网络。日志 SHA-256：
`14513d4f5b31a682d5de3d8d1f8960a1e1850d406b4e62c5015ef26cf2196672`。
原实现同一用例在受影响包 race20 中20/20通过。

R1–R4最终 focused 首跑 exit=0，外层86292.8083ms，日志 SHA-256：
`77851a1d05947521235543677e927ba62c8385180a8776715ef320c46db35e23`。
这批不是对 RED 求绿重跑：RED 是明确替换旧源码/破坏 guard 的独立负向证明，正常源码不使用 overlay。

| 最终用例 | connect/elapsed ns | 注入实际 ns | FINISH reason | 内存 / 持久 |
| --- | ---: | ---: | --- | --- |
| R1 | 15506399100 | 2500363800 | expired | clear / clear |
| R2 | 23006070500 | 10000130200 | expired | clear / clear |
| R3 credential expiry | 15502400300 | 2500465300 | expired | clear / clear |
| R4 caller cancel | 10007413400 | 10000423500 | cancelled | clear / clear |
| 额外 carrier deadline | 15508851800 | 2500355600 | expired | clear / clear |

每条均 FINISH 一次、资源归零、端口重绑成功、1 admission /3 packets、unfinished=0。
R3 额外证明 caller_clear=true、credential_expired=true；默认缺席测试与静态窗口门未修改。

最终 two-phase/revocation focused race20 也 exit=0，外层350660.7912ms；
挂起 FINISH 的真实15s判决20/20，无失败。日志 SHA-256：
`365f57b1d15bd612916403f7dda70baf9ea8b8e03865eea5cab47940f167e6d5`。

最终压力50首跑全部通过：package659.036s，外层664423.0551ms；
GOMAXPROCS=28、28核、56 busy workers、iterations_per_yield=65536、race、fail-fast。
connect 的 nearest-rank p50=13040624700ns、p95=13071769200ns、max=13077757800ns；
connect>=15s样本0。50/50的 FINISH 均 expired，caller_clear=true，内存与持久状态 clear，
资源归零、端口与 owner lock 可重取。日志 SHA-256：
`336164a4577da230c2188b850782c5fa7e94495f0cde6f20739bc68f4b7aa804`。

最终无压力100首跑全部通过：package1305.186s，外层1313211.7483ms；
GOMAXPROCS=28、压力开关关闭、race、fail-fast。
connect 的 nearest-rank p50=13008616200ns、p95=13014100400ns、max=13027280900ns；
connect>=15s样本0。100/100的 FINISH 均 expired，caller_clear=true，内存与持久状态 clear，
资源归零、端口与 owner lock 可重取。日志 SHA-256：
`6d010f2de3a92ad9d4f8b4d0df0044f746f6dbc0cf01f82f3bd2683a1e257563`。

发布前隐私/链接/diff 单列检查；远端 CI 只在 PR 中记录真实首跑，不以本机 PASS 代替。

所有运行限制为原有测试内存/loopback；本机不执行 netns、现场、主机配置或计划任务。
Gate A/B/C 完成阶段、handoff、全部冻结网络数字、配置/工作流均不修改。
无新主动网络入口，无预算退款、自动重试、恢复或新 drain 超时放宽。
仅修改回环显式生命周期；普通 lease 的 probe guard 保持原 Done channel。
