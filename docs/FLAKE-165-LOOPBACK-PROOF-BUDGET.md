# #165：回环证明集合的外层测试预算

## 范围与首跑证据

本修订只调整 `scripts/verify-loopback-connect.ps1` 的 governor 测试集合外层上限，
不改变产品、配置、workflow、测试场景、重复次数或任何内部 deadline。
PR #163 的失败不被随后通过的运行覆盖；本修订独立提交、保持 Draft，等待复审。

[Windows PR 首跑](https://github.com/houyuwushang/winkyou/actions/runs/35628970672/job/106430222929)
在整包 90.021s 时被 `-timeout=90s` 中断。最后的缺席回归只运行约 10s，
尚未达到正常约 13s 的终局，不能据此判定 #111 的持久 safety trip 再现。
[同 head 的 push 首跑](https://github.com/houyuwushang/winkyou/actions/runs/35628964273/job/106430196562)
整包 81.424s 通过，但不能补齐失败运行未执行到的断言。

| 顺序测试组 | PR 首跑 / s | push 首跑 / s | 预算采用值 / ms |
| --- | ---: | ---: | ---: |
| PreFinishInvalidation | 26.70 | 25.62 | 26700 |
| SlowFinishRevokesBeforeDurableIO | 41.77 | 42.20 | 42200 |
| TwoRealProcessesUseIndependentDurableJournals | 8.86 | 0.13 | 8860 |
| CrashAfterNoiseMessageOne | 0.89 | 0.19 | 890 |
| CrashBeforePromote | 1.30 | 0.23 | 1300 |
| AbsentPeerExpiresCleanlyWithoutSafetyTrip | 被外层中断 | 13.04 | 13040 |

失败运行前五组合计 79.52s，只剩 10.48s，不足最后一项正常等待 13.04s。
双进程用例为何从 0.13s 变为 8.86s **尚未定位**；不把它猜测为调度、磁盘或泄漏。
本修订修复的是整组正常证明所需时间已经超过外层上限的问题，不宣称消除了该波动。

## 预算契约

取每组两次首跑的较慢完整样本，合计 **92990ms**。缺席用例的中断样本不是完成时间，
只使用另一独立首跑的 13040ms 完整样本。采用 25% 外层测试余量、向上取整到 10s：

```text
observed_total_ms = 26700 + 42200 + 8860 + 890 + 1300 + 13040 = 92990
timeout_s = ceil(observed_total_ms * 1.25 / 10000) * 10 = 120
```

这是一项由已观测完整证明成本推导的 harness 预算，不是任意宿主负载下完成的保证。
Go 的整包 alarm 仍有界；仍使用 `^TestLoopbackCarrier`、`-count=1`、`-v`，不加 skip、
重试、并行或成功吞错。脚本其余两组不变，任一步失败立即停止。
产品 `AttemptDuration=15s`、`terminalDrainMargin=2s`、缺席约 13s 终局、取消排水及包数预算不变。

## 红回归与变异门

新增 architecture 契约，旧脚本的 90s 必须被拒绝；新脚本必须使用上述逐组样本和推导公式。
变异覆盖旧上限、伪造样本、删除余量、向下取整、硬编码脱离公式、遗漏测试、改 count、
新增 skip、吞错和改变其它证明步骤。测试不运行产品，不产生网络 I/O。

实际验证结果另节追加，首次 RED 保留；尚未运行的批次不得记为通过。

## 验证计划

Go 1.23.1，串行执行：新契约旧脚本 RED → 新脚本 GREEN、mutation race×20、
脚本 Windows 首跑、vet、architecture、全仓 #116 精确分区、独立 relay race×20、
Linux `natlab,c1bproof` tagged vet。推送后只记录 CI 首跑，不 rerun 求绿。
其它问题另行登记，不在本修订中混修 #133/#162 或修改产品预算。

## 本地首跑结果（2026-09-22）

Go 1.23.1、Windows、GOMAXPROCS=4；各重验收批次串行，期间源码与 HEAD 不变。
原始记录保存在仓库外，不发布本机信息。下列耗时不作为 CI 或现场证明。

| 批次 | 首跑结果 | 实测 |
| --- | --- | --- |
| 新契约 + 原始脚本 | RED | 0.724s，拒绝缺失推导的旧 90s 上限 |
| 新契约 + 修后脚本 | GREEN | 0.175s |
| 契约与 13 类 mutation，race×20 | PASS | 1.868s；含 CRLF 等价检查 |
| `./scripts/verify-loopback-connect.ps1` | PASS | 墙钟 106.678s；governor 79.159s |
| `go vet ./...` | PASS | 墙钟 29.371s |
| `go test ./internal/architecture -count=1` | PASS | 墙钟 23.136s |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | PASS | 墙钟 309.007s；88 有测试包 + 11 无测试包 |
| 独立 relay `-race -count=20 -failfast -timeout=15m` | PASS | 包 166.731s；墙钟 184.989s |
| `GOOS=linux CGO_ENABLED=0 go vet -tags=natlab,c1bproof ./...` | PASS | 墙钟 29.052s |

缺席回归为 13.03s，`deadline_error=true`、`memory_clear=true`、`persisted_clear=true`、
peers/attempts/heavyweight=0、reserved_zero=true、journal sequence/records=3/3、
admissions=1、failures=1、unfinished_admissions/packets=0、port_rebound=true。
预 FINISH 与慢 FINISH 原用例也完整通过，未减少注入时长或断言。

本机自然运行没有重现历史的 90s alarm；确定性 RED 指新契约拒绝旧脚本，
历史运行时 RED 仍以上文的 Actions 首跑为证据，不伪造自然复现。
脚本之外只有本证据文件及新增 `_test.go`；production/config/workflow delta=0。

原始日志 SHA-256：

- 旧契约 RED：`ad4e1ace6df614685d6820d1a1f3950095c5dcaa5e8a94af914dc9fbdc12acad`。
- 回环脚本：`097977d5ec11d0e2731d47421b2a8372642d1f740757bdb9f78e26a265a547e0`。
- 全仓分区：`5b4d5a7e5541cbc029887e49edbb93bde089b8f2f731c35ab365f4657fdd60fd`。
- 独立 relay：`2ab34e94940b0a06f9141c88051c572947c8f63d46b30995165241604d3efdd4`。

远端 CI 首跑尚未开始；推送后的结果单列于 PR，不用状态更新反复推送代码。
