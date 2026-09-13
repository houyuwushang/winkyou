# PR #124：NAT-lab outbound 失败的 test-only 诊断补强

## 1. 原始 RED 与因果边界

维护者授权在原 PR 分支补充诊断；不改生产、配置、工作流或任何时间窗/预算。
受检基线为 `ee069333f4958746626f93dc6abeeac917b87a84`。该 head 的首次 CI 为
57/58 PASS、1 FAIL；没有 rerun。同 SHA 的另一触发路径通过不能抵销 RED。

[push 首跑失败 job](https://github.com/houyuwushang/winkyou/actions/runs/34702249257/job/103575959648)
在 `TestLinuxGateB3MappingLifetimeProof/M_X_single_side_filter_before_selection`
失败（用例 48.76s，包 401.39s）：

```text
Gate B3 NAT outbound witness did not drain accepted emissions: got=13 want=16397
Mappings=10 Outbound=13 Inbound=11 TUNRead=1043 CandidateRead=1030
CandidateReadBySlot=[1024 6 0 0 0 0 0 0 0 0 0 0 0 0 0 0]
CandidateForwarded=0 RunFailure=outbound_forward MappingCapHit=false
kernel_tun_tx_dropped=0 kernel_counter_valid=false
```

仓库外保存的完整首跑日志 SHA-256：
`3836e40e63b62d3b964d0c005ec69f906694375e5a4d2244ebd6e5ac3df09f71`。

10 个 mapping 和 13 个 outbound 恰是 evidence 阶段；第一个 direct mapping 尚未加入。
左侧断言先 Fatal，右侧快照缺失，底层错误未留存，常规零残留断言也未执行。
这定位了首个 direct mapping 的建立链，但不能区分 peer barrier、DROP 查询、bind 等原因。
`before_selection` 注入须等最后一个 candidate 转发，此例尚未到达该注入点。
这既不是 #132 的 tail 双端 exhaustion 签名，也不是 #135 的 result-wait deadline。

之前的仓库外 Windows 零网络刻画原样执行所抽取的当前方法，race×20 共 100/100 PASS：
查询错误退出约 50–79ms，但 waiter 只在约 2000ms 报 deadline；另一受控例中 peer 到达
约 1100ms、查询再耗约 1303–1524ms，使成功 DROP 见证晚于 waiter 的原 2s 窗口。
这证明日志歧义与相对窗口差异存在，**不是原 Linux CI 的唯一历史根因或 netns 重现**。
该刻画日志 SHA-256：`1eeee488a82c7119cf88e7e6ffc28492cc09706ad78a7a9202aef5161c0bc91b`。

## 2. 本次观察契约

- 任一侧 outbound 断言退出前记录双侧路由器快照，不能让左侧 Fatal 遮住右侧。
- 首个 direct mapping 的 preferred entry/deadline、peer-ready、first-sent、DROP 查询、
  first-denied、preferred return、bind、write 使用同一单调时钟原点的相对纳秒。
  固定字段/固定容量，仅首包和首个错误留存；不增加逐包日志或 worker。
- 原始错误仅在发生处归类：context、白名单 errno/操作、子进程 exit/WaitDelay。
  不记录 error 文本、stdout、命令参数、endpoint、namespace、PID 或本机路径。
  observer 错误、router 首个 terminal、Close 结果分开保存，cleanup 不覆盖首因。
- 失败路径另作有界 drain/residue 见证；有效计数与查询失败分开，未知不写作零。
  清理成功不撤销原场景 RED，也不冒充其尚未到达的 ledger/协议终局验收。
- 保持原 `firstDenied` 正计数 release 条件、2s barrier/observer、1ms 查询间隔、
  命令参数与 WaitDelay、10s outbound 等待、38/45/47s 产品窗口及全部包数/PPS。
  observer 查询错误仍按原逻辑退出；此补丁不改变 waiter 的返回规则，不加 retry。

实现只位于 `test/natlab/*_test.go`；没有新网络能力、产品 hook 或入口。
纯测试注入只替换既有查询的执行结果，不改变真实 netns 命令与成功判据。

## 3. 验证与停止条件

先运行诊断的正/负面及并发所有权测试、受影响测试 race×20、architecture 与 Linux
natlab cross-vet，再按 #116 分区运行全仓、独立 relay race×20 和全仓 vet。
检查增量仅测试/文档、`git diff --check`、隐私和链接。

本机无已授权可运行的 Linux netns 环境时不伪造本地 OS 证明；推送后记录新 head
**第一次** required CI 的双端原始脱敏诊断。保留此前 RED，不 rerun 求绿。
如新证据要求修改冻结 barrier/规则或生产路径，停下报告，等待独立裁决。
保持原 PR Draft、不合并、不进入下一 Gate。

本节后续只追加实测结果；计划本身不代表验证已经通过。

## 4. 实现与本地结果（2026-09-13）

测试实现：`ff3cd257880b1dfdcde57e54ad10223127f10317`；此前
`8c418ad8e4f2368d979905f2e56869b4768dde88` 只冻结上述诊断范围。
基线之后生产、配置、workflow、依赖及原协议向量 delta 均为 0。

日志读法：`side=0` 是 initiator NAT，`side=1` 是 responder NAT；每侧保留原完整
路由器计数，20 个固定 phase 槽只记录第一次到达。`Seen=false` 不构成证据；
`peer_ready` 是原 base preferred 的返回点，只有 error 为 none 才表示 barrier 成功。
所有 `at_ns` 与 query 起止值以本用例同一 `started` 为原点；不是墙钟时间。
DROP query 汇总只在首发侧记录，`first_sent` / `first_denied` 在两侧使用同一个采样时刻。
query error、router first_failure、terminal、首次 Close 各自独立，后来的正常 Close
返回不覆盖此前错误。失败 cleanup 七项顺序是：endpoint/monitor、observer、socket close、
停止后 packet 稳定性、OS socket/process、conntrack、namespace/veth/恢复读回。
不可用的计数标 `valid=false`，从不以返回结构里的零冒充测得零。

Go 1.23.1，Windows amd64；各正式批次 fail-fast，无人工 CPU 压力。
新增测试还覆盖命令 exit code、错误/地址格式化毒丸、并发快照、21 项接线变异
（其中三个逐一删除不同 Fatal 前的双侧快照），以及七处清理失败均不跳过后续步骤。

| 验证 | 本地实测 |
| --- | --- |
| 诊断首个 focused race×20 | PASS，3.050s（当时尚未加入最后三个 AST 变异） |
| 完整 `test/natlab -race -count=20` | PASS，4.404s；15 个顶层测试各 20 次，300 PASS，0 FAIL；包含 helper 的普通无操作调用，不包含 Linux OS 用例 |
| `go vet ./...` | PASS，exit 0 |
| `go test ./internal/architecture -count=1` | PASS，9.176s |
| `GOOS=linux CGO_ENABLED=0 go vet -tags=natlab ./test/natlab` | PASS；更新后的 `-tags=natlab,c1bproof` 同样 PASS |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | PASS，88 个测试包、11 个无测试包、0 FAIL |
| 独立 relay `-race -count=20 -failfast -timeout=25m` | PASS，143.566s；20/20、最长 7.14s、20 次 observer join；未与其他重测试并行 |

本地整包 race 日志 SHA-256：
`189f45c68636d99ed102f0bef182ed982ed6def057bed6d46fa79a7bfa6c35ea`。
全仓分区日志 SHA-256：
`294c6cfa0253ed5f76db0fe771fb00b178f94d6ba03edc190aed4fd67ddc7515`。
独立 relay 日志 SHA-256：
`5ab601cf8fdbff79b15195f43d04582a15566a413c9a3c278eff62eba4ab15a6`。
原 `gateB3LateHitMappingPlan.preferred` 文本单独与基线核对完全相同。
最终全仓 vet、格式/diff 检查、增量隐私扫描通过；未改主 checkout、主机配置或停机状态。

Linux tagged 的原 observer/Close/outbound-Fatal 行为测试通过交叉 vet，但本地没有执行
Linux 内核；不可把它写成 netns 或 failure-path OS 排水验收。其实际 race×20 与真实
矩阵由原 required CI 执行，当前 head 的首跑结果另记在 PR 描述，不制造证据提交循环。
