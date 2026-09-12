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
