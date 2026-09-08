# #101 N2d 连续重复诊断

Status: Draft，定位中，尚未宣称修复。基线 `fde8dfa`，2026-09-08。

## 已核实与待证伪假设

- 现行 `newN2DTopology` 已使用递增原子序号生成 namespace/veth 名；不能再次把“改成 fresh 名”当作本 PR 的修复。
- 当前 punch 每端 opener 只发一次，initiator 收 SYN_ACK 后才发唯一 ACK；没有 punch 重试。不得以“重试预算”解释 A 签名或增加发送。
- EIM fixture 已有静态 DNAT/SNAT，required 三次重复与所有协议时限保持。仅观察 TIME_WAIT/端口相同不能证明跨 namespace 状态污染。
- `assertNoLeaks` 证明可见 namespace/veth 消失，不证明 kernel RCU 内部 reclamation 完成。本 PR 不以额外 sleep 冒充这个证据。

## 诊断方法

独立 evidence job 跑 3 轮 × 10 次 fresh EIM×EIM；原 required job 仍为 3 次。
子进程 stage 增加本进程 monotonic 相对时间；外部每 100ms 尽力采样现有 iptables 计数器、
conntrack 数量、TCP TIME_WAIT 数量和 rendezvous 双 slot 帧计数。外部采样是顺序快照，
不声称原子同步，也不能把两个 child 相对时钟直接相减。命令输出只解析数量，不输出地址、路径或 PID。

采样前记录初始流数，结束前记录 terminal 流数与端口是否和前次重复相同；不输出实际端口。
observer 自身会有调度/进程开销，须和未开启诊断的 required job 对照。没有通过观察端修改
packet、deadline、重试或协议顺序。现有 child stage 文件写入次数不变。

失败清理改为幂等 `t.Cleanup`：停止两端、join observer、执行原 packet/socket/process/
conntrack/server/netns/veth 排水断言。正常与 Fatal 路径使用同一个收尾，不删除 RED。

## 永久负向契约

required 成功断言显式调用纯 terminal/计数谓词；以下不能被接受为成功：

| 签名 | terminal/class | direct I/R | control I/R | written TCP I/R |
| --- | --- | --- | --- | --- |
| A | expired/punch_timeout | 1/1 | 3/2 | 6/5 |
| B | expired/verify | 2/1 | 4/2 | 7/5 |

两端都覆盖。另将错误结果重新标为 success 但保留缺失 packet/control/read/write 的变体
设为负例，防止仅重命名 terminal 求绿；原 safety/ledger/资源/同 socket 校验不删除。

## 验证与结论

- Windows 本地 Linux/natlab 交叉编译及 `go vet -tags=natlab ./test/natlab` 通过；这不是 netns 实测。
- 本地 architecture 与无 natlab tag 的测试通过。
- CI 30 次时序与首次结果：待采集后回填，不把诊断准备当作 30/30。
- production delta=0。尚无证据支持端口/teardown 修复；若证实生产竞态，停止并给最小提案，等待维护者裁决。

不放宽任何 deadline/断言，不更改 Gate A/B/C，不关闭 issue，不合并本 Draft。
