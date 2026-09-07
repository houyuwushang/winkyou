# Gate C1b 产品组合证明（Draft，待独立评审）

状态：维护者已接受 ADR §19 的 R1 完成确认；本分支已实现 C1b，三种拓扑与故障证据如下。
本文件不是独立审查结论或现场授权；最后提交的 CI 状态以 Draft PR #104 的 checks 为准。
基线：`0a61c5882381b5518400dc233edc1801bab4da4b`。实现遵循
[Gate C1 ADR](adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md) §16–§19；R1 细节先以独立文档提交冻结。
真实 OpenSSH loopback 与 required netns 已有成功实测，和 memory 证据分列，不互相替代。

2026-09-06：[Issue #109](https://github.com/houyuwushang/winkyou/issues/109) 的完成阶段时间边界按 [ADR §19.5](adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md) 修订；[本轮红→绿与未闭合验收](#6-issue-109-完成阶段修复与未闭合验收2026-09-06) 单列于 §6。§1–§5 是 #104 历史快照，不能覆盖本轮反例或代替当前 CI。

## 1. 已落地的 memory 组合

- 实际 Cobra root → `solver direct connect/child` → private request/config/artifact parser →
  durable responder slot claim → isolated machine owner → Gate B reservation/burn/executor →
  production TransportLease → WireGuard memory-TUN → durable FINISH/detach → OOB drain → echo/CLOSE。
- `c1bproof` 才包含 owner/factory/process runner seam。SSH assembly 使用真实 reservation、exclusive
  claim、byte accounting 和 drain；只有 process runner 为 fake。它不启动 OpenSSH，不证明真实 SSH
  子进程已退出。此事实与 `sshassembly.Witness` 的模拟进程计数明确区分。
- 所有成功样例都保留固定 deterministic artifact/Noise/NAT schedule；每次重新创建两个临时
  namespace/journal 和 WireGuard key，旧 slot 不能再次 claim。100 次重复证明生命周期，不证明
  100 个随机 NAT 均可穿透，也不重试失败的 credential。
- consumer readiness 使用 §17 的 40-byte WYCR frame 和独立 AD；原 Noise cipher 单次移交，
  原 WYHB parser 仍拒绝新 frame。R1 在 responder durable FINISH 后增加唯一 40-byte WYCF 确认，
  两端 establishment 合计均为 3 outbound / 3 inbound（含 readiness/确认），没有第九个 OOB
  frame。第四个 outbound 在底层 I/O 前拒绝，confirmation 不计作无限 active data。

## 2. 本地实测快照（2026-09-05）

下表是较早的 Windows 本地快照，不代表最后 SHA 的跨平台出口。后续 Linux required 重复已发现
§3.9 的产品完成竞态；此前的 100/100 不能覆盖或推翻这一反例。

| 证明 | 结果 | 限定 |
| --- | --- | --- |
| 三 profile 的底层 product pipeline，race ×20 | 60/60，144.460s | memory composition，尚非 CLI/真实进程 |
| 三 profile 的实际 CLI + durable slot + fake runner，race ×20 | 60/60，173.908s | predictive/asymmetric 测试窗口 500ms，仍低于生产上限 |
| 实际 CLI，100 个 fresh namespace lifecycle | 100/100，195.764s | profile 分布 34/33/33；固定可复现成功样例；失败即停 |
| readiness codec/shared cap/session 定向 race ×20 | 通过 | 包括 wrong role/generation/context/winner、replay、oversize、cancel、deadline |
| architecture 与 mutation | 通过 | 普通构建移除 test tag、越层 import/constructor、raw capability 等负向 |
| 普通与 c1bproof tagged `go vet` | 通过 | 未执行现场网络动作 |
| workflow syntax (`actionlint`) | 通过 | 不代表远端 CI 已运行 |

100-run 每轮检查：`ActivePacketConns=0`、`ActiveMappings=0`、`QueuedPackets=0`、
`ActivePeers=0`、`ActiveAttempts=0`、`HeavyweightAttempts=0`、`Reserved=0`、safety trip clear。
这些是进程内模拟与真实临时 governor 的见证，不冒充 `ss`/conntrack/子进程 OS 残留证明。

### 2.1 R1 修复后的重复实测

- 两入口三 profile 加真实 governor handoff 的 Windows `-race -count=20` 通过，343.717s；
  100 fresh CLI/slot lifecycle 通过，193.520s。每轮仍检查上述模拟资源与 governor 归零。
- 六个受影响包的完整 `-race -count=20`：probeio 54.347s、gatecorchestrator 3.208s、
  gatecchildstream 3.206s、hardnatcontrol 103.183s、sshassembly 146.899s、sshchildwrapper 1.460s。
- 实际 CLI + fake SSH runner 的 evidence-drift / candidate-exhaustion 矩阵 race×20 通过，61.377s。
  前者在观测中途改变 NAT allocation，两端均 13 evidence / 0 candidate；后者在 13 次观测后改变
  mapping，两端均 13 evidence / 32 candidate 后耗尽。双方 durable burn/FINISH、零 data/handoff、
  无重试、无 trip、无模拟资源或 governor residue。
- product lease 的八种 binding/未 Promote 负向加 standby consumer crash，race×20 通过，2.315s；
  底层 writes=0，未完成的 attempt 不 detach。
- required Linux 的真实 SSH/UDP/TUN 证据为 §4；旧红色 CI 保留在 §3，不以 rerun 抹去。

## 3. 保留的失败记录与修复

1. 最初无 readiness barrier 的 race 重复中，一次 hard-16K 样例出现 initiation 已发送、对端无
   response。源码存在 `AttachTransport` 启动 reader 先于 `IpcSet` 的窗口；维护者接受 §17。
   确定性测试在 responder consumer 未安装时阻止 binder 消费 READY，并证明零 WireGuard 发射。
2. readiness 纳入原 3/3 后，responder 的末个 keepalive 正好填满 inbound 额度。其随后挂起的
   polling read 不能被当成“已收到第四包”立即关闭；gate 现在不再做底层读，等待受控状态切换。
3. 引入真实 CLI 后，测试曾把冻结 artifact 验证时钟误用于 session deadline；已将 test-only
   artifact clock 与真实 active/session wall clock 分开，生产两者仍来自 `time.Now`。
4. CLI race 首次 ×20 有一次 predictive 在人工压缩的 100ms 窗口内仅发送 22/0 candidates 后
   双边有界耗尽。CLI 测试窗口调整为 500ms；不更改生产 envelope、PPS、packets、retry 或候选数。
   修正后的 CLI race ×20 完整通过，不以单次 rerun 抹去失败。
5. 首次全仓测试暴露一个本 PR 新增的 handoff 单测遗漏 readiness 步骤；已补真实双向屏障。
   原有 v1/v2/N3b/Gate A/B golden 未作任何修改。
6. session 的终局 reader 现在关闭接口并等待退出；post-FINISH 错误路径也关闭 detached transport。
   responder 的诊断 stderr 在 FINISH 后可随 SSH/OOB 关闭，不再让预期的 closed pipe 破坏数据面；
   FINISH 前和 initiator 侧仍传播诊断写失败。
7. `bfd03af` 的 [首跑](https://github.com/houyuwushang/winkyou/actions/runs/33963668253) 在新 netns
   job 的 SSH 环境检查退出，尚未执行产品 attempt；未用 rerun 掩盖。随后将 `/run/sshd` 放入
   helper 私有 mount namespace；缺少 sshd 时只解包测试程序，不执行 package/service 安装脚本。
8. `7fbd00d` 的 [第二轮](https://github.com/houyuwushang/winkyou/actions/runs/33963899522)
   暴露两处测试问题：私有 `/run/netns` 非递归 bind 没有保留命名 namespace 的子挂载；claim 单测
   只注入 session clock，没有注入已经拆分的 artifact clock。`68eca51` 保留固定 namespace 校验，
   改用递归 bind，并补正确的单测时钟注入；全仓 Linux/Windows 普通测试随后通过。
9. 同一 required Linux memory job 的三 profile × 两条入口 ×20 中有 12 个失败子样例：底层 7、
   CLI 5。initiator 已 FINISH 并关闭 OOB，responder 仍处于成功 FINISH 之前，触发已有 EOF 终局。
   这是阻断，不是可隔离的随机 NAT 失败。ADR §19 保留双端 trace、固定顺序与 R1/R2 修订提案。
   历史提交 `45512fc` 的 `go test -race -tags=c1bdiagnostic ./internal/probeio -run '^TestC1bUnilateralFinishGapDiagnostic$'
   -count=20 -timeout=1m` 在 Windows **20/20 命中，exit 1，0.487s**；明确不算通过。
10. `68eca51` 的 [第三轮](https://github.com/houyuwushang/winkyou/actions/runs/33964194965) 中，
    既有 N1、N2d/N3b、Gate A/B2/B3 required job 均通过；新真实 SSH/netns job 在首个
    loopback-SSH/predictive 样例等待 responder 私有结果时超时，未取得全链路/零残留出口证据。
    此失败需独立定位，不冒充已证明与 memory 完成竞态同源；未进行 rerun。
11. R1 首次本地组合仍在 hard-16K 出现已 FINISH 而 echo 失败。排空 reader 在 decrement
    inFlight 后才处理取消，此时状态可能已推进；另有排队等待读取锁的 polling context 先行
    到期。两者都不能误关已移交 session。新增确定性回归并保留原 deadline 后，两入口三
    profile 加 governed handoff 的 race×3 通过（58.944s）；此为中间验证，不是最终出口。
12. `ae1ec97` 的 [required SSH/netns 诊断](https://github.com/houyuwushang/winkyou/actions/runs/33967538739/job/101310187950)
    为 AcceptedKey=0、FailedKey=1、FileRejected=1、SessionStarted=0，presence 前关闭且 burn=false。
    与 R1 无关：fixture 的 authorized_keys 位于共享临时目录祖先之下，不满足
    [OpenSSH 9.6 safe_path 的逐层父目录规则](https://github.com/openssh/openssh-portable/blob/V_9_6_P1/misc.c#L2086)。
    改为现有私有 mount 内 `/root/.ssh/authorized_keys`（0700/0600），保留 StrictModes 与 root
    forced-command 要求；没有放宽认证或接触宿主 home/SSH。后续完整管线仍须 CI 证明。
13. `6cb6290` 的 [required 真实 SSH 运行](https://github.com/houyuwushang/winkyou/actions/runs/33967873724/job/101311076228)
    已为 AcceptedKey=1、SessionStarted=1、双端 FINISH/OOB drain，仍在 post-OOB echo 失败；
    initiator SSH Killed=true。原 assembly 仅关闭管道，不请求仍等待 remote session 的 SSH client
    退出，必然可能耗尽 2s drain，与 responder 的 2s echo 窗口竞争。按原 ADR §5.3 补对
    已持有 Linux child handle 的 SIGTERM 请求，2s 后才 SIGKILL 的上限不变；Windows 不发送
    console/group signal，原 pipe/Job Object 规则不变。fake 确定性测试检查请求先于等待/kill；
    真实 SSH 是否无强杀完成并保住 data plane 仍交由下一轮 required 取证。
14. `e77b1ae` 的 [required 运行](https://github.com/houyuwushang/winkyou/actions/runs/33968297402/job/101312205843)
    已通过 loopback-SSH 三 profile（真实 OpenSSH + TEST-NET UDP + memory-TUN），post-OOB echo
    成功，challenge 均 3/3。UDP 计数 predictive=50/49、asymmetric=82/530、hard16=16403/16401；
    随后的 netns-SSH/predictive 在 presence 前超时、burn=false。B2 NAT 模型的 lan0 policy
    route 将 TCP 一并送入 UDP-only TUN；C1b harness 增加仅匹配固定 SSH TCP tuple/回包的
    main-table 优先规则，UDP 模型与产品 authority 不变。规则仅在测试 NAT namespace，
    并显式清理；尚未取得 kernel-TUN 分支的成功出口。
15. `c9ec4f5` 的 [required netns 分支](https://github.com/houyuwushang/winkyou/actions/runs/33968695931/job/101313254845)
    已跨 namespace 完成 SSH 与 Gate B VERIFY；handoff 被普通 `NewMemoryWireGuard` 的 memory-only
    guard 正确拒绝。新增精确 `linux && natlab && c1bproof` 测试构造器只接受 harness-owned
    `wink-c1b-proof` TUN，仍强制 no-op native bind；原 memory guard 不改、不伪装接口类型，
    architecture 对 tag/native bind/name/type/port 和生产消费者做变异检测。同时测试 route helper
    使用私有配置中的绝对工具路径，responder 的固定无 PATH environment 不放宽。
16. `0e2e922` 的 [required TUN 计数](https://github.com/houyuwushang/winkyou/actions/runs/33970103244/job/101316970377)
    实测 initiator KernelReads=3、InnerSends=2、NonIPv4Reads=1，echo/CLOSE 本身已通过。
    新建 TUN link-up 产生额外 IPv6 控制包；harness 在精确 namespace/接口验证后，仅对新建且尚未
    up 的 `wink-c1b-proof` 禁用 IPv6，并回读确认。没有改变 host/default/all 设置，也没有放宽
    KernelReads=InnerSends、KernelWrites=InnerReads 的精确断言。`13734ba` 的下一轮通过全部矩阵。

## 4. root 执行域与 OS 证明的当前范围

- §18 已冻结 UID 0、root-owned 0700 wrapper/binary、0600 私有材料、key-only forced command、
  `PermitRootLogin forced-commands-only`。没有安装或修改维护者的 SSH/service/firewall/task。
- root effective-config 与执行计划的纯测试、非 root/错误 command/弱认证负向已通过。
- exact `linux && natlab && c1bproof` seam 只消费既有 sealed B2/B3/SSH factory；不提供新 raw
  unicast boolean。普通 build 的 authority 和 parser 不变。
- 新 harness 使用真实 SSH client、私有 sshd/安装/stage/canonical governor、race 子进程；kernel
  TUN 分支的 echo 经内核 UDP → route → TUN → WireGuard，而非 memory shortcut。
- cleanup 的 PID 操作仅在固定 endpoint namespace 内，以 pidfd 固定已核对的测试进程；失败清理
  不算成功排水。通过路径先要求 endpoint 自行退出，再核对 OS 资源；不能靠 cleanup 杀掉残留而通过。

### 4.1 真实进程与内核数据面

`13734ba` 的 [required race-enabled OS 运行](https://github.com/houyuwushang/winkyou/actions/runs/33971212225/job/101319945035)
首跑通过 6 个完整链路 + 7 个故障，176.71s，无 rerun。两种 SSH 拓扑所得外层计数一致：

| profile | evidence I/R | candidate I/R | OS UDP I/R | establishment I/R |
| --- | --- | --- | --- | --- |
| predictive | 13/13 | 31/32 | 50/49 | 3/3 |
| asymmetric | 13/13 | 64/512 | 82/530 | 3/3 |
| hard-16K | 13/13 | 16384/16384 | 16403/16401 | 3/3 |

这里的 3/3 是每端 outbound/inbound shared readiness + WireGuard + R1 allowance；UDP 总计还包含
命中后的单 winner 与 post-FINISH data。每端 iptables 实测值严格等于各分类计费之和。SSH/OOB
退出后 initiator 仅发送一个 echo request 与一个 CLOSE，responder 仅回复一个 echo；真实 SSH client
`Exited=true, Drained=true, Killed=false`，该实测值仅属于 Linux 分支。Windows 的 `RequestExit`
为 no-op，真实 ssh.exe 尚未取证；预期是在 pipe 关闭后若仍存活至 2s drain 界，由 Job Object
强杀并见证 `Killed=true`。C1c Windows 取证不得仅因该值判定回归，但仍须证明已 FINISH/detach
的数据面在预期 EOF 后完成 post-OOB echo 与排水；本节不将平台预期冒充实测。
carrier 仍最多 8 frame / 8256 byte，每方向单列计数。

loopback-SSH 分支的 UDP 仍位于 TEST-NET NAT，inner interface 为 memory；netns-SSH 分支的 inner
interface 是真实、非 persistent TUN，KernelReads=InnerSends、KernelWrites=InnerReads，额外 IPv6=0。
两者都是真实 child，不将 fake process runner 冒充真实 SSH。

### 4.2 真实 child 故障与磁盘见证

| 注入 | OS UDP I/R | ledger sequence I/R | 终局前实测 wall ms |
| --- | --- | --- | --- |
| presence 前 stdout EOF | 0/0 | 1/1，未 burn | 1742 |
| parent cancel | 0/1 | 3/3 | 1741 |
| stdout writer error | 13/13 | 3/3 | 21493 |
| WireGuard peer key 不匹配 | 47/46 | 3/3 | 7177 |
| post-burn parent SIGKILL | 0/1 | 2/3 | 1710 |
| post-burn child SIGKILL | 0/0 | 3/2 | 1747 |
| consumer FINISH 后 SIGKILL | 49/48 | 3/3 | 6214 |

wall 包含固定测试启动；writer error 在原 20s active + drain 内结束，不宣称即时检测。
sequence=2 是已 durable burn、未 FINISH 的崩溃见证，不伪造正常 FINISH；正常失败保持 sequence=3，
无退款、无第二 attempt。SIGKILL 不能写进程内 result，故用磁盘 journal、私有固定 marker 与 OS
process/socket/lock 见证；日志中的空 peer class 不被伪装成对端成功。

全部正常/故障路径均先验证 packet counters 在终局后稳定，关闭 observer/router，然后要求
`sockets=0, processes=0`；重新取得 machine owner 验证 lock 已释放。conntrack 在显式清理后为 0，
最后验证 namespace/veth=0；非 persistent TUN、测试 address/route 也不存在。
conntrack 的零值是 **teardown 后**，不是声称内核立即自然老化；failure cleanup 不计作排水通过。

暂停前的本地回归：`go vet ./...` 与 `go test ./... -count=1 -timeout=12m` 通过
（governor 214.634s）；architecture/mutation、CLI、root wrapper、orchestrator 定向通过；
root wrapper/orchestrator `-race -count=20` 通过（1.259s / 2.345s）；Linux
`-tags=natlab,c1bproof` 交叉 vet 通过。`git diff --check` 干净，相对链接检查为 0 broken，
新增 diff 的私有路径/设备代号扫描为 0；已有 v1/v2/N3b/Gate A/B golden 没有修改。
这段保留暂停前快照；后续 R1 与 required OS 证据见 §2.1/§4，不覆盖历史失败记录。

## 5. 验收映射与剩余门

| ADR §10.2 | 证据入口 |
| --- | --- |
| 三 profile / 三拓扑全管线 | `TestGateC1bMemoryCLIAndClaimedChildPipeline`、`TestLinuxGateC1bProductProof` |
| local target / raw capability 零 I/O | Gate C request/entry preflight、Gate C1b architecture mutation、原 Gate B target scope 回归 |
| lease-before-Promote / binding / old handle | `TestGateC1bGateBProductHandoffRetainsOwnershipUntilFinish`、`TestWireGuardProductLeaseRejectsBindingAndMissingPromotionWithoutIO`、原 TransportLease poisoning 回归 |
| shared 3/3 / FINISH / R1 | `TestWireGuardSessionGate*`、`TestConsumerFinished*` 与字节 golden；真实 OS 精确计数 |
| OOB 后 echo / replay / role | `TestPostOOBEcho*`、真实 CLI 的完整 progress 前缀与 post-OOB echo |
| conflict preflight | `TestConflictPreflightRejectsBeforeSSHOrGateBFactory`（up/key/interface/route，spawn=0、factory=0） |
| cancel / EOF / drift / exhaustion / error / crash | §2.1、§4.2；`TestForegroundResponderSessionTerminationModes` 分别证明 CLOSE/inactivity/absolute/cancel |
| 100 fresh / race×20 / 隔离 | 两平台 required memory + Linux required race binary；architecture/mutation |
| 旧协议与默认 up 不变 | 既有 v1/v2/N3b/Gate A/B golden 零修改；全仓 Windows/Linux 测试 |

剩余交付门：最后提交的 CI checks 全绿、独立评审；PR 保持 Draft，不自行合并。

本分支不授权 C1c/C2、LAN/公网、宿主 interface/route/firewall/service/task/sshd 改动或自动恢复。
未签发现场窗口；保留单个 Draft PR、不得自行合并的交付约束。

## 6. Issue #109 完成阶段修复与未闭合验收（2026-09-06）

状态：**Draft，未完成全部验收，不应合并或关闭 #109**。修复基线为
`c2d1ef50e354da87eea536176f8dddfe55aa4b6e`；#105/#108 已合入，但不在这里实现 liveness、
映射寿命模型或 C1c。最初仅修改 `wireguard_consumer_finish.go` 的本地阶段 context；
2026-09-07 经单独授权，扩展为完成失败见证及已落盘 FINISH 后的 Gate B 错误清理（§6.6）。
不改 TransportLease、ProductHandoff、Gate B 发包执行、orchestrator、carrier、SSH/child stream。

§6.1–6.3 保留 `0b7800b` 及以前的原始反例和暂停记录；内存/OS 分列验收已获维护者同意，
修订规范为 ADR §19.6，新验证另列 §6.4–6.5；第二次授权与实测见 §6.6 / ADR §19.7。
慢 fixture 的新反例与维护者授权的测试窗口修订见 §6.8–6.9 / ADR §19.8。
历史红结果不是被覆盖成绿，也不再是待裁决事项。

### 6.1 原始反例与确定性红→绿

保留 [#109 原 required Windows 红运行](https://github.com/houyuwushang/winkyou/actions/runs/33992470623/job/101377022894)。
该签名是 initiator 已 durable FINISH 且已认证 peer FINISHED，但本地旧 challenge context
到期，AttemptDetached=false、gate=closed；对侧 active 并不能代替双方 post-OOB echo 成功。

修复前先提交回归 `0717d8c`，执行：

```text
go test -race ./internal/probeio -run 'TestConsumerFinished(Completion|ResponderWriteRetains|DetachAfter)' -count=1 -v
```

首次 RED（4.038s）：实时接收与先缓冲再认证两分支均在 3.20s 复现：

```text
completion after challenge deadline rejected:
gate_error=true deadline=true finish=true peer_finish=true
detached=false state=closed reads=3 writes=3
```

两侧慢 detach 分支也 RED；session 回调立即取消分支未保留 Canceled 原因。absolute 到期与
responder 迟写分支按原规则拒绝。`791e6e7` 的同一命令 GREEN（4.719s）；原 gate/readiness/
FINISHED/lease-failure 定向回归 GREEN（5.441s）。不是删测、改期望或重复运行原代码转绿。

| 回归 | 实测要求 |
| --- | --- |
| initiator 本地 FINISH 至原 challenge deadline + 200ms | 实时/缓冲认证两路 active；FINISH/peer confirmation/detach=true；底层调用读 3、写 3 |
| initiator FINISH 跨原 absolute deadline | FINISH=true；不 detach、不 active；transport 关闭，读写仍 3/3 |
| FINISH 回调内立即取消 session | 同上，并保留 Canceled 原因，不等待 AfterFunc 调度才检查 |
| responder FINISH 至原 challenge deadline + 200ms | 关闭；CompletionWrites=0，底层读 3、写 2；已写 FINISH 不撤销 |
| 两侧 FINISHED 在 3s 内完成，detach 延迟至 3.2s | active，底层读写仍 3/3；无 active-data I/O |

首轮完整三包 `-race -count=20` 又发现一次 absolute 负向失败（probeio 114.037s；另外两个
包通过）。gate 已 closed、FINISH/peer confirmation=true、gate 的 AttemptDetached=false，
但组合 ownership 断言失败。没有把一次通过冒充 20 轮通过。

随后 `0f4a249` 增加确定性取消传播屏障：保留父 context 的 Deadline/Done/Err，只阻塞子
取消回调的调度；原检查会错误地返回成功，证明问题不是 transport 关闭见证读取过早：

```text
go test -race ./internal/probeio -run '^TestConsumerFinishedCompletionAbsolutePropagationDoesNotDetach$' -count=1 -v
expired parent accepted before child cancellation:
gate_error=false deadline=false lease_detached=true state=active
```

该 RED 在 1.00s 出现。`f8b93b2` 仅在同一 completion 函数内同步检查 `gate.attemptCtx.Err()`
与 `sessionCtx.Err()`，不依赖派生子 context 的取消已完成；同一确定性测试 GREEN（2.572s）。
测试屏障在 defer 中解除并等待回调结束，没有延长任何生产 timer 或修改 lease 的行为。

### 6.2 慢 FINISH 管线与计数口径阻塞

注入仅存在于 `c1bproof` 的 `_test.go`：在 initiator 的真实成功 FINISH append+fsync 后，
把回调返回延迟 3.5s，保持实际 journal、锁、顺序、单次成功及原时钟。没有 fake FINISH、
新增生产 hook 或重启 timer。新 Hard16 用例使用原 45s profile absolute envelope，而非原有
快速 fixture 的 lower-only 6s；原用例及其窗口不改。predictive/asymmetric 原 20s 不变。

首次运行（在 `791e6e7` 上添加待提交注入用例）：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryProductPipelineReachesPostOOBEcho/slow_initiator_finish' -count=1 -v -timeout=2m
```

结果 **RED（19.987s）**：三 profile 的双端均到达 `data_plane_ready`，仅下表的继承 OS 总计
断言失败。每个 fixture 的成功落盘回调恰好一次、post-fsync delay 实测 3500ms；每端
FINISH/detach=true、shared challenge=3/3、carrier=8/8、OOB/echo drained=true、attempt released。
initiator PeerFinishConfirmed=true、completion 写/读=0/1；responder 对应 false、1/0，含义不变。
既有 residue 断言仍在计数错误后执行，未报告 memory connection/mapping/queue、governor
attempt/peer/reservation 残留或持久 safety trip；这不是 OS socket/netns 的新实测。

为区分“修复新增报文”和“fixture 本身不同”，另执行一次 **无延迟原场景对照**，不是重新
运行失败用例求绿：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemoryProductPipelineReachesPostOOBEcho/(predictive|asymmetric|hard-16k)$' -count=1 -v -timeout=2m
```

对照 PASS（8.778s），保持原候选窗口、Hard16 原 6s 快速 fixture，使用同一修复后 gate。
下表记录两次运行的实际数值，不声称是未运行的 main 二进制结果或未来 20 轮的恒等式。

| profile | 提示词继承的 OS UDP I/R（§4.1） | 内存无延迟对照 I/R | 内存慢 FINISH I/R | 内存 candidate I/R | 内存 winner I/R |
| --- | --- | --- | --- | --- | --- |
| predictive | 50/49 | 51/49 | 51/49 | 32/32 | 1/0 |
| asymmetric | 82/530 | 146/530 | 146/530 | 128/512 | 0/1 |
| hard-16K | 16403/16401 | 16402/16402 | 16402/16402 | 16384/16384 | 0/1 |

分项可核算：内存每端 evidence=13、establishment=3；post-OOB active writes 为 I=2/R=1。
每端实际 UDP 等于 evidence + candidate + winner + establishment + active writes。
§4.1 原 OS 场景则为 predictive candidate=31/32、asymmetric=64/512、Hard16 winner=1/0。
因此首次内存差额逐项有来源，不能靠调 PPS/候选窗口、减半调度或挪 winner 来凑原表。

**当时待维护者裁决（历史记录；现已接受第一项，见 §6.4）：**

- 修订内存验收口径：按同一 fixture 的分项计费、3/3/no-extra-I/O、完成/排水见证验证，
  与 OS 证明分列；§4.1 OS 原表与 required netns 断言保持不变。
- 或仍要求内存精确重现 OS 场景：另行明确批准可调整的 test fixture/调度证明范围；不能
  把调整掺入这个 completion-only 修复，也不授权改求解器或扩大预算。

`0b7800b` 当时保留 §19.5 第 4 项以及新用例的原失败断言。已有 required CI 精确 selector 会运行该
子用例，预期在此拒绝；不 skip、不放宽比较、不修改 workflow，不以“其他检查通过”代替。

### 6.3 首轮验证及当时尚未达到的出口（历史快照 `0b7800b`）

- `go vet ./...`、`go vet -tags=c1bproof ./internal/governor` 通过。
- `go test ./internal/architecture -run 'GateC1b|GateC1a|GateB' -count=1` 最终代码通过（2.150s）。
- `go test ./internal/probeio ./internal/v2/directconnect/gateb ./internal/v2/gatecorchestrator -race -count=20`
  在 `f8b93b2` 通过：113.366s / 1.732s / 1.839s。此前失败、确定性反例及针对性修改保留于 §6.1，
  不是对同一代码 rerun 求绿。
- Windows `go test ./... -count=1` 首跑 **FAIL**：仅
  `pkg/client.TestRelayWGGoTwoEnginesExchangeIPv4Packets` 在 33.02s 等待 relay transport 超时
  （`relay_wggo_test.go:62`）；症状与已隔离 #97 同类，不据此声称根因已确认，也不顺手修复。
  其它包通过，其中 governor 201.322s、probeio 11.914s。没有重跑全仓掩盖此失败；生成的
  测试 key、endpoint、时间戳和 runtime dump 不复制进公共证据。
- c1bproof 的已知红计数用例不通过；不得报告该矩阵 race×20 全绿。远端 required job 结果
  以本修复 Draft PR 的精确 head checks 为准，不能引用 #104 的成功代替。
- 本机没有可用的 WSL/Linux/Docker，未执行本地 Linux/netns/真实 SSH 证明；Linux 全仓和
  required OS 证明交由现有隔离 CI，本 PR 不增加任何现场权限。
- 原 3s/3 包常量、40-byte FINISHED、nonce 8/9/10、AD、所有既有 golden 与成本表零修改；
  未改 workflow、依赖、TransportLease 或其它生产模块。不混修 #97/#101/#106/#107。
- `git diff --check` 干净；七文件精确范围、严格 UTF-8/NUL、52 个相对文件链接与新增证据
  anchor 校验通过；新增 diff 的凭据/私有地址/本机身份与路径扫描为 0。停用任务保持 Disabled。

在计数口径裁决、全部 required 验证和独立复审完成之前，保持 Draft/未合并，#109 不关闭；
不推进 liveness/M/C1c 或现场 I/O，不启用计划任务或自动恢复。

### 6.4 接受分列验收后的证明（2026-09-06）

维护者明确接受“内存按自身场景分项计费、慢 FINISH 无新增报文；OS/netns 原表不变”。
先以 `a8967b3` 写入 ADR §19.6，再以 `c038657` 修改测试；没有继续扩大生产修改。
新增的 `gate_c1b_packet_accounting_c1bproof_test.go` 只核算本次真实分项，不重排候选或 winner，
也不把另一组固定总计替换成新的内存常量。

- 独立的底层 NAT 计数必须精确等于 evidence + candidate + winner + establishment + active；
  evidence=13，既有 role 候选上限、asymmetric target-set/Hard16 完整 schedule 与双方一个 winner
  均独立检查，再与 Gate B 分项、总计、冻结的 attempt 预算交叉核对。
- 在真实 initiator FINISH append+fsync 后、原 3.5s 等待前后，读取双侧 NAT 发包快照；两侧
  必须分别不增长，且快照必须落在 establishment 已完成、active 尚未开始的精确计费边界。
  getter 只读计数，不开 socket、不发送、不暂停另一线程、不更换时钟或 ledger writer。
- 仍断言双方 ready/FINISH/detach、shared challenge 3/3、carrier 8/8、单个 echo/CLOSE 与排水。
  新核算报错后仍继续执行原 residue/safety 检查，不用提早退出跳过清理见证。
- 20 个纯输入负向用例包括两侧额外 UDP、等待期间新增报文、错误阶段边界、少等待/重复 FINISH、
  第四个建立包、额外 active、分项不符、越权候选及不完整 schedule；新增报文即使自报分项
  一起变化也须满足原上限和固定数据阶段，不能仅用自报总计自证。

首次新口径慢 FINISH 验证：`-race -count=1` PASS（20.902s），每侧结果均 ready，且：

| profile | 底层等待前 I/R | 等待后 I/R | 全程实际 UDP I/R | post-fsync 等待 |
| --- | --- | --- | --- | --- |
| predictive | 48/48 | 48/48 | 50/49 | 3500ms |
| asymmetric | 144/529 | 144/529 | 146/530 | 3500ms |
| hard-16K | 16400/16401 | 16400/16401 | 16402/16402 | 3500ms |

本次 predictive candidates=31/32，和 §6.2 首跑的 32/32 不同；本表是一次实测，不是允许
硬编码的新 expected total。§4.1 OS 表和所有 netns 断言未动。纯核算的 3 个正向、20 个负向
用例 `-race -count=20` PASS（3.298s）；全仓与 tagged governor vet PASS，完整 architecture
（含 mutation）PASS（5.270s）。更广的重复验证已执行，未通过；见 §6.5。

旧 head `0b7800b` 的 CI 最终结果另行保留：**28 SUCCESS / 5 FAILURE / 33**。
[PR-event](https://github.com/houyuwushang/winkyou/actions/runs/34017008251) 和
[push-event](https://github.com/houyuwushang/winkyou/actions/runs/34016973185) 均为首次运行。
四个 Linux/Windows memory job 被原继承 OS 总计的断言拒绝；PR 两平台日志未出现 pipeline error
或 test timeout。两个 C1b netns required job 通过，不能因此冒充当前新 head 的 OS 验证。

第五个失败来自 push 的 Gate B3 `fifty_percent_candidate_loss`：initiator
`attempt_expired/verify`（candidate=16384、winner=1、UDP=16398），responder
`attempt_expired/candidates`（candidate=16384、winner=0、UDP=16397），共同见证以
`initiator_common_witness` 拒绝；同 head 的 PR-event B3 通过。这里不据症状认定新根因，
不宣称该失败场景 residue 已通过，不混修 #100/#106，不手动 rerun。旧 Windows 全仓本地 #97
失败同样保留；旧 head 远端 Linux/Windows 全仓通过不抹去它。

### 6.5 race×20 新反例与停止条件（代码 `c038657`）

```text
go test -race -tags=c1bproof ./internal/governor -run GateC1b -count=20 -timeout=20m -json
FAIL: 777.224s; first run, no retry
```

20m 仅为本地全选择器测试 runner 的外层 watchdog，不是任何产品/fixture deadline 的变化；
CI 原分拆 selector、12m/3m runner 与全部预算未改。原始 JSON 保存在仓库外，公共证据只保留
脱敏计数和稳定失败类，不上传生成的身份、PID 或完整 runtime dump。

| 本地重复项 | 结果 |
| --- | --- |
| 普通 memory 三 profile | 各 20/20 |
| CLI/claimed-child 三 profile | 20 轮入口全部通过 |
| CLI evidence-drift / exhaustion | 20 轮入口全部通过 |
| lease/ownership 回归 | 20/20 |
| 慢 FINISH predictive / asymmetric / Hard16 | **19/20、20/20、20/20** |
| 只读 post-fsync 快照 | 60/60 恰好一个回调，3500–3501ms；双侧计数全部不增长 |
| 核算正向 / 负向变异 | 60/60、400/400 |

第 11 轮 slow predictive 失败，子用例 7.27s。其等待前/后计数均为 **48/48**，没有新增发射；
但这不能代替完成/排水验收：

- initiator：`wireguard_binding_failed`，progress 止于 `data_plane_challenge → terminal`；
  `PeerFinishConfirmed=true`、`FinishRecorded=true`、`AttemptDetached=false`、`State=closed`，
  shared trace 3/3、active writes/reads=0/0。
- responder：`post_handoff_validation_failed`，progress 到 `finish_recorded → oob_drained → terminal`；
  `FinishRecorded=true`、`AttemptDetached=true`、`State=closed`，同样 3/3、active=0/0；
  双方 `DataPlaneReady=false`。不把 responder 已 FINISH 当作双方成功。
- natsim connection/mapping/queue 的原检查未报错；**initiator governor residue 明确失败**：
  active peer/attempt/heavyweight 各 1，仍预留 socket=8、target=64、PPS=32、packet=64、
  five-tuple=64，safety trip clear。测试 deferred governor/network Close 不是正常路径排水证据。
- 核算校验随后也拒绝缺失的成功分项；它是管线失败的后果，不是再次出现内存/OS 计数口径问题。

受保护生产代码的只读核对发现了残留的确切控制流：

1. `gateb/product_handoff.go:90–101` 的 durable 回调成功后，将 `runtime.authorization=nil`、
   `runtime.finishRecorded=true`；后续 `FinishAndActivate` 错误进入 `runtime.cleanup`。
2. `gateb/connect.go:2038–2049` 的 cleanup 却只以 `finishOK := !runtime.burned` 初始化，
   只有非 nil authorization 再次成功 FINISH 才把它设为 true，未使用已有 durable 见证。
3. `gateb/connect.go:2100` 因而跳过 controller/attempt/peer 释放，和本次残留一致。不能通过
   重写 FINISH、退款或无条件释放来修复；这里没有修改该函数。

启动此次终局的更早原因尚未细化：orchestrator 暴露通用 `wireguard_binding_failed`，现有结果
没有区分具体父取消、session ceiling 或 lease 错误来源；**不能仅凭慢回调就认定 5s session
ceiling 是根因**，更不能加长它求绿。

这命中 #109 修复提示词 §0 的明确停止条件：时间修订仍未闭合原签名时，在同一 Draft PR 报告
见证，不静默修改其它模块。暂停新增实现；需要单独授权精准取消/时间源见证与 FINISH 后错误
清理的修复范围。没有修改 Gate B、orchestrator、TransportLease 或任何超时/调度参数；不重跑
失败矩阵，不以其它测试或后续 CI 偶然成功覆盖这次反例。PR #110 未达到合入条件，#109 不关闭。

### 6.6 授权的 FINISH 后清理与失败来源见证（2026-09-07）

维护者已单独授权这两项，先提交 `20ed1a4` 写入 ADR §19.7，再实现；§6.5 的停止记录属于
旧 head，不是仍待回答的授权问题。旧 head `40826a5` 的两次自动 CI 已完成 **33/33 SUCCESS**，
但这不覆盖本地 59/60 与残留反例，也不证明新代码已经通过 CI。

**清理控制流先红后绿。** `a401239` 的 `TestCleanupHonorsPreviouslyDurableFinish` 在真实临时
governor 上覆盖 controller / 直接 attempt 两种持有方式，每种分别测试 preflight、已 durable
FINISH、缺失 FINISH、失败 FINISH；每个场景重复 cleanup，factory 打开次数必须为 0。

```text
go test -race ./internal/v2/directconnect/gateb -run '^TestCleanupHonorsPreviouslyDurableFinish$' -count=1 -v
RED: 1.371s; both previously-durable cases retain peers=1 attempts=1 heavy=1
GREEN at 9472f7a: 1.824s; all 8 cases pass
```

唯一清理条件修订为 `finishOK := !runtime.burned || runtime.finishRecorded`；后者只能来自本
runtime 已成功落盘的本地见证。没有 FINISH、失败 FINISH 仍保留原 fail-closed 预留，不重写
FINISH、不退款、不返回 active。布尔真值表单测不冒充持久化证明，真实 journal 另测如下。

**真实落盘后取消。** 新 `c1bproof` 子用例位于原 required memory selector 内，只在 initiator
实际成功 FINISH append+fsync 后取消原 caller，不延迟或重写 journal。首次组合证明 PASS
6.917s；补失败来源采集后的同一组合 PASS 6.285s。每侧真实 ledger 最终 sequence/records=3/3、
admissions=1、consecutive failures=0、unfinished=0，证明未二次 FINISH 或退款。

- initiator 在 `after_durable_finish` 失败，见证为 attempt=canceled、session=active；采集时
  相对剩余分别为 18949ms / 4934ms，challenge=取消传播后的 canceled。先采集，再本地 Close；
  这些是本次实测而非新的时限常量，也不据此倒推 §6.5 的旧失败来源。
- 双侧 FINISH=true、attempt released、carrier drained；initiator 不 detach、不 active；
  responder 已 detach 后终局。每端 shared challenge 恰好 3/3、active I/O=0/0、carrier=8/8。
- 每端底层 UDP 严格等于 Gate B 已计费发射 + 3 个建立包；原 memory connection/mapping/queue、
  governor peer/attempt/reservation 与 safety 断言全部执行且通过，未靠 deferred Close 遮盖残留。

**脱敏、只读诊断。** `ca54cc3` 在原失败点、清理取消之前，记录固定 point/cause 与
attempt/session/challenge 的状态和相对剩余毫秒；只有首个失败有效，返回深度足够的值副本。
不保留 context 或原始 error 文本，私有 cancel cause 归类为 `other`；不参与授权、计时或
错误返回裁决。成功路径省略新增字段，原 JSON、协议 golden 与错误类不变。七个负向场景
覆盖两种父 context 的取消/到期、落盘错误、lease 关闭和带私有 cause 的取消，并检查返回
副本不可变、二次调用不覆盖首个见证；加成功 JSON 兼容测试，定向 race PASS 2.231s。

本轮三包 `go test -race ./internal/probeio ./internal/v2/directconnect/gateb
./internal/v2/gatecorchestrator -count=20` 全绿，耗时分别为 128.063s / 10.770s / 2.562s。
`go vet ./...`、tagged governor vet 通过，完整 architecture/mutation PASS 4.354s。

同一新代码的全选择器首轮验证：

```text
go test -race -tags=c1bproof ./internal/governor -run GateC1b -count=20 -timeout=20m -json
PASS: 836.014s; first run, no retry
```

| 本轮重复项 | 实测 |
| --- | --- |
| 普通 memory / CLI 三 profile | 各入口 20/20 |
| slow predictive / asymmetric / Hard16 | 各 20/20，共 60/60 |
| 真实 FINISH 后 caller 取消 | 20/20；40 个双侧终局见证均满足 FINISH/计费/清理 |
| 只读 post-fsync 快照 | 60/60 单次回调、3500–3501ms，两侧底层计数都不增长 |
| 分项核算正向 / 负向 | 60/60、400/400 |
| CLI drift/exhaustion、lease/ownership | 各入口 20/20 |
| 原 connection/mapping/queue、governor residue/safety 断言 | 全部通过，没有 deferred 清理代替正常终局 |

`Fresh100` 仍按原环境开关在本地这个命令中 skip；它是两平台 CI 的单独 required 步骤，不把
20 轮结果冒充 100 次 fresh run。没有任何真实 OS/netns 或 SSH 本地执行；该权限与证据仍只在
原隔离 CI 中使用。原始 JSON 在仓库外保留，公开记录没有生成的身份或完整 runtime dump。

这次没有重现 §6.5 更早的完成失败，因此只能确认已授权清理修复及新见证通过本次验证，不能
倒推旧反例一定来自某个父 context；旧失败保留。预算、3s/3 包、5s session fixture、profile
envelope、调度、netns 原断言、workflow、依赖均未改，不混修其它 issue。

本轮新代码 Windows 全仓 `go test ./... -count=1 -json` 首次 **PASS**，88 个有测试的包通过，
其中 governor 213.753s、probeio 8.654s、client 33.373s；没有 rerun。§6.3 的旧全仓 #97 失败
仍保留，不声称本次改变修复了它。最终累计 13 文件；严格 UTF-8/NUL、52 个相对链接、增量
隐私扫描与 `git diff --check` 通过，§4.1 OS 原表逐段比较不变。

远端 required 结果以 [Draft PR #110](https://github.com/houyuwushang/winkyou/pull/110) 的精确
head checks 和 PR 验证汇总为准；不能引用旧 head 的成功代替。独立复审前不合并、不关闭 #109，
也不增加任何现场或后续 gate 权限。

### 6.7 新取消回归的 CI 分组与首跑 runner 超时

`b7a43e8` 的首次 [PR CI](https://github.com/houyuwushang/winkyou/actions/runs/34072897788) 与
[push CI](https://github.com/houyuwushang/winkyou/actions/runs/34072896223) 已完成：**31 SUCCESS /
2 FAILURE / 33**。两项失败均为 Windows 主管线的 test runner 12 分钟总时限；没有手动 rerun。

| Windows 首跑 | 原始错误 | 包耗时 |
| --- | --- | --- |
| [PR job](https://github.com/houyuwushang/winkyou/actions/runs/34072897788/job/101593426732) | `panic: test timed out after 12m0s` | 721.495s |
| [push job](https://github.com/houyuwushang/winkyou/actions/runs/34072896223/job/101593422200) | 同上 | 720.192s |

两份失败日志未记录 `--- FAIL` 断言、completion failure witness 或 data race；不据此断言
被 runner 截断的余下测试或 residue 已通过。Linux 同一主管线通过；两个完整 Linux memory
job、两个 C1b OS/netns job 和其它门禁通过，不能代替 Windows 的未完成验收。

原因属于测试分组：新增取消场景进入原 selector 后也重复 20 次。本地已通过的 JSON 中，
主管线、CLI、ownership 三个入口的实测合计为 767.20s，已超 720s，尚未计 runner 开销。
因此保留原产品/fixture 时限与旧 CI 步骤，只将新增场景移动为独立顶层
`TestGateC1bMemoryCancellationAfterDurableFinish`，在同一个两平台 required job 中新增一个
显式 `-race -count=20 -timeout=3m` 步骤。旧 selector、12m/3m/9m、25 分钟 job 上限、其它
测试体及所有产品代码不变；不 skip、不降低重复次数、不并发重排产品管线或追加重试。

新分组的完全相同取消 fixture 首次单独验证 PASS **75.217s**（20/20）；`go test -run GateC1b`
仍包含该回归。§6.6 的全仓/三包/全选择器记录属于分组前相同生产代码，不冒充新的 CI 结果。
本节唯一 workflow 增量是该必过步骤；此前“workflow 未改”的记录保持其旧 head 时点含义。

### 6.8 分组后实际 session 到期反例（历史 `1cadf84`）

精确 head 首次自动 CI 最终 **32 SUCCESS / 1 FAILURE / 33**；[PR run](https://github.com/houyuwushang/winkyou/actions/runs/34074262254)
通过，[push run](https://github.com/houyuwushang/winkyou/actions/runs/34074259573) 仅
[Windows C1b job](https://github.com/houyuwushang/winkyou/actions/runs/34074259573/job/101597221866)
失败。slow predictive 子用例 7.36s，包最终 723.070s；日志没有 runner timeout 或 race report，
不能仅凭总耗时接近 12 分钟就把它误判为 §6.7 的同类问题。

| 清理前首个见证 | 实测 |
| --- | --- |
| point / cause / gate state | `after_durable_finish` / `deadline_exceeded` / `finish_confirming` |
| attempt | active，剩余 12712ms |
| session | deadline_exceeded，剩余 −1257ms |
| challenge（已完成阶段） | deadline_exceeded，剩余 −3272ms |
| 已成功 FINISH 后注入 | 单次 append+fsync 后等待 3500ms |
| 双端等待前 / 后 UDP | 48/48 → 48/48，零增长 |

initiator FINISH/peer FINISHED=true，未 detach；responder FINISH/detach=true。双方最终 closed、
DataPlaneReady=false，shared challenge=3/3、active=0/0、carrier=8/8。但与 §6.5 旧反例不同，
两侧 **AttemptReleased=true、OOBDrained=true**，其后原 connection/mapping/queue、governor
peer/attempt/heavyweight/reservation/safety 检查执行通过。清理修复在该失败路径生效；不能
以这次清理成功把原本要求的双端连接成功改成允许失败。

两侧当时配置的 `SessionCeiling=5s` 小于挑战最多 3s 加注入 3.5s 的允许组合耗时，更没有本地
完成余量。这次新见证定位到该反例的 session 到期，不倒推 §6.5 原反例必定具有相同来源。

同 head 本地原 CI selector 加 `-json` 的 12m 首跑另有 **FAIL 721.444s**，明确是
`panic: test timed out after 12m0s`，仅完成 17/20 主管线/CLI、51 个慢窗口。它和上述 CI 断言
失败分开保留；被 watchdog 截断的尾部与残留不能算通过。两种失败都没有手动 rerun。

### 6.9 授权的慢测试 10s session 与独立 required 验证（2026-09-07）

维护者已授权修正测试时间配置，先以 `11c64ca` 写入 ADR §19.8，再修改测试。慢 FINISH 三个
profile 的双端 session 本轮采用 10s；其它普通、CLI、取消、fresh100 fixture 仍为 5s。
原挑战 3s/3 包、3.5s 注入、Gate B profile absolute envelope、候选调度与 drain 均未改变。
这不是产品默认值变化或无限等待授权，不能宣称该测试已经证明长期在线可用性。

新增纯配置回归覆盖三 profile × 六种场景，确保慢窗口与普通窗口分离、不修改原 profile。
三个慢场景的原测试体、计费/完成/清理断言移至
`TestGateC1bMemorySlowDurableFinishReachesPostOOBEcho`；Linux/Windows 原 required job 新增
独立 `-race -count=20 -timeout=10m` 步骤，与配置回归一起必跑。原普通主管线 selector 的
12m、其它步骤与 25 分钟 job 上限不变，广义 `-run GateC1b` 仍覆盖所有场景；不 skip 或减次数。

首次定向执行：

```text
go test -race -tags=c1bproof ./internal/governor -run '^TestGateC1bMemory(FixtureSessionWindows|SlowDurableFinishReachesPostOOBEcho)$' -count=1 -v -timeout=2m
PASS: 24.328s; slow profiles 3/3, configuration cases 18/18
```

| profile | 等待前 I/R | 等待后 I/R | 实际 UDP 总计 I/R | post-fsync 等待 |
| --- | --- | --- | --- | --- |
| predictive | 48/33 | 48/33 | 50/34 | 3500ms |
| asymmetric | 144/529 | 144/529 | 146/530 | 3501ms |
| hard-16K | 16400/16401 | 16400/16401 | 16402/16402 | 3500ms |

双端均 ready/FINISH/detached、challenge=3/3、carrier=8/8，完成 post-OOB echo 与原残留检查。
predictive 本轮候选为 31/17，仍按 §19.6 原分项规则精确核算，不把这次总计硬编码为新期望。
该表仅为首轮观测；完整 race×20、全仓与最终 required CI 结果另以
[同一 Draft PR #110](https://github.com/houyuwushang/winkyou/pull/110) 的精确 head 汇总记录，
不以历史绿结果替代。§4.1 OS 表、required netns、协议 golden 与所有生产文件在本增量零改动。

### 6.10 完整 race×20 的不同挑战阶段反例（10s fixture 首跑）

```text
go test -race -tags=c1bproof ./internal/governor -run GateC1b -count=20 -timeout=20m -json
FAIL: 990.046s; first run, no retry
```

普通 memory/CLI 三 profile、ownership、取消、drift/exhaustion 各入口均 20/20；配置检查
360/360、核算正向 60/60、负向 400/400。慢 predictive 为 **19/20**，asymmetric 和 Hard16
各 20/20。60 次慢场景中 59 次实际执行单次 3500–3501ms 等待，两侧计数全部不增长；另一次
在 initiator 注入之前失败，不能把它计为通过。fresh100 仍由 CI 原 required 步骤单独证明。

失败在第一轮 slow predictive（10.53s），与 §6.8 的已过期 5s session 不同：

| 各端清理前的失败采集 | initiator | responder |
| --- | --- | --- |
| point | `receive_confirmation` | `after_durable_finish` |
| cause | `deadline_exceeded` | `deadline_exceeded` |
| attempt | active，剩余 15858ms | active，剩余 10899ms |
| session | active，剩余 7015ms | active，剩余 2060ms |
| challenge | 已到期，剩余 0ms | 已到期，剩余 −4956ms |
| FINISHED 写 / 读 | 0 / 0 | 0 / 0 |

initiator 尚未认证 FINISHED，慢 FINISH hook 调用数为 0；responder 在成功 durable FINISH
返回后发现原 challenge 已到期，依 §19.5 拒绝 FINISHED 写。两端未 detach、未 active，
DataPlaneReady=false；最终 Handoff.FinishRecorded/AttemptReleased/OOBDrained 均为 true，
接口/tunnel 关闭，原 memory/governor residue 与 safety 检查执行通过。initiator 的最终
Handoff FINISH 是失败清理记录，不冒充 WireGuard 成功 FINISH 或 peer confirmation。

本次两个源见证定位到了仍受原 3s 约束的确认路径，不提供 `Finish` 内锁等待、append、fsync
各阶段的分段耗时。不能把它直接归因为磁盘、系统调度或同时执行的 vet/architecture 检查，
也不能声称改 10s session 已解决它。保留完整首次日志于仓库外；错误路径未输出底层最终
UDP 总计，不能填入成功场景的计数冒充实测。

原规范明确要求 responder FINISH 与 FINISHED 写在 3s 内（ADR §19.5），且有迟写必须失败的
永久回归。本增量不改变该生产语义，不把两端必成功改成接受失败、不删测、不重跑求绿。
当前完整验收未闭合，保持同一 Draft PR 阻塞并报告此独立反例；扩大 fixture session 不能
替代对确认阶段时序及真实持久化延迟的独立分析。其它测试/CI 通过也不覆盖该首次失败。

本增量其它首次本地验证结果：

| 验证 | 结果 |
| --- | --- |
| `go vet ./...`、tagged governor vet | PASS |
| 完整 architecture/mutation | PASS，15.751s |
| 三个核心包 `-race -count=20` | PASS；probeio 134.046s、gateb 15.443s、gatecorchestrator 2.097s |
| Windows `go test ./... -count=1 -json` | PASS，88 个有测试的包；governor 245.805s、client 34.698s |
| 相对 `1cadf84` 范围/隐私/UTF-8/链接/diff | 仅四文件，生产 delta=0；12 个相对文件链接有效，§4.1 原文不变 |

没有复跑失败矩阵；core/全仓是不同且原要求的验证集合，不代替新的 tagged race×20 反例。

### 6.11 R1 确认交换移入完成阶段：裁决与验证

2026-09-07 维护者接受 [PR #110 独立复审裁决](https://github.com/houyuwushang/winkyou/pull/110#issuecomment-5565715193)，
先以 docs-only commit 冻结 [ADR §19.9](./adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md#199-r1-确认交换的时间边界2026-09-07维护者接受独立复审裁决)。
§6.1–6.10 历史证据不修改、不删除；§6.10 反例是本次纠正 R1 时间模型的依据。
旧 `TestConsumerFinishedResponderWriteRetainsChallengeDeadline` 将按裁决替换为超过 3s、
未过原 absolute/session 时必须完成 FINISHED 的回归；不得把它描述为保持旧期望值。

本节初始为规范冻结记录，代码、红→绿、完整 race×20 与新 head CI 尚待实测回填。
新 responder 慢 FINISH 与旧 initiator 慢 FINISH 分开运行；前者快照在 FINISHED 写前，
后者在 FINISHED 认证后，均按真实阶段精确核算且等待期间双侧发包计数必须不变。
