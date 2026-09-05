# Gate C1b 产品组合证明（实现中）

状态：维护者已接受 ADR §19 的 R1 完成确认，C1b 继续实现和取证。
本文件是中间验证记录，不是出口、独立审查结论或现场授权；required CI 尚未全绿。
基线：`0a61c5882381b5518400dc233edc1801bab4da4b`。实现遵循
[Gate C1 ADR](adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md) §16–§19；R1 细节先以独立文档提交冻结。
真实 OpenSSH loopback 和 required netns 的全产品组合证明尚未完成，不以 memory 结果代替。

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

## 4. root 执行域与 OS 证明的当前范围

- §18 已冻结 UID 0、root-owned 0700 wrapper/binary、0600 私有材料、key-only forced command、
  `PermitRootLogin forced-commands-only`。没有安装或修改维护者的 SSH/service/firewall/task。
- root effective-config 与执行计划的纯测试、非 root/错误 command/弱认证负向已通过。
- exact `linux && natlab && c1bproof` seam 只消费既有 sealed B2/B3/SSH factory；不提供新 raw
  unicast boolean。普通 build 的 authority 和 parser 不变。
- 新 harness 使用真实 SSH client、私有 sshd/安装/stage/canonical governor、race 子进程；kernel
  TUN 分支的 echo 经内核 UDP → route → TUN → WireGuard，而非 memory shortcut。该分支只有
  交叉编译/vet 证据，因前序失败尚未完成 required OS 运行，不能宣称通过。
- cleanup 的 PID 操作仅在固定 endpoint namespace 内，以 pidfd 固定已核对的测试进程；失败清理
  不算成功排水。现阶段不承诺真实 child/UDP/TUN/conntrack 的全链路零残留已被证明。

暂停前的本地回归：`go vet ./...` 与 `go test ./... -count=1 -timeout=12m` 通过
（governor 214.634s）；architecture/mutation、CLI、root wrapper、orchestrator 定向通过；
root wrapper/orchestrator `-race -count=20` 通过（1.259s / 2.345s）；Linux
`-tags=natlab,c1bproof` 交叉 vet 通过。`git diff --check` 干净，相对链接检查为 0 broken，
新增 diff 的私有路径/设备代号扫描为 0；已有 v1/v2/N3b/Gate A/B golden 没有修改。
这些通过项不替代 §3.9 的红色 required pipeline，也不代表已满足全部受影响包 race×20 出口。

## 5. 未完成门禁

- ADR §19 的 R1 已冻结并实现；最终 SHA 的双端确认/失败矩阵与重复取证仍须全绿。
- dedicated literal-loopback OpenSSH/forced-command wrapper 的真实 child/pipe 生命周期。
- required Linux netns：三个 profile 的真实 SSH child + UDP + harness TUN 全产品组合，以及
  packet/socket/process/conntrack/governor lock 的进程外零残留见证。
- 对上述真实拓扑的 EOF/parent kill/child kill/writer error/failure matrix。
- 最终 SHA 的全仓重跑、远端 CI 全绿、独立评审。

本分支不授权 C1c/C2、LAN/公网、宿主 interface/route/firewall/service/task/sshd 改动或自动恢复。
未签发现场窗口；保留单个 Draft PR、不得自行合并的交付约束。
