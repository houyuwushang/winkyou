# Gate B3：Hard-16K 隔离实现证据

状态：**Accepted isolated implementation evidence。PR #96 最终 head
`553b4c8152979a9ecf66eaf6a2b40c9e8d1964b3` 已通过独立复审并合入。接受范围仍只覆盖
memory、natsim 与 required Linux network namespace；不授权 Gate C、产品入口、disposable
router、LAN/公网、真实 observer 或现场 campaign。**

权限来源：[`ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md`](./adr/ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md)
§18。实现基线为 `main` = `3b40c4cf82f24604a52d4e8f2f861d2f46154602`。

## 1. 精确范围

实现只接受下列 exact arm：

```text
artifact_profile: winkyou-test-hard-nat-attempt/1
direct_attempt_profile: winkyou-test-hard-nat-control/1
planner_profile: hard_birthday_campaign/1
resource_class: hard_16k_lab/1
governor_profile: phase1_hard_nat_campaign
ledger_record_class: hard_nat_campaign/1
roles: initiator | responder
runtime_fallback: disabled
```

`hard_16k_lab/1` 的 B1 `Executable` 在本实现中按裁决从 false 翻为 true，新的 source、directional
plan 与 joint digest 已进入字节级 golden。`hard_32k_candidate/1` 仍是 plan/probability-only，
没有 artifact、budget、executor 或网络能力。未知/重复字段、交叉 profile/resource、错误 role
与旧 artifact 均在 stream/socket I/O 前拒绝。

双方仍独立重算 local/peer source commitment、directional plan、joint commitment、evidence、
cost 与 `ExecutionEnvelopeDigest`。peer 不能提供 endpoint、candidate list、port span、socket、
PPS 或 packet count，也不能把 non-executable plan 改成 executable。

## 2. 不可互换的资源 envelope

`phase1_hard_nat_campaign` 是 machine-only exact profile，只允许一个 heavyweight
`OperationBirthday` attempt：

| 资源 | exact reservation ceiling | 协议实际最大值 |
| --- | ---: | ---: |
| active peer / attempt / heavyweight | 1 / 1 / 1 | 1 / 1 / 1 |
| OOB stream / child process | 1 / 0 | 1 / 0 |
| UDP socket | 16 | 16 |
| target | 16,400 | 16,388 |
| five-tuple | 16,400 | 16,395 |
| establishment outbound UDP | 16,432 | 16,398 |
| packets per second | 512 | 512 |
| active / drain / governor duration | 45s / 2s / 47s | 不得提高 |
| OOB frame / application bytes（每方向） | 8 / 8,256 | 8 / 8,256 |

实际 establishment slice 固定为 13 个 fresh-evidence packet、16,384 个 one-shot candidate，
以及 0 或 1 个 winner ACK。34 packets、12 targets 与 5 five-tuples 是不可消费 headroom；
不能转成 retry、额外 observer、替代 tuple、第二 winner、第二轮、fallback 或 data-plane packet。
handoff 后每方向三个 fixed-target challenge packet 由 `TransportLease` 单独见证。

第 16,385 个 candidate、协议第 16,399 个 establishment packet、第二 winner，以及 governor
ceiling 后的第 16,433 个 packet、第 16,401 个 target/five-tuple、第 17 个 socket 与同秒第
513 个 packet 均在底层 factory I/O 前失败并进入持久 `hard_limit_exceeded` safety trip。

## 3. Campaign ledger

campaign 与 ordinary admission 共用同一个 machine OS lock、pairing journal、校验和、容量和
fail-closed 打开语义；没有 sidecar ledger 或第二写者。journal 的 additive `record_class` 对
ordinary record 省略，因此原有 schema-v1 字节保持不变。

- `BURN_AND_ADMIT` 原子预留 16,432 packets；24 小时最多一份 campaign；
- 未用 headroom、提前命中、失败、崩溃与 reset 均不退款；
- post-burn 非成功 terminal 先写 FINISH，再打开 campaign circuit，最后释放 attempt；
- pending restart 会重建为 circuit-open，零续跑；
- reset 必须匹配 sequence 并留下 note，只清 circuit，不清 admission/packet window；
- ordinary circuit 阻断 campaign；campaign circuit 不阻断或消耗 ordinary window；
- clock rollback、capacity、corruption 与 indeterminate 均把 campaign 视为预算已满。

跨进程门覆盖 32 个并发 contender 只有一个 admission，以及 1,000 次相同 credential 重启只有
一个进程外 emission witness。后者只在 required Linux job 通过
`WINKYOU_GATE_B3_LEDGER_REQUIRED=1` 启用，普通测试不能把 required 证据静默 skip 为通过。

## 4. 固定执行与终局

实现复用 Gate B2/Gate A 的单一 absolute context、双向认证 FIRE barrier、Noise control、
fresh-evidence revalidation、lease-bound promotion 与 FINISH-before-release 顺序。Hard-16K 只增加
一个固定的 16 × 1,024 role-separated permutation schedule：每个 tuple 至多发送一次，没有
retry、fallback、seed rotation、扩窗或第二 attempt。

512 PPS 使用逐 packet-lane 的绝对时间约束：packet `N+512` 只能在 packet `N` 的真实 UDP
commit point 满 1 秒并留出 1ms clearance 后发送。它不会把每个 512-packet batch 的系统调用/
调度耗时累计 31 次，也不会把整批非零发送跨度误当成同一时刻；底层 rolling-window governor
仍是最终权威。该调度不改变 38s candidate 子窗口、45s active envelope、packet/tuple/target 预算
或第 513 包的 fail-closed 规则。

```text
preflight -> oob_adopt -> present -> burned -> activated -> handshake -> prepare
  -> sockets -> fresh_evidence -> plan_committed -> ready_fire bilateral barrier
  -> 16K one-shot candidates -> bilateral winner selection
  -> [winner -> verify -> transport_lease -> handoff -> 3-packet data_plane_challenge
      | no winner -> authenticated exhausted acknowledgement]
  -> durable finish -> drain
```

Gate B3 的 `READY_FIRE` 在一个认证 frame 中同时携带原 READY commitment 与 bilateral FIRE
barrier；Gate B2 wire 不变。双方完成完整 16K schedule 后，responder 报告首个认证 candidate
或 absence，initiator 以“本地 observation 优先、否则 responder observation、否则 none”的固定
规则封存唯一选择。selection 只含 role/ordinal/socket-slot/digest，并绑定 Noise AD、joint plan 与
execution envelope；只有被选中的 receiver 可以复用该 tuple 发 1 个 winner。含双向 VERIFY 在内
每方向仍恰好不超过 8 carrier frame。该语义不是 fallback：它不生成新 candidate、不更换 tuple、
不补位、不发起第二轮，全局 winner 总数至多为 1。no-winner 时 responder 使用空出的第 8 个 frame
发送认证 `EXHAUSTED`，initiator 收到后才关闭 carrier；缺失确认仍 fail-closed。candidate exhaustion、50%
loss、evidence drift、OOB EOF/cancel 与 deadline 都是有界 terminal；post-burn failure 打开 campaign
circuit，但普通 exhaustion/cancel/timeout 不触发 machine safety trip。

## 5. Capability 与 architecture boundary

普通 build 没有 Hard-16K 非回环 factory。memory/natsim 只注入无 OS capability 的 fake；真实
UDP 只能由 `linux && natlab` 文件中的密封 factory 构造。factory 在每次 open/send 前复核当前
network namespace，并只允许：

- 仓库固定 TEST-NET topology 的 exact local/peer 地址；
- exact RFC 5780 observer cross-product；
- peer 的编译期 49152–65535 universe；
- wildcard + ephemeral 本地绑定。

loopback、私网、其他 TEST-NET、公网、任意端口、raw `UDPFactory` 和 remote source payload
都不能取得该能力。stdio v1/v2、CLI、runtime、scheduler、legacy、`wink-signal`、WireGuard、
daemon 与其他产品包不能导入/构造 campaign profile、factory、consumer 或 handoff。architecture
test 含 product import、wrong constructor、build tag、call shape 与 selector-count 变异自检。

## 6. Memory 与 natsim 证据

- deterministic full-shape 双侧各生成并发送 16,384 个 candidate，只提交一个 winner，随后完成
  Gate A handoff 与 3/3 challenge，所有 mapping、队列、transport、governor reservation 为零；
- full exhaustion 完成完整 one-shot schedule，写 FINISH、打开 campaign circuit，且不触发 machine
  trip；50% candidate loss 也先完成双方固定的 16,384-packet schedule，再按已认证 observation 做
  唯一 selection：命中则 handoff，未命中则 exhaustion；任一终局都不补位、不重试、不产生第二
  attempt；
- duplicate/reorder/replay、wrong role/generation/context、跨 AD 域重放与第二 winner 均稳定拒绝；
- FIRE 前 evidence drift、candidate 阶段 OOB EOF 与 caller cancel 均令后续 candidate/winner/data
  emission 为零；
- endpoint-dependent port-reuse natsim model 能用相同公网端口区分不同 remote endpoint，EIM
  模型启用该模式会被拒绝；
- required repetition 使用 100 组 fresh artifact ID、PSK、planner key 与 NAT allocation seed，
  每侧仍精确走 16,384-candidate full shape，并在每轮证明零 residue。

## 7. Required Linux namespace 设计

required harness 使用五个 fresh namespace、veth、两个 endpoint 子进程、两个测试专用 APDM TUN
router 与四 socket RFC 5780 responder。地址全部来自 RFC 5737 TEST-NET。endpoint 只能经密封
factory 打开 wildcard-ephemeral UDP socket；OOB 由 caller 预先提供的 Unix socketpair 模拟。

尾部命中用例只在 test router 的 OS mapping open 前注入一个固定 allocation realization：前 16,383
个 ordinal 的两侧 source-port 函数不存在互惠二环，最后一个 ordinal 才把双方 target 交叉用作
source port。它不改变 planner、candidate 顺序、packet 数、endpoint allowlist 或真实 UDP 路径，且
任一指定端口无法绑定即 fail-closed；由此 required job 能证明“最后 ordinal 命中”，而不是把约
63.21% 的概率事件错误写成每轮必然成功。

矩阵包括：完整尾部命中、完整 exhaustion、50% candidate loss、共同 kernel ceiling
降至 1,024 的 conntrack-full、evidence 后注入 ENOBUFS、post-burn child kill/OOB EOF、parent
kill/Pdeathsig，以及 100 次真实 endpoint pre-FIRE cancel + fresh namespace teardown。

Linux 不允许 non-init namespace 独立写入 `nf_conntrack_max`。本 harness 按 ADR §19 使用三重
证据：每个 test NAT router 在开 OS mapping socket 前各自执行 40,000 mapping hard cap；外层
guardian 只在 GitHub-hosted disposable runner 的 init namespace 中把共同 kernel ceiling 暂时降为
40,000；两个 NAT namespace 在 attempt 期间持续采样自己的真实 `nf_conntrack_count`，终局另取快照。
guardian 取得独占锁、保存原值、
逐值验证安装并在 signal/失败/child crash 后精确恢复；不能证明 init namespace、不能安全降低、不能
恢复或原值低于 40,000 时 required job 在 topology/campaign 前失败。该值覆盖每侧最多 16,395 个
已登记 establishment five-tuple 及 kernel witness 余量，但不是可发射 packet budget。完整 schedule
的真实 APDM router 每侧精确打开 16,394 个 mapping；提前命中时则精确为 10 个 evidence mapping
加实际 candidate 数。socket 0 为认证入站 STUN reply 登记的第四个 observer source 不承载出站请求，
因此占一个受控 five-tuple 登记、但不创建 NAT mapping。

每个终局都核对 application/iptables 计数、PPS、socket/target/five-tuple、per-router mapping、两侧
conntrack count、drain latency，并在 owned cleanup 后证明 packet counter 静止、socket/process/
conntrack/governor lock/netns/veth 全部为零。共同 ceiling 不是 per-netns 独立配置，也不是多个
namespace count 的聚合值。内核先递增 `nf_conntrack_count` 再比较 ceiling；单 writer 的
conntrack-full 故障允许采样到被拒分配造成的瞬时 `max+1`，但 terminal 必须 `<= max`，瞬时
`max+2` 仍失败。该计数语义不是额外 mapping/packet 授权；产品代码不获得 sysctl 或 test-router
capability。高负载 topology 删除并通过 namespace/veth 零残留断言、且全部 LIFO cleanup callback
结束后，harness 另留固定 1s 供内核回收已删除 namespace 的 conntrack/RCU 对象；它不重建、
不重试 campaign，也不进入 attempt 时长或发包预算。后续 topology 若仍失败，只输出稳定 setup stage，
以及 `timeout/conflict/resource/busy/permission/other` 之一的稳定错误类；不输出 namespace、设备名、
底层命令文本或原始错误。

100 次 pre-FIRE fresh teardown 在每轮显式删除并证明 namespace/veth 名称零残留后、下一轮创建前
也使用同一固定 1s kernel-release margin，隔离 userspace 已不可见但内核仍在完成的 netdevice/RCU
生命周期。该 margin 不重试失败的 link create、不复用 topology、不发包，也不计入任何 attempt。
每对 veth 的两端由一条 `ip -n <left> link add ... peer ... netns <right>` 操作直接创建到各自 owner
namespace；不会先把临时接口暴露在 init namespace 再执行两次 move，因此 host network manager
与上一轮 RCU teardown 没有可竞争的中间 host-link 状态。这仍是一次 setup，失败时不重试。

ENOBUFS seam 只存在于 `linux && natlab`，在冻结的 13-packet evidence slice 后对首个 candidate
返回 OS `ENOBUFS`；它不改变 endpoint allowlist，并必须触发持久
`resource_exhausted` safety trip。parent helper 的 endpoint child 固定设置 `Pdeathsig=SIGKILL`；
父进程死亡后必须在 2 秒排水窗口内留下零 namespace process/socket。

应用与 OS 的精确 packet 见证以 UDP 系统调用完成为 commit point：完整成功的 write 即使紧接着
发生 context cancel 仍记为已发；调用前取消或实际 write error 仍为零发射。OOB reader 同样先交付
EOF 前已完整解码的认证 frame，再报告由同一 EOF 传播的 terminal；无关的 caller 预取消仍优先且
不消费队列。两条顺序性都由确定性回归测试守住，不改变任何 Gate B3 预算、重试或排水窗口。

Gate B3 no-winner 终局进一步把 active emission 与 terminal drain 拆成同一 caller/absolute deadline
下的 sibling context：carrier EOF 仍立即取消前者并令后续 UDP 为零，后者只允许接收 EOF 前已经
认证的 `EXHAUSTED`，且不能进入任何 socket/packet API。caller cancel、candidate deadline 与整个
active envelope 对两者仍共同生效。

如果下层因上述 carrier cancellation 只返回通用 `context.Canceled`，分类器会恢复
`context.Cause(activeContext)` 中的稳定 transport cause，因此 child death/OOB EOF 始终报告
`oob_stream_closed`。只有非通用、确属 carrier 的 cause 可以覆盖通用 context 错误；本地 caller
cancel 与本地 deadline 继续报告 `attempt_expired`。双端共用同一绝对 deadline 时，先到期的一端
会关闭子流，因此 peer 可以先观察到 `oob_stream_closed`；回归门要求至少一端保留本地 deadline
见证，且两端后续 UDP emission 都必须为零。协议错误也不能使用 terminal queue drain。

## 8. 验证状态

实现证据 head `2d60c514273c6ed35a831afb7eed242f8cb0217c` 的本地 Windows 验证：

- `go vet ./...` 通过；
- `go test ./... -count=1 -timeout=10m` 通过（261.1s）；此前同一实现链的一次全仓运行仅在
  `TestTwoNodesDiscoverEachOther` 命中过一次状态文件/CLI 读取时序失败，随后该用例 focused
  `-count=20` 为 20/20（107.571s），再一次完整全仓运行通过；该首次失败未从证据中删除；
- Gate B/OOB carrier `-race -count=20` 通过；Gate B2/B3 聚焦重复通过；
- required Fresh100 在本地累计 1,000 个 fresh full-shape campaign 通过（386.527s），末次
  EOF 收窄后另跑 200 个通过（76.267s）；
- Linux+natlab tagged vet 与 race-enabled 测试二进制交叉编译、`git diff --check` 通过。

本机没有运行真实 namespace、非回环 socket、route、firewall、observer、daemon、LAN 或公网 I/O。

同一 evidence head 的两份完整 required CI 均成功：
[run 33311821725](https://github.com/houyuwushang/winkyou/actions/runs/33311821725) 与
[run 33311819859](https://github.com/houyuwushang/winkyou/actions/runs/33311819859)。两份
Fresh100 分别为 100/100 exhaustion、每侧 16,384 candidate、零 residue（23,224ms 与
23,663ms）：[job 99258146047](https://github.com/houyuwushang/winkyou/actions/runs/33311821725/job/99258146047)、
[job 99258140362](https://github.com/houyuwushang/winkyou/actions/runs/33311819859/job/99258140362)。

两份 race-enabled Gate B3 kernel job 的实测见证如下：

- conntrack-full：共同 cap 1,024；双方 packet `16,397/16,397`、PPS 512；peak
  `1,024/1,024`；terminal 分别为 `1,024/1,024` 与 `1,023/1,024`；36,244ms / 36,261ms；
- 尾部命中：成功，packet `16,398/16,397`，双方各 16 socket、16,388 target、16,395
  five-tuple；conntrack peak `32,660/32,629` 与 `32,670/32,660`；37,219ms / 37,201ms；
- full exhaustion：失败终局，packet `16,397/16,397`，PPS 512；36,921ms / 36,940ms；
- 50% loss：本次两份均为 exhaustion，packet `16,397/16,397`，PPS 512；37,104ms /
  36,912ms；
- ENOBUFS：注入侧 candidate 0，对端在 terminal cancel 前分别发 19/14 个 candidate；持久
  resource trip 为 true，residue 0；
- child kill：`post_burn=true`、peer class `oob_stream_closed`、terminal 后 packet counter
  稳定、residue 0；parent kill：`Pdeathsig=true`、pre-burn、socket/process/residue 0；
- pre-FIRE fresh namespace：两份均为 100/100、residue 0（235,272ms / 235,485ms）。

完整日志：
[job 99258146064](https://github.com/houyuwushang/winkyou/actions/runs/33311821725/job/99258146064) 与
[job 99258140551](https://github.com/houyuwushang/winkyou/actions/runs/33311819859/job/99258140551)。
日志中的 `conntrack_terminal` 是 owned flush 前快照；job 随后仍逐 namespace flush 并断言
conntrack/socket/process/governor lock/netns/veth 全部零残留。Docker smoke 与两份 advisory
NAT lab 也在该 head 成功。独立复审同时接受 ADR §20 的六项实现期协议闭合；PR #96 随后以
merge commit `39ff9780ec295ca8af7339bca8f5e023adf17931` 合入。以上只闭合隔离实现证据，不授权
Gate C、产品接线、disposable router 或任何现场 I/O。

## 9. Issue #100 终局分类复核（Draft，2026-08-31）

PR #99 首个 push-event required Gate B3 job 的 50% candidate-loss 子场景在 44,670ms 得到
initiator=`oob_stream_closed`、responder=`hard_nat_candidate_exhausted`；双方仍 fail-closed，
没有资源或残留风险。原始证据保留于
[job 99363628221](https://github.com/houyuwushang/winkyou/actions/runs/33350795006/job/99363628221)。
同 SHA 并行 job 与 rerun 通过不能消除该结果。

本轮在 `main` 基线 `16ab491a55207abb4e4f6f2a01dfe4a1e934fe5c` 上将等价 50% loss natsim
完整用例重复 100 次，结果 100/100 通过（146.011s），每次均保持完整 16K schedule 与双侧
exhaustion。该 natsim 使用同步 `net.Pipe`，所以只排除了确定性协议状态错误，不能排除真实 OS
buffered stream 在最终控制帧与 EOF 之间的排序差异。

初版 ADR §22 因而先冻结两个有方向的 no-winner 终局元组，并在 required netns 中逐字段守住
完整 schedule、零 winner、精确 frame shape、durable FINISH、campaign circuit、无 safety trip、
排水与零残留。该门在 PR #103 首个 head 的一份 required job 中再次拒绝同样的公开 class 对；
仅有 class 的旧日志不足以说明是哪项见证不同，因此下一 head 增加了不含 endpoint、PID、路径或
机器信息的稳定 rejection class 与双端计数。

聚焦重跑随后在
[job 99543139669](https://github.com/houyuwushang/winkyou/actions/runs/33405265180/job/99543139669)
再次命中（43.15s），并证明它不是 no-winner/EOF 元组：

- initiator：`stage=verify`、winner=1、UDP=16,398、carrier read/write=`7/8`、
  `oob_stream_closed`；
- responder：`stage=candidates`、winner=0、UDP=16,397、carrier read/write=`8/7`、
  `hard_nat_candidate_exhausted`；
- 双方 evidence=13、candidate=16,384、credential burn、durable FINISH、campaign circuit、
  drain 与零 residue 均完整；无 safety trip 与 data-plane packet。

因此 required gate 的拒绝是正确的：允许集合仍要求 winner=0，且新增 mutation 把上述
winner/VERIFY 分裂逐字段固化为负向用例。根因是 selection、唯一 winner 与 winner 接收错误继承
了 38 秒 candidate context；高负载下 async reader 已读入后续控制帧，主状态机却先按 candidate
deadline 返回 exhaustion。修复只在完整 16K schedule 与 rolling-PPS clearance 后切换 context
ownership：停止并排空 candidate readers、冻结 proposal，再在原 45 秒 active envelope 的剩余
时间内完成 role-ordered selection、最多一个 winner 与 VERIFY。wire、预算、packet/PPS、target、
tuple、socket、ledger、active lifetime、drain、retry/fallback 与 attempt 数均不变。

确定性 natsim 回归把 responder 第 7 帧延迟到 candidate window 之后但 active deadline 之前，要求
双方仍互认唯一 winner 并完成 VERIFY；真实 required netns 继续负责 OS packet、conntrack 与零残留
证明。本地修复验证包括：terminal contract 普通 100 次与 race 20 次；delayed-selection 与原 50%
loss 组合 race 20/20；Gate B3 受影响矩阵重复通过；`gateb`/`hardnatcontrol` 各 20 次；全仓 vet、
architecture gate 20 次、Linux+natlab tagged vet 与测试二进制交叉编译通过。首次全仓测试只命中
既有 Issue #97 的 legacy relay-wggo 启动停滞；该原样用例随后 5/5 通过（56.315s），完全不改源码
的全仓复跑通过（291.8s）。首轮失败未从证据中删除，也未混入本 PR 修复。

修复 head `6dd57acea133a760df19def75fb36b978b2c1a29` 的两个独立触发 required job 中，一份完整
通过（398.49s，50% loss 子场景 38.50s）；另一份没有再命中 winner/VERIFY 分裂，却暴露了
test-only 用户态 NAT witness 的背压缺口：endpoint 已报告完整 16,384 candidate，但 1,024 深度的
TUN 队列在较慢 runner 上只处理了 `14,057/13,854` 个 outbound，mapping snapshot 因而提前失败；
随后 child-kill 的 15 秒 post-burn 观察窗又被子进程慢启动消耗。原始失败保留于
[job 99565379987](https://github.com/houyuwushang/winkyou/actions/runs/33415604752/job/99565379987)，
成功对照保留于
[job 99565390415](https://github.com/houyuwushang/winkyou/actions/runs/33415608089/job/99565390415)。

该次失败不以 rerun 删除，也不通过降低 mapping、packet 或 terminal 断言处置。后续 head 仅修正
Linux+natlab harness：Gate B3 NAT router 的有界队列从通用默认 1,024 提升为已冻结的单端最大
16,432 packets；endpoint 终局后最多等待 10 秒，让用户态 router 完成已经由 endpoint socket 接受的
packet，再取得原样的精确 mapping/conntrack witness；超过上限或多处理一个 packet 仍立即失败。
child-kill 则先取得双端 ready witness，再开始原 15 秒 post-burn 阶段窗口。它们不延长 45 秒 attempt、
不新增 emission/retry/fallback，也不改变 2 秒产品 drain；下一 head 的原始 CI 结果仍须独立通过。

本节等待独立复审，合入前 Issue #100 与 C1b 冻结仍保持打开。

## 10. #106 映射寿命反例（2026-09-06，未闭合）

上节为 #103 实现期历史记录；#103 已独立复审合入，#100 已关闭。本节是新的证据，
不撤销历史记录、不自动重开 #100，也不宣布本次修复完成。

[诊断 Draft PR #107](https://github.com/houyuwushang/winkyou/pull/107)，head
`1da0bccd3047845991c1ce48cc08a90c6c991c1a`，在与本 docs-only 提案独立的分支上增加
early one-way hit 和只读 kernel flow 见证；未修改生产协议/预算。两份 required job 均为 RED：

- [PR-trigger job](https://github.com/houyuwushang/winkyou/actions/runs/33988801311/job/101367177233)：
  early-hit 子测试 48.40s。两侧普通 UDP idle=30s；双方 candidate=16,384、evidence=13，
  responder 发出全局唯一 winner 时 mapping 年龄 32,286ms、peer reverse flow=0、peer winner
  入站=0。UDP=16,397/16,398、carrier 两侧 7/7、data=0；I 为 `attempt_expired/candidates`，
  R 为 `oob_stream_closed/verify`。burn/FINISH/circuit=true、machine trip=false；原样全量
  packet/ledger/零 residue 检查在成功断言拒绝之前完成。
- [独立 push job](https://github.com/houyuwushang/winkyou/actions/runs/33988778671/job/101367119243)：
  新用例先失败于 router outbound `16,381 != 16,397`，原因未确认，未到全量 residue 检查。
  不能将其算作第二次寿命反例或零残留证明；不得放宽精确计数。

该诊断 head 最终 CI 31/33；没有 rerun。原 #105 的失败未采集 reverse-flow-before-winner，
所以不能追溯认定与这个已复现机制完全同源。完整原始见证见
[#106 报告](https://github.com/houyuwushang/winkyou/issues/106#issuecomment-5554497891)。

[映射寿命与提前确认 ADR](./adr/ADR-N3C-HARD16-MAPPING-LIFETIME.md) 已按 D1–D6 接受：分别裁决稳定
模型/失效层（M，接受）与提前确认协议（E，仅研究方向）。60s/30s 新 fixture、失效验收和 early-stop 均未
实现或获实现授权；不得把文档合入、本地测试通过或其他 CI 绿灯视为关闭 #106、接受 #107 或开启 C1c/现场。

## 11. #107 M 实现与首跑记录（2026-09-07，Draft）

维护者本轮授权执行 [M ADR](./adr/ADR-N3C-HARD16-MAPPING-LIFETIME.md) D1–D6；接续原 #107，
不删除 §9–§10 的历史 RED，不修改生产协议、候选调度、预算、终局 class、WireGuard 或产品入口。
以下把已实测的 harness 修复与尚待首次 OS 验证的寿命矩阵分开。

### 11.1 入队缺口：先定位、独立修复，再建立 M fixture

`39acfcfe7f17adac90cb82e2b654520fc860996b` 将同步 winner 前 `conntrack -L` 移出转发路径，
同时增加 TUN read、parser reject、各 socket-slot/final-ordinal、candidate forwarded 与 kernel
`tx_dropped` 见证；原 10s 等待、精确相等和 16,398 单端上限均不变。
[独立 push 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34092452794/job/101648643126)
仍失败，但第一次把新缺口定位到用户态 reader 之前：

| 项目 | 实测 |
| --- | --- |
| endpoint 已发 / router outbound | 16,397 / 16,216，缺 181 |
| TUN 已读 / parser reject | 16,219 / 3 |
| candidate read / forwarded | 16,203 / 16,203，进入转发器的 candidate 全部发出 |
| kernel TUN `tx_dropped` | 182，计数读取成功 |
| router 状态 | 仍运行；不是 winner 同步观察阻塞后停机 |

这证明现有 harness 未约束内核 TUN ring，单独扩大 Go channel 不能回收已经丢在内核的包。
不能追溯断言旧 `1da0bcc` 缺失的 16 个包对应哪一个 slot/ordinal：旧日志没有这些见证。
本轮按“独立证明并修复既有 harness 缺口”闭合前置，不把不同数量的缺口冒充同一次复现。

修复只给新建的 IPv4-only test TUN 设置 `txqueuelen=16,398`，与既有单端最大值一致；
禁止自动 IPv6 地址生成/组播仅作用于该新 test interface，不修改 host sysctl。
暂停读取、一次发出 48 个合成 UDP 包的隔离对照先命中自动控制报文污染，首跑失败保留于
[`bc0f80d` job](https://github.com/houyuwushang/winkyou/actions/runs/34094066006/job/101653604996)。
`6bc3c551adccb888810c19eadbea1150eeba686f` 修正 test interface 配置后，
[原始 PR-trigger job](https://github.com/houyuwushang/winkyou/actions/runs/34095992952/job/101659672843)
给出：

| TUN ring capacity | 发出 | 收到 | kernel drop | 独立清理 |
| --- | --- | --- | --- | --- |
| 32 | 48 | 32 | 16 | socket/process/conntrack/netns/veth 零残留 |
| 16,398 | 48 | 48 | 0 | socket/process/conntrack/netns/veth 零残留 |

同 job 的 default-30s tail hit 与 50% loss 成功，UDP 均为 16,398/16,397；full exhaustion
为 16,397/16,397；精确 router/packet/ledger 和清理均通过。旧 early-hit success 断言仍 RED：
完整 16K、UDP 16,397/16,398、两侧 carrier 7/7 与 793/793 byte；R winner age 32,193ms，
异步 **发送后** reverse flow=0，I/R 均 `attempt_expired`，stage 为 candidates/verify，
burn/FINISH/circuit=true、trip=false、data=0，清理已完成。该 job 446.62s、仅旧反例失败。
异步发送后快照不是 M-E 所要求的“发送前曾存在且消失”证明。

### 11.2 M fixture、观察语义与隔离纪律

新增 `TestLinuxGateB3MappingLifetimeProof`；每个场景使用 fresh TEST-NET topology、双真实
endpoint 进程、原 governor/ledger 与原完整 schedule。尚未以 M 的结果宣称支持真实 NAT。

- M-S：mapping/filter idle 与两档 kernel UDP timeout 均为 60s；early hit 两方向、tail hit、
  full exhaustion、50% candidate-only loss。普通 loss predicate 及其负向 mutation 原样保留。
- M-E：全部 30s，两个 winner 方向单独命名；先固化 ADR §4.4 的负向向量，再执行 OS 证明。
  必须同时有每端完整 16K、全局一个 winner、对端零 winner 入站、缓存的 kernel flow
  PRESENT→GONE→winner 顺序、未刷新命中 tuple、至少一侧真实 deadline cause、精确帧/包/byte、
  FINISH 与清理。若实际 role/frame 形状不同，测试失败并停止后续 M-X，不修改 ADR 表。
- M-X 本轮实现最小两个点：最后一个 candidate 发出后、selection 之前；唯一 winner 系统调用
  之前。在一个 NAT 上一次性切换 inbound filter policy，直到终局不恢复；kernel flow 应仍在，
  所以不冒充 TTL 失效。仍要求完整 schedule、唯一未交付 winner、原有界失败与 data=0。
- 为获得两种单向 early hit，test NAT 仅排序首个 reciprocal tuple 的创建/出站：未来 winner
  先发，另一侧尚未开启 reverse filter；不使用 candidate-aware drop 注入。该初始排序共用
  原 2s mapping-plan barrier，不改变任何 endpoint candidate/port/slot/order/pacing。
- 用户态寿命以注入的单调 duration 表达；mapping/filter 独立到期，入站不刷新。过期后的下一次
  已授权出站创建新逻辑 generation，不复活旧状态；test socket 仅是 emulator 的 carrier，
  其仍打开不等于旧 mapping/filter 仍有效。原 tuple、发射次数与 governor 计费不变。
- 每侧一个独立 worker 每 250ms 读取已观测命中 tuple 的 reverse flow（最多 16,384 key，
  单次命令 1s 上限、关闭 2s 上限）；转发器只取已完成缓存，不执行 `conntrack` 或等待观察。
  winner 前缓存缺失/过旧即失败，不能用发送后的读数补齐。精确 tuple 和原始 conntrack 文本不日志化。
- caller stream 的独立、每方向 8,256-byte 有界 recorder 比较双端每帧长度/密文摘要与 carrier
  计费，日志只报布尔结果。它不读取 PSK、不解密 selection；双边认证依赖原协议对第七帧和
  joint/execution AD 的验证，不能把被动摘要匹配称为独立密码学重算。
- 两个 NAT timeout 原值全部保存后才写；绑定新 namespace inode 与固定 topology，拒绝 init。
  设置后逐值回读，并对 init 与新建旁侧控制 namespace 作前后只读对照。结束先恢复/回读，再
  删除 named handle 和验证消失；子进程 kill 路径复用原 post-burn crash/ledger/OS 清理门。
  整个 runner 消失仍由 disposable VM 回收；不将 Go cleanup 说成能在进程自身 SIGKILL 后执行。

旧 `early_one_way_hit_winner_delivery` 按 D6 移为显式历史负向入口，原 success 断言保留；
required 主集合的 default-30s tail、full exhaustion、50% loss、cap、kill、fresh100 不改。
新增独立 required M job（job 12min、测试 10min），旧 Hard16 job 的 10min ceiling 不动。
M job 仍经现有 `nf_conntrack_max` guardian/REQUIRED/sudo/race；timeout 隔离失败不能 skip。

### 11.3 首次运行前的验收清单（当时快照；结果见 §11.4–§11.5）

| 项目 | 当前状态 |
| --- | --- |
| kernel TUN 独立缺口/修复 | 已实测，见 §11.1；不追溯猜测旧缺 16 包的位置 |
| Windows→Linux natlab vet / 编译 | 通过（`GOOS=linux GOARCH=amd64 CGO_ENABLED=0`）；不是 Linux OS 运行 |
| M-S 五场景、M-E 双方向、M-X 两点 | 已实现，待首次 required OS 运行，尚不填成功数字 |
| model 30s 前/等于/后、独立 expiry/refresh/新 generation | 纯函数测试已写，required M job race×20 |
| namespace 正常/子进程 crash 恢复与隔离 | 已写强断言，尚待 required OS 见证 |
| 其余 M-X 点、容量驱逐、VERIFY 边界 | 未做，后续独立测试工作，不声称 §7 全部闭合 |
| M-E 每种 local deadline/EOF 先到排列 | 不人为改变时限；按首跑真实结果逐项报告，未出现的排列不算覆盖 |
| natsim fresh100 / ledger restart1000 / 原 architecture gates | 保留原 required job；未给这些旧结果贴上新增寿命模型覆盖标签 |
| E2 状态机/时间/概率/wire | 未做、未获实现授权 |

实现仍在 Draft #107；首跑失败必须保留。M 不提高生产成功率，不开启 E、C1c、现场 I/O，
#106 只在独立复审通过并合并后关闭。后续表须分别列出首跑失败、修正后的新 head 与仍未闭合项。

### 11.4 M 首跑 RED（`c0243c53552a747dd835805bfd220cf86a295d08`）

[PR-trigger M job](https://github.com/houyuwushang/winkyou/actions/runs/34101188957/job/101675781841)
与 [独立 push M job](https://github.com/houyuwushang/winkyou/actions/runs/34101185307/job/101675769586)
均保留为首次失败（241.98s / 243.32s），没有 rerun：

| 场景 | 实测结果 |
| --- | --- |
| pure model / expiry 负向 predicate | 通过；普通 loss 未接纳 expiry 元组 |
| namespace + child crash | 两份均通过；60/60 安装、init/control 不变、恢复回读、handle/residue=0 |
| M-S early initiator | 两份通过；UDP 16,398/16,397；8/8 frame、873/873 byte；winner age 32,142/32,158ms；reverse flow 发送前在，未刷新命中 tuple |
| M-S early responder | 失败：实际仍为 I winner；不是预期方向的成功证明 |
| M-S tail | 两份通过；UDP 16,398/16,397，8/8 frame，winner age 961/994ms |
| M-S full exhaustion | 两份通过；UDP 16,397/16,397；I 8/7 frame、802/754 byte，R 7/8、754/802；双 `hard_nat_candidate_exhausted` |
| M-S 50% candidate-only loss | PR-trigger 成功（唯一 I winner）；push 无命中（双 exhaustion），均通过原严格 predicate 与零残留 |
| M-E responder | 失败：实际 I winner；PR-trigger 另有 observer error，不能把它记为 flow 消失；未取得完整 M-E 因果/残留证明 |
| M-E initiator / M-X | 未运行：M-E 首个失败后停止，不能报通过 |

首包方向 fixture 的原因已确认：既有 N2d topology 在 WAN 链路配置传播延迟，原 fixture
在首个 send 返回时即放开另一侧 mapping；send 返回不是对端收到/过滤完成，因此实际两个方向
都收到 candidate。后续修正不加 sleep：在原 default-deny 路径增加等价 verdict 的计数分支，
独立 worker 见证首个 peer opener 已被原策略拒绝，才释放原 2s mapping-plan barrier。
没有附加 candidate drop、端点调度变化、重传或延期。

flow observer 的首跑错误没有足够诊断，暂不作根因归因；后续改为 exact-tuple `conntrack -G`，
避免 dump 整张动态表，且增加脱敏的退出码/deadline 分类。只有工具明确的 conntrack ENOENT
诊断可记为 GONE；任意失败、半结果或未知输出仍拒绝，不能以错误代替失效证明。
后续新 head 的结果独立记录，不覆盖本节。

### 11.5 修正后首次完整验收（`d4cd90a8bd6fb9c9c80b19bb3c80bddac2de1907`）

该代码 head 的两个独立触发 CI 均首跑通过，汇总 **35/35 SUCCESS，0 pending**：
[PR-trigger CI](https://github.com/houyuwushang/winkyou/actions/runs/34103701622)、
[push CI](https://github.com/houyuwushang/winkyou/actions/runs/34103698667)。没有 rerun、merge 或
close。本段是随后的文档回填，不拿新 head 通过覆盖 `c0243c5` 的首跑失败。

M job 原始证据：[PR job](https://github.com/houyuwushang/winkyou/actions/runs/34103701622/job/101683768572)
391.26s、[push job](https://github.com/houyuwushang/winkyou/actions/runs/34103698667/job/101683759465)
396.08s。每份 5 个 M-S + 2 个 M-E + 2 个 M-X 全过，即 **18/18 完整 OS campaign**；另有两份
post-burn child crash/namespace 恢复证明与两类纯函数 contract。以下 read/write 均按本端口径，
不是把两端计数相加；表中 TTL 两档与用户态 mapping/filter 相同。

| fixture / TTL | I/R terminal 与 stage | UDP I/R | frame read/write：I；R | byte read/write：I；R |
| --- | --- | --- | --- | --- |
| M-S early I / 60s | 双 success | 16,398 / 16,397 | 8/8；8/8 | 834/873；873/834 |
| M-S early R / 60s | 双 success | 16,397 / 16,398 | 8/8；8/8 | 873/873；873/873 |
| M-S tail / 60s | 双 success | 16,398 / 16,397 | 8/8；8/8 | 873/873；873/873 |
| M-S full exhaustion / 60s | 双 `hard_nat_candidate_exhausted/candidates` | 16,397 / 16,397 | 8/7；7/8 | 802/754；754/802 |
| M-S 50% / 60s，PR-trigger | 双 `hard_nat_candidate_exhausted/candidates` | 16,397 / 16,397 | 8/7；7/8 | 802/754；754/802 |
| M-S 50% / 60s，push | 双 success（I winner） | 16,398 / 16,397 | 8/8；8/8 | 834/873；873/834 |
| M-E R winner / 30s | I `attempt_expired/candidates`；R `attempt_expired/verify`（PR）或 `oob_stream_closed/verify`（push） | 16,397 / 16,398 | 7/7；7/7 | 793/793；793/793 |
| M-E I winner / 30s | I `oob_stream_closed/verify`、R `attempt_expired/candidates`（PR）；I `attempt_expired/verify`、R `oob_stream_closed/candidates`（push） | 16,398 / 16,397 | 7/8；8/7 | 754/873；873/754 |
| M-X before selection / 60s | I `attempt_expired/candidates`；R `oob_stream_closed/verify` | 16,397 / 16,398 | 7/7；7/7 | 793/793；793/793 |
| M-X before winner / 60s | I `attempt_expired/candidates`；R `oob_stream_closed/verify` | 16,397 / 16,398 | 7/7；7/7 | 793/793；793/793 |

共同见证：每端 evidence=13、candidate=16,384、socket=16、target=16,388、five-tuple=16,395，
reservation=16,432；UDP 仅为 16,397 + 本地 winner 数。成功路径 synthetic data 为每方向 3，
所有 M-E/M-X/full-exhaustion 失败 data=0、burn/FINISH/circuit=true、trip=false；逐项原 governor
shape、真实 packet counters、独立 wire byte/digest、carrier drain 与永久 admission 均通过。

寿命/注入因果链（PR / push）：

- M-S early I winner age **32,171 / 32,154ms**，early R **32,183 / 32,195ms**；发送前 reverse
  flow 在、未曾消失。tail 为 **958 / 902ms**。命中 tuple 在 winner 前都仅有一次出站，没有保活刷新。
- M-E R winner age **32,206 / 32,175ms**，I winner **32,198 / 32,171ms**；四次均见证
  PRESENT→GONE→winner，缓存负面样本在 winner 前取得，winner out=1、peer in=0、额外故障注入=0。
  initiator-winner 的此前未实测 7/8、8/7 表得到首次有效 OS 负向验证，没有修改冻结数字。
  三种允许 class pair 本轮均实际出现；I-winner 同时覆盖了本地 deadline 与 peer EOF 两种先到结果。
- M-X 两个点均恰好一次单侧 filter change；发送前 reverse kernel flow 仍在、没有 TTL 消失，
  winner out=1/peer in=0。故障没有被假装成 M-E，也没有第二 winner、换 tuple、retry/fallback 或假成功。
- 每个场景均记录 kernel 60/60 或 30/30 安装、两个 owned non-init namespace、init/control 前后值
  不变、恢复回读成功、named handle 消失；socket/process/conntrack/governor lock/netns/veth residue=0。
  post-burn 子进程 crash 的同套恢复/清理也通过。整个 harness 自身 SIGKILL 的恢复不新增保证；
  仍受既有 disposable-runner guardian 与 VM 回收边界约束，不伪称 Go cleanup 会在 SIGKILL 后运行。

本地 Linux 交叉 vet/编译、architecture/mutation（8.381s）、`git diff --check` 均通过；
Linux required M job 另执行纯函数/expiry predicate `-race -count=20`。原 Hard16 job（含 default-30s
tail 与普通 50% loss）、fresh natsim100、campaign restart1000、其余全仓/required gates 均通过。
这是本批获授权的最小 M 证明，不是 §7 所有未来工作闭合：容量驱逐、其余 M-X/VERIFY 边界、
更多重复寿命分布与 E2 仍未做。PR 保持 Draft 等独立复审，不自行合并、不关闭 #106、不推进现场。

### 11.6 50% loss 场景的模型归属（2026-09-08，复审收尾）

按 [#107 独立复审](https://github.com/houyuwushang/winkyou/pull/107#issuecomment-5568851125)
及维护者续令，本次仅从 `TestLinuxGateB3Hard16Proof` 移除
`fifty_percent_candidate_loss`；其它子测试、原 CI job 时限和全部断言保持原样。

默认 30s 模型下，随机 candidate-only 丢包把**成功、双 exhaustion、early-hit 失效**三种
已知路径混在一个随机结果中；普通 loss gate 必须拒绝 winner-positive/timeout 元组，
不能把它放宽成“有界结束即通过”。迁移依据保留为
[#105 首跑 RED](https://github.com/houyuwushang/winkyou/actions/runs/33987292922/job/101363121187)
与 [#107 首跑 RED](https://github.com/houyuwushang/winkyou/actions/runs/33988801311/job/101367177233)：
后者证明了 early-hit reverse flow 在 winner 前消失的机制；前者缺少相同 kernel 见证，
仍不追溯认定其唯一根因。§10、§11.4 及 `TestLinuxGateB3HistoricalEarlyHitCounterexample` 全部保留。

因此默认 30s job 不再把随机 50% loss 作为 required 断言。成功与无命中由已有
`M_S_fifty_percent_candidate_loss`（60s）继续严格验收，`testGateB3FullShapeLifetime` 的
失败分支仍调用原 `validGateB3FiftyPercentLossTerminal`；只允许严格成功或
Gate B §22 原两个 no-winner 元组。失效由 M-E（30s）按已有独立因果与精确终局见证确定性证明，
`validGateB3ExpiryPair` 不并入普通 loss 谓词，M-S/M-E/M-X 实现均不改。

默认 30s 的 `full_shape_tail_hit`、`full_exhaustion`（`dropEvery=1`）与
`loss_terminal_contract`（含 #106 元组负向变异），以及 cap、kill、fresh100 等其它入口原样保留。
这里调整的是测试场景归属，不延长产品窗口、不改变生产能力；E 仍为研究方向，不因此推进。

本次本地 Linux 交叉 vet/编译、host contract×3（0.530s）、architecture（13.429s）均通过；
不是本地 netns 运行证明。新 head 的首次 CI 结果记录于
[PR #107 描述](https://github.com/houyuwushang/winkyou/pull/107)。旧 Hard16 与 M
required job 都须通过；不 rerun 求绿，失败保留。PR 继续 Draft，等待复审合并后才关闭 #106。
