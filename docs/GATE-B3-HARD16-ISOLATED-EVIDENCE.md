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
