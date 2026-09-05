# ADR 草案：Hard16 映射寿命与提前确认

- 状态：**Draft / 待维护者与独立评审裁决；仅获准起草 docs-only 提案。**
- 日期：2026-09-06
- 文档基线：`main = f2df7456a553ee731fa8801114985413ebb49540`
- 跟踪：[#106](https://github.com/houyuwushang/winkyou/issues/106)；诊断
  [Draft PR #107](https://github.com/houyuwushang/winkyou/pull/107)，head
  `1da0bccd3047845991c1ce48cc08a90c6c991c1a`，尚未合并。
- 上位约束：[Gate B ADR](./ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md) §18/§20/§22、
  [Gate A ownership/handoff](./ADR-N3C-OOB-DIRECT-HANDOFF.md)、
  [restart safety](../PAIRING-RESTART-SAFETY-CONTRACT.md)、
  [cancellation/drain](../CANCELLATION-DRAIN-CONTRACT.md)。

本文所有新增规则、数值、测试层和协议方向均为**建议**，不覆盖现行 Accepted 规则。
准许写提案不等于接受提案，也不授权实现、修改测试期望、设置 netns 参数或现场 I/O。
本 PR 不改变任何代码、测试、配置、工作流、golden、artifact 或 parser。

## 1. 要解决的问题与推荐顺序

目标仍是单个用户在不可配置 NAT 后的自有设备之间取得可用直连，保留 WireGuard 数据面。
这里处理的是**已命中的候选能否存活到验证和移交**，不是端口转发、FRP 功能扩张或数据面替换。
可观察成功必须仍包含双向 VERIFY、lease-bound handoff、challenge、durable FINISH 和完整排水。

建议分两个独立裁决推进，不能把第一步包装成第二步已完成：

1. **M：明确映射寿命模型和失效验收。** 保留现行完整 schedule 协议，建立受控的稳定映射成功层，
   并永久保留短寿命失效负面层。它纠正证据和测试条件，不提高真实 NAT 穿透成功率。
2. **E：研究提前确认命中。** 若希望利用原协议确认前就会失效的早期命中，必须重新冻结停止发送、
   双方唯一选择、wire/AD 和接收所有权；现阶段只提出约束与比较，不提供可开工的协议批准。

建议先裁决 M，同时保留 E 为必须解决的求解能力问题。M 的测试通过不代表 E 完成，
也不代表“困难 NAT 已全部支持”。两者都不授权保活、重发、补位、自动恢复或下一次 attempt。

## 2. 已有证据：证明了什么，尚未证明什么

原 #105 的 required job 失败于 50% candidate loss；没有 winner 发送前的 kernel flow 见证，
不能追溯断言其唯一根因就是映射超时。#107 新增受控 early-hit 用例后得到以下结果：

| 见证 | initiator | responder |
| --- | --- | --- |
| kernel 普通 UDP idle timeout（只读） | 30s | 30s |
| router candidate 入站（注入丢包前） | 1 | 1 |
| evidence / candidate / winner packets | 13 / 16,384 / 0 | 13 / 16,384 / 1 |
| establishment UDP / data packets | 16,397 / 0 | 16,398 / 0 |
| winner router outbound / inbound | 0 / 0 | 1 / 0 |
| winner 发送时用户态 mapping 年龄 | — | 32,286ms |
| 发送前对端对应 reverse kernel flow | — | 0 |
| terminal / stage | `attempt_expired` / `candidates` | `oob_stream_closed` / `verify` |
| carrier frame read / write | 7 / 7 | 7 / 7 |

双方 burn、FINISH、campaign circuit 均为 true，machine trip 为 false。
该次 48.40s 子测试在终局拒绝前完成了原样 packet/ledger 和 socket/process/conntrack/
governor lock/netns/veth 零残留检查。48.40s 是含 harness 的子测试耗时，不是新 active envelope。
证据：[PR-trigger job](https://github.com/houyuwushang/winkyou/actions/runs/33988801311/job/101367177233)。

这个反例说明：用户态 mapping/socket 尚在，不等于内核允许返回报文的状态仍在；一次 candidate
命中不是后来 winner/VERIFY 一定可达的证明。它是有界失败，不是持续发包或资源风暴。

同 head 的[独立 push job](https://github.com/houyuwushang/winkyou/actions/runs/33988778671/job/101367119243)
在新增用例先失败于 router outbound `16,381 != 16,397`，原因未确认，未取得完整残留证明。
它不能算第二次寿命缺口复现，更不能通过增加等待/队列或放宽相等断言忽略。该 job 的原 50% loss
反而成功：winner mapping 年龄 32,171ms，但 peer kernel flow 为 1；**mapping 年龄不能代替
kernel flow 的实际剩余寿命或刷新历史**。

完整原始链接、双端见证与区别见 [#106 诊断报告](https://github.com/houyuwushang/winkyou/issues/106#issuecomment-5554497891)。
#107 当前 CI 31/33；本提案不移除它的 RED 用例、不修改允许终局，也不把历史失败标为已解决。

## 3. 现行协议的时间约束

Gate B §20 要求完整发完每端 16,384 candidates、清空最后的 rolling-PPS 窗口，才执行
role-ordered selection 和最多一个 winner；§22 仅修正 candidate/active context 归属，
没有取消完整 schedule 前置条件。

```text
16,384 / 512 = 32 个 lane 窗口
第一个窗口可在 t=0 开始；第 32 个最早在 t≈31s 开始
最后 candidate 后仍需一个完整 PPS interval + clearance
因此最早 winner 距首个 candidate 约 32s，实际还包含 I/O、调度和 OOB 延迟
```

推导依据是当前 executor 的逐 packet-lane pacing 和最后一次 clearance，不能把
`16,384 / 512` 当成所有实现都适用的精确墙钟时长。38s candidate 子窗口和 45s active
envelope 是上界；它们不证明某个早期 tuple 能活到上界。

Linux [conntrack 文档](https://docs.kernel.org/networking/nf_conntrack-sysctl.html) 区分普通 UDP
30s 默认值和 stream 的更长超时；[UDP 实现](https://github.com/torvalds/linux/blob/master/net/netfilter/nf_conntrack_proto_udp.c)
还依赖已见回复、时间与状态，不是出现一个双向报文就无条件获得长期存活。资料核对日期
2026-09-06；具体 runner 的值以实测为准，不能外推成所有 NAT 的默认值或最低保证。

同时区分两种 freshness：

- **FIRE 前证据 freshness**：现有五秒、来源绑定、双方独立重算及 joint commitment，全部保留。
- **FIRE 后候选路径有效期**：映射/过滤可能过期或被驱逐。五秒证据通过不授予它 45 秒寿命。

未来概率说明也必须写清：B1 的完整集合碰撞概率是条件模型输出，不自动等于具有丢包、过滤、
超时和端点移动时的 verified-handoff 成功率。提前停止后的实际 prefix 不得套用完整 16K
成功概率；没有时间模型证明就报告未估计，而不是用候选数比例乘出一个概率。

## 4. 建议 M：显式模型，不隐式改变产品

### 4.1 寿命模型和信任边界

测试记录分别包含 mapping idle、filter idle、kernel unreplied/replied timeout、刷新事件、
容量驱逐/行为变化模式与时间来源；不能只给 NAT 贴一个 EIM/APDM 标签。

- natsim 使用可注入单调时钟，分开表达 mapping、filter 和两方向状态；不用测试耗时充当时间模型。
- 测试 router 的用户态映射和 kernel flow 独立计数，需有曾存在、刷新/静默、消失与 winner 交付的见证。
- 记录发射/观测阶段、单调时间差、packet 和 flow 计数；精确 tuple 仅留在隔离进程内匹配，
  不输出地址、hostname、用户名、本机路径、命令行、密钥或原始 conntrack 文本。
- 真实 executor 无权读取远端路由器的内核状态。远端自报 TTL、内存模型配置和 observer 的另一
  个 mapping 均不能作为当前 direct tuple 的可信剩余寿命；未知就是未知。
- 本裁决不建议新增一个无法证实的公共 `mapping_expired` 错误类。实际 timeout/EOF 仍诚实保留，
  寿命故障归因只在具有受控 fault 和独立见证的 harness 中成立。

### 4.2 建议测试层

以下数值是本草案请求裁决的 fixture 值，不是编译期实现常量或用户配置：

| 层 | mapping/filter idle；kernel unreplied/replied | 场景与验收目标 |
| --- | --- | --- |
| M-S 稳定层 | 全部 60s；无主动驱逐 | 60s > 47s 资源生命周期；保留 early/tail hit、完整 exhaustion、50% candidate-only loss，成功/无命中仍按原协议严格验收 |
| M-E 失效层 | 全部 30s；禁止隐式延寿 | 首个 reciprocal tuple 命中后不再刷新该 tuple；确认前见证其消失，唯一 winner 未交付，必须有界失败 |
| M-X 注入层 | 独立受控驱逐/单侧变化 | 在 selection、winner、VERIFY 边界驱逐或改变状态；禁止换 tuple、第二 winner、重试或伪造成功 |

60s 只是覆盖现有 attempt/排水期的隔离模型选择，不是要求用户配置路由器，也不代表确认了
真实网络的寿命下界。M-E 把 replied 也设为 30s 是为了固定反例，必须区别于 #107 首次只读普通
30s 的历史证据；没有执行过的配置不能写成实测。

### 4.3 未来 isolated harness 的设置权限建议

仅在 M 被接受并另行授权实现后，才允许在 **fresh、已证明 owned、非 init 的 NAT namespace**
中设置上述两个 UDP timeout；namespace、TEST-NET topology 和既有 required guardian 都须验证。
设置前保存原值，设置后逐值回读，完成后恢复/回读并删除 owned namespace；进程崩溃也须由
harness cleanup 完成。namespace 已删除时必须证明其身份/句柄消失，不能以跳过回读当作恢复成功。

必须另外证明这些 sysctl 在目标 kernel 上实际按 namespace 隔离：init 和旁侧控制 namespace 的
事前/事后值均不变。不能证明隔离、设置或回读失败时，required job fail-closed；不得改 host 的
UDP timeout，也不得退回 host 默认值。`nf_conntrack_max` 仍只按 Gate B §19 的独立守护规则处理，
不与 UDP timeout 的隔离性混为一谈。

这些是**未来 test-only 权限建议**。本文不执行 sysctl、不改 firewall/route/service/task，不给
Windows、普通 build、产品进程或远端设备任何新的能力。每个模型仍保留实际 kernel conntrack cap、
精确 packet 相等、原 10s observer catch-up 上限和全量 teardown；不得靠 TTL 提高掩盖容量压力。

### 4.4 不把失效层变成宽松的通过条件

M-S 的原 50% loss gate 不接受 timeout/winner-positive 元组。M-E 只能在独立命名且显式启用的
expiry fixture 中接受受证据约束的失败，不能把该集合并入普通 loss helper。

M-E 必须共同证明：双方完整 16K schedule、同一已认证 selection、全局恰好一个 winner、
对应 reverse flow 曾存在且确认前消失、winner outbound=1 / peer inbound=0、无别的注入故障、
本地 deadline 至少一侧成立、FINISH/排水/零残留。普通 timeout 或仅用户态 mapping age 超过 30s
都不足以通过。出现另一个 router 计数缺口时仍失败，不能归入寿命预期。

建议按 winner 发送者冻结两个方向的精确见证，不使用“任意错误均通过”：

| winner 发送者 | initiator stage；carrier read/write | responder stage；carrier read/write | UDP I/R |
| --- | --- | --- | --- |
| responder | `candidates`；7/7 | `verify`；7/7 | 16,397 / 16,398 |
| initiator | `verify`；7/8 | `candidates`；8/7 | 16,398 / 16,397 |

两个方向的 class pair 仅建议允许 `(attempt_expired, oob_stream_closed)`、
`(oob_stream_closed, attempt_expired)`、`(attempt_expired, attempt_expired)`，并须带上述
本地 deadline 与独立 expiry 证据；双 EOF、auth/protocol 错误、无 FINISH、任意额外发射均失败。
initiator-winner 的 frame 形状是当前 role-ordered VERIFY 代码推导，**尚未在该 expiry 层实测**，
须先成为模拟/真实 OS 负向向量，不能借本草案自动放宽。

两侧仍各自报告已观察到的 class，不把 EOF 改写成已认证 exhaustion。每端 reserve 16,432，
每端实际 establishment 为 16,397 + 本地 winner 数；data=0、trip=false、burn/FINISH/circuit=true。
socket/target/five-tuple 仍是 16 / 16,388 / 16,395；carrier byte 数以实际 framing 精确核对，
上限仍 8,256，不借失败路径获得额外帧。

原 #107 的 early-hit success 断言及失败链接须保留为旧模型反例。未来修改应显式区分旧反例、
M-S 成功证明和 M-E 失效证明，并由独立评审批准测试期望变化；不能只把原断言换成接受 timeout。

## 5. 建议 E：提前确认是新协议工作，不是延长寿命

希望达到的效果是：在真实命中后及时停止未发送的候选，并在该 tuple 仍可用时完成唯一 winner/
VERIFY；不向不可控制的 NAT 索要配置权。它只能增加利用早期命中的机会，不能保证未知寿命、
任意 OOB 延迟、UDP 阻断或断网下必然直连。

### 5.1 候选路线与推荐

| 路线 | 价值 | 未闭合问题 / 处置 |
| --- | --- | --- |
| E0 现行 full-schedule selection | 既有确定性单 winner 和完整负载证据 | 保留基线；不能解决短寿命早期命中 |
| E1 responder 提前发已有 proposal | 可能缩短 responder-only 命中的等待 | initiator-only 命中仍可能等到 responder 发完整轮；不能宣传为双角色通用修复 |
| E2 双角色可触发的 early-stop + 唯一仲裁 | 有望处理两侧早期命中；建议后续协议研究方向 | STOP 与在途 candidate、交叉 proposal、唯一 decision、OOB/UDP 乱序、8-frame 成本均须先证明 |
| 保活/重试 winner/提高 PPS/扩大窗口 | 改变问题和资源边界 | 不在本次候选或授权中；34-packet headroom 仍不可消费 |

建议 E2 的**研究方向**，不批准 E2 实现。尤其不能恢复 Gate B §20 已证伪的
“initiator 立即 winner、responder 定时 deferred winner”；延时大小不是唯一仲裁证明。

### 5.2 E2 在进入实现前必须冻结的内容

1. **计划不由 peer 重写。** 双方仍独立重算完整 directional plan、source、evidence、cost、
   joint 和 execution digest。提前停止只撤销已发送 prefix 之后的未发后缀，不换 seed/端口/slot/endpoint，
   不把远端 candidate list/span/count 变为请求能力。prefix 的实际成本与完整预留分别见证，不退款。
2. **单一停止点。** 本地经过认证的命中或经过认证的合法 peer-stop 触发发送闸门撤销；
   闸门之后不再申请/提交 candidate I/O。此前已进入系统调用的操作须有 commit-point 归属并有界
   等待，不能把已发包算成取消未发。远端在看到 stop 之前继续的合法 prefix 也须精确计费。
3. **一个 receive owner。** 停止并等待旧 readers、排空已认证 event 后才能移交；要定义
   已发但晚到 candidate 与未经授权新发 candidate 的区别。若 UDP winner 先于 OOB decision
   到达，必须冻结零或有界缓冲/认证策略及内存成本，不靠放宽状态机或无界队列解决。
4. **一个不可撤回的选择。** 双方交叉命中、只有 I 命中、只有 R 命中、peer 已发 none、stop 与
   deadline 同时发生时，均须有逐事件状态表；不能由到达速度/本地定时器决定两次 winner。
   OOB 失联仍立即停止发射；不能用 terminal-drain sibling context 继续推进成功路径。
5. **仍受 PPS 约束。** 停止搜索不会清空 rolling-PPS 历史。winner 仍需等待已有 PPS 槽，
   不得作为高优先级包越过 governor；等待会进一步消耗真实映射剩余寿命，须进入条件说明。
6. **互认之后才移交。** selection 不等于 verified path；原 VERIFY、lease-before-Promote、
   consumer adopt/challenge、FINISH-before-release、EOF 截止点及 crash drain 全部保留。
   不能先移交数据面来充当隐式保活，也不能复活已毒化 ProbeSocket。

### 5.3 wire 与成本可行性门：目前尚未闭合

现行计费前缀占每方向前六帧，selection 是第七帧，VERIFY（或 responder 的 EXHAUSTED）是
第八帧。**额外插入一个 STOP/ACK 就可能成为第九帧**。本提案没有证明 E2 可装入原上限，
因此不得把这里当成“按思路直接实现”的提示词。

后续 E2 docs-only mini-spec 必须列出双角色所有分支的 frame/byte 表、确切 type/sequence、
canonical encoding、端序、payload 上限、AD 域和重放终局，包含交叉 proposal、未命中、CANCEL、
半帧、EOF 与握手失败。只列 happy path 或称“复用现有帧”不够。

新语义须有显式且不同的 artifact/control/scheduling-policy identifier，进入 Noise prologue
或固定 AD，并反映到双方独立重算的 commitment。确切 identifier/字节向量在该 mini-spec 冻结，
本草案不注册 `/2` parser、不改变现有 `/1` 的字节解释；未知版本零 I/O 拒绝，无协商/fallback。
端点地址仍由隔离 harness 权威限定，profile 变化不授予新网络范围。

资源目标仍为 §6 原有上限；若不能在该上限内同时证明及时确认与唯一仲裁，就返回维护者裁决，
不能默许第九帧或把额外控制流量记入未声明通道。E1 只能作为明确单侧能力的另一个待审提案，
不能在实现中自动降级为 E1，也不能宣称 E2 已闭合。

## 6. 两条路线都不能提高的资源与权限

| 项目 | 现有上限 / 本提案约束 |
| --- | --- |
| peer / attempt / heavyweight；OOB stream / child | 1 / 1 / 1；1 / 0（Gate B 隔离 executor） |
| socket；target / five-tuple reservation | 16；16,400 / 16,400 |
| packet reservation；实际协议 slices | 16,432；13 evidence + 至多 16,384 candidates + 全局至多 1 winner |
| actual target / five-tuple 最大值 | 16,388 / 16,395 |
| PPS；candidate / active / drain / governor duration | 512；38s / 45s / 2s / 47s |
| OOB frame / application bytes 每方向 | 8 / 8,256 |
| test consumer challenge | 每方向 3 packets，原 TransportLease 边界单列；不转作保活 |
| 24h campaign；退款/复用/自动恢复 | 1 admission、16,432 reservation；全部禁止 |

M 保留现行完整 schedule；E 若以后获准 early-stop，实际候选只能是冻结计划的一个已计费 prefix，
不降低完整负载/无命中路径的验收强度。任一资源违规依旧在 I/O 前阻断并落持久 trip；
普通失效、EOF 和 timeout 不 trip，但 burn 后失败仍进入 campaign circuit。

本提案不修改 C1b 已独立复审的 root/SSH/WireGuard 组合及其预算、stdio v1/v2、CLI、
loopback carrier、live authorization、daemon、scheduler 或永久回归门禁。
它与 [#105](https://github.com/houyuwushang/winkyou/pull/105) 的会话建立后 liveness 提案独立；
本问题发生在 VERIFY 之前，不能借会话心跳替建立阶段续命。

## 7. 后续验收门（均未在本 PR 执行或闭合）

| 门 | 所需证据 |
| --- | --- |
| 模型纯函数 | 单调时钟；mapping/filter 独立到期；30s 边界前/等于/后；刷新方向、已驱逐状态不能复用；无 OS capability |
| M-S | early hit 两方向、尾部命中、完整 exhaustion、50% candidate-only loss；原完整 packet/terminal/digest gate |
| M-E | 两种 winner 方向；分别观察 local deadline/OOB EOF 先到；精确 frame 表与 expiry 因果链，不能接受无故 timeout |
| M-X | 单侧 expiry/容量驱逐/行为漂移，出现在 selection 前后、winner 前后与 VERIFY 边界；0 retry/fallback |
| E2 状态机 | 双方同时命中、仅 I/仅 R、跨序/重复/重放/篡改、stop 与 syscall commit 竞态、任一控制帧丢失/半帧；至多一个选择/一个 winner |
| E2 时间证据 | 短寿命模型中从真实命中到停止、winner、VERIFY 的独立时序；OOB 延迟/背压扫描，失败不扩窗；不要求无限延迟下成功 |
| E2 概率/成本 | 完整预留与实际 prefix 分开，条件模型不冒充成功率；含失败/取消分支的 frame/byte/nonce golden |
| 生命周期 | 32–100 contender/1,000 restart 的原单次 admission 不退化；取消、child/parent kill、FINISH/Promote gap 与 transport residue |
| required OS | race-enabled 两端真实进程、TEST-NET；init/旁侧 sysctl 未变；packet/socket/process/conntrack/lock/netns/veth 全量 witness |
| 重复与回归 | 关键 natsim fresh100；受影响包 race×20；原 full-load、Fresh100 teardown、architecture/mutation、全仓与 required CI 不降级 |

命中数、失效数、交付数与不可归因故障分别计数；不得删失败后重跑只报成功。
#107 的 `16,381 != 16,397` 须单独定位并保持相等断言，不得借 M/E 归因或默认豁免。
新增矩阵的 CI 墙钟可行性也须核算；保留现有 required job 的 10min ceiling，必要时提出独立
必跑 job 的受审拆分，不能静默延长旧 job、取消必过或复用旧 epoch 凑重复次数。

## 8. 裁决栏与实施前置

以下“建议”不是 Accepted；批准人、独立复审、日期和 exact-SHA 接受记录均留待维护者填写。

| 待决项 | 本文建议 | 裁决 |
| --- | --- | --- |
| D1 证据边界 | 接受时间有效性与五秒 FIRE freshness 分离，不追溯认定 #105 唯一根因 | 待定 |
| D2 M 模型 | M-S=60s、M-E=30s，mapping/filter 与 kernel 两档均显式；逐 namespace 权限/回读/清理 | 待定 |
| D3 M-E 验收 | 只在独立 expiry 层接受 §4.4 精确失败证明，不改普通 loss gate | 待定 |
| D4 E 方向 | 研究 E2 双角色提前停止/唯一仲裁；须先证明原 8-frame envelope 可行 | 待定 |
| D5 兼容与资源 | E 需新显式语义标识与 golden；不增加任何上限，不能静默改 `/1` | 待定 |
| D6 实施次序 | 先裁决 M，再独立实现/复审；E 完整 wire 冻结前不开 executor；不推进 C1c/现场 | 待定 |

- 维护者裁决人/日期：未填写。
- 独立评审人/结论：未填写。
- 接受的文档 exact SHA：未填写。
- M 实现授权范围与编号：未填写。
- E mini-spec 接受与实现授权：未填写。

合入本 Draft 文档（若以后发生）不自动关闭 #106、不使 #107 可合并，也不授权任何实现。
恢复 #107 前至少需要 D1–D3/D5/D6 的明确接受、独立评审和新的实现续令；E 还需要 D4 与
§5.3 的完整协议可行性及字节冻结。M 绿灯不能替代 E、C1c inactivity 或任何现场窗口的前置。
