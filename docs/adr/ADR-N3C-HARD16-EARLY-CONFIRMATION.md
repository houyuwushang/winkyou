# Hard16 提前确认 E2 mini-spec

Status: Draft (2026-09-08)。仅设计提案，未批准实现、未证明可达性、未授权现场。

基线：`fde8dfa60b3c4708ca9a2b4fd783270a08c7d87f`（#107 M 已合入）。
依据：[ADR-M](./ADR-N3C-HARD16-MAPPING-LIFETIME.md) D4/D5、
[Gate B ADR](./ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md) §16/§18/§20/§22、
[M 隔离证据](../GATE-B3-HARD16-ISOLATED-EVIDENCE.md) §9–§11。
本文不修改上述 Accepted 决策，也不注册新 parser。

## 1. 结论先行

E2 的**容量核算可行**：把第 7 帧改为双方各一次不可撤回的 proposal，接收合法 proposal
同时表示 peer-stop；双方取得同一对 proposal 后按固定角色优先级独立选出唯一 winner。
不需要额外 STOP、ACK 或 decision 帧。每方向最多 8 帧、本文形状上界 905 bytes，
小于原 8,256 bytes。容量证明不是状态机实现证明或网络成功率证明。

建议独立复审 E2，而非立即实现。仍有两项**显式修订提案**必须裁决：

> 🔴 P1：任务要求无早命中时“逐字节退化现行协议”，但 D5 要求新标识进入 Noise/AD，
> 必然改变握手 hash、派生密钥、计划和密文。无法同时保证跨版本完整 wire 字节相同。
> 提议保留 `/1` 的 parser、golden 和全部行为原样；E2 无早命中保留既有帧形状、计费、
> role-order 与终局语义，不承诺与 `/1` 密文相同。若不接受这个最小修订，E2 应搁置。

> 🔴 P2：E2 停止后必须容忍**合法但晚到**的 candidate，仅丢弃、不产生新 proposal。
> 这不等于 `/1` 的 selection 后接收规则自动放宽。线上的旧 candidate 没有可信 syscall
> 时间戳，接收方不能仅凭到达时刻证明它在 stop 前还是后发送。提议 `/2` 明确区分本地
> commit 见证与远端可验证的计划/认证/nonce，不能虚构“远端 stop 后零发包”的密码学证明。

裁决前，现行完整 schedule 仍是唯一实现；E1 也未获批准，不存在运行时降级。

## 2. 冻结事实与源码核对

| 项目 | 保持不变 |
| --- | --- |
| candidate / PPS | 每端至多 16,384 个 one-shot candidate；512 rolling PPS |
| 时间 | 38s candidate / 45s active / 2s drain；47s governor envelope |
| 资源 | 16 sockets；16,400 target/tuple reservation；16,432 packet reservation |
| 协议实际最大 | 13 evidence + 16,384 candidate + 全局至多 1 winner；单端至多 16,398 |
| headroom | 34 packet 差额不可消费，不可用作 STOP、重传、保活或 challenge |
| OOB | 单 stream；每方向 8 frames / 8,256 application bytes，含 WYRC header |
| admission | 一次/24h campaign；burn 后不退款；无 retry、扩窗或 fallback |
| 信任 | 双方独立重算 plan/source/evidence/cost/joint/execution，不接收远端资源请求 |
| handoff | 双向 VERIFY、lease-before-Promote、adopt/challenge、FINISH-before-release 原样 |
| EOF | 立即撤销 active 发射权；2s 只排水，不是延长 I/O 窗口 |
| M | M-S/M-E/M-X fixture、成功/失效谓词与历史 RED 均不修改 |

源码定位：[`oobcarrier/cost.go`](../../internal/v2/oobcarrier/cost.go)、
[`rendezvouswire/wire.go`](../../internal/v2/rendezvouswire/wire.go)、
[`hardnatcontrol/control.go`](../../internal/v2/hardnatcontrol/control.go)、
[`gateb/connect.go`](../../internal/v2/directconnect/gateb/connect.go)。

现行前六帧**包含 presence 与 ACTIVATE**，不是六个加密控制帧：每端一次 presence、
一次 activation、一次 Noise、PREPARE、SOURCE、READY_FIRE。现行第 7 帧 R 先报告，
I 返回最终决定；E2 则让 I/R 各提交自己的不可变 proposal，双方本地算决定。
这是实质协议变更，不能直接修改 `/1` 的 `SealWinnerSelection`。

## 3. 双方向帧、字节与分支

### 3.1 公共前缀 P（每个分支的第 1–6 帧）

下表的 payload 指 WYHB 的 AEAD 明文（前三行指 WYRC payload）；每帧合计包含 8-byte
WYRC header。WYHB 为 24-byte header + 明文 + 16-byte tag。`—` 表示不是 WYHB sequence。
I/R 各自只有表中一帧，不把对端帧计入本方向。

| 序号 | I → R / R → I | sequence | payload 上限 | 本方向 bytes 上限 | 触发条件 |
| --- | --- | --- | --- | --- | --- |
| 1 | PRESENCE / PRESENCE | — | 50 | 58 | secret-free；I 先发，R 验证后回 |
| 2 | ACTIVATE / ACTIVATE_READY | — | 0 | 8 | 本侧 durable burn 后，沿用 activation 顺序 |
| 3 | HANDSHAKE / HANDSHAKE | Noise 各一次 | 48 | 56 | NNpsk0 空 handshake payload；不是应用数据 |
| 4 | PREPARE / PREPARE | 0 | 0 | 48 | 握手完成，TakePacketCipher 后 |
| 5 | SOURCE / SOURCE | 1 | 407 | 455 | 本 generation 证据与受限 compact source |
| 6 | READY_FIRE / READY_FIRE | 2 | 64 | 112 | 独立重算 commitment、双边 freshness barrier |
| 合计 P | 每方向 6 帧 | | | **737** | 不增加第二次握手/激活 |

presence 为 `1 + 32-byte profile + 16-byte channel ID + 1-byte slot = 50`。
Hard16 SOURCE 为 `151 + coverage(≤256)`；预测端口数组长度必须为零，不能借 SOURCE
输入 candidate list/span/count。上界不是实测 fixture 长度；现行 M 某些成功轨迹为
873/873 bytes，不应把这个观测值误作协议上限。

### 3.2 后缀记号

| 记号 | type / domain | sequence | 明文 / WYRC 合计 | 含义 |
| --- | --- | --- | --- | --- |
| S(x) | WinnerSelection=8 / control=1 | 16401 | 40 / 88 | 本侧接收过且已认证的一个 reciprocal candidate proposal |
| S(∅) | WinnerSelection=8 / control=1 | 16401 | 1 / 49 | 本侧不提出 proposal，不是允许重发/恢复 |
| V | Verify=6 / control=1 | 16402 | 32 / 80 | 唯一 winner 的确认；双向 V 才能成功 |
| X | Exhausted=10 / control=1 | 16402 | 0 / 48 | 仅 R、双方 none、完整 schedule 耗尽 |
| C | Cancel=7 / control=1 | 16403 | 0 / 48 | 仅可替代尚未占用的尾帧；无确认、无后续 I/O |
| W | Winner=5 / direct=2 | 16400 | 39 / UDP 79 | 不占 OOB 帧；全局最多一次 |

S(x) 的 sender 是 **proposal 提出者/候选接收者**；其中 CandidateSender 是另一角色。
E2 仍不允许通过 selection 指定 endpoint、资源数量或新的计划。

### 3.3 所有分支展开

每格 `P;7=…;8=…` 完整引用 §3.1 的六行（同样的 sender、sequence、上限与条件）。
选中 `pI` 的 winner 发送者为 I，选中 `pR` 的为 R；不要把候选发送者与 winner 发送者混淆。

| 分支 | I → R 第 1–8 帧 | R → I 第 1–8 帧 | 决定与触发 | 本方向最大 bytes I/R |
| --- | --- | --- | --- | --- |
| E-a 仅 R 早命中 | P;7=S(∅);8=V | P;7=S(pR);8=V | R 冻结命中并停止；I 收 S 后停止并回复；R 得到双提案后发 W | 866 / 905 |
| E-b 仅 I 早命中 | P;7=S(pI);8=V | P;7=S(∅);8=V | 对称；I 得到双提案后发 W | 905 / 866 |
| E-c 交叉命中 | P;7=S(pI);8=V | P;7=S(pR);8=V | 两个 S 可同时在途；固定 I-proposal 优先，只有 I 发 W | 905 / 905 |
| E-d 对方已发完但尚未 S | P;7=S(pI 或 ∅);8=V | P;7=S(pR 或 ∅);8=V | 已结束 sender 不恢复；已有 proposal 冻结后参加同一仲裁 | ≤905 / ≤905 |
| E-d R 已发 none、I 后命中 | P;7=S(pI);8=V | P;7=S(∅);8=V | R 的 none 不撤回，I 发 W；无第二 S | 905 / 866 |
| E-d I 已发 none | P;7=S(∅);8=无 | P;7=S(∅);8=X | 只有 I 已先收到 R 的 none 才能发生；此后命中不改变决定 | 786 / 834 |
| E-e 无早命中、完全耗尽 | P;7=S(∅);8=无 | P;7=S(∅);8=X | 保留完整 schedule、R 先 S、I 后 S、R 最后 X | 786 / 834 |
| E-f 有效 stop 先于 candidate deadline | 按 E-a/b/c/d，至多 P;S;V | 同左 | stop 线性化后仅已准许的 winner/VERIFY 可使用原 active 剩余时间 | ≤905 / ≤905 |
| E-f deadline 先或同一判定时刻 | 已提交前缀；可用尾槽 C 或无 | 同左 | deadline 优先；不新提案、不 winner，不延长 38s | ≤8 帧 / ≤905 各自 |
| E-f OOB EOF/半帧/写失败 | 截断前缀，无补发 | 截断前缀，无补发 | EOF/absolute deadline 立即终局；不能补帧凑完整表 | ≤8 帧 / ≤905 各自 |
| E-f 主动 CANCEL | 已有前缀；下一个空尾槽 C；其后无 | 收到后停止；无 C ACK | 第 8 帧已消费则只关闭，不发第 9 帧 | ≤8 帧 / ≤905 各自 |

握手/前缀失败也只是表的截断前缀；burn 前不允许任何安全控制帧。半帧的实际 bytes
包括已写的 header/payload，不能因未形成完整帧而免费；carrier 继续使用原硬上限。
C 不可在资源拒绝或 EOF 后强行发送，不得为发 C 保持额外活动窗口。

结论是容量足够，**不是需要第九帧的 E2 不可行性结论**。但 P1 若坚持完整密文同一，
在第 3 帧即与 D5 矛盾，帧容量再多也解决不了。

## 4. 状态机与所有权

### 4.1 单一停止点与不可撤回 proposal

状态为 `sending → stopping → stopped → proposals_complete → selected/empty → terminal`。
每侧只有一个 candidate sender、一个 stop 闸门、一个本地 proposal 槽和一个 peer proposal 槽。
原来的每 socket 单 reader 由同一协调者管理；OOB 始终只有一个读取 owner。

| 事件 | 本地动作 | 之后允许的候选提交 |
| --- | --- | --- |
| 经认证且 reciprocal 的本地命中 | 线性化 stop；冻结一个 proposal；等待已提交发送返回 | 0 |
| 收到合法 peer S | 验证 role/plan/execution/nonce 后线性化 stop；冻结本侧已有 proposal 或 none | 0 |
| 本侧完整 schedule 结束 | 保持 sender 停止；R 可发送 S；无 proposal 的 I 等 R 的 S | 0 |
| 同时出现两个命中 | 两端分别冻结；收到对端 S 后固定选 pI，否则 pR | 0 |
| 本侧 S 已提交后新命中 | 不更新 proposal，不重发 S；仅处理为晚到包 | 0 |
| 双方 none | I 不发 W/V；R 在完整耗尽证据下发 X | 0 |
| deadline / EOF / cancel | 终局优先；清 proposal/缓冲、取消所有 worker，按原合同排水 | 0 |

一旦获得 `(pI,pR)`，算法是 `pI 非空 ? pI : pR`，不是“先到的 proposal 获胜”。
每个 proposal 在本侧 stop 快照中选择一个已认证事件；它本身可能受真实到达轨迹影响，
但对**同一对不可撤回的 proposal**，两侧独立重算的决定不依赖到达速度或本地定时器。
不能宣称双方凭自己的单侧观测就能重建对端全部命中集合。

candidate syscall admission 与 stop 必须共用线性化闸门：取得原 governor 预算、检查
active/candidate deadline、在闸门内提交唯一 sender 的 syscall 许可。stop 禁止新许可；
已跨 commit point 的一次 syscall（包括尚未返回的）属于已计费 prefix，不称为“取消未发”。
必须等待它返回并记录 OS/send witness 后才能发本侧 S。若无法在原绝对边界内等到退出，
直接 terminal drain，不能在后台继续发送。不可把不受控 syscall 放到 unlock 后再开始。

远端在收到 S 前继续提交的合法 prefix 同样计费；双方 prefix 长度可以不同。S 不携带
远端可请求的 packet count，也不把未用 reservation 退款。stop 不撤回已烧 credential。

### 4.2 单一 receive owner、在途包与 early winner

stop 先阻断 sender，保留 active 取消传播；`finishReaders()` 必须取消并 join 全部旧 UDP
reader，再 `drainQueued()`，再把 socket 读取权移交 winner 阶段，绝不能两组 reader 竞争。
旧队列的合法候选不再改变已冻结 proposal；不以“再等一个命中”为由延时。

P2 的具体判据：认证、role、generation、AD、计划 ordinal/slot/tuple 和 replay 检查失败
仍终局；合法但此前未见的晚到 candidate 只计入接收见证并丢弃，不回包、不刷新时限。
收到重复 nonce 仍是 replay 终局。是否在远端 stop 后执行 syscall 只能通过该端独立
emission witness 验证，无法从晚到 UDP 的单个时间戳推断。

唯一 W 可能先于另一方向 OOB S 到达。提议 `/2` 将 AEAD/tuple 验证与协议状态消费分离：
只允许一个已认证 W 的 pending 槽，最多 79-byte wire + 固定 tuple/slot 元数据，**128 bytes**
编译期总存储上限；第二 W/重复/认证失败终局。未取齐 S 不 Promote、不发送 V。
取齐后独立算 winner，再消费匹配的 pending W，否则终局。缓冲不延长 deadline，不接受
任意帧队列；退出时清空。新增 128-byte 暂存是显式内存成本，不消耗 34-packet headroom。

每侧必须先完成自己的 S 写入并收到 peer S，才具备发 W 的本地权限。这不声称对端已
读到自己的 S；pending 槽解决双传输乱序，双向 VERIFY 解决最终确认。没有额外 ACK。

### 4.3 时间窗竞态

candidate deadline、stop、EOF 在同一 owner 中定序；`now >= candidateDeadline` 且尚未
提交有效 stop 时，候选阶段失败优先，不在边界制造 late proposal。有效 stop 已提交时，
候选阶段结束，W/V 只受**原** active deadline 与 EOF 控制，不创建新的 45s context。
只有原本已完成完整 schedule 的双 none 分支可沿用 §22 的 terminal-only X 读取上下文；
该上下文无 UDP 权限，不能用于 E2 成功分支续时。排水 2s 不允许任何新网络发射。

## 5. PPS、时间下界与概率

不清空 rolling-PPS 历史。保守保留现行 winner 槽：至少等到本端最后一次 candidate
commit 后 `1s + 1ms`，且在 syscall 前再次通过原 PPS gate。若在首个本地 candidate
前即收到命中，则以已有 evidence 发射记录与 PPS ledger 求槽，不把零时间戳当无限额度。

设真实命中后认证/停止/读者 join 耗时为 `d`，OOB 两方向传输/排队为 `r1,r2`，
peer 停止与快照为 `dp`，winner 侧尚需的 PPS 等待为 `q`。单侧早命中且回到该侧发 W 时：

`tW - tHit >= max(d + r1 + dp + r2, q)`；若两项串行执行，下界还不足以代表实际耗时。
交叉 proposal 可以并行交换，不应机械加两个 RTT；仍要等待两侧 S 的本地完成条件。
`q` 取决于真实历史，不能声称总是 0 或总是 1s；W 到对端还有 UDP 传播时间，VERIFY
还有 OOB 往返及排队。上述是因果下界，不是 45s 内成功保证。

M-E 已记录 full schedule 的早命中 tuple 在 W 时年龄约 32s、30s reverse flow 已消失。
E2 若把等待降低到例如“1 RTT + 停止开销，与 PPS clearance 的较大者”，可能覆盖仍有
数秒余寿命的 tuple；只有实测 `mapping_remaining > stop/selection/PPS/UDP/VERIFY` 才能
判定该次可交付。不能覆盖已过期/驱逐、极短寿命、OOB 长背压或不可达 winner。不能用
liveness 刷新建立阶段的 mapping，也不以 M-S=60s 证明所有 NAT。

prefix 成功概率目前**未估计**。early-stop 是依观测选择的 stopping time，两侧已发
数量是随机且相关的；不能代入完整 16K 碰撞率，也不能把已命中条件下的样本当无条件
用户成功率。后续统计须同时报告预留、实际 prefix、命中、唯一 W、双 V、handoff、
clean failure；保留未命中全量对照与条件模型假设。

## 6. 标识、canonical encoding 与向量草案

提议单独 artifact `winkyou-test-hard-nat-attempt/2`、control
`winkyou-test-hard-nat-control/2`、manifest `winkyou-test-hard-nat-manifest/2`。
资源档仍仅 `hard_birthday_campaign/1` + `hard_16k_lab/1`；不开放 hard32 或其他 profile。
沿用受限 artifact 字段集合，仅改固定标识；禁止 endpoint/host/path/资源数字或 candidate
列表。无协商、无自动 fallback；未知值、`/1` 与 `/2` 混配在 adopt/socket 前拒绝。

### 6.1 绑定与字节规则（待裁决，不是现行实现）

保留 `pairingcontext.BuildNoisePrologue` 的完整规范化 context；后接 LF 与现行
`hardnatattempt.NoisePrologue` 的固定 binding 行序，artifact/control 两行改成上述 `/2`。
不加入可选、未认证或本地私有 policy。其他行、LF、UTF-8、无 BOM、无 CRLF 规则不变。
context digest 仍用同一 canonical material 算法，包含新 artifact/control；完整 prologue
通过 Noise final hash/exporter 绑定到双方独立重算的 planner/source/evidence/cost。

额外冻结独立重算的执行承诺：`X2 = SHA256(UTF8("winkyou-hardnat-e2-execution-v1\0") ||
LP32(control/2) || X1)`，其中 X1 是双方各自重算的现行完整 execution 编码摘要，不可
直接相信对端给的 X1。所有 READY_FIRE/selection/W/VERIFY 都绑定 X2；底层 cost 数值
及 B1 编码不变。joint/source/evidence 原始证据仍各自重算，不由 X2 替代。

`LP32(s) = uint32BE(UTF8字节数) || UTF8(s)`，注意现行 AD 是 **32 位长度前缀**，不是16位。
AD 完整字段顺序：

```text
UTF8("winkyou-hardnat-frame-ad-v1\0")
|| LP32("winkyou-test-hard-nat-control/2")
|| attempt_id_raw[16] || context_digest[32] || final_handshake_hash[32]
|| generation_uint64BE
|| LP32("hard_birthday_campaign/1") || LP32("hard_16k_lab/1")
|| envelope_digest[32]
|| (joint_digest[32] || X2[32]，仅 READY_FIRE/CANDIDATE/W/SELECTION/VERIFY/EXHAUSTED)
|| (directional_plan_digest[32]，仅 CANDIDATE)
|| WYHB_header[24]
```

域仍为 control=1 / direct=2，由 header 与认证 AD 同时绑定；carrier 只投递 control。
PREPARE/SOURCE 尚无 joint，不得伪造全零 joint 填入；CANCEL 沿用不带 joint 的编码。
每方向固定带洞 sequence：0、1、2、16…16399、16400、16401、16402、16403；type/sequence
不符、重复、跨域/版本重放、wrong role/context/generation、超长、认证失败一律终局。
VERIFY 和 EXHAUSTED 共用 16402，因此绝不允许两者都发送。

### 6.2 可展开的逐字节向量草案

以下是**结构完整但尚未运行加密的向量模板**。尖括号标识固定长度占位，不是允许在线
发送的 ASCII；实现授权后必须生成跨语言逐字节 golden，再独立审查。
仅用合成 `attempt=01..10`（16字节）、`context=11×32`、`hash=22×32`、
`envelope=33×32`、`joint=44×32`、`X1=55×32`；generation 为 1。
X2 严格由 §6.1 导出，不把任意 55 字节当作最终执行承诺。

```text
LP32(control/2) = 0000001f || UTF8("winkyou-test-hard-nat-control/2")
generation      = 0000000000000001
proposal pI     = 01 || 02 || 00000007 || 0003 || <DW:32>
DW = SHA256(UTF8("winkyou-hardnat-winner-v1\0") || X2 || 02 || 00000007 || 0003)
  # 01=hasWinner; 02=candidate sender R; ordinal=7; receiver slot=3

I SELECTION WYHB header (24 bytes):
57594842 01 01 08 01 0000000000004011 0000 00000000 0038
I SELECTION outer header (8 bytes):
57595243 01 06 0050
whole = outer[8] || WYHB[24] || AEAD(sequence=16401, AD=above, pI)[56]
      = 88 bytes

R none WYHB header:
57594842 01 01 08 02 0000000000004011 0000 00000000 0011
outer = 57595243 01 06 0029; plaintext=00; whole=49 bytes

I selected W (receiver slot=3; peer candidate ordinal=7):
57594842 01 02 05 01 0000000000004010 0003 00000007 0037
plaintext = 02 00000007 0003 <DW:32>; no WYRC wrapper; whole=79 bytes

I VERIFY:
57594842 01 01 06 01 0000000000004012 0000 00000000 0030
outer = 57595243 01 06 0048; plaintext=<DW:32>; whole=80 bytes
R VERIFY: replace sender 01 with 02; same DW, independent directional AEAD key

R EXHAUSTED:
57594842 01 01 0a 02 0000000000004012 0000 00000000 0010
outer = 57595243 01 06 0028; plaintext=empty; whole=48 bytes

CANCEL: type=07, sequence=0000000000004013, slot/ordinal=zero,
ciphertext length=0010; outer=57595243 01 06 0028; whole=48 bytes
```

nonce 按现行 Noise PacketCipher 的 sequence 映射，不能拿 header 的 BE 序号直接猜
AEAD nonce 端序。向量实现须把实际 nonce bytes 单列，并覆盖最大 candidate、重复 S、
S/W 跨 AD 域、V/X 同 sequence、两种方向和不同 profile。AEAD 输出、X2、DW 尚未计算，
本 PR 不把占位模板冒充密码学 golden 或网络测试。

## 7. M、liveness、C1c 与备选边界

M 仍独立验证完整 16K 与 30s/60s 寿命；E 不迁移/删除任何 fixture 或放宽 M-E 失败谓词。
liveness 仅在建立后，不能在 candidate/selection 中发 PING 续命。C1c 还需完成其独立
前置、liveness 实现复审及具名窗口授权；本草案不提供 SSH assembly 或现场权限。

若 P1/P2 不获接受或后续状态证明失败，建议**搁置 E**而不是暗中切 E1。E1 仅 R 可早发
已有 proposal，不能对称解决 I 早命中；它需要同等级独立 mini-spec，本文不授权该路线。
搁置时产品只能如实记录：tuple 余寿命小于 full schedule + PPS + 确认耗时会失败，
45s/2s 终局与单次 burn 不退款保持；现场必须记录寿命与失败阶段，不能声称所有困难 NAT
都能穿透。M 成功仅证明指定模型下的现有实现，不消除这个可用性限制。

## 8. 实现前验收门（全部未执行）

| 门 | 必须补充的确定性与 OS 证据 |
| --- | --- |
| 容量/向量 | E-a…f 双端精确 frame/byte/sequence/AD/nonce；无第九帧；P1 裁决后 `/1` golden 零变化 |
| 仲裁 | 同时/交叉/单侧提案、none 已提交、winner 抢先于 S；两端独立决定相同、全局 W≤1 |
| 停止线性化 | stop 在 syscall 许可前/中/后；deadline 同刻；完成前不得 S；prefix 计费与外部发射计数相等 |
| receive owner | 旧 reader join→drain→新 owner；pending W 0/1/2、超长/错tuple/重复、128-byte 上限、退出清零 |
| 生命周期 | selection 半帧/背压/EOF、sender error、child/parent kill、FINISH gap、无重启退款或新 attempt |
| 时间模型 | M-E 30s 下 I/R 早命中、寿命边界前/等/后、OOB delay/backpressure 扫描；从命中到 W/V 的独立时间线 |
| PPS/概率 | rolling PPS 不清零；首个 candidate 前命中；冻结完整预留与实际 prefix 分列；未命中 full-load 对照 |
| 必跑 OS | race 二进制、fresh TEST-NET netns、init/旁侧 sysctl 不变、packet/socket/process/conntrack/lock/netns/veth 零残留 |
| 回归 | fresh natsim100、受影响包 race×20、原 required full-load/Fresh100/restart/architecture/mutation 全保留 |

这些门没有因本 PR 的文档核算而勾选。任一门不成立，返回设计裁决，不提高预算或时限。

## 9. 裁决栏

| 待决项 | 维护者 / 独立评审裁决 |
| --- | --- |
| P1 跨版本密文同一要求的最小修订 | |
| P2 晚到包与 syscall 见证的可证明边界 | |
| 是否接受 E2 / 改走 E1 / 搁置 | |
| 是否接受标识、仲裁、128-byte pending W 与向量结构 | |
| 是否授权实现；exact SHA / 范围 / 日期 | |

空白不是同意。本文仅 Draft，不改变任何已合入二进制、网络权限或现场前置。
