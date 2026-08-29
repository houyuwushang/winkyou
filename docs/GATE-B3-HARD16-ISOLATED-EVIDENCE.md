# Gate B3：Hard-16K 隔离实现证据

状态：**Draft implementation evidence。只覆盖 memory、natsim 与 required Linux network
namespace；不授权 Gate C、产品入口、disposable router、LAN/公网、真实 observer 或现场
campaign。独立复审通过并合并前，不得把本实现视为产品或现场能力。**

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

```text
preflight -> oob_adopt -> present -> burned -> activated -> handshake -> prepare
  -> sockets -> fresh_evidence -> plan_committed -> ready_fire bilateral barrier
  -> 16K one-shot candidates -> bilateral winner selection -> optional winner
  -> verify -> transport_lease
  -> handoff -> 3-packet data_plane_challenge -> durable finish -> drain
```

Gate B3 的 `READY_FIRE` 在一个认证 frame 中同时携带原 READY commitment 与 bilateral FIRE
barrier；Gate B2 wire 不变。双方完成完整 16K schedule 后，responder 报告首个认证 candidate
或 absence，initiator 以“本地 observation 优先、否则 responder observation、否则 none”的固定
规则封存唯一选择。selection 只含 role/ordinal/socket-slot/digest，并绑定 Noise AD、joint plan 与
execution envelope；只有被选中的 receiver 可以复用该 tuple 发 1 个 winner。含双向 VERIFY 在内
每方向仍恰好不超过 8 carrier frame。该语义不是 fallback：它不生成新 candidate、不更换 tuple、
不补位、不发起第二轮，全局 winner 总数至多为 1。candidate exhaustion、50%
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
  trip；50% candidate loss 若命中则按 §18.5 停止尚未发出的 tuple 并完成 handoff，若未命中则完整
  耗尽，任一终局都不补位、不重试、不产生第二 attempt；
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
capability。高负载 topology 删除并通过 namespace/veth 零残留断言后，harness 另留固定 750ms
供内核回收已删除 namespace 的 conntrack/RCU 对象；它不重建、不重试 campaign，也不进入 attempt
时长或发包预算。后续 topology 若仍失败，只输出稳定 setup stage，不输出 namespace、设备名或底层
命令文本。

ENOBUFS seam 只存在于 `linux && natlab`，在冻结的 13-packet evidence slice 后对首个 candidate
返回 OS `ENOBUFS`；它不改变 endpoint allowlist，并必须触发持久
`resource_exhausted` safety trip。parent helper 的 endpoint child 固定设置 `Pdeathsig=SIGKILL`；
父进程死亡后必须在 2 秒排水窗口内留下零 namespace process/socket。

## 8. 验证状态

本地 Windows 已通过：`go vet ./...`；全仓 `go test ./... -count=1 -timeout=10m`（271.6s）；
受影响包聚焦测试（236.5s，其中含 100 次 fresh full-shape natsim）；governor/ledger/状态机
race×20（305.0s）；probeio、协议与 architecture/mutation race×20（312.9s）；planner/golden
race×20（153.2s）；Linux+natlab tagged vet 与测试二进制交叉编译；`git diff --check`。本机没有
运行真实 socket、namespace、route、firewall、observer、daemon、LAN 或公网 I/O。

required Linux 的 race-enabled full-load 实测数字与 CI run/job 链接将在 Draft PR 的远端 required
job 完成后写入本节；在该证据写回、全仓测试与 vet 全绿前，本文件不声称 Gate B3 验收闭合。
