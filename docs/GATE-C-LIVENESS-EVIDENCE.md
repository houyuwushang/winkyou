# Gate C session liveness 隔离实现证据

状态：Draft PR #112 实现中；时钟修订 A 已接受，修订后全矩阵与独立复审仍须核对。不授权 C1c、disposable router、
现场 I/O 或新网络能力。基线 `fde8dfa60b3c4708ca9a2b4fd783270a08c7d87f`。
权威：[Accepted ADR](./adr/ADR-N3C-SESSION-LIVENESS.md) §11/§12 与
[维护者方案 A 裁决](https://github.com/houyuwushang/winkyou/pull/112#issuecomment-5579897333)。
时钟修订另外依据 ADR §12.4，不能把 admission A 与时钟 A 混为同一裁决。

## 1. 不变量与实现位置

- §7.2 原文保留：普通 admission 满额仅丢弃、计数；消费 slot/high-water，不补发、不借额。
  WG 自动控制超限、admission 绕过和 writer/drain 硬违规由同一仍持锁 owner 持久 trip。
- 文件专属 trusted policy：`pkg/config/session_liveness.go`；缺省仍走原 C1b 路径。
  env、未知字段、null、非整数不产生新授权。K=20s、R=5s、M=2/3，L=45/65s 不改。
- 通用 exact-tuple tap：`pkg/tunnel/inner_tap.go`；解密及 AllowedIPs 后分流，业务恰好
  交付一次。控制回调只复制/非阻塞入队，和 revoke/drain 互斥，不能在 drain 后留下事件。
- 许可与两类分账：`internal/probeio/wireguard_active_policy.go` 及
  `internal/v2/gatecorchestrator/liveness_*.go`。写前检查与独立 watchdog 同时存在。
  仅匹配 pending 的 PONG 从本地发送时间续租；对端 PING、raw RX/TX、WG 自动控制不是续租 API。
- 两个新增 worker、同时至多两个显式 timer、入/出队各 2、pending 1、high-water 1。
  控制 worker 不调用业务 `ReceivePacket`，不增加 socket/target/attempt/OOB frame。
- FINISH → detach → OOB drain → 原 post-OOB echo → arm → DataPlaneReady。
  原 3/3、R1、8 frame/8,256 byte、Gate B/M 预算、WYCE parser、WireGuard 版本及 Keepalive=0 不改。
- 旧 JSON 的可选字段在无 policy 时不出现；五类新错误及 preflight unavailable 有独立 golden。
  nonce/sequence/密钥/端点不出 witness；输出只有计数、elapsed、绑定成功和 drained。

## 2. 计账解释

| 段 | 扣账/见证 | 是否给 liveness 续租 |
| --- | --- | --- |
| 建立、Gate B、challenge/R1 | 原 governor/probeio 和原 3/3 witness | 否 |
| post-OOB echo | 原一次 WYCE；active datagram witness | 否 |
| WYCL | inner admission：N / N+1 / 2N+1，rolling 20s=4 | 仅匹配 pending 的 PONG |
| WG 自动控制 | active 写前：types 1/2/3/空 type 4，rolling 1s=4、总 4×ceil(T/s) | 否 |
| 业务 | 原 fixed-target 数据面；不扣 probe 5 PPS 或 WYCL 账 | 否 |
| teardown | 原许可仍有效时一次 best-effort CLOSE | 否 |

admission 是不可退款的已接受 intent，不伪称已经成为 OS datagram；writer 失败/撤销可能
使 intent 未发射。NATsim 实际 WriteTo 与 Linux iptables 计数独立核对：
`UDP total = Gate B UDP + challenge/R1 UDP + gate ActiveWrites`，不重复计费。
自动控制另按 initiation/response/cookie/empty 细分，避免把 empty keepalive 冒充 rekey。

## 3. 时钟修订前的本地实测（Windows，Go 1.26.5）

本节保留首次实现结果，不用于否定 §6 的时钟反例，也不替代修订后的验证。

| 证明 | 结果 |
| --- | --- |
| config/tap/clock/codec/model/写强制点 | 四个完整受影响包 `-race -count=20` 通过 |
| 同一 durable owner | normal admission / automatic control excess / bypass / owner unavailable，四路 `-race -count=20` 通过；两种硬违规重开 latch 均阻断，正常限流 clear |
| 正常空闲 | 三 profile 真 WireGuard、每侧 ≥180s，全部通过，双侧每次 8–9 个 PONG proof；未触发旧 15s inactivity |
| 黑洞 | M2/M3 × 双向及两种单向，共 6/6；所有端以 liveness_timeout 干净结束、trip clear、资源归零 |
| 业务共存 | 三 profile 各方向 3 包，逐字节完整交付；控制 tap 不抢业务 reader |
| writer/foreground stall、错误、并发 revoke | 新 fake-clock worker/tap 矩阵 `-race -count=20` 通过 |
| 100 fresh | 全新 credentials/owner/journal/NAT/WG 生命周期轮换三 profile，100/100，无 owned resource residue |
| Linux natlab | 三标签交叉编译通过；本机未运行 Linux namespace，不将编译算作实测 |
| vet / architecture | `go vet ./...`、全量 architecture 与变异检测通过；收尾以当前 head 重跑为准 |

第一轮正常空闲的脱敏双端计数（每格为两个 endpoint 的观测，不推断返回顺序等于 role）：

| profile | elapsed ms | PING | PONG | valid proof | WG control | active UDP | 全 attempt UDP |
| --- | --- | --- | --- | --- | --- | --- | --- |
| predictive | 180007 / 180028 | 9 / 8 | 8 / 8 | 8 / 8 | 1 / 10 | 19 / 28 | 60 / 76 |
| asymmetric | 180005 / 180028 | 9 / 8 | 8 / 9 | 9 / 8 | 5 / 10 | 23 / 29 | 552 / 173 |
| hard-16k | 180006 / 180028 | 9 / 8 | 8 / 8 | 8 / 8 | 3 / 10 | 21 / 28 | 16422 / 16428 |

第一轮黑洞在双方已有一次 proof、约 25s 时注入；M2 在 session elapsed 约 65s、M3 约 85s
结束，均在故障后 45/47s 或 65/67s 停发/排水边界内。旧首轮日志的 `maximum_new_write_ms`
实际上打印的是**约束值**，不是实测最大值；后续测试已改为分别打印实际 last-write delta、
实际 drain delta 与约束，不能把旧字段当作更强证据。

## 4. required CI 与 OS 证明

工作流 `session-liveness.yml` 的非 advisory 聚合 job 检查每条依赖都为 success，跳过也失败。
这不是修改 GitHub branch-protection 设置。

- model/owner：Linux + Windows，受影响包完整 race×20、门禁变异、三类 disposition、业务共存。
- real WireGuard：Linux + Windows，三 profile 180s 空闲并断言真实 rekey 类型；六路黑洞。
- fresh100：独立 Linux job；新 credentials/owner/ledger，失败即停。
- 九路隔离 OS job：loopback SSH 与真实 TUN idle；两种载体各 M2/M3 黑洞；SIGSTOP/SIGCONT；
  post-FINISH parent kill 与 consumer crash。race 二进制及 `WINKYOU_LIVENESS_NETNS_REQUIRED=1`
  强制运行；全部复用 TEST-NET/private mount/SSH/NAT 拓扑，不使用宿主服务。
- SIGSTOP/SIGCONT ≥3s 是真实**进程调度暂停**，两类 OS 时钟仍前进，不等于系统 suspend。
  时钟发散与多次短暂停累计另由固定起点 fake clock 证明。
- OS 输出计数与 ss/process/conntrack/TUN/route/governor lock 的原独立 cleanup 见证必须全部闭合；
  consumer 被 kill 时不伪造其进程内结果，以持久 FINISH 和进程外证据代替。

首次实现 head `1bdf1578e5fae2227e6a526603720ebd8d6a3308` 的全部 checks 为 54/54 SUCCESS；
[Session Liveness 首轮](https://github.com/houyuwushang/winkyou/actions/runs/34201049081)
15/15（含九路 OS）通过。真 TUN idle 双端 elapsed=180025/180022ms，proof=8/8，
WG control=11/4（initiation=1/0、response=0/1、empty=10/3），OS UDP=77/70，
既有资源归零断言通过。这只是该 head 的实测；随后的 §6 自查证明绿色不能代表模型正确。
时钟修订后的最终 run/head 与逐场景数字在本 PR 的验证记录回填，不覆盖上述原始 run。

## 5. 首次失败与边界

- 本次全仓首跑命中既有 Windows `TestRelayWGGoTwoEnginesExchangeIPv4Packets` 启动 timeout
  及 TempDir cleanup residue；保留仓库外首跑日志，不混修 #97/#101/#111。不上传原日志中的
  本机路径、动态 key 或 legacy 调试明文。不能据此称全仓首跑通过。
- 新增测试的一次 vet 报错为使用了 Go 1.25 的 WaitGroup.Go，而模块声明 Go 1.23；已改为
  Add/go/Done。新增 Linux harness 的未用 import 编译错误与 preflight fixture 缺字段均已修正。
  这些是新测试实现错误，不是调大 ADR 工程值、放宽预算或修改旧测试期望。
- 远端原 docs-only head 的失败继续保留在 PR 历史，本实现不以推新 head 隐去旧 RED。
- 当前未观测到需要调大已接受常量的超限；若首次真实工程实测超界，依 ADR 停止并报告，
  不以放宽断言、补发或恢复求绿。

## 6. 时钟修订 A：原反例与实现变化

[原停止报告](https://github.com/houyuwushang/winkyou/pull/112#issuecomment-5581624144)
证明 origin-max 的差值会拉长 R/1s/L 窗口，且直接作为 WG 计费时钟会把合法 UTC 回拨判为 cap。
维护者接受时钟 A 后，`419290b` 先写入 ADR §5.1/§12.4，`e5c915f` 保存永久 RED 回归，
`8bc74ed` 再修实现；没有先改代码再自我批准。

- 每个 pending、最近有效 proof 和 intent 保存两种本地发送时刻。事件年龄是两种
  source-relative 差值的 max，不是两个 max 相减；R/1s/L 相等即过期。
- intent 保留接纳时的原 proof 起点；后来的有效 PONG 不延长该 intent 的原许可。
  阻塞 writer 的 watchdog 与 best-effort CLOSE 使用相同窗口规则。
- fixed-origin 漂移检查、UTC 回拨 witness、原 absolute/固定槽保持；rolling 20s/1s
  只用已验证 monotonic 读数。四次合法 WG control 可跨 RTC 回拨，真正第五次仍在 I/O 前 trip。
- 原双时钟反例、渐进收敛、主导源切换、多次回拨、UTC 较快时提前结束、大 monotonic 起点、
  saturating subtraction、旧 proof grant、writer 卡住与 RTC 调整的组合均进入永久测试。
- 旧 equal-clock 测试只把已移除的单值 `leaseUntil` 内部引用改为 send-mono+L；
  85/145/65s 期望值不变。短 absolute 测试删除已不存在的冗余 lease 字段赋值，仍原样
  断言 5s 相等拒绝。旧 wire/error/config/建立路径 golden 不修改。
- architecture 新增双时钟事件年龄、pending-send 续许可唯一写点、两种 monotonic 计费
  来源、intent/watchdog 写期限的变异检测；未减少原能力门禁。

首轮新回归另有一处测试编译错误：typed int64 常量不能赋值 time.Duration；仅修正测试类型，
保留失败日志。随后三包 focused `-race -count=20` 通过：orchestrator 4.516s、probeio 1.238s、
architecture 24.307s；全仓及 tagged vet 通过。完整矩阵结果以当前 PR 验证记录为准。

## 7. 补充终局证明

- 相同 artifact：三个 profile 双端先完成 FINISH，再释放并重开同一 owner/ledger，重新
  解析原 artifact bytes。必须 `credential_used`、零 factory/stream 调用、无 SSH spawn，
  journal sequence 保持 3；这不是“新 credential 正常启动”的替代证明。
- 非 proof 流量：真实 WG 内存路径持续 I→R/R→I 业务、WG 自动控制、无效认证 raw packet，
  仅丢弃此合成 fixture 的 WYCL。四路均须 0 matching PONG、自然 liveness timeout、
  safety clear；双向业务测试仍逐包校验内容及恰好一次交付。
- 128-byte 丢包选择器只用于该固定合成测试（业务加密后 80 bytes），不是产品分类器，
  不参与生产计费；生产仍只在 inner admission 与公开 WG control type 两点计费。
- required CI 加入上述重启和四路非 proof 流量测试，旧 job、预算、独立评审与隔离范围不变。
