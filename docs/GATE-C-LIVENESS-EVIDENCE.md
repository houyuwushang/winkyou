# Gate C session liveness 隔离实现证据

状态：Draft PR #112 实现中；等待 required CI 与独立复审。不授权 C1c、disposable router、
现场 I/O 或新网络能力。基线 `fde8dfa60b3c4708ca9a2b4fd783270a08c7d87f`。
权威：[Accepted ADR](./adr/ADR-N3C-SESSION-LIVENESS.md) §11/§12 与
[维护者方案 A 裁决](https://github.com/houyuwushang/winkyou/pull/112#issuecomment-5579897333)。

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

## 3. 本地实测（Windows，Go 1.26.5）

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

本文件初次提交时，新 required CI 尚未执行；最终 run/head 与结果须回填，不预报全绿。

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
