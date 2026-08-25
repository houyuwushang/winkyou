# N2d namespace/NAT-lab 双进程组合证明

- 状态：**已合入 main；必跑 Linux CI 已通过；证据仍为 test-only，独立评审记录与 N3 授权另行闭合**
- 权限来源：[`ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md`](./adr/ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md) §6、§9 第 5 步
- 构建约束：`linux && natlab`
- 产品入口：**无**
- 现场网络：**NO-GO**

本证明第一次把已合入的 N2a 协议、N2b 状态机语义与 N2c adapter 放入真实 Linux
network namespace、真实 OS TCP/UDP socket 和受控 NAT 中。它只回答这些组件能否在隔离
实验室内遵守既有预算、顺序、一次凭证和排水契约；不接入 stdio、CLI、runtime、
`wink-signal`、daemon 或计划任务，也不授权 LAN、公网或真实设备测试。

## 1. 隔离拓扑

```text
endpoint A netns -> NAT A netns -> public netns <- NAT B netns <- endpoint B netns
                                      |     |
                              STUN responder
                              opaque TCP rendezvous
```

- 每个 endpoint 是独立子进程，并使用独立临时 machine governor namespace；
- 所有接口地址仅来自 RFC 5737 的 TEST-NET-1/2/3；测试结果与日志不记录 endpoint；
- NAT 通过 netfilter 提供三档：显式 1:1、端口保持的 EIM 参考档；仅端口保持 SNAT、
  保留 conntrack address+port-dependent 过滤的 **port-restricted 档**（盲发同时开洞
  语义所针对的代表场景）；以及随机端口加同样过滤的 EDM 档。两个 NAT 网关像消费级
  路由器一样丢弃发往自身 WAN 地址的未经请求 UDP——否则过早到达的对端开洞报文会被
  conntrack 确认为网关本地流，毒化 SNAT 端口保持，使被测映射失真。WAN 链路统一以
  netem 建模 5ms 传播时延：真实部署中 FIRE 控制路径必然跨 rendezvous（毫秒级），而
  SYN 出站紧随本端 FIRE 写出（微秒级），零时延实验室会反转该物理顺序，使被过滤的
  盲发 SYN_ACK 在无重传的冻结语义下无从恢复；时延建模只还原物理顺序，不改协议；
- public namespace 内运行现有 `internal/stunserver` 与 N2c 的两方、有界、不透明帧
  test server；两者均由 harness 创建和销毁；
- 本地 UDP 仍是 wildcard + ephemeral bind。endpoint 只经 `ProbeSocket.LocalAddr` 取得
  端口，不获得 raw socket、fd、`PacketConn` 或固定接口绑定能力。

## 2. 固定组合顺序

每端均执行同一条不可跳步的管线：

```text
strict artifact parse (zero I/O)
  -> full N2AttemptCost admission
  -> one governed rendezvous preconnect
  -> presence (<= 3s, no pairing data)
  -> durable BURN_AND_ADMIT + authorization consume
  -> activation and empty-payload NNpsk0
  -> encrypted PREPARE
  -> one governed wildcard-ephemeral UDP socket
  -> same-socket STUN
  -> encrypted READY(observed endpoint)
  -> authenticated peer target registration
  -> FIRE
  -> blind SYN/SYN_ACK and ACK on the same socket
  -> bidirectional VERIFY
  -> PromoteTerminal
  -> FINISH + drain
```

完整 attempt 继续预留 N2c 已冻结的 coarse TCP/DNS/UDP 成本。`probeio` controller 使用
一个只能下调、不能扩大 lease 的 UDP 子预算视图，固定为 1 socket、2 target、2
five-tuple、5 packet、5 PPS 和 15 秒；因此 TCP/DNS coarse 预留不能被误用为第二只 UDP
socket。该机制不改变 `N2AttemptCost()`、same-socket 成本或任何既有调用方的默认行为。

## 3. 必跑场景与判定

| 场景 | 必须成立的证据 |
| --- | --- |
| EIM × EIM | 完整顺序成功；STUN 每端 1–3；direct 精确 2/1；control 精确 4/3；UDP 不超过 5/4；双向 VERIFY 是唯一成功终局 |
| port-restricted × port-restricted | 与 EIM 相同的精确出站见证；两侧 NAT 保留 conntrack 回复过滤，入站只能穿过本端出站报文打开的 pinhole；initiator 的 SYN 允许早于对端 pinhole 而被过滤，responder 仅凭 ACK 完成 |
| 任一侧 EDM | 已 burn、不退款、零重试，在既有预算内有界失败 |
| 对端 burn 前缺席 | presence 在 3 秒内超时；ledger admission 为 0；UDP 为 0 |
| 对端 burn 后消失 | survivor 有界 `expired`；admission 保留；无持久 safety trip |
| punch 中崩溃 | survivor 有界结束；同 artifact 重启被 durable ledger 拒绝且零新增发射 |
| 第二 socket / 第三 target / 第六 packet | 在越界动作发生前 fail-closed；持久 safety trip 落盘且新 governor 可复检 |

EIM 成功用例在同一次 required job 中从全新拓扑重复 3 次。所有应用计数都必须与 endpoint
namespace 的 iptables OUTPUT 计数器逐项相等；TCP 只核对应用 frame，不把 frame 数伪装
成 OS packet 数。

## 4. 排水、门禁与隐私见证

每个场景终局后必须同时证明：

- packet 计数器在观察窗口内不再变化；
- rendezvous active connection 回到 0；
- 所有 namespace 的 `ss -p` process-owned socket 数和 `ip netns pids` 进程数为 0；
- owned conntrack 表在显式排水后为 0；
- namespace 与 veth 删除后均不存在；
- endpoint 报告中的 peer、attempt 和资源预留均为 0；
- architecture 变异测试会抓住 product source 使用 N2d helper、
  `AllowedTargetIsolatedUnicast` 或 same-socket `AllowNonLoopback`；
- 测试 stdout 只输出场景名和聚合计数，不含 IP、hostname、用户名、本机路径、artifact、
  credential、endpoint 或 pairing secret；仓库不上传临时配置与结果文件。

缺少 root/netns 权限的本地环境会明确 skip；`WINKYOU_N2D_REQUIRED=1` 时同一情况必须失败，
不能静默跳过。GitHub CI 的 `N2d Netns NAT E2E Proof (required)` job 以 race binary、sudo
netns 和 5 分钟测试超时执行全部矩阵，job 总超时为 6 分钟。

## 5. 复现

需要 Linux、root、Go 与 `iproute2`、`iptables`、`conntrack`：

```bash
go test -race -c -tags=natlab -o /tmp/winkyou-n2d.test ./test/natlab
sudo env WINKYOU_N2D_REQUIRED=1 GORACE=halt_on_error=1 \
  /tmp/winkyou-n2d.test \
  -test.v -test.run '^TestLinuxN2DEndToEndProof$' -test.count=1 -test.timeout=5m
```

合入本证明仍只完成 N2 隔离证据。N3 产品入口、现场授权模板以及任何 LAN/公网 I/O 继续
保持 NO-GO，必须另开 ADR/PR 并接受独立评审。

## 6. Required CI 实测证据

2026-08-24，commit `9b826c4` 的 required Linux race job 在 25.60 秒内完成整个矩阵：

| 场景 | STUN | direct | UDP 合计 | control | TCP frame（写） | 终局 |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| EIM × EIM，repeat 1 | 1/1 | 2/1 | 3/2 | 4/3 | 7/6 | success |
| EIM × EIM，repeat 2 | 1/1 | 2/1 | 3/2 | 4/3 | 7/6 | success |
| EIM × EIM，repeat 3 | 1/1 | 2/1 | 3/2 | 4/3 | 7/6 | success |
| port-restricted × port-restricted | 1/1 | 2/1 | 3/2 | 4/3 | 7/6 | success |
| initiator EDM | 1/1 | 1/1 | 2/2 | 3/2 | 6/5 | bounded expired |
| responder EDM | 1/1 | 1/1 | 2/2 | 3/2 | 6/5 | bounded expired |
| burn 前缺席 | 0/0 | 0/0 | 0/0 | 0/0 | 1/0 | presence timeout, admission=0 |
| burn 后缺席 | 0/0 | 0/0 | 0/0 | 0/0 | 3/0 | bounded expired, no trip |
| punch 中 kill + restart | 1/1 | 1/1 | 2/2 | survivor 2 | survivor 5 | restart ledger reject, zero delta |
| 三类硬违规合计 | 5/0 | 0/0 | 5/0 | 0/0 | 0/0 | each persisted trip |

表中双值均为 initiator/responder。EIM 的实际 UDP 计数是 3/2，低于冻结的最坏上限 5/4；
上限没有因一次响应即成功而缩小。三次成功与两个 EDM 用例的 iptables 计数均逐项等于
应用计数。

所有场景的终局见证均为 `sockets=0 processes=0 active_connections=0`，packet counter
稳定；owned conntrack 在清理前分别处于 1–8 条的场景内有界值，清理后全部为 0，随后
netns 与 veth 均删除。required job 证据见
[`N2d Netns NAT E2E Proof`](https://github.com/houyuwushang/winkyou/actions/runs/32751905287/job/97510574069)。

这些数字是隔离测试证据，不是现场成功率、真实网络地址或产品 SLO。

评审补充（2026-08-25，commit `f698032`）：port-restricted 代表场景由独立评审加入并在
连续四轮 required run 中通过。前两轮 required CI 依次暴露并修正了两个实验室模型缺陷
——网关把发往自身 WAN 地址的未经请求 UDP 确认进 conntrack 从而毒化端口保持，以及
零时延链路反转 FIRE 控制路径与本地 SYN 出站的物理顺序；两处修正都只还原真实路由器
与真实网络的行为，未改动任何协议或预算语义。
