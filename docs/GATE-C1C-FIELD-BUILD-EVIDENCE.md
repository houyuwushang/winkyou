# C1c-2a 端点 field build 隔离实现证据

基线：`9b74fe61fe56384b0eb78dfd1d4d95e4a38fd37a`。日期：2026-09-21。
状态：实现与独立评审准备中；本文不签发 C1c-3，不是现场连通率或可部署声明。
规范：[C1c mini-spec §4](./adr/ADR-N3C-GATE-C1C-DISPOSABLE-ROUTER.md#41-c1c-2-冻结端点实现2026-09-21)。

## 1. 权限与实现差异

- `NewFieldAuthority` 是 #161 不透明 concrete token 的第三个私有 scope：`fieldScope`。
  不恢复可由外部实现的 interface，也不借用 natlab authority。原 Bind/argv/spawn 三处复核保留。
- `fieldc1c` 是独立编译边界。实例严格对齐模板全部 88 字段，绑定 exact SHA、自身文件摘要、
  VCS clean 状态、依赖和两份配置摘要、唯一角色、本机 scope 与有效窗口。
- 首轮只接受 Linux 与 IPv4 literal underlay；observer 为精确双地址/双端口，peer 为单地址。
  factory 绑定 caller 已取得的精确 attempt lease；候选只来自独立重算后的本地 slot/port plan。
  不增加 governor、retry、socket headroom 消费、native WireGuard bind 或生产预算。
- TUN 只添加 trusted config 中的接口、IPv4 地址和唯一 peer `/32`；不替换已有 owner。
  对已有 native/userspace WireGuard owner 保守拒绝，而不是查询别人的私钥或复用其接口。
  配置只用一枚有界本地 AF_NETLINK/NETLINK_ROUTE 控制 fd，不是新增 IP 探测通道。
- 固定 wrapper 与固定 child 使用同一 field binary；wrapper 校验原 command/安装权限后 exec
  替换自身，不新 fork。SSH argv/env 与普通 child schema 不变。普通构建没有 field 子命令。
- 一次私有 evidence 目录 claim 永不自动撤销；stdout 仅白名单。外部残留未知值保持 null，
  不把进程内 close 返回值冒充外部零残留。mapping age 等 router 侧关联证据属于 C1c-2b，
  本 PR 不实现 router/observer 现场工具。

drop privileges、seccomp/landlock、低权限 parser 均未实现；原因与 root 残余风险登记在
[mini-spec §4.3](./adr/ADR-N3C-GATE-C1C-DISPOSABLE-ROUTER.md#43-三项硬化处置与验收)，
实例必须如实接受。固定 argv、tag 与本地双签记录都不等于内核 sandbox 或新数字签名协议。

## 2. RED 与定向验证

首个红回归要求精确 field issuer，未实现时 RED。其后首轮 architecture 对新增依赖和本地
内核 socket 能力报 RED；补入逐文件、逐构造点白名单及变异，而非整体放开 package。
初次删除校验门有三处名称与实现不符，保持 RED 记录，修正测试定位后通过；未改任何预算。
原始本地输出保留仓库外，不入库、不上传原始日志。

完整 architecture×20 首跑 RED（包 533.753s，墙钟 536.753s），仅两类重复签名：
实例中的 `TransportLease` 字符串元数据与能力标识撞名；field adapter 用于拒绝混入 natlab
factory 的 `!= nil` 检查尚无精确例外。前者改 Go 字段名，JSON 键不变且 Gate A 门不改；
后者只允许该 tagged 文件中该 receiver 方法的 nil 拒绝表达式，赋值/返回/反向判断仍由
新增变异拒绝。修正后全 architecture 定向一轮通过 31.752s；原 20 轮 RED 不覆盖、不改写。
复查本批新 netlink 实现时补入 DONE 错误状态检查：非零或未知 payload 不可当作无冲突见证。

修后 architecture×20 另有一次 field 符号构建 120s deadline RED（包 639.210s，墙钟
641.575s），独立登记 [#162](https://github.com/houyuwushang/winkyou/issues/162)。只补稳定
失败类、耗时、输出字节数与摘要，保留 120s 上限；没有原样 rerun 或宣称修复。系统枚举的
`compile -V=full` 条目已退出且未证明属于本批，不能当作活进程残留或超时根因。
独立版本查询 20/20（76–123ms）仅属工具诊断，不能代替失败构建的验收。该批期间有后续
小提交，亦不应冒充最终 SHA 的完整证明。

| 验证 | 已观测结果 |
| --- | --- |
| 严格实例解析、88 字段对齐与空值/未知/重复/SHA/窗口/角色/许可负向向量 | 定向通过，0.889s |
| #161 token + field issuer shape / Gate C1a 边界 | 定向通过，0.675s |
| Linux 全组合标签 vet | 首次通过；无 OS 运行声明 |
| field 包、probeio、SSH 定向 `-race -count=20` | 全部通过；包耗时 13.047s / 1.984s / 1.735s，命令墙钟 20.720s |
| nm：普通、单独 c1bproof、单独 natlab、fieldc1c | 4/4 通过，56.003s；前三者零命中，后者 7/7 正向命中 |
| 删除校验/issuer/标签/构造器变异 | 修正定位后通过，0.929s |
| docs/source 隐私 + 精确边界 + CI 契约 | 定向通过，3.220s |

nm 门显式列举 `fieldc1c.Load`、`sshassembly.NewFieldAuthority`、
`probeio.NewFieldUDPFactory`、`netif.NewFieldInterface`、`tunnel.NewFieldWireGuard`、
`gatecorchestrator.RunFieldInitiator`、`sshchildwrapper.ExecFieldRoot`，使用相同 Linux
目标构建的反向与正向见证。无空正则，不以一条未命中的字符串冒充整个能力集合。

## 3. 完整本地批次

工具链固定 Go 1.23.1；本地 Windows。下表保留首次失败，未完成项不写 PASS。

| 命令 | 首跑状态 |
| --- | --- |
| `go vet ./...` | 首次 PASS；墙钟 23.302s；最终代码复核 PASS，8.984s |
| `go test ./internal/architecture -count=20 -timeout=60m` | 首跑两类边界 RED 已修；修后 120s 符号构建超时 #162，未满足全绿 |
| 受影响包 `-race -tags=fieldc1c -count=20 -timeout=90m` | 首跑 9/9 PASS；墙钟 241.249s |
| `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | #116 分区首跑 PASS，墙钟 273.620s；其中 architecture 单轮 34.230s |
| `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20` | 独立首跑 PASS；包 164.688s，墙钟 174.218s |
| `GOOS=linux CGO_ENABLED=0 go vet -tags=fieldc1c,natlab,c1bproof ./...` | 首次及最终代码复核 PASS；后者墙钟 16.065s |
| 最终源码边界、变异与公开 docs/source 隐私门定向 `-count=20` | PASS；包 24.777s，墙钟 27.172s；不包含失败的 nm 构建批次，不替代完整 architecture×20 |
| 相对链接、`git diff --check` | 提交前检查通过 |

受影响包集合为 fieldc1c、probeio、sshassembly、directconnect/gateb、gatecorchestrator、
sshchildwrapper、netif、tunnel、cmd/wink/cmd。Windows 不执行 Linux TUN；该层由下述 required
Linux job 的 `-race -count=20` 单元边界与真实 OS 证明承担，不能记成本机已实测。

包耗时依次为 13.849s、235.057s、97.121s、2.596s、5.090s、1.416s、2.532s、4.619s、
55.135s。包间按 Go 默认调度；没有额外压力程序或另一重验收批次同时运行。

## 4. Required exact-binary netns 证明

测试 harness 标签为 `linux && natlab && c1bproof && fieldc1c`；被测产品二进制只有
`fieldc1c`，由完整提交 SHA 注入且带 race。实际经历 canonical 实例预检、固定路径 wrapper
exec、真实 SSH child、governed UDP、Promote、真实 WireGuard 和 owned TUN。
不会使用注入 runner 或复用 test authority 代替 field binary。

| 场景 | 必过见证 | 当前状态 |
| --- | --- | --- |
| predictive APDM × APDM | 真实双端字段校验、密文打洞、TUN kernel ICMP 往返、单次 SIGINT 与全部 owned drain | 待 CI 首跑 |
| asymmetric initiator mapping-set | 同一完整实例链；原预算与 plan 不变 | 待 CI 首跑 |
| 两场景公共残留门 | packet 计费与进程外计数相等；接口/地址/路由、socket、进程、conntrack、governor lock 归零 | 待 CI 首跑 |

所有地址来自仓库已冻结 TEST-NET topology；配置、密钥、实例与原始 evidence 只在测试私有
临时目录。job 只发布固定 stage/class、计数与布尔见证，不上传这些文件。REQUIRED 开关缺
失时本地干净 skip；CI 明确置 1，环境不可用即失败。没有本机 Linux 权限时不以静态验收
代替 OS 证明。

新增 job 预算按 1.25 倍推导，向上取整到分钟：

| 项 | 秒数 / 依据 |
| --- | --- |
| 既有 C1b job 准备至证明启动 | 63；main run `35594822353` 的首跑时刻差 |
| 四组 nm 构建与检查 | 56；本批首次本地实测 |
| 额外 exact field binary build | 23；同 baseline build step 作为初始测量代理 |
| 定向 field race | 21；本批首次本地实测向上取整 |
| 隔离矩阵 | 240；两个场景的测试总 envelope，不是成功耗时承诺 |

`ceil((63 + 56 + 23 + 21 + 240) × 1.25 / 60) = 9` 分钟。
workflow 与契约测试同时锁定 9min job、4min matrix、count=1、REQUIRED、真实 field binary。
CI 实际首跑用时与结果另列，代理测量不得标作 CI 已通过。

## 5. 交付边界

### 5.1 首轮隔离 CI 的 RED（2026-09-22）

提交 `496ec4a` 的 push run `35622299123` 与 PR run `35622347468` 均在真实 field proof 的
predictive 场景失败（总测试均 57.28s）：两端 `wireguard_binding_failed`，未达到 data-plane ready。
此前该 job 的 Linux vet、专用单元 race×20、架构/符号门及 exact binary 构建均已通过。
不能把这些前置成功写成端到端成功；asymmetric 未执行，完整残留见证也尚未成立。

原日志只输出终局 stage，掩盖了失败前的阶段。下一诊断提交仅在测试失败报告中输出已有证据的
最后非 terminal 阶段、接口/tunnel 关闭布尔值、WireGuard readiness/消息计数与 FINISH 布尔值。
不增加产品 hook、不打印原始证据/身份/地址、不改失败条件或时限；不是同一代码 rerun。
根因目前未定位，不猜测，也不把本轮失败归入旧 flake。

诊断提交 `038d1e5` 的 push run `35623758358` 再现同一失败（57.17s）：两端接口均已关闭、
tunnel 均已停止，consumer-ready 为 false，readiness 与 WireGuard 收发计数全为零，FINISH 为 true。
这证明接口创建与 WireGuard Start 已走过，不证明错误落在其中。后续仅为新 field 对象增加私有
操作结果见证：Start/AddPeer 是否调用及成功、TUN reader 是否在 close 前失败、失败的原有阶段。
不收集底层错误原文或密钥；包装只透传既有返回值，保留 one-shot handshake 接口，不改协议与时限。

两份首次完整下载日志仅留仓库外，SHA-256（push / PR）分别为
`9c0efb7af8ec2d7c3ec98fb6732c56829c2876f06f1943b2b9c838a7544576bc` /
`4af58bbb91e827746eb374e53feeb2bb83732441eb94a3dc93b7fdaa547c21ee`。

只交 C1c-2a Draft PR，等待独立复审、不合并。C1c-2b 本轮未实施，C1c-3/C2 未授权。
未连接现场地址、未创建云资源、未部署 server、未改宿主网络/防火墙/服务/计划任务。
安全任务保持 Disabled；仅既有 loopback 测试与 required TEST-NET netns 可以产生测试报文。
