# ADR：N3c Gate C1 SSH/OOB assembly 与产品入口设计冻结

- 状态：**Draft（2026-08-31）：仅供独立评审；本 PR 为 docs-only，不授权实现、构建现场
  binary、SSH 连接、非回环 UDP、WireGuard 接线、disposable router 或任何现场 I/O**
- 日期：2026-08-31
- 基线：`main` = `39ff9780ec295ca8af7339bca8f5e023adf17931`
- 跟踪议题：[#98](https://github.com/houyuwushang/winkyou/issues/98)
- 上位决策：
  [`ADR-N3C-OOB-DIRECT-HANDOFF.md`](./ADR-N3C-OOB-DIRECT-HANDOFF.md)、
  [`ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md`](./ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md)、
  [`ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)、
  [`PAIRING-RESTART-SAFETY-CONTRACT.md`](../PAIRING-RESTART-SAFETY-CONTRACT.md)、
  [`CANCELLATION-DRAIN-CONTRACT.md`](../CANCELLATION-DRAIN-CONTRACT.md)
- 空白现场模板：
  [`N3C-GATE-C-LIVE-AUTHORIZATION-TEMPLATE.md`](../N3C-GATE-C-LIVE-AUTHORIZATION-TEMPLATE.md)

> 本 ADR 回答“怎样把已经通过隔离评审的 Gate A/B 能力装配成第一次可审查的产品路径”。
> 它不把设计文档当作网络权限，也不把一次真实成功当作普适 NAT 穿透证明。只有本 ADR
> 经独立评审 Accepted、对应实现 exact SHA 复审通过、disposable-router 门闭合，并为具名
> 环境填写一份未入库的授权实例后，维护者才能另行签发一次现场 invocation。

## 1. 用户、任务与可观察成功

目标用户是同时控制两台设备、但不能控制两侧 NAT 的开发者或小团队。两台设备已经通过
现有 SSH/overlay 管理路径可达，并完成带外身份核对；用户希望管理路径只承担一次建立控制，
最终业务数据改走独立、端到端加密的 UDP P2P 路径。

本 Gate 的 job-to-be-done 是：

> 操作员显式选择一个已评审 profile，用一个一次性 credential 和一个固定 plan，经一条
> host-key pinned、仅公钥认证的 SSH 子流交换有界控制；得到 verified `PacketTransport`
> 后把它交给同进程 WireGuard consumer，关闭 SSH 子进程，并证明 WireGuard 数据仍能双向
> 到达。失败时保留原管理路径，不重试、不扩大计划、不启动恢复循环。

可观察成功必须同时满足：

1. profile、完整 worst-case cost、conditional probability 与限制在任何网络 I/O 前可见；
2. SSH 只产生一个子进程、一个 TCP 连接和一个 OOB byte stream；
3. UDP socket、target、five-tuple、packet、PPS 与 lifetime 逐字消费 Gate B 冻结 envelope；
4. 双向 VERIFY 后，同一 fixed-target socket 进入 `TransportLease`，旧 probe 句柄永久失效；
5. WireGuard pre-FINISH challenge 通过，durable FINISH 先于 attempt release；
6. SSH 子进程和 OOB stream 排空为零后，再有一轮 WireGuard 数据证明成功；
7. 最终 packet witness 证明数据不经过 SSH/OOB relay；
8. Ctrl-C、child death、consumer crash 和普通失败均有界关闭，进程/socket/lock/conntrack
   residue 为零。

这与 FRP、普通 SSH 端口转发或 relay 的差异是：SSH 不承载最终数据，也不提供目的端口
转发；它只交付端到端加密的建立控制。WinkYou 的价值仍是状态层析、固定成本求解与
`PacketTransport -> WireGuard` 交接，不是再实现一个通用反向代理。

## 2. 已闭合前提与本 Gate 必须解决的缺口

### 2.1 Gate B3 的隔离前提已经闭合，但权限没有继承

PR #96 的最终 head `553b4c8152979a9ecf66eaf6a2b40c9e8d1964b3` 已由独立复审接受，
§20 的单 winner、rolling-PPS lane、terminal drain、`EXHAUSTED`、UDP commit point 与
shared-deadline 六项闭合也被明确接受；随后以 merge commit
`39ff9780ec295ca8af7339bca8f5e023adf17931` 合入 `main`。

这只证明 memory/natsim/required netns 内的隔离实现。现有 architecture gate 仍正确阻止
stdio、CLI、runtime、scheduler、legacy、WireGuard 和普通 build 构造 Gate B executor 或
非回环 factory。本 ADR 不从 PR #96 继承任何现场权限。

### 2.2 stdio 进程不能跨进程移交 Go transport

`winkyou.stdio/v2` 的 `connect_test` 只返回脱敏结果并关闭 transport；它不拥有长期
WireGuard session。让独立 `wink solver serve --stdio` 进程把 Go
`transport.PacketTransport`、socket 或 fd 交给另一个 `wink up` 进程，会新增未经设计的 IPC、
fd/handle transfer、双 owner 与 crash recovery。

因此 Gate C1 裁决为：

- v1/v2 schema、方法集、golden、loopback 与 N3b behavior 逐字节不变；
- **首个产品入口使用同进程、前台、one-shot CLI，不实现 stdio v3；**
- `winkyou.stdio/v3` 仅保留为未来版本名，不在本 Gate 注册、advertise 或协商；
- 不把 transport、socket、fd、PacketConn 或 handle 返回给调用方。

只有未来另一个 ADR 能决定 stdio server 是否自己拥有完整 tunnel/session，或设计经过审查的
跨进程 session IPC；本 Gate 不猜测该答案。

### 2.3 真实 target 不能由远端 report 决定

Gate B2 首轮评审已经证明，任意 global-unicast boolean 会把远端自报地址变成 LAN/公网发包
能力。Gate C 不能简单删除 natlab allowlist 后复用该模式。

第一版使用本地、私有、逐实例的 `expected_peer_public_address` 作为 target authority：

- 它由本地操作员在具名窗口内显式批准，不进入 artifact、OOB frame、repo 或日志；
- 它只是一枚 canonical literal IP，不接受 hostname、CIDR、range、port list 或第二地址；
- 远端 authenticated evidence/source commitment 必须与该地址一致，否则在 direct emission
  前返回 `peer_address_not_authorized`；
- port 只来自本地重新计算的 exact plan。request、artifact 或 peer 都不能上传 port/span、
  candidate、socket、PPS 或 packet count；
- observer endpoint 另有 exact allowlist，不能成为 peer candidate target；
- address 在 attempt 中变化即终局，不更新 authority、不换地址、不 fallback。

这是一项**逐实例操作员授权**，不是对地址所有权的互联网级密码学证明。若产品以后允许
不互信的两个 operator 自动建立，必须先引入 independently reviewed、签名的 observer
attestation；本 Gate 不把普通 RFC 5780 响应伪装成可转授的所有权证明。

特别地，`hard-16k` 向一个地址的 16,384 个端口发射可能触达共享 CGNAT 上其他订户的映射。
首次 live hard-16K 不得只凭“两台设备归同一用户”推导出地址级权限；必须证明目标是受控
disposable gateway/独占地址，或取得地址/网络 operator 的明确许可。没有该外部证据时，
`hard-16k` 只能停留在 natsim/netns/disposable-router，不能由确认 flag 解锁到共享公网。

### 2.4 SSH lifetime 必须服从 profile，而不是固定写死 13 秒

Gate A 的未来 SSH 注记使用 13 秒；Gate B2/B3 后来分别冻结 20 秒与 45 秒绝对 active
envelope。Gate C 不提高任何值，而是让 assembly 从 exact profile 表取得不可修改的 deadline：

| profile | active | drain-only | SSH connect/presence 子上限 |
| --- | ---: | ---: | ---: |
| `predictive_edm/1` | 20s | 2s | 3s |
| `asymmetric_birthday/1` | 20s | 2s | 3s |
| `hard_birthday_campaign/1` + `hard_16k_lab/1` | 45s | 2s | 3s |

SSH child、carrier、UDP executor、handoff 与 pre-FINISH challenge 共用同一个 absolute context；
2 秒只用于 FINISH 后排水。caller 不能提供更长 duration。若本表未被独立接受，Gate C1a
只能测试 Gate A 的 13 秒 profile，不能装配 Gate B。

## 3. Gate C 拆分与权限递增

上位 ADR 要求 Gate C 至少拆开 SSH assembly 与产品入口/campaign。实现顺序冻结为：

1. **Gate C1a：SSH assembly + 新 artifact/generator/staging。** 一个 Draft PR；只允许纯内存、
   fake child 与 literal-loopback SSH integration。不得导入 probeio、Gate B executor、
   WireGuard 或构造非回环 UDP。
2. **Gate C1b：前台产品 composition。** 一个独立 Draft PR；把 caller-owned stream、Gate B、
   production `TransportLease` consumer 与 WireGuard memory-TUN/required netns 组合。普通
   LAN/公网 factory 仍不存在，不能据此现场运行。
3. **Gate C1c：disposable-router field build。** 另行授权的 exact-SHA PR/构建；只增加本 ADR
   的单地址 target authority 与具名 observer allowlist，不进入默认 `wink up`，先在一次性
   路由器完成近尾命中、exhaustion、crash 与 teardown。
4. **Gate C2：具名现场窗口。** 不再改代码；每个 scenario 使用单独未入库模板、credential、
   invocation、kill switch 与第二人复核。任何代码变更都使既有签发失效。

不得把 C1a、C1b、C1c 合并为一个“先拿到能力再补门禁”的 PR。Issue #97 的 legacy
relay-wggo 启动停滞独立处理，不混入 Gate C；若现场 workflow 依赖 relay，则必须在对应窗口
前闭合该问题。

## 4. Product artifact、manifest 与本地 request

### 4.1 Exact identifiers

Gate C 不把 `test-only` artifact 改名后继续复用 parser。新 exact profile 为：

```text
artifact_profile: winkyou-direct-oob-attempt/1
manifest_profile: winkyou-direct-oob-manifest/1
direct_attempt_profile: winkyou-direct-hard-nat-control/1
oob_carrier_profile: ssh-bounded-child-stream/1
local_request_schema: winkyou-gate-c-local-request/1
data_plane_consumer_profile: wireguard-direct-session/1
data_plane_challenge_profile: wireguard-handshake-echo/1
secure_channel_profile: noise-nnpsk0-25519-chachapoly-sha256/1
auth_scope: operator-initiated-one-shot/1
runtime_fallback: disabled
```

artifact 继续固定 generation=1、双方 machine scope、initiator/responder、五个 pairwise-distinct
ID、十分钟时效、PSK、planner profile/resource class 与 asymmetric planner roles。以上所有
profile、role、generation、no-fallback、OOB channel ID、Gate B execution-envelope digest 与
data-plane consumer/challenge profile 都进入 Noise prologue 或固定 authenticated AD。

`auth_scope` 只阻止后台、scheduler 与自动恢复消费该 artifact；它不是 live authorization，
也不能代替 §11 的双人签发记录。

以下 parser 必须两两互拒并有 golden：

- N3b `winkyou-test-direct-attempt-oob/1`；
- Gate A `winkyou-test-direct-oob-attempt/1`；
- Gate B `winkyou-test-hard-nat-attempt/1`；
- Gate C `winkyou-direct-oob-attempt/1`。

Gate C 只允许：

| 用户选择 | planner profile | resource class | 角色规则 |
| --- | --- | --- | --- |
| `predictive` | `predictive_edm/1` | `predictive_32/1` | initiator/responder |
| `asymmetric` | `asymmetric_birthday/1` | `asymmetric_128x512/1` | operator 固定 mapping-set 一侧 |
| `hard-16k` | `hard_birthday_campaign/1` | `hard_16k_lab/1` | initiator/responder |

`hard_32k_candidate/1`、full-65K、unknown profile/resource 与交叉组合始终零 I/O 拒绝。

### 4.2 离线生成命令

提案命令：

```text
wink solver pair oob \
  --profile predictive|asymmetric|hard-16k \
  [--mapping-set-role initiator|responder] \
  --out-dir <NEW_PRIVATE_DIRECTORY>
```

规则：

- `--out-dir` 必须不存在；拒绝 symlink/reparse、pre-created leaf 与不安全 parent；
- 只生成 `initiator.artifact.json`、`responder.artifact.json`、`manifest.json` 三个文件；manifest
  最后原子落盘，目录/文件权限沿用已评审 pair generator 的 owner-only 规则；
- endpoint、SSH user、identity path、host key、命令、observer、WireGuard key、peer address 与
  authorization instance 不进入 artifact 或 manifest；
- PSK、fingerprint、ID、文件内容和输出路径不进 stdout/stderr/log；成功只输出稳定
  `oob_pair_created`；
- Gate C **不提供 clipboard**。这比 N3b 更窄，避免 high-cost campaign secret 留在 clipboard
  history；
- `asymmetric` 必须显式指定 mapping-set role；其他 profile 出现该 flag 即拒绝；
- 生成 `hard-16k` artifact 的确认 flag、文件或模板不能被描述为网络授权。只有另行签发的
  exact-SHA live instance 才能授权一次 invocation。

### 4.3 私有 local request

artifact 不承担本地 routing 与数据面配置。每台设备另有一份**不得提交仓库**的严格 JSON：

```json
{
  "schema": "winkyou-gate-c-local-request/1",
  "role": "initiator",
  "artifact_file": "<PRIVATE_LOCAL_FILE>",
  "peer_ref": "<LOCAL_CONFIG_PEER_REF>",
  "expected_peer_public_address": "<CURRENT_LITERAL_IP>",
  "observer_set": {
    "primary": "<LITERAL_ADDRPORT>",
    "alternate_port": "<LITERAL_ADDRPORT>",
    "alternate_address": "<LITERAL_ADDRPORT>",
    "alternate_address_port": "<LITERAL_ADDRPORT>"
  },
  "ssh": {
    "endpoint": "<LITERAL_ADDRPORT>",
    "user": "<PRIVATE_USER>",
    "identity_file": "<PRIVATE_KEY_FILE>",
    "known_hosts_file": "<PINNED_ONE_HOST_FILE>"
  }
}
```

上例只定义字段，不是可运行配置。responder request 必须省略 `ssh`；initiator 必须包含。
outer/observer/ssh 对象全部拒绝 unknown/duplicate member，文件最大 16 KiB。规则为：

- `artifact_file` 只在本机读取，必须是 owner-only regular file，拒绝 symlink/reparse/hardlink
  异常；artifact bytes 不复制进日志、argv、环境或 OOB adapter；
- `peer_ref` 只能查找已有本地 WinkYou/WireGuard peer identity；request 不能携带私钥、
  public key、AllowedIPs、route、interface、keepalive 或替换 peer identity；
- `expected_peer_public_address` 是一个 canonical literal IP，无 zone/DNS/CIDR/list；
- RFC 5780 observer set 必须满足 A1:P1、A1:P2、A2:P1、A2:P2 的双地址/双端口 topology，
  全部 canonical literal、同一地址族、互不混淆；operator permission 只写私有授权实例；
- `ssh.endpoint` 只接受一个 canonical literal IP:port，0 DNS；不接受 host alias、ProxyJump、
  URL、command、extra argv 或 endpoint list；
- raw request、path、user、address 与 host key 永不进入 progress、terminal result、report 或
  repository artifact。

### 4.4 responder staging

为了让 SSH remote command 保持固定、避免把 secret/path 拼进 remote shell，responder 先在
本机离线执行：

```text
wink solver direct stage --request-file <PRIVATE_RESPONDER_REQUEST>
```

它只做本地严格校验并以 O_EXCL 将一份 pending request 放入 canonical private slot；不开
socket、不取得 active governor、不 burn credential。规则：

- 每台机器最多一个 pending slot；0 个或多于 1 个都使 remote child 零 I/O 退出；
- stage 成功不授权 attempt，也不绕过十分钟 artifact expiry；
- remote child 启动时原子 claim slot，claim 后 child death 不自动 re-arm；
- 过期/失败 slot 只能由显式、expected-fingerprint 匹配的本地清理命令移除；不提供扫描、
  retry、queue 或 daemon；
- slot、fingerprint、path 与 request 内容不出现在 SSH command、进程 witness 或日志。

## 5. SSH/OOB assembly

### 5.1 包边界

首个实现包暂定 `internal/v2/sshassembly`。它只接收已经严格解析、**不含 PSK/artifact bytes**
的 local SSH config、exact profile deadline 和一个 process/drain lease，返回 Gate A
`BoundedStream`。

它可以使用 `os/exec` 启动系统 OpenSSH，但不得：

- import Gate B planner/executor、probeio、WireGuard、legacy/Tailscale SDK；
- 调用 shell、`cmd.exe`、PowerShell、`sh -c` 或拼接 operator command；
- dial/listen/DNS/reconnect/poll/ControlMaster/ProxyCommand/ProxyJump；
- 读取 artifact、PSK、WireGuard key 或把 stdout 当日志；
- 暴露 raw `*os.Process`、pipe、fd 或 arbitrary `io.ReadWriter` 给 product caller；
- 接收裸 `netip.AddrPort`、字符串 endpoint 或 request 结构体作为发包权限。

### 5.1a 密封 SSH endpoint authority 与 exclusive assembly sub-lease

仅禁止 DNS/ProxyJump 不能限制 SSH/TCP 的目的地址。为了让 SSH child 服从与 UDP factory
相同的四级 capability 递增，`sshassembly` 只接受一个不可伪造的
`SSHEndpointAuthority`（最终名称由 C1a 实现 PR 固定）作为唯一 endpoint 来源：

- **C1a/C1b ordinary build** 只能构造 literal-loopback authority；任何非回环地址在构造时
  fail-closed。required Linux netns 证据使用 build-tagged sealed helper，仿照 Gate B2/B3 的
  `IsolatedNATLabFactory` 模式：验证当前 network namespace 身份并把 endpoint 固定为仓库
  TEST-NET topology 常量，不接受调用方地址；
- **C1c exact field build** 才允许从一个私有 authorization instance 构造恰好一个非回环
  endpoint authority；spawn 前 assembly 必须对 authority 再次核验 endpoint、地址族与端口，
  第二 endpoint、attempt 中地址变化、raw config/argv 直达 `exec.Command` 全部 fail-closed；
- authority 是 value-sealed capability（unexported marker method），product caller、request
  parser 与 orchestrator 都不能自行合成；local request 的 `ssh.endpoint` 字段只被用来与
  已签发 authority 精确比对，不再直接成为 spawn 参数。

initiator 的 `SSHAssemblyCost`（1 owned child / 1 outbound TCP / 0 DNS / 0 retry / 0 queue）
不是仅做结构体相等判断的注记，而是同一 attempt lease 上不可互换的 exclusive sub-lease：
assembly 在 spawn 前必须 `ClaimExclusive` 一个 Gate C 专属 claim 名并 `RegisterDrain`；
one-spawn 状态使同一 attempt 的第二次 spawn 在 `exec` 前失败。responder child 由 sshd 启动，
必须在原子 claim pending slot 后、任何 socket/governor 消费前取得同一 machine governor
owner；取不到 owner 时零 I/O 退出且不 re-arm slot。

### 5.2 固定 OpenSSH profile

production 只允许系统已知位置的 OpenSSH client；普通 PATH shadowing 和 request-provided
executable 均拒绝。Windows 与 Linux 的 exact path 列表由 C1a 实现 PR 固化并单独评审。

首个现场 platform matrix 只接受 **Windows initiator -> Linux responder**；这与项目的第一
GPU/lab 用户故事一致。Linux -> Linux 可以作为 CI/disposable-router 证据，但不会自动扩展
首个现场授权；macOS、Windows responder 与第三方 SSH client 均留给后续 ADR。

参数语义固定为：

- `-F none`：按 OpenSSH 官方语义同时禁止读取 user 与 system-wide ssh config，是唯一
  可证明的"零配置文件"方式；不得用"不传 `-F`"或只覆盖个别 keyword 代替；
- `BatchMode=yes`、`NumberOfPasswordPrompts=0`；
- `PasswordAuthentication=no`、`KbdInteractiveAuthentication=no`、
  `GSSAPIAuthentication=no`；
- `PubkeyAuthentication=yes`、`IdentitiesOnly=yes`、`IdentityAgent=none`，恰好一个
  private key file，不咨询 agent；
- `StrictHostKeyChecking=yes`、`UpdateHostKeys=no`、`VerifyHostKeyDNS=no`、
  `CheckHostIP=no`，`UserKnownHostsFile` 指向恰好一个 owner-only 单条目文件，
  `GlobalKnownHostsFile=none`；
- `ControlMaster=no`、`ControlPersist=no`、`ControlPath=none`；
- `ProxyCommand=none`、`ProxyJump=none`、`CanonicalizeHostname=no`；
- `ClearAllForwardings=yes`、`ForwardAgent=no`、`ForwardX11=no`、`Tunnel=no`、
  `PermitLocalCommand=no`、`SessionType=exec`，无 `-L/-R/-D/-W`、`-T` 禁用 TTY、
  `EscapeChar=none`；
- `ConnectionAttempts=1`、`ConnectTimeout` 不超过 profile 的 3 秒子上限；无 application
  reconnect；
- remote command 是固定常量 `wink solver direct child --stdio`，没有 request-derived token、
  path、environment 或追加 argv；
- child 进程以显式最小 environment 启动（`os/exec` 传入固定 env 列表，不继承 parent
  environment 中与 SSH 行为相关的变量，特别是 `SSH_AUTH_SOCK`、`SSH_ASKPASS*`）。

C1a 必须为每个受支持平台提交两类 golden：完整 argv golden 覆盖上述每个禁用项，以及
`ssh -G` effective-config golden 证明这些 override 在该平台 exact OpenSSH 版本上逐项生效。
任一 keyword 在目标平台不被支持或 `-G` 输出与期望不符，该平台 fail-closed。实现不得在
本表之外自行挑选"语义等价"参数。

responder 端必须使用一把只服务本 Gate 的 SSH public key，其执行域按以下规则闭合，而不是
依赖 `restrict` 一个词：

- OpenSSH 官方语义下 forced command 仍经用户 login shell `-c` 执行，且原始 client command
  会暴露为 `SSH_ORIGINAL_COMMAND`；因此 `authorized_keys` entry 的 `command=` 必须是一个
  **固定绝对路径**指向已审核的 Gate C child wrapper，不含任何相对路径或 PATH 查找；
- wrapper 与其所在目录必须是 root/owner-only regular file，拒绝 symlink、hardlink 与
  group/other 可写 parent；wrapper 只以绝对路径 `exec` exact reviewed binary 加固定 argv；
- wrapper 启动时清空继承 environment 并只设置固定最小值与 umask；`SSH_ORIGINAL_COMMAND`
  要么被忽略、要么与固定常量逐字验证，验证失败零 I/O 退出；
- server 侧 `PermitUserEnvironment=no` 必须生效，entry 不携带 `environment=` 选项；
- entry 使用 `restrict`（禁用 forwarding/agent/X11/pty/user-rc）加固定 `command=`；该
  dedicated account/key 不允许普通交互 shell 用途；
- 私有部署/授权记录必须包含：dedicated account 的 login shell、forced-command 绝对路径、
  wrapper 与 binary checksum、`authorized_keys` entry checksum，以及一份
  `sshd -T -C user=...,addr=...` effective-config 证明（含 `permituserenvironment no`）。

普通可登录 shell 的既有 key 不满足首个现场门。安装或修改该 entry 属 C1c 的另行部署授权，
本 docs-only PR 不执行。

如果某平台 OpenSSH 不能逐项证明这些 override 生效，该平台在 C1a 中 fail-closed，不用
第三方 SSH SDK 或放宽参数补齐。

### 5.3 stream、stderr 与进程所有权

- child stdin/stdout 是唯一 OOB byte stream；stdout 只能包含 WYRC frame，任意 banner/text
  触发 `oob_protocol_violation`；
- stderr 单独读取，最多 4 KiB，只映射稳定 class，内容随后清零且不回传；超限终止 child；
- carrier 继续执行每方向 8 frame/8,256 application byte ceiling；SSH/TCP OS packet 数不得
  从 frame 推导；
- initiator 的 assembly cost 是 owned OpenSSH child=1、outbound TCP connection=1、DNS=0、
  retry=0、queue=0；这些是编译期 `SSHAssemblyCost`，必须与 selected profile 一起在 spawn
  前精确校验；responder 不再 spawn 第二个 child，它本身就是 sshd 启动的 fixed endpoint
  process，并只接受该一条 SSH channel；
- active context cancel、EOF、deadline、parent death 或 child death 立即关闭 pipes、请求
  child 退出并等待；2 秒 drain 结束仍存活才强制 kill；
- witness 只报告 spawned/exited/killed、stdin/stdout/stderr bytes、deadline、drained，禁止
  endpoint、username、path、host key、PID、command 或底层 error。

关闭 dedicated SSH child 不得停止、重配或删除 operator 的 Tailscale、VPN、SSH server、
route、firewall 或其他管理信道。

## 6. 前台产品入口与 fixed pipeline

### 6.1 命令与生命周期

initiator 的首个入口提案为：

```text
wink --config <PRIVATE_CONFIG> solver direct connect \
  --request-file <PRIVATE_INITIATOR_REQUEST>
```

命令保持前台直到 session 结束；成功前后 stdout 都不承载 secret。remote side 只由固定 SSH
child command 启动。此 Gate 不增加 daemon、service、scheduled task、`wink up` strategy、
runtime recovery、startup persistence 或后台 improvement。

Ctrl-C 是唯一普通停止入口；它取消 session、关闭 WireGuard transport、排空 child/UDP 并
退出。process crash 由现有 durable ledger 在重启时拒绝同 credential 继续发送。不存在
“恢复上一次 direct attempt”或“重新 attach pending slot”。

### 6.2 固定顺序

Gate C orchestrator 不复制 Gate B 协议，按以下顺序组合：

```text
strict local request + product artifact + local peer/config validation (zero I/O)
  -> read-only machine scope / safety trip / ledger / pending-slot preflight
  -> freeze exact profile cost + local target authority
  -> acquire one machine owner + complete attempt reservation
  -> spawn/adopt one SSH bounded child stream
  -> secret-free presence
  -> durable BURN_AND_ADMIT
  -> Noise + PREPARE
  -> accepted Gate B fresh evidence / bilateral plan / READY-FIRE semantics
  -> emit the fixed plan once
  -> authenticated winner + bidirectional VERIFY
  -> issue exact production TransportLease before PromoteToLease
  -> same-socket PromoteToLease; poison old probe handles
  -> WireGuard consumer adopt + mark standby
  -> bounded WireGuard handshake/echo challenge
  -> durable FINISH
  -> detach attempt; close and drain OOB child
  -> post-OOB WireGuard echo
  -> data_plane_ready; foreground session remains until cancel
```

任一步失败都不重试、不换 SSH endpoint/host key/observer/address/profile/seed/universe，不启动
第二 attempt。现有管理 underlay 不被关闭。`mapping_not_directly_usable`、evidence insufficient/
drift、candidate exhaustion、child EOF 和 data-plane failure 都是本 invocation 的终局。

### 6.3 WireGuard consumer

新增的唯一 production consumer kind 为 `wireguard-direct-session/1`。它由 Gate C orchestrator
以本地 trusted peer config 创建，artifact、OOB frame、remote report 与 planner 都不能签发
lease 或改变 peer binding。

consumer 必须：

- 只接收一个 lease-owned fixed-target `PacketTransport`；
- 复用已有 `pkg/session` binder 与 `pkg/tunnel` transport boundary，不把 Gate B 细节放进
  tunnel；
- peer public key、AllowedIPs 与 virtual identity 只来自本地现有 config；request 只能用
  `peer_ref` 查找，不能覆盖；
- pre-FINISH 使用 `wireguard-handshake-echo/1`：persistent keepalive=0，最多每方向 3 个
  outer WireGuard datagram、最长 3 秒、0 retransmission；超出 ceiling 在下一次 write 前关闭
  transport，不能把它记入 probe 5/64/512 PPS；
- challenge 通过后先 durable FINISH，再 detach attempt。正常 WireGuard 用户流量此后由
  `TransportLease`/foreground session 独立拥有，不消耗已经结束的 establishment budget；
- OOB child 完全退出后，再完成一次固定 in-tunnel echo；失败则关闭 session，稳定返回
  `post_handoff_validation_failed`，不复活 OOB、不 retry direct；
- session cancel/consumer crash 在 2 秒内关闭 transport、tunnel peer 与 interface ownership，
  不触发新 attempt。

#### 6.3a Lease-bound WireGuard gate 与冻结的 challenge 顺序

"每方向最多 3 个 outer datagram"必须由一个 lease-bound gate 在 I/O 前强制执行，而不是事后
计数。仓库现状不能直接承载本节保证：`pkg/tunnel` 的 transport bind 以
`context.Background()` 写底层 `PacketTransport`，`TunnelBinder.Bind` 在 AddPeer 后即返回，
`TransportLease` 也不区分 capped challenge 与 FINISH 后正常数据。C1b 实现因此必须：

- 在 lease 层新增 production WireGuard gate（最终命名由实现 PR 固定），状态机至少为
  `standby -> challenge_capped -> challenge_passed -> finish_detached -> active`。
  `challenge_capped` 阶段第 4 个 outer write 必须在底层 I/O 前失败并关闭 transport；所有
  write 受同一 absolute/caller context 约束，`context.Background()` 直写路径对 Gate C
  consumer 不可达；durable FINISH 成功后才能原子解除 challenge cap，FINISH 失败则 cap
  永不解锁；
- 冻结 challenge 注入顺序以匹配当前 wireguard-go（`f333402bd9cb`）真实行为：initiator 在
  启用 peer **之前**先 stage 一个 attempt/context/role-bound inner echo request，使
  handshake response 到达后 `SendKeepalive` 发送的是 staged data 而非空 keepalive。成功
  路径固定为 initiation → response → data(echo request) → data(echo reply)，双方各 ≤3。若
  实现选择不预 stage，则 initiator 第 3 个额度必须显式记为 handshake 完成时的 keepalive，
  且 echo 移入 post-FINISH 阶段——两种选择必须在实现 PR 里二选一并用 packet-type trace
  golden 证明，不得混用；
- cookie reply、`RekeyTimeout`(5s) handshake retransmit、或任何第 4 个 pre-FINISH outer
  datagram 都判定本次 challenge 失败并终局，不得静默放宽或重试。

#### 6.3b Post-OOB echo 的所有权与协议

post-OOB echo 由 **Gate C orchestrator** 拥有；`pkg/tunnel` 只承载 WireGuard transport，
不实现 echo 语义。冻结为：

- inner request/response 是固定格式 datagram，绑定 attempt/context digest、role 与
  exact src/dst virtual identity；有界 timeout；重复/重放/错角色拒绝；
- 不复用默认 `pkg/client` ping responder（端口 33434 daemon），也不新建任何未计费的
  长驻 listener；echo listener 与 session 同生命周期，Ctrl-C 即回收；
- echo 计数单列进 witness，不混入 establishment 或 challenge ceiling。

#### 6.3c Interface/route 生命周期

- C1b 只允许 memory-TUN 与 required netns 中由 harness 创建的 TUN；不触碰宿主 OS
  interface、address 或 route；
- C1c exact field build 才取得 sealed OS TUN/Wintun capability 与 exact interface/route
  authority；interface 名称、virtual address 与 route 只来自本地 trusted config，request、
  artifact 与 peer 都不可覆盖；
- preflight 发现已有 `wink up`、相同 WireGuard private key、目标 interface 或冲突 route
  owner 时，在任何 SSH/UDP I/O 前拒绝并稳定返回 `gate_c_request_invalid`；
- 私有授权模板必须记录所需 privilege/capability、interface/route 创建与回滚步骤，teardown
  证明 interface/route/address 零 residue。

"3 outer datagram/方向、0 retransmission"是本 Draft 的安全提案；上述顺序若与实现期真实
packet trace 不符，评审必须先修订本 ADR，不能在实现 PR 中静默增加。

## 7. 网络能力与资源边界

### 7.1 UDP target authority

Gate C1b/C1c 的 factory 只能由 Gate C orchestrator 构造，并接收已经取得的 exact attempt
lease；factory 自己不得 acquire governor。它只允许：

1. wildcard + ephemeral local bind；不得绑定固定端口或任意 interface；
2. local request 中 exact RFC 5780 observer topology；
3. 一个 `expected_peer_public_address`；
4. 本地重算并通过 bilateral commitment 的 exact candidate ports；
5. 命中后同一 address 的一个 authenticated winner endpoint。

它拒绝：raw `UDPFactory` 注入、global-unicast boolean、第二 peer address、DNS、CIDR/range、
remote candidate、unplanned port、second attempt、fallback 与任何 legacy/Pion path。hard-16K
端口仍只能是 49152–65535；headroom 仍不可消费。

### 7.2 Profile 成本

Gate C 不创造第四套 envelope：

- `predictive_edm/1` 与 `asymmetric_birthday/1` 逐字消费 Gate B §16 的 complete exact cost；
- `hard_16k_lab/1` 逐字消费 §18.3 的 16 sockets、16,400 targets/five-tuples、16,432
  reservation、16,398 protocol max、512 PPS、45s+2s、同一 journal 与一次/24h circuit；
- SSH assembly 在 initiator 另加恰好 1 owned child/1 outbound TCP/0 DNS；responder 是一个
  fixed endpoint process/1 accepted channel，不再 spawn child。frame/byte 仍是 carrier 既有
  8/8,256；
- pre-FINISH WireGuard challenge 单列最多 3 outer datagram/方向，不得兑换 probe headroom；
- post-OOB echo 属已完成 FINISH 后的 data-plane witness，单列计数，不得伪装为 establishment
  成功或提高命中概率。

普通 timeout、absence、evidence failure、exhaustion 与 challenge failure是干净终局；未登记
target、超 candidate/packet/PPS/socket、第二 attempt、ownership/generation 违规、连续 OS write
failure 或 drain failure仍按既有规则持久 trip。

## 8. Progress、结果与稳定错误

### 8.1 Progress

产品 progress 只增加 assembly/data-plane 外层阶段；Gate B 内部阶段保持原顺序：

```text
preflight -> ssh_spawn -> oob_adopt -> present -> burned -> activated -> handshake
  -> prepare -> sockets -> fresh_evidence -> plan_committed -> ready -> fire
  -> candidates -> winner -> verify -> transport_lease -> handoff
  -> data_plane_challenge -> finish_recorded -> oob_drained
  -> data_plane_ready -> terminal
```

Gate B3 的 `READY_FIRE`/selection/`EXHAUSTED` 是 wire 细节，不新增远端可控 progress 字段。
失败只发已完成最长前缀与一个 terminal。progress 只含 stage、remaining absolute budget、
cancellable；禁止 endpoint、address、port、profile seed、role、ID、path、user、host key、PID、
packet bytes 或底层 error。

### 8.2 Gate C 新增稳定 class

Gate A/B 已冻结 class 原样复用。外层只新增：

| class | 阶段 | burn | 含义 |
| --- | --- | --- | --- |
| `gate_c_request_invalid` | preflight | 否 | local request/profile/config 不合法 |
| `peer_address_not_authorized` | preflight/evidence | 否或实际值 | peer evidence 与本地单地址 authority 不符 |
| `ssh_profile_invalid` | preflight | 否 | SSH exact profile/path/host-key file 不满足约束 |
| `ssh_host_identity_rejected` | ssh_spawn | 否 | pinned host key 未通过；不暴露细节 |
| `ssh_transport_unavailable` | ssh_spawn/present | 否 | 单次 child/connection 未建立 |
| `ssh_child_terminated` | 任意 | 以实际值 | child/parent/pipe terminal |
| `ssh_budget_exceeded` | 任意 | 以实际值 | child/stderr/frame/byte/deadline ceiling |
| `wireguard_binding_failed` | handoff | 是 | 本地 peer/tunnel consumer 无法绑定 exact transport |
| `post_handoff_validation_failed` | oob_drained | 是 | OOB 退出后 WireGuard echo 失败 |
| `session_drain_failed` | terminal | 是 | foreground data-plane session 未有界排空；持久 trip |

所有错误固定 `retryable=false`，只报告 class、stage、credential_burned、profile、resource class
与脱敏本地计数。不得回传 `ssh` stderr、OS errno、certificate/host key、endpoint、user、path、
artifact/fingerprint、public address、candidate port 或 WireGuard key。

## 9. Architecture gate

实现必须把权限精确限制为：

- `internal/v2/sshassembly` 是 zero-UDP-capability zone；唯一新增能力是 fixed OpenSSH child，
  `os/exec`/pipe 使用进入静态 inventory；
- C1a 只有新 fake/loopback harness 与 exact Gate C orchestrator adapter 能消费 assembly；
- C1b 的 Gate C orchestrator 是 Gate B executor、production TransportLease consumer 与 tunnel
  binder 的唯一组合点；
- `pkg/session`/`pkg/tunnel` 只看 lease-owned `PacketTransport` 与本地 peer config，不 import
  artifact、sshassembly、hardnatplan/control/budget 或构造 network factory；
- stdio v1/v2、`wink up`、runtime、scheduler、legacy、`wink-signal`、recovery 与 autonomous mesh
  不得 import Gate C；
- ordinary `go build ./cmd/wink` 在 C1b 评审前不能取得 field unicast capability；C1c 的 exact
  field build、build tag/command 与普通 release 隔离方式须另行评审；
- architecture mutation 必须抓住：arbitrary executable/shell、password、host-key bypass、
  SSH config/ProxyCommand、第二 child/connection、raw stream、PSK 进入 adapter、remote target
  address、第二 address、unplanned port、raw factory、stdio/runtime import、无 lease Promote、
  handoff 后旧句柄复用、WireGuard challenge 超包与 retry/fallback；
- 另须抓住本修订新增的能力面：ordinary build 构造非回环 `SSHEndpointAuthority`、裸
  endpoint/字符串绕过 authority 直达 `exec.Command`、同一 attempt 的第二次 assembly spawn
  （exclusive claim 复用）、缺失 `-F none`/`IdentityAgent=none` 的 argv、pre-FINISH 第 4 个
  outer datagram 到达底层 I/O、绕过 gate 的 `context.Background()` 直写、post-OOB echo 复用
  ping daemon 或新建长驻 listener，以及 C1b build 触碰宿主 interface/route。

## 10. 必过证据

### 10.1 Gate C1a

- OpenSSH argv golden 覆盖 Windows/Linux exact path、每个禁用项（含 `-F none`、
  `IdentityAgent=none`、`GlobalKnownHostsFile=none`、`-T`）与固定 remote command；每平台
  另附 `ssh -G` effective-config golden；
- `SSHEndpointAuthority`：ordinary build 非回环构造 fail-closed、netns sealed helper 固定
  TEST-NET、裸 endpoint 绕过 authority 在 `exec` 前拒绝、exclusive claim 使同一 attempt
  第二次 spawn 失败；
- fake child 覆盖半帧/粘帧/banner、stdout/stderr backpressure、4 KiB stderr、EOF、deadline、
  caller cancel、parent death、child nonzero、graceful exit 与 forced kill；
- password/command/environment/ProxyJump/ControlMaster/host-key bypass 全部在 spawn 前拒绝；
- wrapper 执行域：绝对路径 exec、environment 清空、`SSH_ORIGINAL_COMMAND` 忽略或逐字验证、
  symlink/可写 parent 拒绝，均有正反测试；
- pairing secret、artifact、path/user/address 不出现在 argv、stderr mapping、witness 或 test log；
- responder pending slot 的 O_EXCL、0/2 slot、expiry、claim crash、symlink/reparse/ACL 与无自动
  re-arm；
- 四套 artifact/parser 互拒、manifest/permissions/crash/secret scan、无 clipboard；
- loopback sshd integration（若 CI 可证明 exact client profile）或等价受控 child，不访问 LAN。

### 10.2 Gate C1b

- memory/loopback/required netns 经真实 CLI 与 remote child 走 predictive、asymmetric 和
  hard-16K full pipeline；
- local target authority mismatch、第二 address、remote overwrite、unplanned port、DNS 与
  raw factory 全部零 UDP；
- production TransportLease 在 Promote 前签发，binding mismatch/attach timeout/consumer crash
  零 handoff；旧 ProbeSocket/Controller/attempt 句柄不可用；
- userspace WireGuard memory-TUN 使用 lease transport 完成 max 3/3 pre-FINISH challenge，
  packet-type trace golden 证明冻结顺序（含 staged-echo 或显式 keepalive 二选一）；
  第 4 个 pre-FINISH outer datagram 在底层 I/O 前失败；FINISH journal 顺序可见，FINISH
  失败时 cap 不解锁；OOB child 归零后由 orchestrator 完成 post-OOB echo，重放/错角色拒绝；
- interface 冲突 preflight：已有 `wink up`、相同 private key、interface/route owner 时在
  SSH/UDP 前拒绝；
- cancel、SSH EOF、evidence drift、exhaustion、writer error、WireGuard failure、parent/child kill
  全部有界，100 fresh runs 与 `-race -count=20` 无 goroutine/fd/process/socket/lock residue；
- v1/v2、N3b/Gate A/B golden 和默认 `wink up` 行为逐字节不变。

### 10.3 Gate C1c disposable router

- exact field build/checksum、具名一次性路由器与 observer permission 先签发；
- predictive APDM×APDM、asymmetric 两个 orientation、hard-16K near-tail 与 exhaustion 分别使用
  新 credential/窗口，绝不 reset ledger 赶进度；
- 真实 packet/socket/process/conntrack/child/ledger/TransportLease/WireGuard witness；
- hard-16K 继续满足共同 conntrack ceiling、local router cap、512 PPS、16,398 protocol max、
  45s+2s 与零 residue；
- SSH child 退出后 WireGuard traffic 继续，packet capture 证明不经过 OOB underlay；
- 只有本门独立复审通过，才能签发 Gate C2 的一个真实网络 instance。

## 11. 现场签发纪律

空白模板只定义字段，不是配置或 capability。规则：

- 一个 authorization instance = 一个 scenario = 一个 credential = 一次 foreground invocation；
- exact SHA/checksum、双方脱敏设备代号、profile/resource、私有 target address、observer permission、
  SSH host-key pin、时间窗、kill switch、ledger/circuit 与 teardown 均事前由两人复核；
- Gate A 的 peer absent、wrong PSK、OOB EOF、evidence unusable、lease/consumer failure与 nominal
  success 先在低成本、分别签发的窗口闭合；
- hard-16K 受一次/24h与失败开 circuit 约束，不能为了现场 failure matrix 在同一天重跑；其
  fault/exhaustion 门主要由 disposable router 完成，真实窗口只运行模板明确签发的一个 fixed
  campaign；
- kill switch 只停止本次 foreground WinkYou/SSH child 并验证 drain，不禁用用户的独立管理
  overlay；任何 firewall/route/service 操作都必须作为另一项显式授权记录；
- 公开证据只提交 profile、stable class、计数、duration、ceiling 与 residue；真实 IP、hostname、
  username、path、host key/fingerprint、SSID/MAC、设备/运营商信息、artifact 与 topology 永不
  入库。

## 12. 明确拒绝

- 修改 `winkyou.stdio/v2` 或借 v2 `connect_test` 返回长期 transport；
- 把 socket/fd/PacketConn/PacketTransport 交给另一个进程；
- password、keyboard-interactive、agent forwarding、任意 SSH command、shell、user ssh config、
  ProxyCommand/ProxyJump、ControlMaster、host-key accept-new/bypass；
- 从 Tailscale netmap、peer report、DNS 或任意 global-unicast boolean 取得 target authority；
- artifact 携带 endpoint、SSH、observer、WireGuard identity、authorization 或资源数字；
- remote 上传 candidate/port/span/socket/PPS/packet，或 local request 选择 hard-16K universe；
- 同 attempt 自动选择 profile、predictive 升级 birthday、失败换 seed/扩大窗口/retry/fallback；
- 把 SSH/OOB 当 data relay，或在 direct 失败后自动破坏原管理路径；
- 直接接入默认 `wink up`、daemon、scheduler、recovery、自启动或 autonomous mesh；
- 实现/启用 `hard_32k_candidate/1`、full-65K 或宣称 universal symmetric-NAT traversal；
- 把模板、确认 flag、stage file、合并、CI 或一次真实成功表述为可复用现场授权。

## 13. 独立评审问题

本 ADR 进入 Accepted 前，请专家逐项裁决：

1. 是否接受“首个产品入口为同进程 foreground CLI，stdio v3 延后”，而不是新增 transport IPC？
2. Gate C product artifact/auth scope 与三套 test artifact 的隔离是否足够，是否应继续使用同一
   NNpsk0 profile？
3. 逐实例、local-only `expected_peer_public_address` 是否足以覆盖两台自有设备的第一现场
   threat model；若不足，签名 observer attestation 的最低协议是什么？
4. 固定 OpenSSH child profile能否在 Windows initiator/Linux responder 上逐项证明；系统 client
   exact path 与禁止读取 ssh config 的平台差异如何处理？
5. responder canonical pending slot 是否比把 artifact/path 放进 remote command 更安全；claim
   与过期清理语义是否闭合？
6. WireGuard pre-FINISH challenge 的 3 outer datagram/方向、3 秒、0 retransmission 是否与当前
   wireguard-go 实际握手一致；post-OOB echo 应由哪一层拥有？
7. 是否接受 C1a/C1b/C1c/C2 四级递增，特别是 field unicast capability 不进入 C1b 普通 build？
8. Gate B3 §20 的 PR #96 独立接受记录与本 PR 的最小状态回写是否准确？

任何一项要求改变 artifact trust、target authority、SSH child 数、WireGuard challenge、profile
cost、live capability 或实现拆分时，先修订并接受本文；不得在实现 PR 中自行选择更宽方案。

## 14. 独立评审修订记录（2026-08-31）

首轮独立复审（PR #99 评论）裁决：foreground 入口、artifact 隔离、local-only 单地址
threat model、pending slot 与 C1a/C1b/C1c/C2 分级方向接受；PR #96 状态回写准确；同时提出
三项设计级阻断。本修订按评审要求闭合：

1. **SSH/TCP field-unicast authority**（§5.1/§5.1a）：新增 value-sealed
   `SSHEndpointAuthority` 与 exclusive assembly sub-lease；C1a/C1b ordinary build 仅
   loopback，netns 用 build-tagged sealed helper，C1c 才可从私有授权实例构造恰好一个
   非回环 endpoint；§9/§10.1 增加对应 mutation 与证据门。
2. **responder forced command 执行域**（§5.2）：client 侧冻结 `-F none`、
   `IdentityAgent=none`、`GlobalKnownHostsFile=none`、`-T`、显式最小 environment，并要求
   per-platform `ssh -G` golden；server 侧冻结绝对路径 wrapper、environment 清空、
   `SSH_ORIGINAL_COMMAND` 处理、`PermitUserEnvironment=no` 与 `sshd -T -C` 证明。
3. **WireGuard cap/顺序/所有权**（§6.3a–§6.3c）：新增 lease-bound gate 状态机（第 4 包
   I/O 前失败、FINISH 前 cap 不解锁、消除 `context.Background()` 直写）；按当前
   wireguard-go `f333402bd9cb` 冻结 staged-echo 或显式 keepalive 二选一的注入顺序；
   post-OOB echo 归 orchestrator 拥有并冻结协议；C1b/C1c interface/route 生命周期与
   冲突 preflight 显式化。

评审问题 4 与 6 由上述修订回答；其余问题维持原文供复审确认。评审同时指出的 Gate B3
`fifty_percent_candidate_loss` 双端 terminal 分类竞态属非阻断遗留，独立记录于
[Issue #100](https://github.com/houyuwushang/winkyou/issues/100)，须在 C1b 组合 Gate B3
前关闭或以新裁决明确允许的双端 terminal 集合。本节不改变授权边界：本 ADR 仍为
docs-only Draft，实现与现场 I/O 须另行授权。
