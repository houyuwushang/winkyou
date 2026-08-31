# Gate C1a：SSH assembly 隔离实现证据

状态：**Draft implementation evidence；只覆盖纯内存、fake child、字面回环 OpenSSH profile
验证与 `linux && natlab` 编译期 authority。它不授权 C1b child pipeline、Gate A/B 产品组合、
WireGuard、非回环 SSH/UDP、部署、现场 I/O 或任何自动恢复。**

权限来源：
[`ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md`](./adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md)
§3、§5、§6、§9、§10.1 与 §15。实现基线为 `main` =
`ccacc96733323e24bac2716f3480f110fc1cf22a`。

## 1. Product artifact、request 与 one-shot staging

新增 product artifact 与此前三套测试 artifact 严格分离：

```text
artifact_profile: winkyou-direct-oob-attempt/1
manifest_profile: winkyou-direct-oob-manifest/1
direct_attempt_profile: winkyou-direct-hard-nat-control/1
oob_carrier_profile: ssh-bounded-child-stream/1
observation_profile: rfc5780-allocation-tomography/1
data_plane_consumer_profile: wireguard-direct-session/1
data_plane_challenge_profile: wireguard-handshake-echo/1
secure_channel_profile: noise-nnpsk0-25519-chachapoly-sha256/1
auth_scope: operator-initiated-one-shot/1
runtime_fallback: disabled
generation: 1
lifetime: 10 minutes
profiles: predictive_edm/1 | asymmetric_birthday/1 | hard_birthday_campaign/1
```

artifact 不含 SSH endpoint、用户名、命令、路径、hostname、TLS 或部署信息；`oob_channel_id`
与其余四个 identifier pairwise distinct，并绑定 Noise prologue。Gate C、Gate A、Gate B 与 N3b
四套 parser 的 4×4 互拒矩阵及确定性 SHA-256 已进入 golden。

`wink solver pair oob` 只接受 `predictive`、`asymmetric` 或 `hard-16k`，创建不存在的私有目录，
以 O_EXCL 写入 initiator/responder artifact，并最后写 secret-free manifest 作为 commit marker。
生成失败会删除本次尚未提交的完整输出；无 clipboard、terminal secret 或日志 secret 路径。

本地 request 固定为 `winkyou-gate-c-local-request/1`，上限 16 KiB，拒绝 unknown/duplicate field、
非 canonical endpoint、错误 RFC 5780 四点拓扑、相对路径和 role/SSH arm 不匹配。responder 通过
`wink solver direct stage --request-file ...` 只建立一个固定名称 pending slot；claim 先 durable
写入 claimed tombstone，再删除 pending。中途崩溃会留下 fail-closed 冲突而不会自动 re-arm。
`wink solver direct cleanup --manifest-file ...` 只删除固定 slot 且必须逐个匹配 manifest fingerprint；
不扫描、不排队、不取得 governor、不 burn credential，也不启动进程或网络。

## 2. Sealed SSH endpoint authority

`internal/v2/sshassembly` 不接受裸 endpoint authority。ordinary build 唯一公开构造器
`NewLoopbackAuthority` 只接受 canonical literal loopback；request 中的 endpoint 还必须与该 sealed
authority 完全一致。非回环构造器只存在于 exact `linux && natlab` build，调用方不能传地址，且会
先验证当前 network namespace，再按固定 TEST-NET topology 返回 endpoint。

architecture 与 mutation gate 证明：

- stdio v1/v2、CLI runtime、scheduler、legacy、`wink-signal`、WireGuard、Gate B executor 不能导入
  或构造 assembly；
- assembly 不导入 UDP、probeio、WireGuard、Tailscale、Pion、QUIC 或 shell；
- `os/exec` 仅存在于一个固定 process runner，只有一个 `exec.Command`、一个
  `ClaimExclusive` 与一个 `RegisterDrain` call site；
- production source 新增第二个 process spec、authority bypass、network/process capability 或错误
  build tag 会被 mutation self-test 捕获。

## 3. Exact OpenSSH profile

系统 client 路径与 remote command 固定为：

| platform | executable | child environment |
| --- | --- | --- |
| Windows | `C:\Windows\System32\OpenSSH\ssh.exe` | `SYSTEMROOT`、`WINDIR`、`PROGRAMDATA` 的固定系统值 |
| Linux | `/usr/bin/ssh` | `LANG=C`、`LC_ALL=C` |

remote command 固定为 `wink solver direct child --stdio`。完整 argv golden 强制 `-F none -T`、
key-only、single identity、strict host key、single owner-only known-hosts file、零 agent/password/GSS、
零 Proxy/ControlMaster/forwarding/tunnel/local command、`SessionType=default`、零 `-N/-s`、
`ConnectionAttempts=1` 与 `ConnectTimeout=3`。request 不能提供 executable、附加 argv、command 或 env。

Windows 的零连接 `ssh -G` 实测还证明：即便使用 `-F none`，系统 OpenSSH 仍需读取固定
`PROGRAMDATA=C:\ProgramData` 才能完成配置展开；只有 `SYSTEMROOT/WINDIR` 时会在启动前失败。
因此该变量作为第三个固定系统值进入最小 child environment，但 `PATH`、`HOME`、`USERPROFILE`、
`SSH_AUTH_SOCK` 与 `SSH_ASKPASS*` 仍不继承。该测试只展开 effective config，不建立连接。

## 4. Process ownership、预算与 drain

assembly 必须消费 caller 已取得且与 selected Gate B profile/resource/operation/cost **完全相等**的
真实 `governor.AttemptLease`，再取得唯一 exclusive claim 与 drain handle，才允许启动一个 child：

| 资源 | 固定上限 |
| --- | ---: |
| owned child | 1 |
| outbound TCP connection | 1 |
| DNS resolution | 0 |
| retry / queued attempt | 0 / 0 |
| SSH connect timeout | 3s |
| predictive/asymmetric active + drain | 20s + 2s |
| hard-16k active + drain | 45s + 2s |
| captured stderr | 4 KiB |

artifact、request、authority、key/known-hosts owner-only 状态、exact cost 或 absolute deadline 任一不符，
都在 spawn 前失败。stdin/stdout 是唯一 byte stream；stderr 独立有界读取并清零，内容从不返回。
EOF、caller cancel、lease stop、absolute deadline、writer failure 或 child exit 都是 terminal；先关闭
pipe，最多排水 2 秒，随后 kill 唯一 owned child。Witness 只包含 spawned/exited/killed/drained 与
stdin/stdout/stderr byte count，不含 endpoint、用户名、路径、命令、PID 或 stderr 原文。

父进程异常死亡由 OS 级 containment 闭合：Linux 在专用 locked OS thread 上创建 child，并固定
`Pdeathsig=SIGKILL`，直到 `Wait` 完成才释放该 thread；Windows 先以 `CREATE_SUSPENDED` 创建 child，
把它放入 active-process=1、kill-on-close 的 Job Object，确认唯一 primary thread 后才 resume。因此
不存在 child 已开始执行但尚未归属 containment 的窗口。真实本地 helper 测试强杀 parent 后证明
child 在 5 秒见证窗内消失，测试结束后进程 residue=0；该测试不运行 OpenSSH，也不建连接。

## 5. Responder wrapper 边界

`internal/v2/sshchildwrapper` 在 C1a 只提供纯 plan 与离线验证，不安装、不修改 sshd：

- fixed wrapper：`/usr/libexec/winkyou/gate-c-child-wrapper`；
- fixed binary：`/usr/libexec/winkyou/wink`；
- exact original command：`wink solver direct child --stdio`；
- direct absolute exec argv：`solver direct child --stdio`；
- fixed environment：`LANG=C`、`LC_ALL=C`，umask 077；
- authorized-key options：`restrict,command="..."`，并要求 `PermitUserEnvironment no`。

Linux 离线校验拒绝 symlink、hardlink、错误 owner/mode 与 group/other-writable parent。仓库没有
`solver direct child` 或 `solver direct connect` product command，因此该 wrapper 计划在 C1a 不能被
现场调用；真正 child pipeline 与安装属于 C1b/C1c 的新授权。

## 6. 自动化证据与未授权项

测试覆盖：三 profile artifact 与 parser separation golden；原子生成、manifest-last、故障清理与
secret zeroization；strict request 与 one-shot stage/claim/crash/cleanup；两平台完整 argv golden；
本机 `ssh -G` effective-config golden；exclusive lease、fake echo、半帧/粘帧/banner、cancel、deadline、
writer error、graceful/forced drain、stderr 分类与 4 KiB hard cap；wrapper command/env/path/sshd 配置；
三种 exact profile envelope、真实 governor/peer/attempt lease 保留 caller ownership、Windows/Linux
parent-death OS containment；architecture boundary 与 mutation self-test。

本 PR 没有执行 SSH connect、没有打开监听或 UDP socket、没有接入 Gate A/B orchestrator，也没有
修改 sshd、authorized_keys、firewall、service、scheduled task 或现场授权模板。C1b 仍被独立 gate
以及 Gate B3 race issue 阻断；本证据不能被解释为 live-network authority。
