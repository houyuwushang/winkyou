# birthday_punch 真机联调实录（Field Log）

> 配套 [`BIRTHDAY-PUNCH-DESIGN.md`](./BIRTHDAY-PUNCH-DESIGN.md)（设计与代码现状）。
> 本文给**接手 M6/M7 真机联调的帮手**：读完能理解拓扑、跑通 `punchtest`、看懂已试过什么、知道下一步该干什么。
> 更新于 2026-07-17。**凭据（SSH 账号/密码、sudo 密码）不在本文，由项目负责人通过私有渠道提供。**
>
> 本文保留 M6/M7 当时的现场状态和操作顺序，不是当前 rollout
> 指南。后续 `cmd/meshnode` 三节点 graph、r9 maintained-edge recovery，
> 以及 post-r9 recovery-card self-bootstrap 的当前边界分别见
> [`MESH-REJOIN-FIELD-EXPERIMENT.md`](./MESH-REJOIN-FIELD-EXPERIMENT.md) 和
> [`SELF-BOOTSTRAP-RECOVERY.md`](./SELF-BOOTSTRAP-RECOVERY.md)。后者目前只有
> 本地源码证明，未在公网重启中验证。

## 1. 真机拓扑

本机既是**控制机**又是**节点 B**。目标是在 inner（节点 A）和本机（节点 B）的**公网 IP** 之间打通 UDP 直连。

| 角色 | 系统 | 公网 IP | natpierce | Tailscale | 其它 | 备注 |
|---|---|---|---|---|---|---|
| **inner**（节点 A） | Linux `node-c-host` | `198.51.100.20`（教育网） | 网关 `10.20.0.1` | `100.64.0.10` | 本地 `172.20.0.11` | **Go 1.18，不能本地编译**，二进制需交叉编译传入 |
| **本机**（节点 B + 控制机） | Windows | `192.0.2.10` | `10.20.0.3` | `100.64.0.11` | `10.0.0.10` / `192.168.11.x` | 有管理员权限；透明 wink 数据面仍受 Wintun 阻塞（见 §8），M7 固定目标 bridge 不使用 Wintun |
| **node-b**（可选 coordinator 宿主） | Windows | `203.0.113.30` | 时有时无 | — | `192.168.50.217`（本机局域网可达） | natpierce 两跳的跳板；不稳 |

**SSH 通道**（凭据私有渠道给）：
- **Tailscale 直连** `ssh node-c-user@100.64.0.10`：稳定，但 251ms 高延迟，传大文件慢/易超时。
- **natpierce 两跳** `ssh inner-gw`（`~/.ssh/config` 已配 `ProxyJump node-b`）：8ms 快，但**频繁断线**。
- **WinkYou 公网 bridge** `ssh -o ProxyJump=none -p 22022 node-c-user@127.0.0.1`：M7 已实测；本机仅监听 loopback，底层为 punch 获胜 socket 上的 QUIC/mTLS，不需要 Tailscale/natpierce/Wintun。
- 本机无 `sshpass`/`plink`，密码认证用 OpenSSH `SSH_ASKPASS` 脚本（`<scratchpad>/askpass.sh`，按 prompt 分发密码）+ `SSH_ASKPASS_REQUIRE=force DISPLAY=:0`。

## 2. NAT 行为实测（最关键的事实）

**两端都是 symmetric NAT（EDM×EDM 最难档）。** 用 `punchtest` 实测：

- `inner`：**sequential**，delta `+1`，drift≈0（连续 probe 得 `55342→55344→55346`，只有 probe 自身消耗端口）。高度可预测。
- `本机`：**random**。`punchtest mapping`（同 socket 打 3 个不同 STUN）实测：cloudflare→`1134`、google→`17490`、miwifi→`18831`，端口随目标乱跳。

> **✅ 已修正（2026-07-16）**：`punchtest probe` 现在默认以同一个 socket 打多个 STUN 判断 EIM/EDM，并让后续新 socket 轮换这些目的地采样分配序列；输出同时包含 `mapping_type`、`pattern`、原始 samples 与实际目的地址。`punchtest mapping` 仍保留为快速独立复核工具。仅传一个 STUN 或多目标映射一致时，mapping 证据仍不足，结果保持 `unknown`。
>
> **分类会随时间变**：修复后的本机连续实测先得到 `random`（6 samples 中出现多个大幅端口跳变），十秒后又得到 `preserving`（12/12 映射端口等于本地端口）；两轮公共 IP 均为 `192.0.2.10`，Google/Cloudflare 实际目的 IP 也未变化。把每轮输出当快照，打洞前必须重测，不要沿用旧标签。

## 3. punchtest 工具（`cmd/punchtest/`）

独立于 wink 的 CLI，**不需要 Wintun/管理员**。四个子命令：

```
punchtest probe   --stun stun:a:port,stun:b:port --samples N # mapping behavior + 跨目的地端口分配序列
punchtest mapping                                          # 同 socket 打 3 个 STUN → 判 EIM/EDM（权威 NAT 分类）
punchtest punch   --remote-ip IP --role initiator|responder --duration T
   # 可预测对端：--remote-pattern sequential --remote-port N --remote-delta 1 --span S
   # 不可预测对端：--remote-pattern random --birthday K            (每轮每 socket 撒 K 个新随机端口)
   # 通用：--sockets M --burst B --round-delay D --local-port P
   # 命中后在打通的 conn 上跑 ping/echo 验证双向数据面
punchtest bridge  <同一组 punch 参数> --secret-file FILE
   # initiator：--listen 127.0.0.1:22022
   # responder：--target 127.0.0.1:22
   # 命中后不重新拨 UDP；原 socket 直接升级为 QUIC/mTLS，多条 TCP 连接映射为多条可靠 stream
```

## 4. 编译与部署

```bash
export GOCACHE=<稳定目录>          # ⚠️ 见 §7：默认 GOCACHE 会被清、导致链接间歇失败
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o punchtest-linux ./cmd/punchtest   # 给 inner
go build -o punchtest.exe ./cmd/punchtest                                           # 本机
# 传输：压缩后走 natpierce 快（~10s，但会断）或 Tailscale 稳但慢（压缩后 ~1min）
gzip -c punchtest-linux > punchtest-linux.gz          # 6MB → ~3.6MB
scp punchtest-linux.gz node-c-user@100.64.0.10:~/winkyou-live/
ssh node-c-user@100.64.0.10 "cd ~/winkyou-live && gunzip -f punchtest-linux.gz && chmod +x punchtest-linux"
```

## 5. 已试过的打洞配置与结果

| 轮 | inner（responder） | 本机（initiator） | 结果与结论 |
|---|---|---|---|
| 1 | 打本机固定 `50408`（当时误判 preserving） | 256 socket 打 inner `55334`+span512 | 0 入站。本机 symmetric，对 inner 源端口不是 50408，被 inner filtering 丢弃 |
| 2 | 打本机固定 `51000` | `--local-port 51000` 打 inner | 0 入站。固定本地端口对 symmetric 本机无效（`mapping` 证明本机 EDM） |
| 3 | random 撒 1024/socket，128 socket | 256 predict，128 socket | **inner Tailscale 被海量包（~13 万/轮）reset**，打洞中断 |
| 4 | 低速动态 48/socket/轮，96 socket，300ms | 256 predict，128 socket，250ms | inner Tailscale **仍被 reset**；本机跑满 90s；0 入站 |
| 5 / R1 | random 64/socket/轮，128 socket，250ms，完全脱离 SSH | 同参数 | **成功**：双端 HIT + 5/5；本机 RTT 36–37ms |
| 6 / R2 | random 48/socket/轮，128 socket，300ms，完全脱离 SSH | 同参数 | **成功**：双端 HIT + 5/5；降载后仍稳定命中 |
| 7 / R3 | random 48/socket/轮，128 socket，300ms，45s | 同参数 | **成功**：双端 HIT + 5/5；inner pcap 26 包、0 drop |

M6 成功轮次前的多 STUN 重测显示**两端当时均为 symmetric + random**。双向动态 birthday 已在最难档 EDM×EDM 上连续三轮成功。

## 6. M6 成功实录

此前卡点已经确认并解除：问题是 SSH 前台进程生命周期，不是 punch 算法。`setsid` 且完全脱离三个标准 fd 后，即使控制连接关闭，实验也能跑满并落盘。

**已验证的脱离 SSH 启动方式**：

```bash
# 点火即撤，打洞后台跑完整窗口，SSH 断了也不影响
ssh node-c-user@100.64.0.10 "cd ~/winkyou-live && setsid bash -c \
  './punchtest-linux punch --remote-ip 192.0.2.10 --remote-pattern random --birthday 48 \
   --sockets 128 --burst 1 --round-delay 300ms --role responder --duration 120s > punch-inner.txt 2>&1' \
  </dev/null >/dev/null 2>&1 & echo LAUNCHED"
# inner tcpdump 也同样 setsid 脱离，抓 'udp and src host 192.0.2.10' 写文件
# 本机几乎同时启动 initiator（窗口重叠）
# 结束后 ssh 读回：cat ~/winkyou-live/punch-inner.txt / tcpdump 文件
```

**实际成功证据**：R3 的 inner `enp69s0` 抓到 26 个来自本机公网 IP 的 UDP 包、0 kernel drop；payload 以明文 `WKP1` 开头，首包 `192.0.2.10:19786 -> 172.20.0.11:16048` 与 responder HIT 日志完全匹配。Windows 到 `198.51.100.20` 的选路为物理以太网 `10.0.0.10 -> 10.0.0.1`，inner 回程为 `enp69s0 -> 172.20.0.1`；因此本轮 punch 数据面未由 Tailscale/natpierce 承载。注意 Tailscale 仍用于 SSH 点火，两项 overlay 服务也未关闭，这不是“停掉 overlay 后复测”的证据。

**已验证基线**：`--sockets 128 --birthday 48 --burst 1 --round-delay 300ms`。正式 `birthday_punch` strategy 已从初版的 256 sockets × 256 固定 targets/200ms，改为这组低速、每轮 fresh targets 的参数。

M6 真机产物在本机 `.live-run/runs/m6-codex-20260716-r{1,2,3}/`，远端镜像位于 `~/winkyou-live/runs/`。

## 7. M7 无 Wintun 用户态 SSH bridge

### 7.1 实现

- `pkg/dataplane/portforward/` 接管 `puncher.Result.Conn`，在同一个 NAT 映射上启动 QUIC；不会创建 `wink0`，不会初始化 WireGuard/Wintun。
- 32 字节随机 secret 经 HMAC 派生不同的 client/server Ed25519 身份。TLS 1.3 双方固定公钥校验，responder 只允许拨配置中的固定 target，initiator 默认只监听 `127.0.0.1`。
- `quic-go` 固定为 `v0.54.1`，这是仍兼容项目 `go 1.23` 的最新检查版本；`v0.55+` 要求 Go 1.24。
- 每个本地 TCP 连接先发一字节 OPEN，再等远端 target 状态；成功后双向复制到独立 QUIC stream。Windows OpenSSH 完成命令后常返回 WSAECONNRESET 10054，按正常 EOF 收尾，不再误发 QUIC RESET。

### 7.2 真机结果 `no-wintun-20260716-r1`

第一版公网命中约 10 秒：

- 本机：`0.0.0.0:56207 -> 198.51.100.20:26912`，本地监听 `127.0.0.1:22022`。
- inner：`0.0.0.0:60544 -> 192.0.2.10:13152`，固定 target `127.0.0.1:22`。
- 首个全新 SSH stream 返回 `BRIDGE_SSH_OK node-c-host`。

随后设置两端 180 秒自动恢复保险并关闭 overlay：

- 本机：`Tailscale=Stopped`、`natpierce_count=0`；到 `198.51.100.20` 的路由为物理以太网 ifIndex 9，经 `10.0.0.1`，源地址 `10.0.0.10`。
- inner：`tailscale=inactive`、`natpierce_count=0`；到 `192.0.2.10` 的路由为 `enp69s0`，经 `172.20.0.1`，源地址 `172.20.0.11`。
- 在上述状态下另开一个 SSH 连接，返回 `BOTH_OVERLAYS_OFF_BRIDGE_OK node-c-host`。这不是沿用既有控制会话：本地 TCP 与 QUIC stream 都是关闭 overlay 后新建。

修正正常关闭误判后又完成 v2 公网重打洞：本机 `0.0.0.0:53746 -> 198.51.100.20:11459`，inner `0.0.0.0:35239 -> 192.0.2.10:2131`，约 37 秒 HIT；SSH 返回 `BRIDGE_V2_OK`，两端日志不再出现 stream canceled。Windows OpenSSH 仍偶尔打印 `close - IO is still pending on closed socket`，但直接 Tailscale SSH 也同样打印，且命令 exit 0，不是 bridge 独有错误。

本机证据位于 `.live-run/runs/no-wintun-20260716-r1/`；远端位于 `~/winkyou-live/runs/no-wintun-20260716-r1/`。共享 secret 不进 Git，本文不记录其内容。

### 7.3 当前 bridge 的自助使用

只要本机 bridge 仍监听 `127.0.0.1:22022`，就可以直接使用远端 SSH：

```powershell
ssh -o ProxyJump=none -p 22022 node-c-user@127.0.0.1
scp -O -P 22022 .\test.txt node-c-user@127.0.0.1:/tmp/
```

SSH/SFTP 客户端统一填写 host `127.0.0.1`、port `22022`、user `node-c-user`。每个 TCP 会话映射为独立 QUIC stream，可以并发使用。该 listener 只绑定 loopback，因此默认仅本机可访问；底层仍只转发到 responder 配置的 `127.0.0.1:22`，不是任意 IP/端口可达的虚拟局域网。

### 7.4 无重连长时测试

- v2 会话建立于 `2026-07-16 22:13:51 +08:00`。本机 bridge PID `73724`、远端 PID `3397713`；测试策略为 `no_restart_no_repunch`。
- 从 `22:30` 起每分钟新建一条 SSH stream；截至 `2026-07-17 09:12:09 +08:00`，`626/626` 次完整成功，原会话已知连续业务可用时间约 10 小时 58 分。
- `09:13:12` 的下一次探针已经在两端日志中完成 stream OPEN、target connect/accept，远端也出现已认证的 `sshd: node-c-user@notty`，但短命令没有正常退出；`09:17` 的人工交互 SSH 则已获得远端 `pts/1`。到 `09:22` 双端 bridge 进程仍是原 PID，没有重打洞。
- 因此应记录为：**单条 QUIC 会话存活超过 11 小时，626 次短连接完整成功；随后首次出现 stream 收尾卡住，但不能据此判定 QUIC 会话整体已断。** 旧监控器缺少 wall-clock 硬超时，卡住后日志停止增长，这是监控缺陷，也暴露了需要排查的 per-stream 关闭语义。
- 本机原始记录为 `.live-run/runs/no-wintun-20260716-r1/soak-monitor.tsv`、`soak-monitor.state`、`bridge-local-v2.log`；远端对应 `bridge-remote-v2.log`。

### 7.5 后续概念与决策边界

- **长时保活测试**测的是同一 punch/QUIC 会话在不重连时能活多久；当前阶段不应开启自动重连。
- **主引擎 backend**是让 `wink up`/solver 自动创建并管理当前数据面，不是另一个网络协议，也不等于已经实现虚拟局域网。
- **重连生命周期**是故障检测、停止旧会话、重新协调/打洞、恢复服务和状态上报；应与“原连接寿命”分开测试。
- 后续先讨论产品形态：继续固定目标 TCP、扩展多目标/ACL、提供 SOCKS5/HTTP CONNECT，或走用户态 IP 栈。讨论完成前不把接入 `netif.backend: proxy` 当作既定路线。

固定目标 TCP bridge 已经可用，但它不是透明三层 VPN。近期优先事项是给长测探针增加单次硬超时并定位 stream 收尾卡点；产品形态经讨论确定后，再安排主引擎集成、ACL、密钥轮换和自动重连。

## 8. 其它环境坑（避免重踩）

- **GOCACHE 易失**：本机默认 `GOCACHE=D:\go-race-work\cache` 被外部进程周期清理，`go test`/`build` 链接阶段间歇报 "cannot open file …go-race-work…" 或 "package X is not in std"。跑前 `export GOCACHE=<稳定目录>`。
- **本机 Wintun**：`wink up` 建 `wink0` 曾出现 `context deadline exceeded`。Claude 当时先换 DLL，仍超时，随后把测试切到 memory backend；那是测试绕过，不是 Wintun 修复。M7 已用用户态 QUIC/TCP bridge 真正绕开 WireGuard/Wintun，但透明三层路由仍未实现。
- **SSH 后台进程挂住会话**：后台启动长进程必须完全脱离 fd（`setsid` + `</dev/null >log 2>&1`），否则 SSH 等 stdout EOF 而挂起（表现为命令无输出、超时）。
- **耐久探针必须有外层硬超时**：仅设置 OpenSSH `ConnectTimeout`/`ServerAliveInterval` 不足以覆盖“认证成功但 channel 不收尾”；每次探针应由独立 wall-clock deadline 约束，并把 open、认证、命令完成和连接关闭分层记录。
- **pkill 自杀**：`pkill -f wink-coordinator` 会匹配到**自己这条 SSH 命令**（命令行含该串）而杀掉会话，exit 255。用更精确的模式或先启动后清理。

## 9. 给帮手最有用的三句话

1. 先 `punchtest probe` 两端并保留完整 JSON；必要时再用 `mapping` 独立复核（网络和短期端口分配都会变）。
2. 双机实验用 §6 的"脱离 SSH"方式；需要真实可用流量时，用 `bridge --secret-file ...`，不要再回到 `wink0 + Wintun` 才能验证的旧路线。
3. 先以 `128×48×300ms` 为打洞基线；数据面先完成无重连耐久与 stream 收尾诊断，再讨论固定转发、代理或用户态 IP 栈，不能把固定端口转发误称为完整 VPN。
