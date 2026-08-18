# WinkYou 极简 STUN Binding 应答端

`wink-stund` 是供维护者自托管的实验性 RFC 8489 UDP Binding 应答端。它为显式
`wink diagnose --active-stun=<IP:port>` 提供一个可丢弃的观测目标，不是 TURN、ICE、
通用 STUN 服务或 NAT 穿透守护进程。

本组件是 WinkYou 第一个设计为长期监听公网 UDP 的组件。启用它会形成公开可达的服务，
必须先经过安全评审、选择明确的服务器与端口，并配置主机防火墙和云安全组。本仓库与
本 PR 没有执行部署或公网实测。

## 1. 固定协议范围

应答端只接受以下报文：

- UDP RFC 8489 Binding Request，消息类型必须为 `0x0001`；
- magic cookie 必须为 `0x2112a442`；
- 消息长度、属性长度和 32-bit padding 必须完整一致；
- comprehension-optional 属性在验证 framing 后忽略；
- 任何 comprehension-required 属性均视为当前最小 profile 不支持并静默丢弃。

合法请求只得到一个 `0x0101` Binding Success Response，回显 96-bit transaction ID，
并只携带一个 `XOR-MAPPED-ADDRESS`。IPv4 响应固定为 32 字节，IPv6 响应固定为 44
字节。短包、错 cookie、非 Binding、长度错误、未知 required 属性和超限报文均不响应。

这里选择“静默丢弃”而不是发送 420：服务没有认证，错误响应不会帮助当前
`stunobserve.Client`，反而会增加反射面。最小 20 字节请求的响应载荷仍比请求载荷大，
因此不能声称数学意义上的零放大；边界是固定 32/44 字节、绝不扇出、只回原 UDP source，
并由全局与每源限速压住总响应率。响应载荷小于“最小请求载荷 + 对应 UDP/IP header”。

明确不实现：

- STUN 认证、`MESSAGE-INTEGRITY` 或凭据数据库；
- TCP、TLS、TURN、ICE、端口分配或中继；
- 主动探测、DNS 解析、目标选择、重试或定时发包；
- 运行时提高编译上限的接口。

共享报文逻辑位于 `internal/stunwire`。原有 `internal/stunobserve/testkit` 只保留薄适配，
不再维护第二份 Binding Success 编码器；客户端的请求构造和响应解析继续保留自己的方向
特定错误语义。

## 2. 构建与启动

```powershell
go build ./cmd/wink-stund
./wink-stund --version
./wink-stund --listen 127.0.0.1:3478 --max-pps 20
```

`--listen` 必填，只接受字面量 IPv4 `IP:port` 或带方括号的 IPv6 `[IP]:port`；不解析
hostname，端口不能为 0。`0.0.0.0` 与 `::` 可以显式选择，但启动 JSON 日志会设置
`wildcard_listen=true` 与 `exposure=all_interfaces`。

| 参数 | 默认值 | 硬边界 |
|---|---:|---|
| `--max-pps` | 200 | 只能设为 1–200，不能提高编译上限 |
| 每源 IP PPS | 20 | 硬编码；当全局值更低时随之降低 |
| 源 IP 限速状态 | 4096 项 | 满表后拒绝新源；空闲 5 分钟后回收 |
| UDP 读取上限 | 1500 字节 | 多一个 guard byte 仅用于识别并丢弃超长报文 |
| worker/队列 | 1/0 | 单同步收包循环，无请求 goroutine、无排队 |
| 可选日志前缀 | 256 项 | IPv4 `/24`、IPv6 `/48`，满表只增加 omitted 计数 |

`SIGINT` 与 `SIGTERM` 会唤醒当前阻塞读取、停止接收并输出最终计数。进程不会修改路由、
防火墙、计划任务、网卡或 governor namespace。

## 3. 日志与隐私

stderr 只输出 JSON。默认日志包含服务监听地址、上限和聚合计数，不记录客户端 IP、端口、
transaction ID 或报文内容。`--log-prefixes` 是显式隐私降级：开启后，成功响应按 IPv4
`/24` 或 IPv6 `/48` 计数，仍不保留完整地址。

```json
{"time":"2026-08-18T00:00:00Z","event":"started","listen":"0.0.0.0:3478","wildcard_listen":true,"exposure":"all_interfaces","max_pps":200,"per_source_pps":20}
```

示例时间与监听地址仅用于说明 schema。不要把真实服务器地址或运行日志提交到仓库。

## 4. 为什么不接 client governor

client governor 管理主动探测的 socket、目标、five-tuple、PPS、总包数和 attempt 生命周期。
`wink-stund` 没有主动目标：它只在收到并验证请求后，向该请求的原 UDP source 回一个固定
小包。因此它不伪造 client `AttemptLease`，而是在服务器侧使用更贴合风险的硬边界：一个
socket、一个同步循环、无队列、全局/每源响应令牌桶、有限源表和有限日志表。

这一例外不绕过能力审计：生产代码唯一新增的 raw capability 是
`internal/stunserver.Open` 内的一处 `net.ListenUDP`，已登记在
`internal/architecture/testdata/network_capabilities.txt`。任何新增 Dial、第二个 listener、
第三方网络库或调用点漂移都会让架构清单测试失败。

## 5. systemd 模板

先创建不可登录的专用用户，并把二进制安装到 `/usr/local/bin/wink-stund`。以下地址来自
TEST-NET-3，仅作占位；部署者必须在服务器本地配置文件中替换，不能把真实地址提交回来。

`/etc/winkyou/wink-stund.env`：

```text
STUN_LISTEN=203.0.113.10:3478
STUN_MAX_PPS=200
```

`/etc/systemd/system/wink-stund.service`：

```ini
[Unit]
Description=WinkYou response-only STUN Binding responder
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=winkyou-stun
Group=winkyou-stun
EnvironmentFile=/etc/winkyou/wink-stund.env
ExecStart=/usr/local/bin/wink-stund --listen ${STUN_LISTEN} --max-pps ${STUN_MAX_PPS}
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true

[Install]
WantedBy=multi-user.target
```

systemd hardening 不能替代 UDP 防火墙和云安全组。首次公网部署与家庭/蜂窝网络观测属于
单独的 live-network 授权边界，应按照后续现场实测 runbook 逐项执行和清理。

## 6. 当前验证范围

- `internal/stunwire` 覆盖畸形报文矩阵与 IPv4/IPv6 XOR 固定向量；
- `internal/stunserver` 覆盖全局/每源限速、有限状态表、隐私快照和取消退出；
- 进程内 loopback 集成使用生产 `probeio.UDPFactory` 与现有
  `stunobserve.Client` 完成真实 UDP 往返；
- 测试不访问公网，不启动长驻 daemon，也不修改主机网络配置。
