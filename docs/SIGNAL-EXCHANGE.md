# WinkYou 最小测试信令交换点

`wink-signal` 是供两名已协调操作者在一次短时实验中交换各自观测结果的内存信箱。它是
**test-only 临时基础件**，与 solver、配对状态机和未来生产信令零耦合；配对加密实现通过独立
评审后，本组件应被替换，而不是演化成第二套身份或控制协议。

本组件使用明文 HTTP。这样做只为让当前人工实验保持小而可审计，不代表明文信令可用于产品。
服务器、网络路径、操作系统和中间代理都可能看到内容与连接来源。应用本身不把 payload、code
或客户端 IP 写入日志或磁盘，但这不能约束外部基础设施日志。

> **红线：payload 不得包含任何秘密。** 不得放入私钥、pairing token、凭据、身份材料、主机名、
> 账户名或无需交换的拓扑。code 只是带外生成的短期信箱选择值，不是加密密钥或持久身份。

## 1. 启动

```powershell
go build ./cmd/wink-signal
./wink-signal --version
./wink-signal --listen 127.0.0.1:8080
```

`--listen` 必填，只接受字面量 IPv4 `IP:port` 或带方括号的 IPv6 `[IP]:port`；不解析 hostname，
端口不能为 0。显式选择 `0.0.0.0` 或 `::` 时，启动日志会标记
`wildcard_listen=true` 与 `exposure=all_interfaces`。

`SIGINT` 或 `SIGTERM` 会停止接收、在至多 5 秒的退出窗口内关闭 HTTP server，并输出最终聚合计数。
进程不会修改防火墙、路由、计划任务或 WinkYou governor namespace。

## 2. 固定协议

唯一端点是：

```text
POST /v1/exchange
Content-Type: application/json
```

请求 schema：

```json
{
  "code": "0123456789abcdef0123456789abcdef",
  "role": "a",
  "payload": {
    "mapped_endpoint": "<OWN_OBSERVED_ENDPOINT>",
    "window": "<UTC_WINDOW>"
  }
}
```

- `code` 为 16–64 字符，只允许 `[a-z0-9-]`。两端应在仓库外生成并通过独立带外通道传递；例如
  `openssl rand -hex 16` 产生符合字符集的 32 字符值。server 只保留固定长度 SHA-256 digest，查找时
  对所有活动 digest 使用常数时间比较。
- `role` 必须恰好为 `a` 或 `b`，两端各使用一个固定角色。
- `payload` 必须是非 `null` 的合法 JSON，且整个请求 body 不超过 4096 字节。
- 未知字段、query string、其他 path、重定向和静态文件均不支持。

交换过程：

1. 第一端提交后得到 `204 No Content`，payload 暂存在内存中。
2. 第二端用同一 code、另一 role 提交；若第一端仍在 TTL 内，它得到 `200 OK` 和第一端 payload。
3. 第一端用原 role 再次提交同一 payload 进行有退避的轮询；对端已提交后，它得到第二端 payload。
4. 两端都各取走一次后，信箱立即清零并删除。之后复用同一 code 会创建一个全新的信箱。

同一 role 的重复提交不会覆盖首次 payload。每个角色最多取走对端 payload 一次；尚未配对、重复取走、
未知但语法合法的 code 都得到相同的 `204` pending 响应，避免提供独立的 code 枚举接口。调用方不得
高频轮询，应使用退避并服从 `429`。

成功响应：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{"payload":{"mapped_endpoint":"<PEER_OBSERVED_ENDPOINT>","window":"<UTC_WINDOW>"}}
```

错误响应统一为 `{"error":"<class>"}`，稳定类别与 HTTP status 如下：

| status | class | 含义 |
|---:|---|---|
| 400 | `invalid_request` | JSON、code、role、payload、source 或尾随数据无效 |
| 405 | `method_not_allowed` | `/v1/exchange` 使用了非 POST 方法 |
| 413 | `request_too_large` | body 超过 4096 字节 |
| 415 | `invalid_request` | Content-Type 不是 `application/json` |
| 429 | `rate_limited` | 全局、单 source 或有界 source 表拒绝本次请求 |

不存在读取全部 code、删除指定 code、延长 TTL、提高上限、文件上传、认证或代理转发接口。

## 3. 编译期资源边界

| 资源 | 硬边界 | 行为 |
|---|---:|---|
| 信箱 TTL | 120 秒 | 从首次提交开始计时，不因轮询刷新；过期时清零删除 |
| 同时活动 code | 64 | 满表时新 code 的 payload 被丢弃，但仍返回不可枚举的 204；只增加聚合拒绝计数 |
| 请求 body | 4096 字节 | 通过 `http.MaxBytesReader` 在解码边界拒绝 |
| 全局请求速率 | 64 req/s | 一秒容量的 token bucket，不提供运行时调高参数 |
| 单 source 速率 | 8 req/s | 一秒容量的 token bucket |
| source bucket | 4096 项 | 空闲 5 分钟后回收；满表时 fail-closed |
| HTTP header/read/write/idle | 2/5/5/10 秒 | 防止慢连接无限占用 |
| listener | 1 个 TCP listener | 唯一 raw capability，在架构清单中登记 |

信箱只存在内存。进程退出、TTL 到期或双方完成领取都会失去未领取数据；这是预期的 fail-closed 行为，
调用方不能把它当作可靠消息队列。容量饱和只通过 server 聚合计数观察，不能由远端查询活动 code。

## 4. 日志与隐私

stderr 只输出 JSON 启动事件、每分钟聚合计数和停止事件。启动事件固定声明
`test_only=true`、`warning=plaintext_observation_exchange_no_secrets` 及硬边界；计数只包括请求、
存储、交付、完成、过期、无效、限速、容量拒绝和当前活动数量。

应用不记录完整客户端 IP、source prefix、code、role 或 payload，也不写数据文件。监听地址属于服务器
自身配置，会出现在启动日志中。若前面部署反向代理、云负载均衡或额外访问日志，它们不受本程序隐私
约束；测试部署不应添加这些组件。为执行每 source 限速，进程内存会暂存至多 4096 个完整 source IP，
空闲 5 分钟后回收，且永不进入聚合快照或日志。

## 5. systemd 占位模板

下面只说明进程约束，**不是公网部署授权**。地址来自 TEST-NET；真实服务器、TCP 端口、防火墙规则、
执行人、时间窗和回滚人必须在一次单独的 live-network 评审中确定，并只保存在仓库外的受限记录中。
授权后应先创建不可登录的专用用户，并安装已经记录 SHA-256 的评审构建：

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin winkyou-signal
sudo install -o root -g root -m 0755 /tmp/wink-signal /usr/local/bin/wink-signal
```

`/etc/winkyou/wink-signal.env`：

```text
SIGNAL_LISTEN=203.0.113.10:8080
```

`/etc/systemd/system/wink-signal.service`：

```ini
[Unit]
Description=WinkYou test-only observation exchange
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=winkyou-signal
Group=winkyou-signal
EnvironmentFile=/etc/winkyou/wink-signal.env
ExecStart=/usr/local/bin/wink-signal --listen ${SIGNAL_LISTEN}
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

停止时使用精确 service 名并核验 TCP listener 已消失：

```bash
sudo systemctl disable --now wink-signal.service
sudo ss -ltnp | grep ':8080' || true
pgrep -a -x wink-signal || true
```

不得使用模糊的 `pkill -f wink`。独立授权窗口结束时还必须逐条撤销主机防火墙和云安全组中本次新增的
精确 TCP 规则。

## 6. 当前非目标

- 不实现 TLS、Noise、pairing token、身份 roster、持久认证或加密 payload；
- 不接线 `connect_test`、solver、strategy、diagnose、stdio API 或自动恢复控制器；
- 不交换 socket、fd、PacketConn，不创建 UDP socket，也不执行任何主动探测；
- 不提供生产可用性、跨进程可靠队列、水平扩展或多实例一致性。

任何真实双端打洞都还需要单独批准加密实现、目标/资源预算、失败停止条件和第二人安全复核。本组件
合入本身不批准部署，也不批准发送真实网络探测包。
