# WinkYou stdio API v1

状态：Phase 1a 本地 API。传输、方法名和 notification 语义在 `winkyou.stdio/v1`
中固定；`connect_test` 现仅实现经 governor 管理的一次性回环切片。非回环 endpoint
仍稳定阻断，且没有长连接、业务数据、自动重试或重连。

该 API 面向需要嵌入 WinkYou 被动诊断和未来一次性连接测试的本地工具。它不监听
localhost 或 LAN，不传递 socket，也不授予 Node Runtime、恢复或端口映射权限。

## 1. 启动与机器级权威

```text
wink solver serve --stdio
```

进程在读取第一个 JSON-RPC 请求前必须取得 canonical machine governor lock。namespace
缺失、不安全、无权限或已有 owner 时，进程直接以非零状态退出，不建立第二份预算，
也不降级为 per-user scope。若另一个进程持锁，stderr 的稳定前缀为
`governor_lock_unavailable`，并在可信 owner metadata 可用时包含持锁 PID。启动失败时
stdout 不写伪造的 JSON-RPC 帧。

v1 不实现代理转发。成功握手固定报告 `mode=owner`、`proxy_supported=false`。
共享 daemon、Named Pipe 或 Unix domain socket 均不属于本版本。

安装程序或管理员需预先按 [`MACHINE-SAFETY-NAMESPACE.md`](./MACHINE-SAFETY-NAMESPACE.md)
执行 `wink setup-machine-scope`。JSON-RPC 参数、配置文件和环境变量都不能改变 machine
scope。

## 2. Framing

每个消息是一个 UTF-8 JSON body，前面只有一个 LSP 风格 header：

```text
Content-Length: <UTF-8 字节数>\r\n
\r\n
<JSON body>
```

v1 规则：

- header 名不区分大小写，但除 `Content-Length` 外不接受其他 header；重复 header 被拒绝；
- header 必须使用 CRLF，body 后不增加换行；
- `Content-Length` 必须是正十进制整数；零长、半个 header、半个 body 均被拒绝；
- 连续粘连的完整帧按顺序读取；
- header 最多 1024 字节，请求 body 最多 65536 字节，响应/notification body 最多
  1048576 字节；
- 超长或无法安全重新同步的 framing 错误返回一次 `id:null` 错误后终止进程；
- JSON-RPC 顶层对象必须只有 `jsonrpc`、`id`、`method`、可选 `params`；`params`
  只能是对象；
- `id` 只能是 JSON string 或 canonical 十进制整数。v1 不接受 `null`、小数、指数写法
  或 client-to-server notification。

## 3. 进程级硬限制

默认硬限制同时通过 `handshake.protocol_limits` 返回：

| 边界 | v1 值 | 超限错误类 |
| --- | ---: | --- |
| 并发请求 | 4 | `concurrency_limit` |
| 请求速率 | 20/s，burst 20 | `rate_limited` |
| 默认 deadline | 5000 ms | `deadline_exceeded` |
| 客户端可请求的最大 deadline | 30000 ms | `invalid_params` |
| 退出取消等待 | 2000 ms | 进程退出错误 |

每个方法的 `params.deadline_ms` 可向下或在最大值内调整 deadline。`cancel` 是控制方法，
不被普通请求的速率或并发占满所阻断，但仍受 framing 和请求大小限制。

生命周期语义：

- **stdin EOF** 表示"不再有新请求"，不是取消。server 停止接收新请求，把在途请求
  排空到各自完成或到达自身 deadline；仅当排空超过退出等待窗口时才回退为取消，再
  等待一个同样有界的窗口。
- **父 context 取消、进程中断或致命传输错误**会立即取消全部在途 request context，
  并在有界时间内等待处理器退出。
- **`handshake` 是顺序同步方法**：它在分发循环内联完成，因此同一批写入中跟在它
  后面的请求一定能观察到已完成的握手状态，客户端可以安全地流水线
  `handshake + 后续请求`。

## 4. 握手与版本拒绝

除 `cancel` 外，首个成功请求必须是：

```json
{
  "jsonrpc": "2.0",
  "id": "handshake-1",
  "method": "handshake",
  "params": {
    "schema_version": "winkyou.stdio/v1",
    "framing_version": "lsp-content-length/v1"
  }
}
```

两个版本必须精确匹配；没有协商、回退或“尽力兼容”。不匹配返回
`incompatible_version`，握手状态保持未完成。

成功结果包含：

- schema/framing 版本与构建信息；
- 进程级 hard limits；
- machine governor scope/profile、当前 owner、硬资源上限和剩余额度；
- `mode=owner`、`proxy_supported=false`；
- 当前 safety trip 状态；
- `auth_scope=test_only` 和唯一的 `supported_auth_scopes=["test_only"]`。该权限只对应
  下述一次性回环测试，不是成员身份、匿名连接或非回环联网授权；
- 下列六个且仅六个方法；
- `winkyou/progress` notification 能力。

## 5. 固定方法集

### `handshake`

参数见 §4。safety trip 生效时仍可调用，以便客户端读取阻断状态。重复、版本一致的
握手返回新的只读快照。

### `status`

参数：

```json
{"deadline_ms": 2000}
```

所有字段均可省略。返回 governor scope、namespace、owner、safety trip、只读
`pairing_ledger` 和 `network_activity_started=false` 的结构化快照。ledger 字段不包含
credential、attempt、endpoint 或 secret。采集复用 `wink diagnose` 的被动路径，不启动
runtime 或主动网络探测。safety trip 生效时仍可调用。

### `diagnose`

参数与 `status` 相同。成功结果等价于 `wink diagnose --json` 的现有结构化
`winkyou.diagnose/v1alpha1` 报告。它仍是被动采集，但按 v1 safety policy，在 safety
trip 生效时明确拒绝。

### `export_redacted_report`

```json
{
  "path": "<CALLER_SUPPLIED_ABSOLUTE_PATH>",
  "redaction": "strict",
  "deadline_ms": 5000
}
```

`redaction` 省略时也固定为 `strict`，不存在 raw 模式。目标必须是绝对路径、父目录已
存在且目标文件不存在；v1 不覆盖已有文件或 symlink。导出会移除 namespace/config
路径、接口名、owner identity、trip 的 peer/attempt attribution 和 collector detail。
RPC 结果只返回 `written`、`redaction`、`bytes`，不回传报告内容或目标路径；错误也不
反射底层路径和本地错误文本。safety trip 生效时拒绝且不创建文件。

### `connect_test`

v1 envelope 固定为：

```json
{
  "auth_scope": "test_only",
  "complete_bundle": {
    "local_role": "initiator|responder",
    "local_endpoint": "127.0.0.1:<FIXED_PORT>",
    "peer_endpoint": "127.0.0.1:<FIXED_PORT>",
    "offer": {"<mini-spec OFFER fields>": "<value>"},
    "acceptance": {"<mini-spec ACCEPTANCE fields>": "<value>"}
  },
  "deadline_ms": 15000
}
```

`offer` 与 `acceptance` 的字段、编码、fingerprint 和 context 绑定必须精确符合
[`TEST-ONLY-PAIRING-MINI-SPEC.md`](./TEST-ONLY-PAIRING-MINI-SPEC.md) §4，并使用 ADR
选定的 `noise-nnpsk0-25519-chachapoly-sha256/1`。整个 complete bundle 不得超过
4096 bytes；重复键、未知字段、非 canonical 编码、过期或尚未生效的凭据均在取得
attempt 前拒绝。

`local_endpoint` 与 `peer_endpoint` 必须是 canonical 数值 loopback `AddrPort`，端口
非零且二者不同。不解析 hostname，不做 DNS。任一 endpoint 不是 literal loopback 时，
在取得 peer/attempt、burn credential 或发送报文前稳定返回：

```json
{
  "class": "non_loopback_blocked",
  "reason": "non_loopback_blocked"
}
```

两个 artifact 的 governor scope 都必须为 `machine`；`user_acknowledged` 在 burn 前以
`user_scope_blocked` 拒绝。通过这些零网络检查后，执行顺序固定为：machine attempt
完整预留 → durable admission/burn → 一次性授权消费 → `probeio` 回环 socket →
`BeforeFirstEmission` → 同 socket 上两条 48-byte NNpsk0 握手 → 加密
`SYN/SYN_ACK/ACK` → `PromoteTerminal` → 立即关闭 transport → durable FINISH →
attempt 排水。任何错误都不退款，也不会自动生成新 bundle、重试或重连。

成功路径的 progress 顺序固定为 `validating_complete_bundle` →
`loopback_socket_ready` → `terminal_finish_recorded`。其中
`loopback_socket_ready` 只在受管 socket 已绑定且唯一 peer target 已登记后发送，通知不含
endpoint、identifier 或任何 handle；它不是额外网络授权。若通知无法交付，carrier 会在
下一次发射前终止并记录失败。

每端最坏 envelope 固定为 1 socket、1 target、1 five-tuple、3 packets、3 PPS、
15 seconds、heavyweight。initiator 成功时实际出站 3 包，responder 为 2 包。成功响应只
报告一次性证明、实际出站包数、上述最坏 envelope 和脱敏 ledger 状态，不返回 endpoint、
identifier、PSK、prologue、transcript 或可复用 transport。完整边界见
[`LOOPBACK-CONNECT-TEST.md`](./LOOPBACK-CONNECT-TEST.md)。

### `cancel`

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-1",
  "method": "cancel",
  "params": {"request_id": "diagnose-1"}
}
```

命中在途请求时返回 `{"cancelled":true}`，否则返回
`{"cancelled":false,"reason":"not_in_flight"}`。原请求随后以 `cancelled` 错误结束。

## 6. Progress notification

长操作可在最终 response 前交错发送：

```json
{
  "jsonrpc": "2.0",
  "method": "winkyou/progress",
  "params": {
    "request_id": "diagnose-1",
    "stage": "collecting_passive_report",
    "remaining_budget_ms": 4821,
    "cancellable": true
  }
}
```

`request_id` 保留原请求的 JSON 类型和值。`remaining_budget_ms` 是 server deadline 的
单调剩余估计；客户端不得把 progress 当作延长 deadline 或提升预算的授权。最终
response 后不再发送该请求的 progress。

## 7. 错误类

错误遵循 JSON-RPC error object，并固定提供 `error.data.class` 与 `retryable`：

| class | 含义 |
| --- | --- |
| `parse_error` | body 不是合法 JSON-RPC JSON |
| `invalid_request` | envelope、id 或 framing 不符合 v1 |
| `invalid_params` | params schema 或 deadline 不合法 |
| `method_not_found` | 方法不在固定 allowlist |
| `request_too_large` | 请求超过 65536 字节 |
| `rate_limited` | 进程请求速率超限 |
| `concurrency_limit` | 四个普通请求槽位已满 |
| `deadline_exceeded` | server deadline 到期 |
| `cancelled` | client 显式取消或进程退出取消 |
| `handshake_required` | 未完成精确版本握手 |
| `incompatible_version` | schema/framing 不精确匹配 |
| `safety_trip_active` | durable safety trip 阻断该方法 |
| `not_implemented` | 当前进程不具备经评审的 loopback carrier authority；正式 machine authority 不走此分支 |
| `export_failed` | 严格脱敏报告无法安全创建 |
| `invalid_complete_bundle` | complete bundle 的严格 schema、编码、fingerprint 或时效验证失败 |
| `non_loopback_blocked` | endpoint 不是 canonical literal loopback；零发射且不 burn |
| `user_scope_blocked` | bundle 含未获准的 user-acknowledged scope；零发射且不 burn |
| `pairing_admission_blocked` | credential 已使用或持久化预算、circuit、ledger 阻断 |
| `connect_test_failed` | 已准入的一次性回环握手、加密 punch、提升或终局失败 |
| `internal_error` | 未向客户端暴露内部文本的处理失败 |

## 8. 固定负面清单

v1 明确不提供：

- raw socket、file descriptor 或 `PacketConn` 的传递；
- `open_socket`、`send_packet`、批量目标、端口扫描或任意 packet API；
- 提高 governor、PPS、socket、target、packet、five-tuple、deadline、并发或速率硬上限
  的方法；
- 监听 localhost/LAN 的模式；
- Node Runtime、恢复、birthday punch、预测、端口映射、Phase 2 身份或 test-only 到成员
  身份的升级。

未知方法一律 `method_not_found`。新增任何网络入口还会被
`internal/architecture` 的生产网络能力清单拒绝。

## 9. 完整请求帧示例

以下 `Content-Length` 是紧随其后的单行 UTF-8 JSON 的精确字节数：

```text
Content-Length: 146\r\n
\r\n
{"jsonrpc":"2.0","id":"handshake-1","method":"handshake","params":{"schema_version":"winkyou.stdio/v1","framing_version":"lsp-content-length/v1"}}
```

```text
Content-Length: 81\r\n
\r\n
{"jsonrpc":"2.0","id":"status-1","method":"status","params":{"deadline_ms":2000}}
```

最小只读跨语言示例见
[`../examples/stdio_status_client.py`](../examples/stdio_status_client.py)。
