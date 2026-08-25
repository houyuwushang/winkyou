# stdio JSON-RPC API v2

状态：**N3b Draft 实现协议；等待独立安全评审。本文不签发 LAN、公网或现场运行授权。**

`winkyou.stdio/v2` 是显式版本的本地 JSON-RPC 2.0 API。它继续使用
`lsp-content-length/v1` framing，并在不改变 v1 任何字节或行为的前提下，为
`connect_test` 增加 N2 一次性 direct-attempt arm。设计权威是
[`ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)。

## 1. 当前边界

- 客户端必须明确请求 `winkyou.stdio/v2`；无协商、无降级、无自动回退到 v1。
- v1 的 handshake golden、六个方法、loopback bundle parser、progress、结果与
  `non_loopback_blocked` 保持不变。
- v2 direct 仍是 `auth_scope=test_only` 的一次性连通证明，不返回 socket、endpoint 或
  可复用 transport，不接 WireGuard 或业务数据面。
- 本实现没有 retry、reconnect、candidate rotation、后台恢复、daemon 或 scheduler。
- 仓库测试只运行 literal loopback 与 Linux 隔离 network namespace。真实 LAN/公网执行
  仍须另行签发一份具名 authorization instance；合并、构建或 CI 通过都不等于授权。

启动本地进程的命令仍是：

```text
wink solver serve --stdio
```

进程必须先取得机器级 governor owner。取锁失败时，它在任何主动网络 I/O 前退出；不会
启动第二个 governor，也不会代理到共享 daemon。

## 2. Framing 与公共上限

每个 JSON-RPC body 使用唯一的 ASCII `Content-Length` 头与 CRLF：

```text
Content-Length: <DECIMAL_BYTES>\r\n
\r\n
<EXACT_UTF8_JSON_BODY>
```

硬上限继续由 handshake 报告。当前 request body 最大 65,536 bytes；header 最大 1,024
bytes；并发、速率、响应大小、默认 deadline 与 shutdown drain 沿用 v1。direct arm 的
额外上限是：

| 项目 | hard ceiling |
| --- | ---: |
| 内嵌 N2 OOB artifact | 4,096 bytes |
| `deadline_ms` | 缺省 15,000；只可降低 |
| active carrier envelope | 13 seconds |
| terminal drain margin | 2 seconds |
| 自动 retry / fallback | 0 |

## 3. Handshake

第一条方法必须精确为：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "handshake",
  "params": {
    "schema_version": "winkyou.stdio/v2",
    "framing_version": "lsp-content-length/v1"
  }
}
```

v2 response 复用 v1 的 build、protocol limits、governor、safety trip、方法与通知字段，并
增加固定有序数组：

```json
{
  "connect_test_profiles": [
    "loopback_complete_bundle",
    "winkyou-test-direct-attempt-oob/1"
  ]
}
```

同一进程完成 v1 handshake 后不能切换 v2，反之亦然。版本、framing 或进程内版本切换
不匹配时稳定返回 `incompatible_version`。

v2 方法集仍精确为：`handshake`、`status`、`diagnose`、
`export_redacted_report`、`connect_test`、`cancel`。不存在 packet、socket、target、扫描、
提高预算或候选枚举 API。

## 4. `connect_test` tagged union

### 4.1 Loopback arm

```json
{
  "auth_scope": "test_only",
  "attempt": {
    "kind": "loopback_complete_bundle",
    "complete_bundle": {"<existing-v1-object>": "<unchanged>"}
  },
  "deadline_ms": 15000
}
```

该 arm 把原始 `complete_bundle` 交给现有 v1 parser。它仍只接受 canonical 数值 loopback，
保持既有三报文预算、错误类与 progress。出现 `rendezvous`、`stun_endpoint` 或
`oob_artifact` 即在 authority acquisition/I/O 前返回 `invalid_params`。

### 4.2 Direct arm

以下仅是字段形状；尖括号是占位符，不能直接运行：

```json
{
  "auth_scope": "test_only",
  "attempt": {
    "kind": "direct_oob_artifact",
    "oob_artifact": {
      "artifact": "winkyou-test-direct-attempt-oob/1",
      "<remaining-exact-N2-members>": "<recipient-specific-value>"
    }
  },
  "rendezvous": {
    "endpoint": "192.0.2.10:443",
    "deployment_tier": "self_hosted",
    "tls": {
      "verification": "spki_sha256",
      "spki_sha256": "<32-byte-unpadded-base64url>"
    }
  },
  "stun_endpoint": "192.0.2.20:3478",
  "deadline_ms": 15000
}
```

严格规则：

- `attempt.kind` 必填且只接受两个已冻结值；不根据其他字段猜类型。
- 两个 arm 互斥；outer、attempt、rendezvous 与 TLS 对象拒绝 duplicate/unknown member。
- artifact 必须内嵌；不接受 path、argv、环境变量、额外 stdin 或配置文件引用。
- artifact duplicate/unknown/canonical/fingerprint/generation/scope/time/profile 校验仍由
  `directattempt.ParseArtifact` 完成，并保留相应 direct 稳定错误类。
- rendezvous 只接受一个 `host:port`。literal 为 0 次 DNS；hostname 最多一次解析，0 个
  可用结果失败，多个 canonical unicast 结果失败，不任选其一。
- TLS 只接受 `system_roots + server_name` 或 `spki_sha256 + pin` 二选一；固定 TLS 1.3。
- STUN 必须是一个 canonical literal unicast `AddrPort`；没有默认 STUN、DNS 或目标列表。
- raw params 在处理后 best-effort 清零，不进入 progress、错误、日志或报告。

## 5. 固定执行顺序与成本

direct pipeline 不得重排：

```text
strict validation
  -> read-only safety/ledger preflight
  -> exact N2AttemptCost acquisition
  -> TLS preconnect
  -> secret-free presence
  -> durable burn + full envelope reservation
  -> BeforeFirstEmission + ACTIVATE
  -> one empty-payload NNpsk0 handshake
  -> PREPARE
  -> one wildcard-ephemeral governed UDP socket
  -> same-socket STUN
  -> READY + authenticated peer target registration
  -> FIRE
  -> simultaneous-open encrypted punch
  -> bidirectional VERIFY
  -> PromoteTerminal
  -> close UDP/carrier + durable FINISH + drain
```

每端预留的冻结 envelope 为 3 sockets、4 targets、4 five-tuples、5 PPS、5 UDP packets、
15 seconds、heavyweight=true。实际成功上限为 initiator `STUN<=3 + direct=2`，responder
`STUN<=3 + direct=1`。TCP application frame 每方向最多 8、application bytes 每方向最多
8,256；TLS/TCP 的 OS packet 数不会由 application frame 数推导。

presence/preconnect/TLS 失败发生在 burn 前。durable burn 之后的任意成功、失败、取消或
崩溃都不退款；相同 credential 跨进程/重启必须被 ledger 零新增发射拒绝。

## 6. Progress

成功路径的固定序列是：

```text
present -> burned -> activated -> handshake -> prepare -> socket -> stun
        -> ready -> fire -> punch_sent -> punch -> verify -> terminal
```

通知方法仍为 `winkyou/progress`，绑定原 request id，只含 `stage`、单调剩余预算与
`cancellable`。`terminal.cancellable=false`；其他阶段在 terminal commit 前为 true。失败
只发已经完成的最长前缀，再加最多一个 terminal。通知中禁止 endpoint、port、role、ID、
fingerprint、DNS、path 或 PID。progress 无法交付时，不得进行下一次 emission。

## 7. 结果与错误

direct 成功结果的 exact schema 与示例见 ADR §2.7。它只返回：成功终局、双向证明、
promotion/credential/FINISH 布尔值、应用层 emission 计数、既有 governor reservation、
pairing-ledger status 与 safety-trip status。它不返回任何 local/mapped/peer/STUN/rendezvous
endpoint、NAT 永久标签、identifier、fingerprint、Noise transcript、ciphertext、证书或
socket。

direct error 使用统一 JSON-RPC code，兼容键是 `error.data.class`；data 精确增加：

```json
{
  "class": "<stable-class>",
  "reason": "<same-stable-class>",
  "retryable": false,
  "stage": "<frozen-stage>",
  "credential_burned": false,
  "terminal_category": "preflight_rejected"
}
```

完整 34 个 class 与阶段含义以 ADR §2.6 为权威，并由
`internal/solverstdio/testdata/direct-error-classes.golden.json` 固化。底层 error、IP/port、
hostname、certificate subject、DNS answer、ID、fingerprint、PSK、path、username、PID、
errno 与 packet bytes 永不进入 RPC error。caller cancel/deadline 继续由 JSON-RPC 公共
`cancelled` / `deadline_exceeded` 覆盖。

## 8. 配套命令

离线生成一对 recipient artifact、secret-free admission 与 manifest：

```text
wink solver pair direct --out-dir <NEW_PRIVATE_DIRECTORY>
```

目录必须不存在。manifest 最后创建；缺少 manifest 的目录不可交付。成功只在 stderr 写
`pair_created`，不输出目录、文件名、fingerprint、ID、expiry、PSK 或完整 artifact。clipboard
需要 `--clipboard-role initiator|responder --acknowledge-clipboard-history` 双重显式同意，且
一次最多复制一份 recipient artifact。

one-shot transport server：

```text
wink-rendezvous serve \
  --listen <LITERAL_LISTEN_ADDR>:<PORT> \
  --tls-cert <CERT_FILE> \
  --tls-key <KEY_FILE> \
  --association-file <RENDEZVOUS_ADMISSION_FILE>
```

它只转发一个 association 的有界 WYRC 密文帧，固定 TLS 1.3、双 slot、13 秒、零持久化、
零 retry。stderr 只有一条脱敏 terminal aggregate。它不是 `wink-signal`、coordinator、
relay、mailbox、STUN/TURN 或 trust anchor。

这些命令存在不等于获准部署。首次现场 campaign 必须在 N3b 独立安全评审闭合后，按
[`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](./N3-LIVE-AUTHORIZATION-TEMPLATE.md) 为每个 scenario
分别签发、分别生成 credential、分别 teardown；当前仓库没有已签发实例。

## 9. 验证边界

常规 unit/loopback tests 证明 framing、schema、golden、TLS、server 上限、配对输出和排水。
required Linux job 另外在 RFC 5737 TEST-NET network namespaces 中，以两个真实子进程走
完整 stdio v2 → governed carrier → same-socket STUN → encrypted punch → VERIFY 路径，并
核对 iptables、socket、process、conntrack 与 ledger 见证。

这些证据仍不证明消费级路由器、运营商 CGNAT 或公网可用率，也不授权真实网络测试、
自动重试、数据面接线或 production-ready 宣称。
