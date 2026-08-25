# ADR：N3a 产品入口与现场窗口设计冻结

- 状态：**Accepted (2026-08-25)：入口版本、request schema、stable error、one-shot rendezvous、配对材料与签发格式已冻结；仅允许按 §6 验收门开工 N3b。本 ADR 不激活 N3b，不授权 LAN、公网或任何现场 I/O**
- 日期：2026-08-25
- 基线：`main` = `afb7de52ee6f2cf81282cf056cd5cd6078c1990a`
- 跟踪议题：[#70](https://github.com/houyuwushang/winkyou/issues/70)
- 上位决策：[`ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md`](./ADR-NON-LOOPBACK-CONNECT-TEST-BOUNDARY.md) §7、§10
- 空白授权模板：[`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](../N3-LIVE-AUTHORIZATION-TEMPLATE.md)

> 本 ADR 只冻结 N3b 的实现合同与首次具名现场测试的签发格式。当前二进制仍只实现
> `winkyou.stdio/v1` 的 literal-loopback `connect_test`；本文件、Draft PR、CI 通过或
> 合并本身都不会开放非回环网络，也不会授权任何人运行一次现场 attempt。

## 1. 决策摘要与边界

| 事项 | N3a 决策 |
| --- | --- |
| stdio 版本 | **不是 v1 additive。** N3b 使用显式 `winkyou.stdio/v2`；framing 仍为 `lsp-content-length/v1` |
| 方法集 | v2 仍只有 `handshake`、`status`、`diagnose`、`export_redacted_report`、`connect_test`、`cancel` |
| 输入分流 | `connect_test` v2 使用严格 tagged union；loopback complete bundle 与 N2 OOB artifact 不能靠字段猜测 |
| N2 artifact | 请求内嵌 `winkyou-test-direct-attempt-oob/1`，不接受 artifact path，不含 direct endpoint |
| rendezvous | endpoint 由本次请求显式给出；artifact 只提供 association；非回环 transport 必须 TLS 1.3 |
| STUN | 本次请求显式给出一个 canonical literal unicast `AddrPort`；无默认服务、无 DNS |
| rendezvous server | 新的 one-shot `wink-rendezvous`；单 association、双 slot、零持久化、硬上限、不复用 `wink-signal` |
| 配对生成 | 一条离线命令原子生成 initiator、responder 与 secret-free rendezvous admission 三份文件 |
| 现场授权 | 一个授权实例只覆盖一个显式 attempt；失败演练与成功用例各用独立实例、独立 credential |

本切片仍是 `auth_scope=test_only`。它只证明一次受管 direct attempt 是否双向可达，不建立
成员身份，不返回可复用 socket，不接 WireGuard/业务数据面，不启动 daemon、scheduler、
恢复、candidate 轮换、自动重试或 birthday 求解。

## 2. stdio 非回环入口

### 2.1 版本裁决：v2，不修改 v1

现有 v1 同时具备以下兼容性承诺：

1. handshake 必须精确请求 `winkyou.stdio/v1`；
2. `connect_test` envelope 已明确固定为 `auth_scope + complete_bundle + deadline_ms`；
3. method params 使用 unknown-field rejection；
4. v1 的 loopback progress、结果与 `non_loopback_blocked` 已成为可回归行为。

若在同一个版本号下增加 `oob_artifact` 或 rendezvous 参数，旧 server 与新 server 会在都声称
“v1”的情况下对同一请求给出不同 schema 判定。这不是兼容扩展。因此 N3b 必须：

- 保留 v1 handshake golden、固定方法集、complete bundle parser、结果和错误类；
- 新增客户端**显式请求**的 `winkyou.stdio/v2`，不协商、不回退、不自动重发成 v1；
- v2 继续使用 `lsp-content-length/v1`，沿用请求大小、并发、速率、deadline、取消和
  process shutdown 规则；
- v2 handshake 增加 `connect_test_profiles`，精确报告
  `loopback_complete_bundle` 与 `winkyou-test-direct-attempt-oob/1`；客户端未见该 profile
  时不得尝试 direct；
- v2 的方法名仍是原六个，不增加 `open_socket`、`send_packet`、candidate 或 packet API。

当前 main 不识别 `winkyou.stdio/v2`，必须继续稳定返回 `incompatible_version`。只有 N3b
实现、测试和独立评审完成后，v2 handshake 才能出现在二进制中。

v2 handshake 的新增片段精确为以下有序数组；没有动态 profile discovery：

```json
{
  "connect_test_profiles": [
    "loopback_complete_bundle",
    "winkyou-test-direct-attempt-oob/1"
  ]
}
```

### 2.2 v2 严格 tagged union

v2 的 loopback arm 为：

```json
{
  "auth_scope": "test_only",
  "attempt": {
    "kind": "loopback_complete_bundle",
    "complete_bundle": {"<existing v1 complete bundle>": "<unchanged>"}
  },
  "deadline_ms": 15000
}
```

该 arm 仍把 `complete_bundle` 的原始 JSON 交给现有 `loopbackcarrier` 严格 parser。N3b 不得
复制、放宽或重写该 parser；现有 literal-loopback、machine scope、4096-byte、三报文和
`non_loopback_blocked` 语义全部不变。

v2 的 direct arm 为：

```json
{
  "auth_scope": "test_only",
  "attempt": {
    "kind": "direct_oob_artifact",
    "oob_artifact": {
      "artifact": "winkyou-test-direct-attempt-oob/1",
      "<remaining exact N2a members>": "<value>"
    }
  },
  "rendezvous": {
    "endpoint": "<HOST_OR_LITERAL>:<PORT>",
    "deployment_tier": "self_hosted",
    "tls": {
      "verification": "spki_sha256",
      "spki_sha256": "<32-byte unpadded base64url>"
    }
  },
  "stun_endpoint": "<CANONICAL_LITERAL_UNICAST_ADDRPORT>",
  "deadline_ms": 15000
}
```

严格规则：

- `attempt.kind` 必填且只接受上述两个值；不根据对象里“看起来像什么”猜测类型；
- 两个 arm 互斥。loopback arm 出现 `rendezvous`/`stun_endpoint`，或 direct arm 出现
  `complete_bundle`，都在任何 authority acquisition 或 I/O 前返回 `invalid_params`；
- `oob_artifact` 是内嵌对象，最大 4096 bytes，继续由 `directattempt.ParseArtifact` 拒绝
  duplicate/unknown fields、非 canonical 编码、错误 fingerprint、错误 generation/scope、
  未生效、过期或未知 profile；
- 不接受 `artifact_path`、stdin 之外的 secret source、环境变量、argv 或配置文件引用。
  controller 已持有 artifact，内嵌可避免扩大 server 的本地文件读取权限与 TOCTOU 面；
- 整个 JSON-RPC request 仍受 65536-byte v2 transport 上限；
- `deadline_ms` 缺省为 15000，direct arm 只能降低，不能超过 15000；内部 13-second
  carrier envelope 与 2-second drain margin 仍是更强上限；
- 所有 raw params 在处理结束后 best-effort 清零，且永不进入 progress、错误、日志或报告。

### 2.3 rendezvous 与 STUN endpoint

`rendezvous.endpoint` 属于本次 transport routing，不属于配对身份或 Noise 信任锚，因此
显式进入请求，而不写入 N2 artifact。artifact 中唯一关联字段仍是
`rendezvous_association_id`；request 不重复该值，N3b 必须从经严格验证的 artifact 取得。

endpoint 规则冻结为：

- 只接受一个 `host:port`，端口非零；没有列表、SRV、fallback、Happy Eyeballs 或重连；
- literal IP 走 0 次 DNS，必须 canonical、无 zone、非 unspecified/multicast；
- hostname 只允许单个明确输入，最多一次 `LookupNetIP`；零结果为 `rendezvous_dns_failed`，
  多于一个 canonical unicast 结果为 `rendezvous_dns_ambiguous`，不得任选其一；
- DNS/TCP exclusive claim 在 attempt lifetime 内不释放；失败后同一 invocation 不重拨；
- 非回环 carrier 必须使用 TLS 1.3。`tls.verification` 二选一：
  `system_roots` 必须同时给出 certificate `server_name` 且禁止 `spki_sha256`；
  `spki_sha256` 必须给出 SHA-256(DER SubjectPublicKeyInfo) 的 32-byte unpadded-base64url
  pin 且禁止 `server_name`。未知模式、空 pin 或组合字段漂移零 I/O 拒绝；
- TLS 只保护 transport 与降低 on-path 元数据篡改风险。即使是自托管 server，其证书、
  运营者身份和位置也**不是**对端配对信任锚；唯一对端证明仍是一次 NNpsk0；
- TLS handshake、certificate error、DNS 文本和底层 socket error 都不得反射到 RPC。

`stun_endpoint` 是 direct arm 的另一必填字段，因为同 socket mapping observation 无法只靠
rendezvous endpoint 完成。第一版只接受一个 canonical literal global-unicast
`AddrPort`，不允许 hostname、默认公网 STUN、配置继承或 endpoint 列表。它在同一个
attempt 内先登记为 target 1；READY 认证得到的 peer endpoint 随后登记为 target 2。
`wink-rendezvous` 不兼任 STUN responder；现场窗口必须另行记录已获准的 response-only
STUN 服务配置摘要。

### 2.4 固定执行顺序

direct arm 的 N3b 管线不得重排、插入 fallback 或拆分 socket：

```text
strict tagged-union + artifact + endpoint validation (zero I/O)
  -> read-only safety/ledger precheck; used/indeterminate credential stops with zero I/O
  -> acquire exact N2AttemptCost and exclusive carrier claims
  -> one TLS rendezvous preconnect
  -> secret-free presence (<= 3s)
  -> durable BURN_AND_ADMIT + full envelope reservation
  -> BeforeFirstEmission
  -> ACTIVATE
  -> one empty-payload NNpsk0 handshake
  -> encrypted PREPARE
  -> one governed wildcard-ephemeral UDP socket
  -> same-socket STUN
  -> encrypted READY + authenticated peer target registration
  -> encrypted FIRE
  -> simultaneous-open encrypted punch
  -> bidirectional VERIFY
  -> PromoteTerminal
  -> close UDP + carrier, durable FINISH, drain
```

presence timeout、carrier 预连接或 TLS 失败发生在 burn 前；Noise 及其后的任何失败都已
消费 credential。无论在哪一阶段失败，都没有自动 retry、endpoint replacement、candidate
rotation、new artifact、background recovery 或数据面接线。

### 2.5 direct progress 序列

direct arm 只使用 N2d 已证明的 exact stage vocabulary：

```text
present -> burned -> activated -> handshake -> prepare -> socket -> stun
        -> ready -> fire -> punch_sent -> punch -> verify -> terminal
```

规则：

- 成功路径不得跳过、重复或重排 stage；通知在对应 milestone 已完成后发出；
- 失败路径发出已经完成的最长前缀，随后最多一个 `terminal`；pre-presence 失败可以只发
  `terminal`；最终 JSON-RPC response/error 才决定成功或失败；
- stage 只包含上述字符串、原 request id、单调 `remaining_budget_ms` 与 `cancellable`，
  不含 endpoint、port、role、association、credential、fingerprint、DNS、路径或 PID；
- `terminal.cancellable=false`，其他 stage 在 terminal commit 前为 `true`；
- progress 无法交付时，下一次 emission 前终止 attempt，执行 FINISH/drain，不让网络工作
  在 client 不可见时继续；
- v1 loopback 的 `validating_complete_bundle -> loopback_socket_ready ->
  terminal_finish_recorded` 保持不变。

### 2.6 stable error classes

兼容性键是 `error.data.class`。每个 direct 错误固定包含同值 `reason`、`retryable=false`、
一个上述 stage 或 `preflight`、实际 `credential_burned` 布尔值和稳定 terminal category。
`retryable=false` 表示 server 不自动重试；未来人工新 attempt 必须使用新的授权实例与新
credential。现有 JSON-RPC/v1 公共类保持不变；N3b 新增以下全集：

| class | 典型阶段 | 通常已 burn | 稳定含义 |
| --- | --- | --- | --- |
| `unsupported_attempt_profile` | `preflight` | 否 | tagged-union kind 或 N2 exact profile 未知；无协商/fallback |
| `invalid_direct_artifact` | `preflight` | 否 | artifact schema、canonical encoding、fingerprint、role、generation 或 scope 非法 |
| `direct_artifact_not_yet_valid` | `preflight` | 否 | canonical `issued_at` 尚未到达 |
| `direct_artifact_expired` | `preflight` | 否 | canonical `expires_at` 已到达 |
| `rendezvous_endpoint_invalid` | `preflight` | 否 | endpoint/TLS schema 不在冻结范围 |
| `stun_endpoint_invalid` | `preflight` | 否 | STUN 不是单个 canonical literal unicast target |
| `rendezvous_dns_failed` | `preflight` | 否 | 唯一一次解析失败或返回零结果 |
| `rendezvous_dns_ambiguous` | `preflight` | 否 | 唯一一次解析返回多个可用地址；未任选、未连接 |
| `rendezvous_tls_failed` | `preflight` | 否 | TLS 1.3 或 certificate/pin 验证失败 |
| `rendezvous_unreachable` | `preflight` | 否 | 单次 TCP preconnect 未建立 |
| `presence_timeout` | `terminal` | 否 | 3 秒内未见双 slot；已做 secret-free carrier I/O，但未 burn |
| `pairing_scope_changed` | `burned` | 以实际值为准 | owner/scope 在 admission 边界变化；不得伪报未 burn |
| `ledger_indeterminate` | `burned` | 否 | durable ledger 无法确定；预算按已满处理 |
| `credential_used` | `burned` | 否 | credential 已有 durable burn 记录；零新增 emission |
| `pairing_rate_limited` | `burned` | 否 | 1h/24h 持久预算阻断 |
| `pairing_circuit_open` | `burned` | 否 | 持久 admission circuit 阻断 |
| `activation_failed` | `activated` | 是 | burn 后 ACTIVATE/ACTIVATE_READY 未闭合 |
| `secure_handshake_failed` | `handshake` | 是 | wrong PSK、handshake authentication/order/tamper 失败；不区分对外细节 |
| `control_authentication_failed` | `prepare`/`ready`/`fire`/`verify` | 是 | AEAD、sequence、role、context、replay 或 control payload 验证失败 |
| `rendezvous_protocol_violation` | carrier 任意阶段 | 以实际值为准 | wire kind/order/framing 不合法或 burn 前收到 secure frame |
| `carrier_domain_violation` | control 阶段 | 是 | authenticated direct-punch frame 从 rendezvous-control carrier 到达 |
| `rendezvous_budget_exceeded` | carrier 任意阶段 | 以实际值为准 | 8-frame/8,256-byte/deadline 硬上限阻断 |
| `stun_silent` | `stun` | 是 | 最多 3 次发送后没有合格 Binding response |
| `stun_protocol_error` | `stun` | 是 | STUN cookie/transaction/attribute/framing 不符合最小 profile |
| `stun_source_mismatch` | `stun` | 是 | response source 与已登记 STUN target 不同 |
| `ready_rejected` | `ready` | 是 | READY role/context/generation/profile/canonical endpoint 不合法 |
| `punch_timeout` | `punch` | 是 | 固定 2/1 direct packet envelope 内未完成可达性证明 |
| `direct_packet_rejected` | `punch` | 是 | 观察到但拒绝的 punch AEAD/domain/sequence/role/replay frame |
| `verification_failed` | `verify` | 是 | 双向 VERIFY 未闭合，不能 PromoteTerminal |
| `peer_cancelled` | 当前阶段 | 以实际值为准 | 收到合法 authenticated CANCEL；本端立即 terminal |
| `attempt_expired` | 当前阶段 | 以实际值为准 | 13-second active/15-second attempt envelope 到期 |
| `resource_budget_exceeded` | 当前阶段 | 以实际值为准 | socket/target/five-tuple/PPS/packet 或 exclusive claim 硬违规；持久 trip |
| `drain_failed` | `terminal` | 以实际值为准 | 2 秒内无法证明资源排空；持久 trip |
| `direct_attempt_failed` | 当前阶段 | 以实际值为准 | 未能安全归入以上类别的脱敏 terminal failure |

`invalid_params`、`cancelled`、`deadline_exceeded`、`safety_trip_active`、
`pairing_admission_blocked` 与 `internal_error` 继续使用现有含义。错误 message 只能是固定
英文摘要，不得携带底层 `error.Error()`。特别禁止返回 IP/port、hostname、certificate
subject、DNS answer、association/attempt/credential/participant ID、fingerprint、PSK、
路径、用户名、PID、OS errno 或 packet bytes。

### 2.7 成功结果与脱敏

v2 direct 成功结果只允许包含：

- `attempt_kind=direct_oob_artifact`、`terminal=success`；
- `bidirectional=true`、`promoted_terminal=true`；
- `credential_burned=true`、`finish_recorded=true`；
- 每类实际应用 frame 与 UDP outbound packet 计数、预留 envelope；
- 脱敏 ledger state/sequence 与 safety-trip state。

不得返回 local/mapped/peer/STUN/rendezvous endpoint、NAT 类型标签、association/identifier、
artifact fingerprint、Noise transcript/hash、ciphertext、certificate、socket/handle 或可复用
transport。TCP OS packet 数不得从 application frame 数推导或写进结果。

## 3. 可部署 one-shot rendezvous server

### 3.1 二进制与信任边界

N3b 的最小新二进制名冻结为：

```text
wink-rendezvous serve
```

它只实现 N2c `WYRC` v1 stream wire：`presence/presence_ready`、
`activate/activate_ready`、`handshake` 与 `control` 的有界转发。它：

- 不是 signaling、coordinator、relay、mailbox、TURN 或 membership service；
- 不导入、不启动、不代理 `wink-signal`，也不复用其明文 observation protocol；
- 不解析 Noise handshake、control plaintext、READY endpoint 或 direct-punch；
- 不获得 pairing secret、machine governor、UDP/socket promotion 或恢复权限；
- server TLS 只认证 transport endpoint，不认证两台 WinkYou endpoint；
- 无 reconnect、polling、offline queue、cross-attempt reuse、background retry 或 scheduler。

### 3.2 启动输入

命令形态冻结为：

```text
wink-rendezvous serve \
  --listen <LITERAL_LISTEN_ADDR>:<PORT> \
  --tls-cert <CERT_FILE> \
  --tls-key <KEY_FILE> \
  --association-file <RENDEZVOUS_ADMISSION_FILE>
```

所有参数必填；无公网默认地址、默认端口或自动证书。`--listen` 只接受 literal unicast、
loopback 或显式 wildcard。非回环启动必须具备 TLS 1.3 certificate/key 与已签发的 live
authorization；N3b 不提供 plaintext 非回环开关。证书私钥、association 文件及其路径不写
日志。配置项不能提高下述编译期上限。

`rendezvous-admission.json` 是配对生成器同时产生的 secret-free 文件：

```json
{
  "profile": "winkyou-test-direct-presence/1",
  "association_id": "<16-byte unpadded base64url>",
  "issued_at": "<canonical UTC whole second>",
  "expires_at": "<canonical UTC whole second>"
}
```

它不含 PSK、credential/attempt/participant ID、role 或 endpoint。server 只接受该 exact
association 的 slot `a` 与 `b`；initiator 固定使用 `a`，responder 固定使用 `b`。未知
association、重复 slot、第三连接或非法首帧都会让本 one-shot process fail-closed 终止，
不会继续接受下一批连接。该文件虽不是 secret，仍视作私有关联元数据，不得公开或记录。

### 3.3 生命周期与硬上限

一个进程只服务一个 association：

1. 启动后等待到 admission `expires_at`，过期无连接也退出；最长生成有效期 10 分钟；
2. 第一个 TCP socket 被 accept 时立即启动 13-second association wall-clock deadline，
   TLS handshake 与第一条合法 presence 也必须落在其中的 3-second pre-presence deadline；
3. 第二个 slot 必须在同一个 3-second deadline 内到达，否则关闭 listener/connection 并退出；
4. 两侧 presence ready 后，只有双方各自发送 ACTIVATE 才进入 opaque relay；
5. terminal、任一错误、任一连接关闭或 13 秒到期时，同时关闭两侧与 listener；
6. process 退出前输出一次聚合 terminal record，不自动重启。

编译期上限：

| 资源 | server hard ceiling |
| --- | ---: |
| association | 1 |
| transport slot / accepted TCP connection total | 2 / 2 |
| concurrent listener | 1 |
| presence | 3 seconds |
| association lifetime after first accepted connection | 13 seconds |
| application frame | 每 slot 每方向 8 |
| application bytes | 每 slot 每方向 8,256 |
| decoded frame payload | 1,024 bytes |
| persisted state / queue / retry / reconnect | 0 |

TLS handshake bytes 与 TCP OS packet 不伪装成 application frame 计数。server 仍必须给每个
accept/read/write/TLS operation 使用上述总 deadline；不得让半开 TLS、半帧或 silent peer
跨过 association 生命周期。最多接受两个 TCP socket：非法连接会消耗本 one-shot
association 并终止，而不是用无限 accept 抵抗攻击。

### 3.4 日志与最小信任档

默认 stderr 只允许一个 terminal JSON record，字段精确限于：

```json
{
  "event": "terminal",
  "class": "<stable_server_class>",
  "accepted_connections": 0,
  "frames_read": 0,
  "frames_written": 0,
  "bytes_read": 0,
  "bytes_written": 0
}
```

允许的 server class 为 `completed`、`association_expired`、`presence_timeout`、
`association_rejected`、`protocol_violation`、`budget_exceeded`、`tls_failed`、
`peer_disconnected`、`deadline_exceeded`、`shutdown`、`internal_error`。不增加 timestamp
或其他连接元数据，尤其不得含监听/对端 IP 或 port、hostname、username、path、association、slot、
证书内容、frame bytes 或底层 error。server 不创建数据库、状态目录、access log、metrics
listener 或 crash dump；systemd/journal 的外部保留策略属于 operator 责任。

自托管档和最低信任档运行完全相同的二进制、wire、TLS、上限与日志 schema。区别只在谁
运营 transport 及其可用性/元数据责任。两档都必须假设 server 可以丢包、乱序、篡改、
伪造 presence 或拒绝服务；这些行为最多消耗/阻断一次 credential，不能伪造 NNpsk0 对端、
解密 control 或获得 direct/data-plane 权限。

### 3.5 自托管部署模板

手工前台模板只说明未来 N3b 形态，不是当前执行许可：

```text
install reviewed wink-rendezvous binary and verify its checksum
place TLS key/certificate and rendezvous-admission.json in an owner-only directory
apply the pre-approved TCP firewall rule
run wink-rendezvous serve with the four required flags
observe exactly one terminal aggregate record
run the teardown checklist
```

systemd 模板必须使用专用不可登录用户、`UMask=0077`、`Restart=no`，并至少包含：

```ini
[Unit]
Description=WinkYou one-shot N3 rendezvous
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=<DEDICATED_SERVICE_USER>
Group=<DEDICATED_SERVICE_GROUP>
UMask=0077
EnvironmentFile=<PRIVATE_ENV_FILE>
ExecStart=<ABSOLUTE_BINARY> serve --listen ${RENDEZVOUS_LISTEN} --tls-cert ${RENDEZVOUS_CERT} --tls-key ${RENDEZVOUS_KEY} --association-file ${RENDEZVOUS_ADMISSION}
Restart=no
RuntimeMaxSec=620
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
RestrictAddressFamilies=AF_INET AF_INET6
```

仓库只保存占位模板。真实 listen address、certificate path、service user、端口和部署位置留在
具名窗口的受控记录中，不提交到仓库。防火墙/云安全组模板固定为以下策略语义，而不是
可直接复制的真实规则：

```text
ALLOW tcp/<RENDEZVOUS_PORT> FROM <APPROVED_SOURCE_PREFIXES> DURING <AUTHORIZED_WINDOW>
RATE-LIMIT new TCP handshakes to the documented one-shot envelope
DENY tcp/<RENDEZVOUS_PORT> FROM all other sources
REMOVE the allow rule at window end and record the rule identifier plus counter delta
```

如两端 source address 不可预知，授权记录必须明确说明为何只能放宽 source filter，并用
短时间窗、TLS、one-shot process、连接总数 2 和外部 packet counter 补偿；不得静默改成
长期开放端口。

### 3.6 teardown

每次实例无论成功或失败都必须：

1. 停止/等待 one-shot service，确认 `Restart=no` 且 process 数为 0；
2. 移除 firewall/security-group 临时 allow rule，记录 counter delta；
3. 用 `ss` 或平台等价工具确认该 TCP listener/connection 为 0；
4. 确认 server active association/connection 为 0；
5. 删除本次 `rendezvous-admission.json`；若 TLS material 是本次临时生成，再按签发计划撤销/
   删除，不能声称普通删除等于可验证安全擦除；
6. 确认无 timer、scheduled task、service restart、queue、state directory 或 crash artifact；
7. 由第二人复核脱敏证据后关闭授权实例。

## 4. 配对材料生成工具

### 4.1 命令与输出

N3b 的离线命令形态冻结为：

```text
wink solver pair direct --out-dir <NEW_PRIVATE_DIRECTORY>
```

一次 invocation 同时生成：

- `initiator.winkyou.json`：`local_role=initiator` 的 N2 OOB artifact；
- `responder.winkyou.json`：`local_role=responder` 的 N2 OOB artifact；
- `rendezvous-admission.json`：§3.2 的 secret-free server admission；
- `manifest.json`：secret-free 的 profile、共同 artifact fingerprint、issued/expires 时间与
  固定文件名，不含路径、PSK 或其他 identifier。

不提供按 `--role` 分两次独立生成的模式：两次随机生成会产生不匹配的 PSK/context，也更
容易误复用 credential。一个 generation 固定等于一对 recipient artifact、一个 association
admission 和一个 credential。

`--out-dir` 必须不存在。tool 创建 owner-only directory，所有文件使用 exclusive create，
拒绝 symlink/reparse/hard-link/broad ACL，不覆盖、不修复、不跟随现有目标；任一写入、sync
或权限验证失败时，本 invocation 失败并清理自己刚创建的未完成输出。Linux 目标为目录
`0700`、文件 `0600`；Windows 使用只允许当前用户与 SYSTEM 的受保护 DACL。实现 PR 必须
提供崩溃/部分写入见证，不能仅靠文档承诺“原子”。`manifest.json` 在其他三份文件写入、
权限复核与 sync 后最后创建；缺少 manifest 的 directory 永远视为未完成，不能交付或使用。

### 4.2 随机、时效与 fingerprint

- PSK 使用 `crypto/rand` 生成 32 bytes；
- credential、attempt、initiator participant、responder participant、association 五个 ID
  各为独立 16 bytes，canonical unpadded base64url，且 pairwise distinct；
- `observation_generation="1"`，双方 governor scope 均为 `machine`；
- `issued_at` 为当前 canonical UTC whole second，`expires_at` 固定为其后 10 分钟；无
  `--expires-in` 提高开关；
- 两份 recipient artifact 除 `local_role` 外共享 exact context、PSK、ID 和 fingerprint；
- fingerprint 继续使用 mini-spec §7.1 已冻结的 restricted JCS/SHA-256 规则，不另造格式；
- 任何 RNG、clock、encoding、collision 或 permission 异常都零输出/零网络失败。

### 4.3 secret 与终端策略

PSK 和完整 artifact 永不进入 stdout/stderr、日志、argv、环境变量、telemetry、crash message、
shell history 或 manifest。成功只向 stderr 写固定 `pair_created` 状态，不回显 directory、
filename、fingerprint、ID 或 expiry；调用者已知自己传入的目录。

可选 clipboard sink 只允许显式：

```text
--clipboard-role initiator|responder --acknowledge-clipboard-history
```

每次最多复制一个 recipient artifact，另一个仍只写文件；不允许“两份都复制”或 stdout
fallback。tool 必须明确提示 clipboard manager/remote desktop/history 可能持久保存 secret，
且不能声称计时清空能擦除历史。无 clipboard API 或拒绝 acknowledgement 时 fail-closed。

### 4.4 带外交付与一次性责任

- initiator/responder 文件分别通过经过认证且加密的带外渠道交给对应 operator；不得把两份
  artifact 放进 rendezvous server、公开 issue/PR、日志或同一共享链接；
- 双方在受控记录中核对共同 fingerprint 与 10 分钟窗口，但公开摘要不记录 fingerprint；
- `rendezvous-admission.json` 单独交给 server operator；它不是 secret，但仍可关联一次窗口；
- 一次 invocation 等于一个 credential；attempt 一旦 burn，成功、失败、崩溃或取消都不
  退款，旧 artifact 重启必须由 durable ledger 拒绝；
- preconnect/presence 失败按协议不 burn，但本现场流程仍要求丢弃这对 artifact。若要再试，
  必须签发新窗口并生成新 credential；实现不能借此加入自动重试；
- 过期、用后和 aborted 窗口的文件由 operator 从活动目录移除；普通文件删除不被描述为
  可证明的介质安全擦除。

## 5. Live authorization 冻结

空白模板见 [`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](../N3-LIVE-AUTHORIZATION-TEMPLATE.md)。
它是人工签发记录，不是可复用配置文件，也不会因放在命令行而授予代码新能力。
本 N3a PR 只提交空白模板，不填写或签发首个窗口实例；首个实例留待 N3b 评审闭合后由
维护者与独立复核人共同签发。

为同时满足“首次 N3 只允许一个显式 attempt”和失败矩阵，冻结以下单位：

- **一个 authorization instance = 一个 scenario = 一次显式 invocation = 一个 credential；**
- 同一实例禁止 retry、并发第二 attempt、换 endpoint、换 artifact 或延长窗口；
- 首次 campaign 至少由七个分别签发、分别 teardown 的实例组成：peer absent、wrong PSK、
  authenticated ciphertext tamper、authenticated control replay、STUN silent、endpoint crash
  和 nominal success；
- 前六个负向实例各通过一次后，才允许执行 nominal success；七份证据均由第二人复核后，
  才能称该 campaign 成功。任何单个窗口本身不得被宣传成“公网穿透已可用”；
- 多实例安排仍受 durable 60-second minimum、4/hour、12/24h、packet window 和 circuit
  约束；六个 burn 后负向/正向实例不可能在同一个 rolling hour 内全部执行，必须据实排期，
  绝不为赶进度 reset ledger 或提高编译上限。

wrong-PSK、tamper、replay 与 STUN-silent 演练不得给生产入口/server 增加通用 mutation
开关。它们必须使用单独审查、单次、test-only 的 fixture/fault injector，并在授权中记录
其 commit/checksum：

- wrong PSK 只替换一侧 artifact 的 PSK，保持其他 context 不变，以证明 NNpsk0 失败；
- tamper 使用一个终止 TLS、仍不知 PSK 的 test-only bounded rendezvous wrapper，只翻转一条
  burn 后 opaque handshake/control ciphertext 的一个 bit，随后退出；
- replay wrapper 只复制一条已在本 attempt 转发的 authenticated control frame，证明固定
  sequence/replay rejection，随后退出；
- STUN-silent fixture 只在已授权 response-only server 上丢弃本实例的最多三条 Binding
  request，不把请求重定向到未知或无所有权的目标；
- fault injector 不得知道两侧 PSK、生成新 candidate、打开 UDP、重试或留队列；
- 未有独立评审过的注入工具时，该负向实例和整个 campaign 都不能签发为成功。

## 6. N3b 与首次现场窗口的验收门

N3b 至少必须证明：

1. v1 handshake/connect-test golden 与 loopback 全套测试逐字节不变；v2 exact-version、tagged
   union、unknown-field、profile downgrade 与跨版本误发全部 fail-closed；
2. 新 error class、progress 前缀/terminal、脱敏结果各有 golden 与负面测试；
3. one-shot server 的 TLS、双 slot、顺序、连接/frame/byte/deadline、半帧、第三连接、
   日志隐私、取消和 crash drain 全部受测；
4. pair generator 的 RNG failure、十分钟时效、权限、O_EXCL、partial-write/crash、clipboard
   acknowledgement、secret scan 与双 artifact fingerprint 一致性受测；
5. architecture gate 只对白名单入口开放 N2c/N2d 已审查能力，仍拒绝 runtime、legacy、
   scheduler、`wink-signal`、WireGuard 和任何 raw socket escape；
6. loopback/unit/netns 测试先绿；N3b PR 本身不运行真实 LAN/公网，不部署 server，不修改
   firewall/service/scheduled task；
7. 独立安全评审明确接受 N2d 证据、N3a 设计与 N3b 实现后，维护者才可填写并签发
   **一个**真实授权实例；签发必须指明 exact build SHA/checksum、环境、窗口、kill
   switch、见证和 teardown；
8. 现场结束后提交的仓库证据只含脱敏计数与稳定 class，不含个人 IP、hostname、username、
   本机路径、SSID、MAC、设备序列号、运营商账户、artifact、fingerprint 或 topology。

在这些门全部闭合前：当前 v1 非回环仍为 `non_loopback_blocked`，v2 不存在，
`wink-rendezvous` 与 pair command 不存在，现场 I/O 仍为 NO-GO。
