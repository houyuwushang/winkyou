# N3 Live Authorization 空白模板

> **这是空白模板，不是联网许可。** 复制到仓库外的受控位置后填写；未经维护者与独立
> 复核人共同签发，不得启动非回环 `connect_test`、`wink-rendezvous`、临时 firewall rule
> 或 fault injector。填写后的原始实例不得提交到公开仓库；公开结果只能使用本文件末尾的
> 脱敏摘要规则。

设计依据：[`ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)

## 0. 填写规则

- 一个实例只授权一个 scenario、一个 credential、一次 network-capable `connect_test`
  invocation；`attempt_count` 永远为 `1`，无自动或人工“顺手再试一次”。`endpoint_crash`
  另允许一次必须在 ledger precheck 处零 I/O 拒绝的 restart witness；它不能取得 attempt、
  carrier 或 socket；
- 所有 `<...>` 必须在签发前填写或明确写 `not_applicable`，不得留下模糊默认值；
- 时间使用带 offset 的 RFC 3339，窗口到期后授权自动失效；不得追认已经发生的流量；
- 原始记录可以在访问受控位置保存具名 operator、命令、配置与见证，但公开摘要必须移除
  IP、port、hostname、username、路径、SSID、MAC、序列号、账户、拓扑和配对材料；
- 不把 artifact、PSK、完整 fingerprint、association/credential/attempt/participant ID、
  certificate private key、packet payload 或 raw pcap 粘贴进本记录；只记录受控文件的
  checksum 与保管位置引用；
- 每个 checkbox 必须有证据引用。仅写“已检查”不构成见证；
- 任一 hard cap、stage 顺序、进程/socket/conntrack 残留或脱敏规则偏离都立即 ABORT，
  不继续下一 scenario。

## 1. 授权元数据

```text
authorization_id: <N3-LIVE-YYYYMMDD-NNN>
campaign_id: <N3-CAMPAIGN-YYYYMMDD-NNN>
status: DRAFT | APPROVED | RUNNING | ABORTED | CLOSED
scenario: peer_absent | wrong_psk | ciphertext_tamper | control_replay | stun_silent | endpoint_crash | nominal_success
attempt_count: 1
operator: <NAMED_OPERATOR>
independent_reviewer: <NAMED_REVIEWER>
requested_at: <RFC3339_WITH_OFFSET>
approved_at: <RFC3339_WITH_OFFSET>
window_start: <RFC3339_WITH_OFFSET>
window_end: <RFC3339_WITH_OFFSET>
timezone: <IANA_TIMEZONE>
authorization_expires_at: <SAME_AS_WINDOW_END>
```

签发断言：

- [ ] operator 与 independent reviewer 是两个人；
- [ ] scenario 与 campaign 顺序合法；六个负向实例未闭合前不得选择 `nominal_success`；
- [ ] 本实例只含一次 network-capable invocation，窗口长度不被用于绕过 15-second attempt envelope；
- [ ] 与同 campaign 其他实例满足 60 秒最小间隔、4/hour、12/24h 和 circuit 约束；
- [ ] 到期、ABORTED 或 CLOSED 的实例不能复用。

## 2. 精确构建与材料

```text
repository_commit: <40_HEX_SHA>
wink_binary_sha256: <64_HEX>
wink_rendezvous_binary_sha256: <64_HEX>
pair_generator_binary_sha256: <64_HEX>
fault_injector_sha256: <64_HEX_OR_NOT_APPLICABLE>
stdio_schema: winkyou.stdio/v2
framing_schema: lsp-content-length/v1
oob_artifact_profile: winkyou-test-direct-attempt-oob/1
direct_attempt_profile: winkyou-test-direct-attempt-control/1
rendezvous_profile: winkyou-test-direct-presence/1
secure_channel_profile: noise-nnpsk0-25519-chachapoly-sha256/1
pair_manifest_sha256: <64_HEX>
rendezvous_admission_sha256: <64_HEX>
artifact_fingerprint_confirmed_out_of_band: yes | no
artifact_expires_at: <RFC3339_UTC_WHOLE_SECOND>
```

- [ ] 所有 binary 都来自已独立评审并批准用于 N3 的 exact commit；
- [ ] checksum 在两端和 server 独立核对；未使用工作区临时 binary；
- [ ] 两份 recipient artifact 分别保管，未进入日志、shell history、issue/PR 或同一共享链接；
- [ ] server admission 不含 PSK，且未公开 association metadata；
- [ ] artifact 在整个窗口内有效，但 attempt deadline 仍固定不超过 15 秒；
- [ ] 当前 scenario 使用一对新生成 artifact；未复用 preflight 失败、过期或其他实例的文件。

## 3. 设备与网络环境

只使用脱敏代号，不写真实 hostname、用户名、IP、MAC、SSID、设备序列号或账户：

| 字段 | endpoint A | endpoint B |
| --- | --- | --- |
| 设备代号 | `<DEVICE_ALIAS_A>` | `<DEVICE_ALIAS_B>` |
| 角色 | `initiator` / `responder` | `initiator` / `responder` |
| OS 与版本 | `<OS_FAMILY_AND_VERSION>` | `<OS_FAMILY_AND_VERSION>` |
| CPU 架构 | `<ARCH>` | `<ARCH>` |
| 网络类型 | `<HOME_BROADBAND_OR_MOBILE_OR_OTHER_CLASS>` | `<HOME_BROADBAND_OR_MOBILE_OR_OTHER_CLASS>` |
| 接入所有权/许可 | `<OPERATOR_OWNS_OR_NAMED_PERMISSION>` | `<OPERATOR_OWNS_OR_NAMED_PERMISSION>` |
| 预期地址族 | `ipv4` / `ipv6` | `ipv4` / `ipv6` |
| machine scope 状态证据 | `<PRIVATE_EVIDENCE_REF>` | `<PRIVATE_EVIDENCE_REF>` |

```text
rendezvous_deployment_tier: self_hosted | minimum_trust
rendezvous_config_sha256: <64_HEX>
rendezvous_tls_verification: system_roots | spki_sha256
stun_responder_config_sha256: <64_HEX>
firewall_rule_private_ref: <ACCESS_CONTROLLED_REFERENCE>
network_owner_approval_ref: <ACCESS_CONTROLLED_REFERENCE>
```

- [ ] 两侧网络均由 operator 拥有或有具名权限；不是办公/共享/第三方生产网络；
- [ ] request 只有一个 rendezvous endpoint 与一个 literal STUN endpoint；
- [ ] 无默认公网 STUN、DNS fallback、candidate list、端口扫描或第二 socket；
- [ ] `wink-rendezvous` 与 STUN responder 是两个明确边界；未复用 `wink-signal`；
- [ ] 若 firewall 不能限制 source prefix，补偿措施与批准理由已记录；
- [ ] 未授权 WireGuard、SSH、业务数据或持久 tunnel。

## 4. Kill switch

每端与 server 都必须有不依赖 WinkYou 协议成功的独立停止手段：

| 对象 | kill switch 位置/类型 | 事前验证方法 | 执行人 | 私有证据引用 |
| --- | --- | --- | --- | --- |
| endpoint A process | `<PROCESS_AND_NETWORK_SWITCH>` | `<DRY_RUN_OR_PRIOR_PROOF>` | `<NAME>` | `<REF>` |
| endpoint B process | `<PROCESS_AND_NETWORK_SWITCH>` | `<DRY_RUN_OR_PRIOR_PROOF>` | `<NAME>` | `<REF>` |
| rendezvous server | `<PROCESS_STOP>` | `<DRY_RUN_OR_PRIOR_PROOF>` | `<NAME>` | `<REF>` |
| temporary firewall allow | `<RULE_DISABLE_OR_DELETE>` | `<RULE_ID_AND_COUNTER_PROOF>` | `<NAME>` | `<REF>` |

- [ ] kill switch 不依赖 stdio client 正常响应；
- [ ] operator 能在 2 秒排水窗口前立即发起停止；
- [ ] reviewer 能独立确认 process 与 firewall rule 已停止/移除；
- [ ] 没有 supervisor、systemd restart、scheduled task 或 recovery loop 把进程重新拉起；
- [ ] 触发阈值已约定：任何意外 packet、第二 socket/target、重复 stage、未知 process、
  observer 失联或隐私泄漏都立即执行 kill switch。

## 5. 事前安全核对

### 5.1 两个 endpoint

每端分别附证据：

- [ ] `WinkYou-A` 为 Disabled 或 absent；无其他 WinkYou scheduled task/timer/service；
- [ ] 无遗留 `wink`/WinkYou/meshnode/recovery/relay 实验进程；
- [ ] 无遗留 listener、UDP socket、route、interface、conntrack 或临时 firewall rule；
- [ ] canonical machine governor namespace ready、安全且 owner lock 可取得；
- [ ] safety trip 明确为 `clear`，不是 missing/unknown/indeterminate；
- [ ] pairing ledger 可读且不是 `ledger_indeterminate`；
- [ ] ledger 1h/24h 窗口、minimum interval、packet window 与 circuit 均允许本次完整 envelope；
- [ ] 系统时钟与可信来源偏差在已审查范围；artifact 尚未生效/即将过期均拒绝；
- [ ] stdio parent/child PID 识别与退出见证已准备，但公开摘要不记录 PID；
- [ ] packet/socket/process/conntrack/ledger observer 在 attempt 前已取得 baseline；
- [ ] artifact params 不会被 shell、debugger、terminal transcript 或 RPC logger 记录。

### 5.2 rendezvous 与 STUN server

- [ ] `wink-rendezvous` 尚未运行；将以 one-shot、`Restart=no`、单 association 启动；
- [ ] TLS 1.3 certificate/key 权限与 client verification material 已核对；
- [ ] association admission 未过期且只允许本实例；
- [ ] server 启动前 listener、active connection 和 state directory baseline 为零；
- [ ] 临时 firewall allow rule 尚未启用或已确认 exact disabled state；
- [ ] response-only STUN server 的监听、PPS、日志与授权窗口有单独配置证据；
- [ ] 两个 server 默认日志均不输出真实 client endpoint 或配对材料；
- [ ] 没有 `wink-signal`、coordinator、relay 或 mailbox 参与本 attempt。

### 5.3 固定资源 envelope

| 项目 | initiator ceiling | responder ceiling | 见证来源 |
| --- | ---: | ---: | --- |
| heavyweight attempt | 1 | 1 | governor/ledger |
| governed UDP socket | 1 | 1 | process/`ss`/probeio witness |
| UDP target/five-tuple | 2 | 2 | governor + packet counter |
| STUN outbound | 3 | 3 | firewall/packet counter |
| direct outbound | 2 | 1 | firewall/packet counter |
| UDP outbound total | 5 | 4 | firewall/packet counter |
| UDP PPS | 5 | 5 | governor + timestamped counter |
| rendezvous connection | 1 | 1 | server + `ss` |
| rendezvous app frames | 8 | 8 | endpoint/server aggregate |
| rendezvous app bytes | 8,256 | 8,256 | endpoint/server aggregate |
| active carrier / drain | 13s / 2s | 13s / 2s | process timeline |

TCP OS packet 数不得由 application frame 数推导。现场记录只报告真实 packet counter，
不把其差异误判为应用层超预算。

## 6. Scenario 计划与预期

只勾选本实例的一个 scenario；其他行写 `not_applicable`。

### 6.1 `peer_absent`

- [ ] 只启动一侧；对端不会在 presence window 内连接；
- [ ] 预期 `presence_timeout`，不超过 3 秒；
- [ ] 预期 `credential_burned=false`、endpoint UDP outbound=0；
- [ ] server/client carrier 有界关闭，无 persistent safety trip；
- [ ] 即使未 burn，本 artifact 也在本实例后丢弃，不重试。

### 6.2 `wrong_psk`

- [ ] 使用独立评审的 offline fixture，只替换一侧 PSK，不改变 context/association；
- [ ] fixture checksum 已填，且未输出 PSK/artifact；
- [ ] 双侧 presence 与 burn 后预期 `secure_handshake_failed`；
- [ ] 预期 UDP outbound=0、credential 不退款、无 automatic retry；
- [ ] 不把 failure 细分成可关联的 peer/PSK 信息。

### 6.3 `ciphertext_tamper`

- [ ] 使用独立评审、single-shot、test-only fault injector；生产 server 无 mutation flag；
- [ ] 只在 burn 后翻转一条 opaque handshake/control ciphertext 的一个 bit，然后退出；
- [ ] 预期 `secure_handshake_failed` 或 `control_authentication_failed`，具体期望已在下方冻结；
- [ ] injector 不持有 PSK、不打开 UDP、不排队、不重试、不记录 frame；
- [ ] credential 不退款，所有进程/socket/conntrack 有界排空。

```text
tamper_target_stage: handshake | prepare | ready | fire | verify
expected_error_class: secure_handshake_failed | control_authentication_failed
```

### 6.4 `control_replay`

- [ ] 使用独立评审、single-shot、test-only bounded rendezvous wrapper；生产 server 无 replay flag；
- [ ] wrapper 终止本次 TLS，但不持有 PSK，只重复一条已转发的 authenticated control frame；
- [ ] replay 发生在同一 attempt，exact sequence 与 frame type 已在下方冻结；
- [ ] 预期 `control_authentication_failed`，credential 不退款且零越界 emission；
- [ ] wrapper 随后退出，不排队、不跨 attempt 留存 ciphertext、不记录 frame。

```text
replayed_frame_type: PREPARE | READY | FIRE | VERIFY
replayed_sequence: <FROZEN_SEQUENCE>
expected_error_class: control_authentication_failed
```

### 6.5 `stun_silent`

- [ ] 使用已授权、operator-owned 的 response-only STUN fixture；不把请求发往未知目标；
- [ ] fixture 只丢弃本实例最多三条合法 Binding request，不响应、不重定向、不生成其他流量；
- [ ] 预期 `stun_silent`、STUN outbound 不超过 3、direct outbound=0；
- [ ] credential 已 burn 且不退款，失败后不换 STUN target、不重试；
- [ ] fixture 与临时 drop rule 在 teardown 中移除，packet counter 与残留为零。

### 6.6 `endpoint_crash`

- [ ] exact crash point：`punch_sent`；
- [ ] operator 用已验证 kill switch 终止指定 endpoint；
- [ ] survivor 在 envelope 内以 stable terminal 结束，无自动重试/恢复；
- [ ] 用同 artifact 启动一次**零网络 restart-check**，预期 `credential_used` 且 packet delta=0；
- [ ] restart-check 不算第二 network attempt，不得取得 carrier/socket；
- [ ] kill 后 process/socket/conntrack/server active connection 全部归零。

### 6.7 `nominal_success`

- [ ] 六个负向 scenario 已分别由 CLOSED authorization instance 证明；
- [ ] exact progress 为 `present -> burned -> activated -> handshake -> prepare -> socket ->
  stun -> ready -> fire -> punch_sent -> punch -> verify -> terminal`；
- [ ] 双向 VERIFY 是唯一 success，随后 `PromoteTerminal`、FINISH 与 drain；
- [ ] 实际 outbound 不超过 initiator 5 / responder 4，且 direct 为 2/1；
- [ ] 成功只证明本次 bounded attempt；不接 WireGuard/SSH/业务数据，不保留 transport。

## 7. 事中见证

```text
attempt_started_at: <RFC3339_WITH_OFFSET>
attempt_terminal_at: <RFC3339_WITH_OFFSET>
observed_progress_prefix: <STABLE_STAGE_LIST>
final_error_or_success_class: <STABLE_CLASS>
credential_burned: yes | no
finish_recorded: yes | no
safety_trip_after_attempt: clear | tripped | indeterminate
```

| 见证 | baseline | peak/delta | terminal | 私有证据引用 |
| --- | ---: | ---: | ---: | --- |
| endpoint A process count | `<N>` | `<N>` | `<N>` | `<REF>` |
| endpoint B process count | `<N>` | `<N>` | `<N>` | `<REF>` |
| endpoint A owned socket count | `<N>` | `<N>` | `<N>` | `<REF>` |
| endpoint B owned socket count | `<N>` | `<N>` | `<N>` | `<REF>` |
| rendezvous active connections | `<N>` | `<N>` | `<N>` | `<REF>` |
| initiator STUN/direct UDP packets | `<N>/<N>` | `<N>/<N>` | `<N>/<N>` | `<REF>` |
| responder STUN/direct UDP packets | `<N>/<N>` | `<N>/<N>` | `<N>/<N>` | `<REF>` |
| rendezvous app frames/bytes A | `<N>/<N>` | `<N>/<N>` | `<N>/<N>` | `<REF>` |
| rendezvous app frames/bytes B | `<N>/<N>` | `<N>/<N>` | `<N>/<N>` | `<REF>` |
| conntrack entries in scope | `<N>` | `<N>` | `<N>` | `<REF>` |
| ledger sequence | `<N>` | `<N>` | `<N>` | `<REF>` |
| firewall rule packet/byte counters | `<N>/<N>` | `<N>/<N>` | `<N>/<N>` | `<REF>` |

- [ ] observer 本身没有启动第二个 WinkYou attempt 或抓取 packet payload；
- [ ] 任一 counter 超 cap 时已立即 ABORT/kill；未为“看能不能成功”继续流量；
- [ ] progress、RPC result、server log 与 artifact secret scan 均通过；
- [ ] 没有未经说明的 DNS、STUN、TCP 或 UDP target。

## 8. 事后 teardown

必须在窗口结束前执行：

- [ ] 两端 stdio parent/child 与 fault injector process 数为 0；
- [ ] `wink-rendezvous` process/listener/active connection 为 0；
- [ ] endpoint owned UDP socket 为 0；
- [ ] scoped conntrack 为 0；若 OS 延迟回收，保持授权打开且持续观察到明确 deadline，
  不得先写“完成”；
- [ ] 临时 firewall/security-group allow rule 已删除，rule ID 与最终 counter 已记录；
- [ ] server `Restart=no`，无 systemd timer、scheduled task、supervisor 或后台恢复；
- [ ] `WinkYou-A` 仍为 Disabled 或 absent；
- [ ] safety trip 与 ledger terminal 已重新读取；indeterminate 视为失败并停止后续 campaign；
- [ ] 本实例 artifact、association admission 与 fault fixture 已从活动目录移出/删除；
- [ ] 未留下 pcap、core dump、terminal transcript、raw RPC、log 或 config 到公开工作区；
- [ ] 第二人独立复核 process/socket/conntrack/firewall/ledger 为干净终局。

```text
teardown_started_at: <RFC3339_WITH_OFFSET>
teardown_completed_at: <RFC3339_WITH_OFFSET>
second_person_verified_at: <RFC3339_WITH_OFFSET>
residual_state: none | <ABORT_WITH_PRIVATE_REFERENCE>
```

## 9. 结论与签名

```text
outcome: EXPECTED_SUCCESS | EXPECTED_BOUNDED_FAILURE | UNEXPECTED_FAILURE | ABORTED
expected_class_observed: yes | no
all_resource_caps_respected: yes | no
all_residual_checks_zero: yes | no
privacy_scan_passed: yes | no
follow_up_required: yes | no
private_follow_up_ref: <REF_OR_NOT_APPLICABLE>
```

维护者签发：

```text
name: <MAINTAINER>
decision: APPROVE_ONE_ATTEMPT | REJECT
signed_at: <RFC3339_WITH_OFFSET>
signature_or_review_ref: <ACCESS_CONTROLLED_REFERENCE>
```

独立复核人事前签发：

```text
name: <INDEPENDENT_REVIEWER>
decision: APPROVE_ONE_ATTEMPT | REJECT
signed_at: <RFC3339_WITH_OFFSET>
signature_or_review_ref: <ACCESS_CONTROLLED_REFERENCE>
```

独立复核人事后关闭：

```text
name: <INDEPENDENT_REVIEWER>
decision: CLOSE_CLEAN | CLOSE_WITH_FINDING | KEEP_OPEN
signed_at: <RFC3339_WITH_OFFSET>
signature_or_review_ref: <ACCESS_CONTROLLED_REFERENCE>
```

## 10. 公开脱敏摘要（唯一可提交部分）

只有 CLOSED 且通过第二人复核后，才可从原始记录人工生成以下摘要。不要自动复制原始字段：

```text
campaign_alias: <NON_IDENTIFYING_ALIAS>
scenario: peer_absent | wrong_psk | ciphertext_tamper | control_replay | stun_silent | endpoint_crash | nominal_success
build_commit: <40_HEX_SHA>
network_classes: <TWO_GENERIC_ACCESS_CLASSES>
address_family: ipv4 | ipv6
terminal_class: <STABLE_CLASS>
credential_burned: yes | no
udp_outbound_initiator: <COUNT>
udp_outbound_responder: <COUNT>
rendezvous_frames_initiator: <COUNT>
rendezvous_frames_responder: <COUNT>
peak_owned_sockets_per_endpoint: <COUNT>
post_teardown_processes_sockets_conntrack_connections: 0/0/0/0
safety_trip_after: clear | tripped | indeterminate
second_person_reviewed: yes | no
```

公开摘要禁止包含：真实 IP/port、hostname、username、本机/服务器路径、SSID、MAC、设备
序列号、账户/运营商、城市/组织、精确物理拓扑、authorization ID、PID、certificate、
firewall rule ID、artifact/fingerprint/association/credential/attempt/participant ID、PSK、
packet payload、pcap、raw logs 或任何能反推出个人实验环境的信息。
