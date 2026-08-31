# N3c Gate C 具名现场授权模板（空白）

状态：**Draft blank template；不得填写后提交仓库。本文不是配置、credential、网络能力或
现场许可。只有 Gate C1 ADR Accepted、对应实现 exact SHA 独立复审通过、disposable-router
门闭合后，维护者与第二复核人才可在受控私有记录中复制并签发一个实例。**

权威设计：
[`ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md`](./adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md)。
N3b 的 [`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](./N3-LIVE-AUTHORIZATION-TEMPLATE.md) 不能直接
改名复用：Gate C 增加 caller-owned SSH child、Gate B profile/cost、production
`TransportLease`、WireGuard handoff 与 post-OOB 数据证明。

> 一个填写实例只授权：一个 scenario、一个 credential、一次 foreground invocation、一个
> exact profile/resource、一个 fixed plan 和一个时间窗。不得 retry、换 endpoint/observer、
> 换 seed/profile、扩大候选或在进程重启后续跑。

## A. 私有记录规则

- 本模板副本只存放在受控私有位置，不进入 Git、Issue、PR、CI artifact、聊天记录或普通日志。
- 下列字段只在私有副本填写：真实 IP/port、hostname、username、路径、host key、设备信息、
  网络/运营商信息、observer endpoint、artifact/fingerprint、kill-switch 命令与 topology。
- 公开复盘只能写：脱敏设备代号、profile/resource、stable class、资源计数、duration、ceiling、
  residue 与复核结论。
- artifact、PSK、private key、WireGuard key 不复制进本模板；只记录各自 secret-free checksum
  或受控保管位置的引用。

## B. 授权身份与窗口

| 字段 | 私有填写值 |
| --- | --- |
| authorization instance ID | `<PRIVATE_INSTANCE_ID>` |
| scenario | `<ONE_EXACT_SCENARIO>` |
| operator | `<PRIVATE_OPERATOR>` |
| independent reviewer | `<PRIVATE_REVIEWER>` |
| initiator alias | `<REDACTED_ALIAS_A>` |
| responder alias | `<REDACTED_ALIAS_B>` |
| network/environment | `<PRIVATE_NAMED_ENVIRONMENT>` |
| not-before | `<PRIVATE_UTC_TIME>` |
| not-after | `<PRIVATE_UTC_TIME>` |
| timezone | `<PRIVATE_TIMEZONE>` |
| one foreground invocation | `yes / no` |
| retry/fallback/second attempt | `must be no` |

签发：

- [ ] operator 已签名并写入时间。
- [ ] independent reviewer 已签名并写入时间。
- [ ] 两人均确认本实例没有从此前模板、credential 或失败 attempt 继承权限。

## C. Exact build 与来源

| 字段 | 私有填写值 |
| --- | --- |
| repository | `<EXPECTED_REPOSITORY>` |
| implementation PR | `<REVIEWED_PR>` |
| Git SHA | `<EXACT_FULL_SHA>` |
| initiator binary SHA-256 | `<CHECKSUM>` |
| responder binary SHA-256 | `<CHECKSUM>` |
| build tags/profile | `<EXACT_REVIEWED_BUILD>` |
| Go/toolchain | `<VERSION>` |
| Gate C1 ADR revision | `<EXACT_SHA>` |
| independent implementation review | `<PRIVATE_OR_PUBLIC_REFERENCE>` |
| disposable-router evidence | `<REQUIRED_REFERENCE>` |

- [ ] 两端 binary checksum 与签发记录一致。
- [ ] working tree/build inputs 可复现且没有未审查 patch。
- [ ] 普通 release binary 未被误当作 field-capable build。
- [ ] 任一代码、依赖、build tag 或配置 schema 变化都会使本实例失效。

## D. Credential、profile 与固定成本

| 字段 | 私有填写值 |
| --- | --- |
| artifact profile | `winkyou-direct-oob-attempt/1` |
| direct control profile | `winkyou-direct-hard-nat-control/1` |
| planner profile | `<ONE_ACCEPTED_PROFILE>` |
| resource class | `<ONE_MATCHING_RESOURCE_CLASS>` |
| local role A/B | `<INITIATOR_OR_RESPONDER>` |
| asymmetric mapping-set role | `<ONLY_IF_APPLICABLE>` |
| secret-free manifest checksum | `<CHECKSUM>` |
| credential expires | `<PRIVATE_UTC_TIME>` |
| runtime fallback | `disabled` |
| fixed plan/joint digest reference | `<PRIVATE_SECRET_FREE_REFERENCE>` |
| conditional probability shown | `<VALUE_AND_MODEL>` |

- [ ] 本实例使用新生成、从未 burn 的一对 artifact。
- [ ] profile/resource/roles 是 exact combination；无协商、自动选择或 fallback。
- [ ] `hard_32k_candidate/1`、full-65K 和未知 profile 均未出现。
- [ ] 操作员已阅读 conditional probability 与模型限制；timeout 不被描述为求解证明。
- [ ] artifact 未包含 endpoint、SSH、observer、WireGuard identity 或资源数字。
- [ ] 本实例结束后 credential 永不再次使用，即使 pre-burn 失败也不自动 retry。

按所选 profile 复制权威 ADR 的 exact cost，不手工发明数字：

| 资源 | 冻结值 | 事前核对 |
| --- | ---: | --- |
| active attempt/heavyweight | `<EXACT>` | `<PASS_FAIL>` |
| OOB process/channel/DNS | `initiator: 1 owned child/1 outbound TCP/0 DNS; responder: 1 fixed endpoint process/1 accepted channel/0 DNS` | `<PASS_FAIL>` |
| UDP sockets | `<EXACT>` | `<PASS_FAIL>` |
| targets/five-tuples | `<EXACT>` | `<PASS_FAIL>` |
| reserved packets | `<EXACT>` | `<PASS_FAIL>` |
| protocol packet max | `<EXACT>` | `<PASS_FAIL>` |
| PPS | `<EXACT>` | `<PASS_FAIL>` |
| active/drain | `<EXACT> / 2s` | `<PASS_FAIL>` |
| OOB frames/bytes per direction | `8 / 8,256` | `<PASS_FAIL>` |
| pre-FINISH WG outer datagrams | `<=3 / direction` | `<PASS_FAIL>` |
| retry/fallback | `0 / 0` | `<PASS_FAIL>` |

若 profile 为 hard-16K：

- [ ] 24 小时 campaign admission 未使用。
- [ ] 24 小时 16,432 packet reservation 未使用。
- [ ] campaign circuit clear；未通过 reset 退款或提高额度。
- [ ] ordinary ledger 与 campaign ledger 计数独立且均 determinate。
- [ ] local/router conntrack capacity 与 disposable-router 证据满足 Accepted ADR。
- [ ] 本窗口只运行一个 fixed campaign；失败后不在同一天再跑。

## E. 双端安全前检

两端分别填写：

| 检查 | initiator | responder |
| --- | --- | --- |
| canonical machine scope ready | `<PASS_FAIL>` | `<PASS_FAIL>` |
| machine governor owner available | `<PASS_FAIL>` | `<PASS_FAIL>` |
| safety trip clear | `<PASS_FAIL>` | `<PASS_FAIL>` |
| pairing journal determinate | `<PASS_FAIL>` | `<PASS_FAIL>` |
| ordinary/campaign circuit state | `<PRIVATE_RESULT>` | `<PRIVATE_RESULT>` |
| no pending attempt/stage | `<PASS_FAIL>` | `<PASS_FAIL>` |
| no conflicting `wink up`/private key/interface/route owner | `<PASS_FAIL>` | `<PASS_FAIL>` |
| no WinkYou child/session residue | `<PASS_FAIL>` | `<PASS_FAIL>` |
| `WinkYou-A` disabled/absent | `<PASS_FAIL>` | `<PASS_FAIL>` |
| no unauthorized scheduled task/service | `<PASS_FAIL>` | `<PASS_FAIL>` |
| exact binary checksum | `<PASS_FAIL>` | `<PASS_FAIL>` |
| artifact/request owner-only | `<PASS_FAIL>` | `<PASS_FAIL>` |
| system clock within allowed skew | `<PASS_FAIL>` | `<PASS_FAIL>` |

- [ ] cached self-bootstrap/autonomous birthday recovery 仍为 NO-GO。
- [ ] 本实例不会启动 `wink up` recovery、daemon、scheduler 或历史 puncher。
- [ ] 操作员没有修改 governor、ledger、PPS、packet、socket、target 或 duration ceiling。

## F. SSH/OOB 私有核对

| 字段 | 私有填写值 |
| --- | --- |
| SSH literal endpoint | `<PRIVATE_LITERAL_ADDRPORT>` |
| SSH endpoint authority instance | `<PRIVATE_REFERENCE>` |
| pinned host-key reference | `<PRIVATE_REFERENCE>` |
| one-entry known-hosts checksum | `<CHECKSUM>` |
| private-key file checksum/reference | `<PRIVATE_REFERENCE>` |
| remote OS/OpenSSH version | `<VERSION>` |
| fixed remote command | `wink solver direct child --stdio` |
| dedicated account login shell | `<SHELL_PATH>` |
| forced-command absolute path | `<ABSOLUTE_PATH>` |
| dedicated authorized_keys restriction checksum | `<CHECKSUM>` |
| fixed child wrapper/binary checksum | `<CHECKSUM>` |
| `sshd -T -C` effective-config proof | `<PRIVATE_REFERENCE>` |
| client `ssh -G` golden reference | `<REVIEWED_REFERENCE>` |
| responder staged request checksum | `<CHECKSUM>` |

- [ ] endpoint 是单个 literal IP:port；0 DNS；与已签发 `SSHEndpointAuthority` 实例精确一致。
- [ ] host key 已通过第二条独立渠道核对；禁止 accept-new、ignore 或 bypass。
- [ ] 只用一个明确 identity；无 password、keyboard-interactive、agent forwarding；
  `IdentityAgent=none` 生效。
- [ ] client argv 含 `-F none`、`GlobalKnownHostsFile=none`、`-T`；`ssh -G` 输出与 reviewed
  golden 一致。
- [ ] 该 identity 是 Gate C 专用 key；server entry 使用 `restrict` 加固定绝对路径
  `command=`，禁止 shell/forwarding/agent/X11/pty，普通交互登录 key 未被复用。
- [ ] wrapper 与 parent 目录 owner/root-only、非 symlink；wrapper 清空 environment 并以
  绝对路径 exec exact binary；`SSH_ORIGINAL_COMMAND` 被忽略或逐字验证。
- [ ] `sshd -T -C` 证明含 `permituserenvironment no`；entry 无 `environment=` 选项。
- [ ] 不读取 user/global ssh config；无 ProxyCommand/ProxyJump/ControlMaster/port forwarding/TTY。
- [ ] initiator 只有一个 owned child、一个 outbound TCP connection、一次 connection attempt；
  responder 不再 spawn child，只接受一个 fixed SSH channel；无 reconnect。
- [ ] remote command 没有 request-derived path/token/command/environment。
- [ ] pairing PSK/artifact bytes 不进入 SSH adapter、argv、environment 或日志。
- [ ] 关闭 dedicated child 不会停止或重配 operator 的独立管理 overlay/SSH server。

## G. UDP target 与 observer 权限

| 字段 | 私有填写值 |
| --- | --- |
| expected peer public address A sees | `<PRIVATE_LITERAL_IP>` |
| expected peer public address B sees | `<PRIVATE_LITERAL_IP>` |
| RFC 5780 A1:P1 | `<PRIVATE_LITERAL_ADDRPORT>` |
| RFC 5780 A1:P2 | `<PRIVATE_LITERAL_ADDRPORT>` |
| RFC 5780 A2:P1 | `<PRIVATE_LITERAL_ADDRPORT>` |
| RFC 5780 A2:P2 | `<PRIVATE_LITERAL_ADDRPORT>` |
| observer operator permission | `<PRIVATE_REFERENCE>` |
| peer-address/network authority | `<PRIVATE_REFERENCE>` |
| address family | `<ONE_FAMILY>` |

- [ ] peer target 是本地 operator 显式批准的一个地址；不是远端 report、DNS、CIDR 或列表。
- [ ] 双方 fresh authenticated evidence 必须与本地 expected address 匹配。
- [ ] observer topology 为双地址/双端口，同一地址族，且各 endpoint 权限已核对。
- [ ] request/peer 无法上传 port list、candidate、span、socket、PPS 或 packet count。
- [ ] hard-16K candidate port 只可能位于 49152–65535。
- [ ] address/evidence 在 attempt 中变化即终局，不更新、不换 target、不 fallback。
- [ ] 若 profile 为 hard-16K，目标是受控 disposable gateway/独占地址，或已有地址/网络
  operator 明确许可；共享 CGNAT 不能只凭 endpoint 所有权获得 16K 发射权限。

## H. Kill switch 与实时见证

kill switch（私有填写，事前实际演练一次）：

| 层 | 私有动作 | 验证方式 | 最大完成时间 |
| --- | --- | --- | ---: |
| foreground controller | `<PRIVATE_ACTION>` | `<PRIVATE_WITNESS>` | `<BOUND>` |
| SSH child | `<PRIVATE_ACTION>` | process count zero | `<=2s drain` |
| UDP/transport | `<PRIVATE_ACTION>` | socket/counter stable | `<=2s drain` |
| WireGuard consumer | `<PRIVATE_ACTION>` | interface/peer/transport closed | `<BOUND>` |
| interface/route rollback | `<PRIVATE_ACTION>` | interface/route/address restored | `<BOUND>` |
| emergency containment | `<SEPARATELY_AUTHORIZED_ACTION_OR_NONE>` | `<PRIVATE_WITNESS>` | `<BOUND>` |

注意：本模板不自动授权 firewall、route、service 或 scheduled-task 变更。若 emergency
containment 需要这些动作，必须在此实例外另有明确授权与回滚步骤。interface/route 的创建
所需 privilege/capability、具体步骤与回滚顺序必须事前写入私有记录并演练。

实时记录只收集：

- [ ] profile/resource 与 progress stage；
- [ ] SSH child/TCP count、application frames/bytes、drain；
- [ ] UDP packet/socket/target/five-tuple/PPS；
- [ ] conntrack peak/terminal/zero residue；
- [ ] ledger BURN/FINISH/circuit sequence；
- [ ] TransportLease attach/adopt/standby/challenge/detach；
- [ ] pre-FINISH WireGuard outer datagram count；
- [ ] OOB child 为零后的 post-OOB echo；
- [ ] process/listener/interface/lock residue。

任一计数超过 ceiling、出现第二 attempt/child/address、未知 target、unexpected process 或
kill switch 失效：立即停止本实例，不靠 retry 收集更多证据。

## I. Scenario 期望

只勾选本实例唯一 scenario：

- [ ] peer absent（pre-burn、UDP=0）
- [ ] wrong PSK（burn 后 handshake 终局、direct=0）
- [ ] OOB EOF after burn（carrier terminal 后 UDP 立即停止）
- [ ] evidence/address unusable（direct=0）
- [ ] TransportLease/consumer failure（handoff 或 data plane 不可用）
- [ ] consumer crash after Promote（FINISH/close/drain 顺序）
- [ ] candidate exhaustion（仅相应 profile、固定 plan）
- [ ] nominal direct success（SSH 退出后 WireGuard echo 仍成功）

| 字段 | 私有填写值 |
| --- | --- |
| expected stable class/result | `<EXPECTED>` |
| expected burn | `<YES_NO>` |
| expected direct emissions | `<EXACT_OR_BOUND>` |
| expected campaign circuit | `<EXPECTED>` |
| success criteria | `<EXACT>` |
| stop criteria | `<EXACT>` |

负向 fault 不得通过 production 通用 mutation flag 实现；其 fixture、exact SHA/checksum 与
能力边界必须已经独立评审。hard-16K failure/exhaustion 优先在 disposable router 完成；一次
真实 hard-16K instance 不因“演练矩阵”获得第二次 admission。

## J. Teardown 与第二人复核

执行后分别记录并核对：

- [ ] foreground command 已退出或按预期保持；若保持，最终已显式 cancel。
- [ ] SSH child/process/TCP connection = 0。
- [ ] OOB frame/byte counters terminal 后稳定。
- [ ] probe socket/target/five-tuple worker = 0。
- [ ] TransportLease/session/tunnel ownership = 0。
- [ ] WireGuard peer/interface/route 无非预期 residue。
- [ ] conntrack/mapping 回落并满足窗口定义的 zero-owned-residue。
- [ ] machine governor lock 已释放；无第二 owner。
- [ ] durable FINISH/circuit/packet window 与实际 terminal 一致。
- [ ] responder pending slot 不可自动重用。
- [ ] credential/artifact 已移出可运行位置且不会 retry。
- [ ] `WinkYou-A` 仍 Disabled/absent，无新 task/service/daemon。
- [ ] 原管理 overlay/SSH 可用性没有被 WinkYou 修改。

第二人复核：

| 字段 | 私有填写值 |
| --- | --- |
| reviewer | `<PRIVATE_REVIEWER>` |
| reviewed at | `<PRIVATE_UTC_TIME>` |
| observed result | `<PASS_FAIL>` |
| ceiling violations | `<NONE_OR_PRIVATE_REFERENCE>` |
| residue | `<ZERO_OR_PRIVATE_REFERENCE>` |
| authorization closed | `<YES_NO>` |

只有 nominal scenario 同时满足 direct success、SSH/OOB 已归零、post-OOB WireGuard echo、
durable FINISH 与零 residue，才可记录“本具名环境的一次 direct success”。不得由此推导整体
成功率、永久 NAT 类型、production-ready 或 universal symmetric-NAT traversal。

## K. 可公开脱敏摘要

以下是唯一允许进入仓库的摘要形状；不要粘贴本模板私有副本：

```text
profile=<STABLE_PROFILE>
resource_class=<STABLE_RESOURCE_CLASS>
terminal=<STABLE_CLASS_OR_SUCCESS>
credential_burned=<BOOL>
conditional_probability=<PUBLIC_MODEL_VALUE>
udp_packets=<COUNT>/<CEILING>
peak_pps=<COUNT>/<CEILING>
sockets=<COUNT>/<CEILING>
targets=<COUNT>/<CEILING>
five_tuples=<COUNT>/<CEILING>
ssh_children=<COUNT>/1
oob_frames=<COUNT>/<CEILING>
wg_challenge_packets=<COUNT>/<CEILING>
oob_zero_before_post_handoff_probe=<BOOL>
post_oob_data_plane_proof=<PASS_FAIL>
duration_ms=<COUNT>/<CEILING>
terminal_residue=zero|nonzero
second_review=pass|fail
```

公开摘要不得增加地址、端口、hostname、username、path、host key、artifact/fingerprint、
credential/attempt/participant ID、observer、网络/运营商、设备或 topology 字段。
