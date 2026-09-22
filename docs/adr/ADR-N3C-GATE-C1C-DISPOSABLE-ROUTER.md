# Gate C1c 一次性路由器 mini-spec

状态：**Draft 基线已接受；C1c-2 实现已授权（2026-09-18），C1c-3 未授权。** 基线 `ee79fd9`，接受 SHA `abe7ccc`。
本文、空模板、CI 通过或合并均不签发能力。C1c-2 实现与 exact-SHA field build、
C1c-3 一次性环境创建/运行分别需要维护者另行授权与独立复审；之后仍不能自动进入 C2。

依据：[Gate C1](./ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md) §3/§10.3/§11/§18.1、
[Gate B](./ADR-N3C-GATE-B-ENDPOINT-DEPENDENT-SOLVER.md)、
[M 映射寿命](./ADR-N3C-HARD16-MAPPING-LIFETIME.md)、
[E mini-spec](./ADR-N3C-HARD16-EARLY-CONFIRMATION.md) §9、
[session liveness](./ADR-N3C-SESSION-LIVENESS.md)。
执行清单见 [runbook](../GATE-C1C-RUNBOOK.md)，字段见
[空模板](../templates/gate-c1c-authorization.template.json)。

## 1. 用户任务与不授权范围

面向同一操作者拥有的两个端点，证明受控困难 NAT 后的一次直连、WireGuard 数据面与完整
排水；不证明所有 NAT 可穿透，也不是可长期运行的产品默认功能。目标是回答“命中是否活到
VERIFY/移交”，并为 E 是否值得重启评审提供数据，而非把受控 NAT 的配置当成家庭路由器权限。

- C1c-1 不构建、不生成材料、不创建 VM、不接触主机网络或云账号。
- C1c-2 必须单独评审 capability、原普通构建回归、无现场符号、资源与 crash 证明。
- C1c-3 只消费已审查 exact SHA 和一个签发实例；修改 SHA/依赖/标签/配置使签发失效。
- E2 仍搁置，不启用 early-stop/E1/保活/重试/扩窗或运行时 fallback；旧 `/1` 协议不变。
- cached self-bootstrap/autonomous recovery 仍 NO-GO；不接默认 `wink up`、daemon 或 scheduler。

## 2. 角色、环境与布局

拓扑为一台用后销毁的专属云 VM 路由器、initiator 与 responder。router 内两套 owned NAT
域分别承接两端流量，observer 是显式授权的双地址/双端口 RFC 5780 拓扑。管理通道独立，
不得通过 WinkYou 的待测 UDP 路径提供唯一管理能力。一个云 VM 不自动具有两个获准地址，
observer 无法满足拓扑/运营者许可时，在任何建立 I/O 前停止，不拿公网服务代替。

| 角色 | 拟定支持要求与实施前证明 |
| --- | --- |
| router | 专属一次性 Linux VM；拟定最低验证目标为 kernel 5.15，不是已验证兼容性声明；root、network namespace、TUN、conntrack、精确计数器可用；供应商允许对应 UDP/NAT 负载；C1c-2 须对所选内核证明功能、隔离与恢复，否则不得签发。 |
| responder | 首轮 Linux 基线同上；UID 0、owner-only 安装/材料、fixed forced-command SSH、TUN、conntrack 只读见证；root 风险和三项后续硬化逐项登记，不能据“固定命令”声称无解析攻击面。 |
| initiator | 首轮建议同一 Linux 基线并使用相同 exact build；管理员拥有 TUN/路由的限定权限。Windows 不继承 Linux 授权，须先由 C1c-2 单独证明 Wintun、Job Object 与精确回滚再列入实例；不得把缺少 conntrack 工具记成零。 |

“kernel 5.15”只是 Draft 平台验证下限提案，不改变协议时间/资源常量；维护者未接受且
C1c-2 未证明前不能作为可部署承诺。工具版本与实际内核仅填私有记录。

| 布局 | 收益 | 代价 / 证据限制 |
| --- | --- | --- |
| 两端在维护者两台设备上，router 为一次性 VM | 更接近真实移动端和服务器使用方式 | 端点 OS/路由变更也须逐项另行授权；原有上游 NAT 可能叠加，router 模型不能代表全部路径，无法观测的上游状态必须记 unknown。 |
| 两端也在一次性 VM 上，router 独立 | 资源专属、容易复制隔离与销毁，管理风险较低 | 云网络不代表移动/家庭网络；额外实例成本；销毁不可清掉 ledger/circuit 以重新获取额度。 |

两种布局都要保留各 endpoint machine scope 的 durable ledger，销毁前封存其状态和摘要。
重建同角色 VM 不能当成绕过一次/24h 或失败 circuit 的新身份；恢复不确定则 fail-closed。
不得将此 field capability 反向放宽 `linux && natlab` 的 namespace/TEST-NET 验证。

## 3. 一实例一场景

一个 instance = 一个 scenario = 一个新 credential = 一次 foreground invocation。
以下每一行独立签发，两个 asymmetric orientation 不能合并为同一 invocation。

| 场景标识 | 期望与必需见证 |
| --- | --- |
| `predictive_apdm_pair` | 双 APDM、双方独立重算已承诺 plan；双向 VERIFY、handoff 与 OOB 退出后的 WG 数据证明；不能改本地预测窗口冒充对端目标。 |
| `asymmetric_initiator_mapping_set` | 明确 initiator 是 mapping-set 角色；完整原预算、计划与唯一 winner 规则。 |
| `asymmetric_responder_mapping_set` | 交换 mapping-set 角色，另一个 credential/窗口；同等成功与零残留证据。 |
| `hard16_near_tail` | 已审查受控 near-tail fixture；保留原完整 schedule/selection，报告实际命中 ordinal 与 mapping 年龄，不提前停止。 |
| `hard16_exhaustion` | 固定 plan、完整无命中；有界失败、burn 不退款、FINISH/circuit 与零残留；不是 retry 的许可。 |
| `crash` | 独立实例在预先签发的一个阶段注入一次 owned endpoint/consumer crash，存活侧有界终局；引用既有同材料重启拒绝的隔离CI证明，本实例不再次调用建立入口。 |
| `teardown` | 独立低成本实例验证停止、排水、owned OS 资源与基础设施销毁；所有其他场景同样必须 teardown，不能等到本行才清理。 |

peer absent、wrong PSK、burn 后 OOB EOF、不可用 evidence、lease/consumer failure、nominal
success 的低成本前置，沿用 Gate C1 §11，各自单独签发；不能合在一个 credential 中演练。
hard-16K 每 machine scope 一次/24h、完整 16,432 reservation、失败开 circuit；near-tail、
exhaustion 和 hard-profile crash 必须跨获准窗口排期，不 reset/delete ledger，不换机器代号规避。
只证明观测到的 terminal，不把普通 timeout 自动归因为 mapping expiry。

## 4. 密封权限与不可提高的预算

field build 相对普通 `wink` 只增加单地址 target authority 与具名 observer allowlist 的
受限构造路径，不增加通用 unicast boolean、CIDR、目标列表、DNS、第二地址或任意 raw factory。
SSH endpoint 为已签发的单个 literal endpoint；UDP 只接受本地批准 peer address、独立重算的
candidate ports 和认证 winner。远端 report 不是 authority。

采用**专用 build tag 加本地 authorization instance 的双门**：标签名称和实例解析器在 C1c-2
冻结并独立审查，本文不虚构现有可用 flag。实例绑定 exact SHA/二进制哈希、双方 machine scope、
profile/cost、窗口、角色、SSH pin、observer 权限和本地 peer address。只有一个条件成立也不得
创建子进程或 socket。普通构建、默认入口、未知字段/版本及 capability 不匹配必须零 I/O 拒绝。

OS TUN/interface/address/route 权限仍按 Gate C1 §6.3c 的独立密封 authority 逐项绑定本次实例；
不增加任意主机网络管理接口。caller/peer 不能覆盖 trusted config，不允许 fixed-port bind。
router 配置、firewall/service/route 修改是另行具名授权，不由 build tag 顺便授予。

| 项目 | 不变的上位约束 |
| --- | --- |
| predictive / asymmetric | 原 Gate B complete exact cost，不能互换预算或加 candidate。 |
| hard-16K | 16 sockets；16,400 targets/five-tuples；16,432 reservation；16,398 protocol max；512 PPS；38s candidate / 45s active / 2s drain；端口 universe 49152–65535。 |
| OOB / SSH | 每方向8帧/8,256 bytes；initiator 1 owned child/1 TCP/0 DNS；responder 不再 spawn；0 retry/queue。 |
| WG challenge / completion | shared 3 datagram/方向、3s challenge，完成阶段仍按 Gate C1 §19.9，不能从探测 headroom 借额度。 |
| 建立后 liveness | 显式 `challenge_v1`，K=20s、R=5s、M=2/3、L=45/65s；原 absolute ceiling，不以旧15s inactivity 与新 policy 并行。 |

§19.9 的完成与 FINISH-before-release、lease-bound Promote、同一 owner、单 receive owner、
challenge 与 post-OOB echo 顺序全部沿用；本文不修改任何冻结数字。liveness 在原 activation
条件之前零包，不能替 candidate/winner 延寿。

C1c-2 必须在普通构建执行 `go tool nm <ORDINARY_BINARY>` 并断言受审 field 符号集合零命中；
同时验证 architecture/mutation、默认入口与非回环负面回归。符号集合不得用空正则或一次字符串
查找代替能力门。C1c-1 不运行构建，也不将这条未来验收写作已完成。

### 4.1 C1c-2 冻结（端点实现；2026-09-21）

实现基线为 `9b74fe61fe56384b0eb78dfd1d4d95e4a38fd37a`；本节只消费已授权的 C1c-2a，
不是 C1c-3 签发。专用标签为 `fieldc1c`。普通、单独 `c1bproof`、单独 `natlab` 构建不得
包含现场构造器、现场命令或现场权限；组合标签的测试能力也不能成为现场的依赖。

私有实例位置固定为 `~/.winkyou-field/c1c/<instance_id>.json`，证据位置为
`~/.winkyou-field/c1c/evidence/<instance_id>/`。`instance_id` 是本地材料的 attempt ID，
只用于从已 claim 的本地 responder slot 定位**唯一**实例，不扫描目录、不排队、不从报文
或环境变量取得实例路径。artifact、local request、SSH argv 和原有 staging schema 不变。
`wink gate-c1c run --instance <PRIVATE_INSTANCE>` 只启动 initiator；field 构建的固定
`wink solver direct child --stdio` 从本地 slot 选择 responder 实例。没有实例时拒绝，不能
退回其它权限。普通构建的固定 child 仍保留原行为。

部署安装中的固定 wrapper 路径和固定 wink 路径使用同一 exact-SHA field binary 的副本。
仅当进程由冻结 wrapper 路径进入时，field-only dispatcher 调用现有 UID 0 安装/原命令
校验，然后以既有 Execution 的固定 argv/env 替换本进程；没有新 fork、额外 SSH child、
shell 拼接或可变 executable。普通 main 不包含此 dispatcher 的实现；私有 netns 证明必须
执行真实 field binary 的 wrapper/child 两个路径，不能拿注入 runner 代替本次验收。

实例 revision 固定为 `winkyou-gate-c1c-authorization/1`，上限 64 KiB，UTF-8 单个 JSON
object。顶层与空模板的 **88 个字段逐一对应且全部必须出现**；未知、重复字段、尾随第二个
值、错误类型和不支持的 revision 一律拒绝。字符串不作 trim/coercion。预检字段不得 null
或空字符串；布尔许可必须 true。`mapping_set_role` 仅非 asymmetric 时为 null，
`containment_authorization` 可以 null。以下运行后字段在签发时必须 null，不能伪造未来
成功：`tuple_observations`、`raw_evidence_references`、`evidence_sha256`、
`terminal_result_by_role`、`durable_finish_and_circuit_evidence`、`owned_residue_by_layer`、
`ledger_sealed_before_destruction`、`cloud_teardown_evidence`、`independent_management_preserved`、
`redacted_summary_review`、`authorization_closed_at`、`teardown_operator_signature`、
`teardown_reviewer_signature`。实际结果另写证据文件，不覆盖已签实例。

| 复合字段 | 冻结的形状与校验 |
| --- | --- |
| `devices` | 恰好 initiator/responder 两项；每项 `role`、`os`、`request_reference`、`configuration_reference`、`configuration_sha256`、`management_reference`。只接受 Linux；路径为本地私有引用，不来自 peer。 |
| `router_resource_inventory` / `endpoint_resource_inventory` | 分别一项 / 两项；每项 `role`、`reference`、`teardown_reference`，角色无重复。引用是私有记录，不触发云 API。 |
| `observer_topology` | `primary`、`alternate_port`、`alternate_address`、`alternate_address_port`；四个 canonical literal AddrPort，严格双地址/双端口，同族；与本地 request 逐项相等。 |
| 三个 `hardening_*` | `status`、`reason`、`risk`、`evidence_reference`；必须与本节实际实现状态相符，不以任意 true 代替证据。 |
| `interface_route_address_authority` | initiator/responder 各一项：`interface`、`local_address`、`peer_address`、`mtu`；只能与 trusted config 精确比对，不把实例值写回 config。路由仅该 peer 的 IPv4 `/32`，无默认路由或任意前缀列表。 |
| `owned_stop_target_identity` | `kind`、`verification_reference`；kind 固定为 `owned-foreground-and-child/1`，不接受 PID 或任意命令作为杀进程权限。 |
| `expected_terminal_and_fault_stage` | `terminal`、`stage`、`injection_reference`；只绑定本场景受审证据，不在端点实现故障注入开关。 |
| `witness_plan` | `packet`、`socket`、`process`、`conntrack`、`child`、`ledger`、`transport_lease`、`wireguard`、`interface_route_address`；每项为非空私有采集计划引用。外部见证缺失不可写为零。 |

首轮 layout 固定 `disposable-endpoints-and-router/1`。两人身份必须不同且签字、运行许可、
observer 运营者许可、root 风险接受和主机配置授权都不可缺失。这是 owner-only 本地签发
记录的严格检查，**不是新增数字签名协议**；实现不能证明自然语言签字者真实在场，仍须
独立人工核验。一个实例只允许一次 claim；未 burn 的失败也不自动 re-arm。

exact SHA 由 `-ldflags -X` 注入；必须等于实例的完整小写提交 SHA，并等于非空的 VCS
revision。`debug.ReadBuildInfo` 缺少 VCS 见证或 `vcs.modified=true` 均拒绝。运行时读取
`os.Executable` 并计算 SHA-256，与对应角色的 binary digest 精确比对；不接受 caller 提供
自检结果。当前进程角色由固定入口选择，不由实例或远端选择。依赖/配置摘要绑定构建中的
依赖列表及两份 config digest；读取本地 config 后还须逐字节核对其角色对应 digest。
窗口采用 RFC3339 UTC，`signed_at <= not_before <= now < not_after`；profile/resource、
artifact/manifest、双方 scope、角色、材料原始时效、session liveness 与 cost 全部交叉核对。
任何失败在 SSH child、UDP socket 或 TUN 创建前统一为 `gate_c_request_invalid`。

固定 SSH child 环境不包含 HOME。Linux 实例定位只读取受 root 所有、不可被其它用户写入的
本地 passwd 文件中唯一 UID 0 项；不调用 NSS、DNS，不增加 SSH argv/env。实例及其父目录
不允许 symlink 或其它用户写入。`*_machine_scope_reference` 是
`machine-scope-sha256/1:<SHA256>`：摘要输入为 UTF-8
`winkyou-c1c-machine-scope/1\n`、去掉末尾换行的本地 machine-id、一个换行及 canonical
governor namespace 路径。本端只读核对自身引用；对端引用来自双签实例和相同材料摘要，
不是从 peer report 获得的新身份权限。machine-id 缺失或不合法即拒绝，不创建/重置身份。
`exact_cost_reference` 固定为 `gate-c/` 加完整 resource class 字符串。

### 4.2 不透明 capability 与所有权

- SSH 使用 #161 的 concrete token；`NewFieldAuthority(instance)` 是第三个私有
  `endpointScope` 实现 `fieldScope` 的唯一签发点，所有 token 字段继续私有，零值无效。
  Bind、argv 与 spawn 前仍经 `validatedEndpoint()`；每次复核相同 endpoint 和实例窗口。
  host-key pin 与专用 key 只能使用实例所指的本地受保护文件，0 DNS、0 retry。
- UDP 使用仅在 `fieldc1c` 可构造的 `AllowedTargetScopeFieldSingleAddress`，factory 只由
  gatecorchestrator 创建。它不冒充 `IsolatedNATLabFactory`，也不继承测试 namespace 能力。
  仅 wildcard/ephemeral；先允许四个 observer，独立重算并双边承诺后仅允许本地 plan 的
  socket-slot/port；认证 winner 后只允许该 fixed endpoint。第二地址、未计划 port、CIDR、
  DNS、固定 bind、raw factory 注入均拒绝，headroom 不可消费。
- Linux TUN 构造器接受独立不透明本地 authority。仅消费已绑定的 trusted config；先检查
  runtime/key/interface/route ownership，再创建一个 non-persistent、IPv4-only TUN 与唯一
  peer `/32` 路由。只新增而不 replace 已有对象；失败回滚和最终关闭只删除本次拥有对象。
  WireGuard native bind 保持禁用，业务始终通过 Promote 后的唯一 transport。
  配置使用本地 AF_NETLINK/NETLINK_ROUTE 内核控制 fd（单个、有 deadline、无 IP 收发），
  不启动额外 `ip` 子进程，不使用 AF_INET raw socket；该 fd 不冒充 UDP 探测 socket，
  在预检/配置完成即关闭并单独见证。non-persistent TUN 的最后 fd 关闭时内核删除本次
  interface/address/route；正常终局另核对缺失，崩溃由进程外 netns 见证核对。
- 外层入口沿用 SIGINT/SIGTERM/SIGHUP 取消语义、原 completion 与 FINISH-before-release；
  不给 WireGuard、默认 `wink up`、stdio、legacy、scheduler 或 runtime 新增构造权。
  session 到实例窗口末端即取消，drain 仍只用原 2s；不提高既有 session absolute ceiling。
- 原始证据在私有目录 O_EXCL 创建；stdout 仅 §6 白名单。网络身份、文件路径、PID、
  原始错误、attempt/credential/scope 标识不进入公开 summary。未知外部残留保持 unknown。
  field 预检拒绝继承的 WireGuard verbose / TUN packet-trace 开关为 `1` 的环境；不静默
  修改环境，也不改变普通构建的调试行为，避免绕过现场输出白名单。

### 4.3 三项硬化处置与验收

| 项 | 本批处置 | 原因与残余风险 |
| --- | --- | --- |
| drop privileges | 未实现；实例必须如实登记 | 仍消费 §18 的 UID 0 单 owner/同进程 handoff。没有已审查的降权后 TUN/ledger 清理模型；所有 parser 漏洞仍可能影响 root。 |
| seccomp/landlock | 未实现；实例必须如实登记 | 尚无冻结 syscall/filesystem allowlist 与 SSH/WireGuard 平台矩阵；不把固定 argv 当作内核 sandbox，文件和系统调用攻击面仍存在。 |
| 低权限 parser | 未实现；实例必须如实登记 | 需要另行设计进程边界和资源归属；本批不增加子进程、fd 传递或 IPC，网络解析仍在 UID 0 中。 |

以上不是豁免其它 fail-closed 门。三项未做的原因、风险与两人接受必须在每个实例中出现；
不同用户或不可信 peer 不在本次 threat model 内。C1c-2a 的交付仍须 docs → RED → 实现 →
mutation → 验收，普通构建的显式非空 nm 符号集零命中、field 构建正向命中、严格解析与
权限旁路变异、race×20、原全仓回归，以及 required TEST-NET netns predictive/asymmetric
完整实例、kill switch 与零残留证据。当前文本冻结**不预填任何实现或测试通过结果**。

### 4.4 C1c-2b 统一实例裁决（2026-09-22）

维护者针对 [#167](https://github.com/houyuwushang/winkyou/issues/167) 确认采用统一 `/2`，
并授权本 PR 增加 field-only 端点解析支持。基线 `efc160e`。此裁决只扩展实现范围，
不签发现场实例；§4.1 的 `/1` 解析、端点行为与原回归继续保留，不能自动升级或 fallback。

新 revision 为 `winkyou-gate-c1c-authorization/2`：保留原 88 个顶层字段，另加必填的
`router` 对象，恰好 89 字段。端点显式按 revision 分流，router 只接受 `/2`。三角色读取
同一份不可变实例，核验完整格式、SHA、窗口、profile 与两人许可；各角色只取得自己的
不透明 capability。router 不读取 artifact、PSK、SSH key 或 endpoint 配置原文。

| `router` 字段 | 冻结语义 |
| --- | --- |
| `schema` | 固定 `winkyou-c1c-router/1`。 |
| `machine_scope_reference` | router 本机的 `machine-scope-sha256/1` 引用；同 §4.1 派生，不创建 governor 或重置身份。 |
| `dependency_and_configuration_sha256` | router 自身构建依赖与原两端 config digest 的摘要；原顶层摘要仍由端点按原规则验证。不同二进制不能伪装成相同依赖闭包。 |
| `anchors` | 三项，role 按 `initiator/transit/responder` 排列；每项 `role/name/inode`。已具名、专属、non-init 的本机 attachment namespace；工具逐一核对并持有 namespace fd，不创建/删除这些外层资源。 |
| `domains` | 恰好 initiator/responder 两项；每项 `role/mode/endpoint_prefix/gateway_prefix/public_prefix/transit_prefix`。IPv4 canonical literal prefix，同一 link 两地址同网段且不同；仅该实例两个 peer 地址与 observer 地址。无 DNS/任意命令/任意 sysctl。 |
| `allow_global_conntrack_ceiling` | 必须出现的 boolean；只有 true 才可能执行共同 ceiling 路径。false 不写 init namespace；null/缺失/字符串均拒绝。它不由任何非空引用或一般 root 风险接受推导。 |
| `disposable_environment_reference` | 专属一次性环境的双人核验引用；不触发云 API。true ceiling 路径另须 init 身份、独占 guard、原值/headroom、保存及回读恢复见证。 |

所有复合字段完整、无未知或重复成员。namespace 与接口/表名仅作本机作用域绑定，不进入
stdout。新建两 NAT namespace 的名字由 instance 摘要确定，O_EXCL 式占用，不接管同名资源。
四个 veth pair 直接创建在获准 namespace 内，从不短暂暴露在 init namespace。只 add 本次
路由/规则，冲突即失败，不能 replace/flush 既有配置。外层 attachment 的跨 VM 接线由独立
主机配置授权负责；本工具不创建管理链路、不改变宿主默认路由、不修改 SSH 服务。

`predictive_edm/1` 固定两侧 `apdm_sequential/1`；asymmetric 的 mapping-set 侧为
`apdm_sequential/1`、另一侧为 `eim/1`；hard profile 两侧为 `apdm_uniform16/1`。
模型不冒充全部真实 NAT；hard 的可观测结果不得写成已完成 near-tail 证明。allocation 与
过滤独立：APDM 按 internal endpoint + destination 建 mapping，EIM 仅按 internal endpoint；
入站必须命中已出站登记的远端五元组。observer 的 CHANGE-REQUEST 不扩张 peer 权限。

采用 **TUN + 受限 UDP mapping allocator + nftables**：复用既有 B2/B3 参考的 IPv4/UDP
转发与确定性 allocation 语义；nft 仅负责 owned 域的过滤与固定 SSH TCP NAT。理由是仅靠
kernel SNAT 无法承诺 sequential APDM，不能把 random-fully 误称为 EIM；无需修改既有
`tc nat`/NOTRACK 回归。四端口 observer 复用 RFC 5780 codec，response-only，不主动探测。
每 NAT mapping 上限仍 40,000，先检查后开 socket；工具独立的有界队列、采样和公开输出
不能兑换或提高 endpoint 的任何已冻结预算。无 mapping 重试、attempt 重试或 fallback。

`c1crouter run --instance <PRIVATE_INSTANCE>` 为一次前台运行，
`c1crouter teardown --instance <PRIVATE_INSTANCE>` 只消费该实例的持久 owned journal。
run 的 claim 永不删除；teardown 可以在窗口过期后清理，但不能签发新的建网/发包能力。
journal 记录先于资源操作，记录身份与完成见证；清理仅匹配 instance、namespace inode、
接口与进程启动身份的本次资源。SIGINT/TERM/HUP、父退出与窗口终止走同一排水路径。
共同 ceiling 必须由独立 guardian 在 worker 崩溃后恢复，不以 worker defer 代替该证明。

私有输出位于 `~/.winkyou-field/c1c/evidence/<instance_id>/router/`；每个观测产出 §5 全字段，
未认证关联的 hit、未发生的 winner/VERIFY 或不可比较的时钟保持 null + 分字段 reason。
只见到明文 frame header 不等于端点已认证，不据此伪造 hit/VERIFY。conntrack 采样沿用
精确键 GET 与 #129 分类，查询中断/失败不是 absent。stdout 只有 §6 白名单及资源计数，
未知残留不是零。清理核对表保留第二人签字空栏，程序不能代签。

## 5. M/E 现场记录字段（本提案固定）

每个实际命中的 tuple 单独记录，记录名称与含义如下；原始 tuple 仅在私有文件中关联。
全部 duration 是同一见证者的本地单调时间差，单位纳秒；不同机器时钟不得直接相减。
值缺失为 `null` 并填 reason，绝不能把未采样/查询失败写成0或 expired。

| 字段 | 类型 / 精确定义 |
| --- | --- |
| `tuple_ref` / `role` / `witness_clock_ref` | 私有不透明关联字符串 / 本端角色 / 本地时钟域；不发布 tuple 哈希或这些关联标识。 |
| `mapping_age_at_hit_ns` | integer或null；端点认证命中事件与对应router收包见证成功关联后，以router本地时钟计算mapping创建至该收包的年龄；router不认证密文或取得密钥，关联不成立记unknown，不代表剩余寿命。 |
| `mapping_age_at_winner_ns` | integer或null；唯一 W datagram 通过该 router 时的 mapping 年龄，不能借另一 observer tuple 的年龄代替。 |
| `mapping_idle_age_at_winner_ns` | integer或null；同一 mapping 最后已见刷新到 W 的间隔；没有刷新见证则unknown。 |
| `hit_to_stop_ns` | integer或null；本端认证命中到原 candidate send barrier 完成；stop 不是 E2 STOP 帧。 |
| `stop_to_winner_ns` | integer或null；原full-schedule发完、candidate闸门不可再发且在途send排空，到本端唯一W的已计费I/O commit；最后PPS clearance/等待可用槽的耗时包含在内。非winner端记null。 |
| `winner_to_verify_ns` | integer或null；本端 W commit 到本端双向 VERIFY 条件满足；非 winner 端或未达到该条件记null。 |
| `stop_to_verify_ns` | integer或null；本端 stop 到本端双向 VERIFY 条件满足；仅在同一时钟域计算。 |
| `kernel_flow_observation` | `present`、`absent`或`unknown`；另记查询是否成功、观测阶段、刷新历史，不由年龄推导。 |
| `failure_stage` / `terminal_class` | 现行稳定 stage/class 或null；保留两端各自结果，不为使两端相同而改写。 |
| `missing_reason` / `measurement_source` | 分字段 reason 与来源；无权限、无样本、查询超时、时钟不可比、阶段未发生分别记录。 |

stop 在本协议中仍须等待完整 schedule，不能为了测量省略候选或增加网络观测包。只消费既有
受审事件及外部 witness，不给生产路径增加 router 查询权限。若不同见证源无法关联，保留unknown
与各自时间序列；不得用墙钟对齐伪造精确 stop→W→VERIFY。

M-S=60s、M-E=30s、M-X 与实际现场读数分列。上游 NAT 不可见时只报告受控 router 证据。
重启 E2 的输入是上述年龄、stop→W→VERIFY、失败阶段及有效/缺失样本数；这些字段只供人工
独立评审，不触发自动切 E2/E1、调小 K、刷新映射或第二 attempt。

## 6. 见证、kill switch 与销毁

每个实例保存 packet（evidence/candidate/winner/challenge/data/liveness分账）、socket、
process、conntrack、SSH child、ledger BURN/FINISH/admission/circuit、TransportLease
ownership/attach/detach、WG outer/inner/OOB退出后数据证明以及 interface/route/address。
计数同时包含 peak、终局与排水后 owned residue；普通业务与探测计费不混用。

kill switch 只停止本次已验证 PID/启动身份/owned scope 的 foreground controller 与 SSH child；
不停止 sshd、管理 overlay 或未知同名进程。parent death、超限、第二 owner/address/attempt、
异常持续发包、失去 witness、drain 失败都须终止本次实例；不存在“再跑一次确认”。
主动停止不降低持久 trip 的既有语义，也不把 circuit clear 作为清理动作。

router init namespace 的共同 conntrack ceiling 只允许在专属一次性 VM 的独立授权中按 Gate B
既有 guardian 契约处理；保存/回读/恢复与非 init NAT 参数的隔离证明分开，不能写成按 netns
修改全局上限。未证明专属身份则不执行。清理 owned flow 后验证零 residue，再销毁 router 与
选择的其他一次性实例；云侧实例/附属网络/地址/磁盘等资源清单也须由第二人核对关闭。

原始日志只保存在仓库外。公开白名单为 profile、stable stage/class、脱敏计数、duration、
ceiling、residue、审核结论、代码/证据 SHA-256；不发布 IP/域名/用户名/路径/host key、
credential/attempt/machine 标识、云账号/区域、设备属性或原始日志。摘要必须人工复核，隐私
测试不能证明任意自然语言都已脱敏。失败样本与unknown不得删掉再报成功。

## 7. 后续验收门与裁决

- C1c-1：既有全 docs/template 隐私门、相对链接、vet、architecture；纯文档delta。
- C1c-2：另行授权、exact build、普通符号零命中、capability mutation、全部既有预算/回归；
  无现场 I/O；所有 root/Wintun/observer、M/E 可观测性缺口先复审，不以文档代替实现。
- C1c-3：另行签发一个私有实例，两个签字、前置演练、无旧进程/任务、ledger determinate、
  packet/OS/ownership witness、kill switch、VM销毁及第二人复核。每个场景单独闭合。
- C2：C1c 的完整证据独立复审后再签发；本草案不签署任何现场实例。

| 待裁决项 | 维护者 / 独立评审裁决 |
| --- | --- |
| 拓扑/布局与最低内核验证目标 | **接受**（维护者 2026-09-18）：首轮采用"两端也在一次性 VM 上、router 独立"布局；kernel 5.15 为验证目标，C1c-2 须实证。 |
| exact build/双门与普通构建零能力验收 | **接受**：专用 build tag + 本地 authorization instance 双门；tag 名与实例解析器在 C1c-2 冻结；普通构建 `go tool nm` 零现场符号为 C1c-2 必过门。 |
| 场景排期、ledger保留与一次/24h | **接受**：§3 七行各自签发；hard-16K 一次/24h、失败开 circuit、不 reset ledger；销毁前封存双端 ledger。 |
| M/E 字段语义、不可观测值与公开白名单 | **接受**：§5 字段名冻结，unknown 记 null + reason；公开只发布 §6 白名单项。 |
| root 风险与三项硬化登记 | **接受登记**：Gate C1 §18.1 风险由实例中两人签字承担；三项硬化（drop privileges、seccomp/landlock、低权限 parser）在 C1c-2 逐项给出"已做证据"或"未做原因"，不以本栏代替。 |
| 是否接受本 mini-spec；SHA/日期 | **接受为 Draft 基线**，`abe7ccc`（PR #147 合入），2026-09-18。 |
| C1c-2 实现授权；范围/SHA | **授权**（2026-09-18）：基线 `58663e8`。范围 = 端点 field build（tag、实例解析器、sealed SSH/UDP/TUN authority、`wink` 现场子命令、kill switch、nm 门）与 router/observer 工具（两套 owned NAT 域、RFC 5780 观察者、conntrack 见证、销毁核对），两个独立 PR；**无现场 I/O**，全部验证在 memory/netns。 |
| C1c-3 运行授权；私有instance引用 | 未授权。待 C1c-2 独立复审通过后另行签发。 |
