# Gate C1c 一次性路由器 mini-spec

状态：**Draft 基线已接受；C1c-2 实现已授权（2026-09-18）并已合入；C1c-3 首轮运行已授权
（2026-09-23，范围与偏离见 §7）；Windows field 端点 C1c-2c/2d 实现已授权，Windows 实例未签发。**
基线 `ee79fd9`，接受 SHA `abe7ccc`。
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

工具自身的编译期上限（不是端点 budget）：两域合计最多 40,000 个 UDP mapping；每方向
每域最多 65,536 个已转发 datagram；每个有界队列最多 16,398 项，单 payload 最多
9,216 bytes；observer 每实例最多接收/回复 64 个报文。socket 额度在 open 前扣除，
bind 失败不退款、不重试。hard 模型对 observer 与 peer 使用相同的 14-bit permutation
分配机制：按远端独立计数、空间固定 49152–65535；仅不同远端的 connected UDP socket
可复用 public port，同一远端内不得重复。这是可重复 NAT 模型，不是新的加密协议，
不把一个受控模型的成功率冒充真实网络分布。端点的所有冻结常量和协议不变。

`run --instance <PLACEHOLDER>` 的父进程是 guardian；工作进程只接受父进程私有 pipe、
继承的 ownership lock 和 journal 中精确 PID/start identity。初始 namespace 的 ceiling
只有明确 true 时才保存、回读、恢复；false 路径不写初始 namespace。guardian 本身被
不可捕获信号终止时，自动恢复不能得到保证：由独立 `teardown --instance <PLACEHOLDER>`
按私有 journal 重新取得同一锁恢复；若 ceiling 已被第三方改动则拒绝覆盖并保留证据。
PID 信号使用 pidfd，不以同名进程或重新出现的数字 PID 作为所有权。

探测/observer 关闭采用原 2s drain 上界；之后只做 owned 资源清理，独立 20s 工具清理
上界不延长端点 attempt/session 或恢复收发。NAT namespace 的 inode 先持久化，再通过
O_TMPFILE 预留的 mountpoint 发布；清理须同时核对 instance、inode、socket、process、
conntrack、nft、veth，不把删除 namespace 名称等同于所有 fd 已消失。普通构建不编译
router 包/命令，端点也不能 import 此工具。新增
[空 `/2` router 字段目录](../templates/gate-c1c-router-v2.template.json)只用于填写审查，
本身不是可运行授权。

[#169](https://github.com/houyuwushang/winkyou/issues/169) 的 teardown 首跑失败尚无 terminal
class，不能据此确认根因。先保留私有原始 summary、区分 host 的 teardown/run/wait 结果，
再采集两份 summary、清理前后计数和三个 anchor 的固定 ifname；公开仅脱敏 class/stage/
计数，失败 artifact 必须通过文档与源码同款隐私检查。复现按原顺序 down → OS 回读 →
关闭 fd → Unmount/Remove → 立即检查 anchor；只有观察到异步 peer 残留，才允许在
Unmount 前显式删除 owned lan0/wan0，同步移除 peer，删除失败仍为 ErrDrain；不增加
sleep、重试或放宽 onlyLoopback。guardian 已 Clean 后 teardown 的第二次 cleanup 必须
保持六项残留为零，除恢复已记录 ip_forward 外不能改写 anchor 配置；幂等性发现问题即
停止，不顺带修复。Windows 交叉检查不能替代 Linux root-netns 的重复实证。2026-09-22
首轮见证版本 `3c0a043` 的隔离 CI：push 空闲/压力分别命中 200/200、196/200，PR 事件
分别命中 199/200、196/200；因此满足显式删链路的实施前提。同轮 push 的三次组合及
二次 cleanup 检查通过，但 guardian crash 为 drain_failed；PR 的第三次组合为 run
io_failed、teardown success、六项残留均零。原始 RED 保留，后者可能是 guardian 兜底
cleanup 覆盖 worker 失败的结果，不把这一推断冒充原始故障逐项定因；修后同一矩阵须
严格零残留且不得 rerun 求绿。本机缺少 Linux，要求的本地两项各五次仍未执行。

针对 [#171](https://github.com/houyuwushang/winkyou/issues/171) 与
[见证 job 106771779879](https://github.com/houyuwushang/winkyou/actions/runs/35735562171/job/106771779879)
的 run io_failed、teardown success、六项残留为零记录，2026-09-23 冻结以下 terminal
优先级：class 说明实例未成功的权威原因，六项计数说明最终资源状态；兜底 cleanup 成功
不能抹掉 worker 的失败。`reported` 须为存在且通过 `Summary.Encode()` 校验的 worker
报告；`clean` 取子进程退出时 journal 值（不能用兜底后值），`childErr` 表示 Wait 非 nil，
`residueZero` 表示最终六项均非 nil 且为零；平稳类为 `success/cancelled/expired`。

| 行 | 条件（1–5 按优先级首次命中，6 为收尾） | terminal class |
| --- | --- | --- |
| 1 | backstop 为 failed(c) | c；guardian 的失败不被残留规则降级。 |
| 2 | 否则没有合法 worker 报告 | `c1c_router_io_failed`。 |
| 3 | 否则 worker 为平稳类且未 clean 或 childErr | `c1c_router_io_failed`，自述平稳与 journal/退出码不一致。 |
| 4 | 否则 worker 为平稳类 | 保留 worker class。 |
| 5 | 否则 worker 为失败类 | 保留 worker class，不论兜底是否发生或成功。 |
| 6 | 收尾 class 为平稳类且非 residueZero | `c1c_router_drain_failed`；不覆写任何失败类。 |
| 7 | 私有 terminal resolution 写入失败 | `c1c_router_io_failed`，这是 guardian 新发生的 I/O 故障。 |

guardian 在应用最终计数后只调用一次纯 resolver，并用既有 0600、O_EXCL 私有写入器
一次性记录 `terminal-resolution.json`：`schema=winkyou-router-terminal-resolution/1`、
`worker_reported`、`worker_class`（未报告为空）、`clean_at_exit`、`child_exit_error`、
`backstop_cleanup`（not_needed/success/failed）、`backstop_class`（非 failed 为空）、
`terminal_class`、`rule`（1–6）。第 7 行不能伪造一个已成功持久化的文件。该记录及其路径
不进入 stdout 或公开 artifact；公开 Summary 结构、class 枚举、授权 `/2`、预算与 workflow
不变，TMPDIR 观察项不在此次修复范围。原 job 未保留 worker 原始判定，覆盖原因仍是结合
源码的推断；新记录为后续实例直接区分 worker 决策与 guardian 兜底提供证据，不回填历史。

### 4.5 Windows field 端点 mini-spec（B0，待独立复审）

本节是 2026-09-23 的 **设计提案，不是实现验收或 Windows 实例签发**。目标是在维护者
自己的 Windows 端点上保留同一 sealed authority、单次直连和 WireGuard 数据面，并证明
创建、配置、退出、崩溃后的 owned 状态；不借平台移植增加目标、子进程、预算或管理能力。
B0 单独 docs-only PR；接受后才进入 B1（Wintun capability）和 B2（入口及证明），跨机
attachment 仍属另行复审的 C1c-2d。Linux 首轮 A0 的合入门与本节互不替代。

维护者已澄清两项设计前提：preflight 可以读取本机 OS 状态，但不能发网络包或修改配置；
本节可以列出原 B2 文件清单遗漏的 Windows 实例、路径校验依赖。后者须随本节一起复审，
不是任意扩展生产文件的授权；下面标为待决的闭包不得在 B1/B2 中自行补齐。

#### 4.5.1 现状、平台边界与拒绝顺序

基线 `bf8ba21` 的实际限制如下，不以现有 memory/CI 测试冒充 Wintun 证明：

| 现有文件 | 已核对的限制 / 本节处理 |
| --- | --- |
| `internal/v2/gatecorchestrator/field_entry_unsupported.go` | `!linux && fieldc1c` 始终拒绝；新增 Windows 专用入口，unsupported 收窄。 |
| `internal/v2/fieldc1c/instance.go`、`validate.go`、`path_unsupported.go` | Load、device OS 与私有路径都只支持 Linux；必须显式处理，不能只改入口 tag。 |
| `pkg/netif/field_tun_linux.go`、`field_netlink_linux.go` | 只有 Linux sealed interface 与本地 netlink；Windows 不调用或模拟这些 syscall。 |
| `pkg/netif/tun_windows_wg.go` | 普通路径实际使用 `wgtun.CreateTUN` 与 PowerShell 脚本，不是受限 field adapter；不改它，也不复用其可变名称/地址/路由配置。 |
| `pkg/tunnel/fieldc1c_linux.go` | field WG 封装仅 Linux；Windows 需要同等 `memoryOnly`、唯一 promoted transport 与 Start/AddPeer 见证，不能回落普通 native bind。 |
| `internal/v2/sshassembly/process_windows.go` | 已有 suspended-start、单 child、kill-on-close Job Object；复用原路径，保留 `Killed=true` 预期。 |

拒绝顺序固定：严格解析及本地私有材料/构建/角色/时效核验 → 生成不透明 authority →
只读 OS 冲突预检 → 原 machine governor/admission/claim 流程 → 原协议与 field interface
创建。无效 authority 在适配器枚举、地址/路由查询、DLL 加载、child/socket/interface
创建前拒绝。读取授权文件、构建见证和受保护 machine scope 仍是既有必要本地读取；
“零 I/O 拒绝”指零能力 I/O，不能解释为不读输入即可核验材料或发现系统路由冲突。

preflight 的唯一新增 OS 能力是只读的管理员 token、adapter、地址、路由、owned process
状态查询；无 DNS、IPC 探测、ping、powershell、netsh、配置写入或驱动安装。无法可靠
读取时拒绝，不把 unknown 当作无冲突。接口创建前须再次验证实例窗口和冲突快照。

#### 4.5.2 不透明 Wintun authority 与身份派生

保留 `FieldInterfaceAuthority` → `PreflightFieldInterface` / `NewFieldInterface` /
`FieldInterfaceWitness` API。token 字段私有、零值无效、单次 CAS 消费，绑定本地实例、
role、MTU、local/peer IPv4 和唯一 peer `/32`；不暴露 Wintun handle、LUID、raw Device
或通用 IP 配置器。创建后的 `SetIP`、`AddRoute`、`RemoveRoute` 恒为 `ErrFieldInterface`。
close 后 Read/Write/Inject/Receive 全部拒绝；Close 幂等并等待 owned reader 结束。

名称摘要不能直接采用“包含接口名称的完整 JSON 摘要”，否则出现名称与摘要的循环依赖。
本节定义独立、secret-free 的实例身份投影：

```text
D = SHA256(UTF8("winkyou-c1c-wintun-identity/1\n") ||
           BASE64URL_DECODE(instance_id) || 0x00 || UTF8(role))
name = "wcf" || LOWER_HEX(D[0:6])
requested_guid = D[16:32] 按字节顺序分组为 8-4-4-4-12 个小写 hex 字符
```

instance ID 解码必须恰好 16 bytes，role 只能是本地受审入口选定的角色。名称恰好 15 个
ASCII 字符，满足现有命名限制。GUID 从上述规范字符串解析为 Windows GUID，禁止把
16-byte slice 直接 unsafe-cast 成混合字节序结构。identity 投影、GUID 字段与字符串往返
须有双 role golden。trusted config 与实例中的名称都必须已等于派生值，不能运行时改写
config 或制造新实例；完整实例摘要继续承担原有材料绑定，不能被 D 替代。

preflight 枚举已存在及可见的残留适配器：同名 **或** 同 GUID 即拒绝，不调用 OpenAdapter
接管，不按名称先删后建。仅一次 `CreateTUNWithRequestedGUID`，不修改上游全局 GUID/
tunnel-type，不走“创建失败再打开”的回退。创建后按 handle 的 LUID 回读 GUID、名称与
接口身份，必须全等；检查与创建间冲突也必须拒绝，不能重试换名。Windows PnP 不提供
Linux TUN_EXCL 的同一接口，独占性必须以并发占名/占 GUID 的负面 OS 测试证明，不能
仅凭上游 API 名称或注释宣称成立。任何句柄归属不确定时不得删除他人对象。

#### 4.5.3 地址/路由方案：提议 A，类型化 IP Helper

> 复审裁决（§4.5.8）：接受"类型化 IP Helper、逐项 row、禁 Flush/DNS/netsh"的方案本体；
> 打包裁定为 **A′ 仓库内最小子集**，不新增 go.mod 模块。下文对 v0.5.3 的依赖核对保留为
> 参考实现与风险记录，不再是 B1 的引入指令。

| 候选 | 取舍 |
| --- | --- |
| A：仅 `winipcfg` 的逐项 IP Helper 调用 | 提议采用。按 LUID、typed prefix/row 做精确比对，无额外配置 child、无本地化输出解析；更适合 sealed authority 和可验证回滚。 |
| B：固定系统目录的 netsh + typed argv | 不采用。即使固定 executable、无 shell，仍新增 child/输出解析/退出排水责任，与既有一个 SSH child 的计费边界不合；不是因实现工作量而舍弃。不得作为 A 失败时的 runtime fallback。 |

2026-09-23 依赖核对：项目固定 Go 1.23.1。上游
[v1.0.1 go.mod](https://raw.githubusercontent.com/WireGuard/wireguard-windows/v1.0.1/go.mod)
要求 Go 1.25.0，不能顺手升级工具链。提议固定
[v0.5.3](https://raw.githubusercontent.com/WireGuard/wireguard-windows/v0.5.3/go.mod)
（声明 Go 1.18），只引入 `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg`。
仓库外依赖检查已用 Go 1.23.1、现有 `x/sys v0.32.0` 完成 `go list -deps -export`：
非标准库 package 闭包仅 winipcfg、`x/sys/windows`、`x/sys/windows/registry`。
这只是编译/闭包证据，不是驱动、漏洞审查或运行验收。

模块图与链接包闭包须分开报告：该版本 go.mod 还声明 lxn walk/win、x/crypto、x/net、
x/text、x/mod、x/tools、x/xerrors；仅导入上述包不意味着链接 GUI/service/tunnel manager。
未来 go.mod/go.sum 只准加入审核后的必需差异，不复制依赖模块的 replace，不降低已有
x/* 版本；B1 重算 MVS 与链接闭包，漂移则停。v0.5.3 是旧版本，更新维护和安全审查是
显式代价，不能把 Go 兼容性写成安全保证；版本裁决随 B0 复审，不能自动取 latest。

[上游 LUID 实现](https://raw.githubusercontent.com/WireGuard/wireguard-windows/v0.5.3/tunnel/winipcfg/luid.go)
的 `SetIPAddresses` 会先 Flush，故 **不调用**。仅允许新建 owned LUID 的单条地址 Create/
AddIPAddress、单条 AddRoute、对应精确 Get/Delete，以及本接口 MTU 等必要 row 的
get/compare/set/restore。禁止 Flush*、SetRoutes*、SetDNS/FlushDNS、注册自动重配回调。
v0.5.3 包内还含 `os/exec` 的 DNS/netsh fallback，package import 本身不是零 child 证明；
B1 必须给出受审调用子集及链接符号检查，禁止该 fallback 从 field 路径可达。

配置事务只作用于本次新建适配器：保存创建前全局只读快照、创建后的 owned row 初值；
只加本地 `/32` 和唯一 peer `/32` on-link route，保存每个成功动作和完整键值。每次写后
逐值回读（LUID/GUID、地址/prefix、route/next-hop/metric、MTU），错误即停止收发。
不设置系统 DNS、默认路由、全局 metric、forwarding、防火墙或他人接口。与既有地址或
会被新 peer host route 遮蔽的非默认路由冲突即拒绝；默认出口不能被此路由替换。

回滚按逆序 compare-and-delete/restore，只撤销本次成功新增且身份/值仍匹配的对象。
外部已改值时保留冲突/失败见证，不强行覆盖；仍关闭自己的 handle 并检查残留。无关
接口/地址/路由不得变化，不能用全表 restore 抹掉并发变化。Close 返回不是残留为零的
证据，必须独立枚举；部分创建、每个配置步骤失败与 crash 都须覆盖。不改变原 2s drain，
超过即 RED，不能以 Windows 系统调用慢为由延长产品上限。

Wintun DLL 沿用现有 Go wrapper，取自
[官方签名分发](https://www.wintun.net/)的固定版本；B1/B2 私有构建记录保留分发包、DLL
哈希与签名校验结果。只从受保护的受审安装位置加载，禁止工作目录/PATH 搜索降级、
运行时下载或自动换驱动。上游日志须在任何 driver 调用前进入私有受限记录，不能泄漏到
公开 stdout/stderr。首次 driver 安装或遗留 driver-store 状态与 owned adapter 清理分列；
本节不授权主机安装/卸载驱动，更不允许删除别的软件使用的驱动来凑零残留。

#### 4.5.4 kill switch、进程身份与残留见证

复用原 SSH child Job Object 的 suspended-start → assign → resume 和 active-process=1，
不允许 breakaway，不为 field 新建管理 daemon。controller 身份为持有的 process handle
加 PID 和 `GetProcessTimes` creation time；停止前复核相同实例/身份，随后针对该 handle
终止，不能按进程名或重新查询出来的 PID 杀进程。父退出使 owned child Job 关闭，再
等待各 owned process 的退出 handle；Job 句柄关闭本身不能冒充 Wait 完成。
[进程创建时间](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
与 [Job Object](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) 是
两种不同见证。外部测试/维护者持有 controller 的停止权，不给 endpoint 添加第二 child。
Windows 原有 `Killed=true` 是该取消路径的预期，仍需 class、FINISH 和 drain 共同判定。

| 层 | 必需 Windows 见证 / unknown 规则 |
| --- | --- |
| UDP socket | `GetExtendedUdpTable` 的 OWNER_PID 表覆盖 IPv4/IPv6；运行中将行与仍持有的进程身份关联，退出后核对 owned 端点消失。查询失败、PID 复用无法排除、快照不完整记 null/reason，不按 PID 数字单独归属。 |
| interface/address/route | 回读 owned GUID/LUID，正常/异常关闭后适配器不存在、owned 地址/路由为零；前后无关配置 diff 为空。设备暂不可见/枚举失败不是 absent。 |
| process/child | retained process handle Wait、Job 关闭/成员退出、owned child 计数归零；无关管理通道不在 Job 中。 |
| conntrack | terminal/peak/residue 均 null，reason 固定 `windows_no_conntrack`；绝不借 UDP 表或 router 的 conntrack 填本机 0。 |
| packet/lease/ledger/WG | 保留现有 actual/charged 分账、TransportLease ownership、BURN/FINISH/circuit、challenge 与 post-OOB 数据；不从应用帧反推 OS TCP 包。 |

[UDP endpoint 表接口](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)
不是 flow/conntrack 表。原公开 `counts` 中 Windows conntrack 项为 null；提议新增可选
`missing_reasons`（仅固定 key/reason 白名单、Linux 省略保持原输出），禁止 raw OS error、
PID、GUID、地址/路径进入 summary。Windows substitute witness 可证明 owned socket 与
配置排空，不能宣称本机 NAT 状态归零；§7 签发须单列接受这一平台证据限制。

#### 4.5.5 入口、实例与平台路径的最小闭包

新增 `field_entry_windows.go`，tag 精确为 `windows && fieldc1c`；unsupported 为
`!linux && !windows && fieldc1c`。双门、exact SHA、VCS clean、二进制/依赖/config hash、
单次 claim、原 64 KiB、未知/重复字段拒绝与 timeout/circuit 全部保留。不接默认 `wink up`，
不改变 ordinary child、stdio v1/v2、Linux forced-command wrapper 或 router。

本节先提出 **Windows initiator 的本机能力和入口证明**；responder 组合通过受审隔离
fixture 验证协议，不据此宣称已完成 Windows SSH 服务/forced-command 安装。Windows
`RunFieldResponder` 在平台部署闭包另行冻结前保持拒绝；不把 Linux UID 0 wrapper 改成
任意 Windows command。该角色边界须在 B0 复审明确接受，不能在实现中默默决定。

机器 governor 路径直接调用 [namespace.go](../../internal/governor/namespace.go) 的
`MachineNamespacePath`，Windows 来源是
[namespace_windows.go](../../internal/governor/namespace_windows.go) 中 KnownFolder
ProgramData 与固定 `WinkYou-SafetyV2` 子目录；不能采用环境变量 override、临时目录或
user-acknowledged scope。只核对已准备的 scope，不自动创建/reset ledger。

Windows machine-reference 派生不是现有 Linux machine-id 实现已支持的功能。提案是在
field-only `path_windows.go` 中只读受保护本机 registry 的 MachineGuid（64-bit view，
严格 GUID 格式，规范为不带分隔符的小写 32 hex），与 OS 解析的 canonical machine
namespace 路径、独立 `winkyou-c1c-machine-scope/windows/1\n` domain 一起 SHA-256，
输出仍为 `machine-scope-sha256/1:<SHA256>`。路径采用 OS 回读的卷身份与相对路径规范
表示，拒绝 reparse/UNC/device/alternate-stream/相对路径，不使用 hostname、用户名或
随机 owner instance ID。读取失败/标识漂移/克隆冲突 fail-closed，不创建替代标识。
这个新派生规则须有路径大小写、同机器不同用户、重启一致性与克隆风险 golden/测试；
不能声称 MachineGuid 是密码学身份或能抵抗管理员克隆。

实例树从当前受审 token 的 KnownFolder Profile 定位，不读取 HOME/USERPROFILE/PATH。
沿用约定私有树及一个 exact instance ID，不扫描候选。文件用现有 pairgen Windows
owner+SYSTEM protected DACL、single-link、reparse 拒绝约束；父目录逐级核验无非授权
写权限，私有子树不得继承宽松 ACL，不能用 chmod 数字假装 DACL。创建证据/claim 必须
采用受保护的独占创建并持久记录 one-shot claim；不得把现有 directory Sync 在 Windows
报错改成无条件成功。未完成 claim 的崩溃仍不得自动重用实例。

必须保留两类设计前置，不能由平台移植私下改 schema：

- `/1` 的 Linux 行为和拒绝 golden 保留；Windows OS 分支只能在显式 `/2` 下提议扩展，
  当前 `/2` 仍有共享私有路径和共同 endpoint dependency digest。异构构建可能有不同
  linked module 集合，跨 OS 的路径语法也不相同；不能跳过任一 digest 或按本机规则改写
  对端路径。本机 Wintun proof 不依赖真实异构实例；跨机统一实例的路径归属、逐角色依赖
  与是否需要 `/3` 留给 C1c-2d 设计，闭合前真实异构实例仍拒绝。
- 名称/GUID 的 secret-free 派生、Windows 证据持久化与 field WG 封装是必要依赖，不是
  原 B2 两个入口文件能实现的功能。下表是送审的精确增补清单，未接受前不写实现。

| 阶段 | 拟允许文件（含同名专用测试） | 唯一用途 / 不可越界 |
| --- | --- | --- |
| B1 | `pkg/netif/field_tun_windows.go`、`field_ipcfg_windows.go`；`go.mod`、`go.sum`；原 architecture 精确登记 | sealed Wintun、typed owned IP rows、回滚、固定依赖；不改普通 Windows adapter。 |
| B1 必要增补 | `internal/v2/fieldc1c/identity_fieldc1c.go`、`pkg/netif/field_authority_fieldc1c.go` | 从有效 Instance 暴露仅派生身份的窄方法、Windows token 的精确比对；不暴露完整文档或可伪造构造器，不改 Linux 名称规则。 |
| B2 原清单 | `internal/v2/gatecorchestrator/field_entry_windows.go`、`field_entry_unsupported.go`、`field_summary_fieldc1c.go`；`.github/workflows/field-c1c-windows.yml`；`internal/architecture/` 专用测试；`docs/GATE-C1C-WINDOWS-FIELD-EVIDENCE.md` | 显式入口、固定 null/reason、required proof；不修改生产预算。 |
| B2 已获准列入设计的 parser/path 增补 | `internal/v2/fieldc1c/instance.go`、`validate.go`、`path_windows.go`、`path_unsupported.go` | 平台/role 分流、Windows 本机 scope 与私有路径；unsupported tag 收窄，Linux parser 逐项回归；不是跨机 schema 重设计。 |
| B2 另需本节接受的持久化增补 | `internal/v2/fieldc1c/evidence.go`、`evidence_windows.go`、`evidence_nonwindows.go` | 把现有 Linux 路径原样保留在非 Windows helper，Windows 使用持久 one-shot claim 与精确 DACL，补 crash 证明；不改 governor journal/recovery。 |
| B2 另需本节接受的 WG 增补 | `pkg/tunnel/fieldc1c_windows.go` | 与 Linux field WG 封装等价，仍禁 native bind；不动 Gate B/C handoff/completion。 |

若实施需要再动 `gatecstage`、`sshchildwrapper`、普通 `cmd/wink` dispatcher、系统安装器或
表外生产文件，先提交精确缺口复审，不以“移植闭包”无限扩张。Windows responder 服务、
全机状态恢复器、通用 netsh/registry 写能力和跨机接线不在此表。

#### 4.5.6 architecture、nm 与变异门

在 `internal/architecture/field_c1c_boundary_test.go` 中按文件名添加 Windows importer/
constructor 点；只准本节受审入口签发 authority。显式允许 `windows && fieldc1c` 与
`!linux && !windows && fieldc1c`，不得把检查改成“含 fieldc1c 就行”。新本地 DLL/syscall
调用只登记 exact file + function；不准整个 netif/fieldc1c 包获得 raw 网络/exec 权限。

普通 Windows 构建 `GOOS=windows go build -buildvcs=true ./cmd/wink`、单独 natlab 和单独
c1bproof 的 field 符号为零；Windows `fieldc1c` positive set 至少逐一命中：

```text
winkyou/internal/v2/fieldc1c.Load
winkyou/internal/v2/sshassembly.NewFieldAuthority
winkyou/internal/probeio.NewFieldUDPFactory
winkyou/pkg/netif.NewFieldInterface
winkyou/pkg/tunnel.NewFieldWireGuard
winkyou/internal/v2/gatecorchestrator.RunFieldInitiator
```

Linux 原 positive set（含 ExecFieldRoot）和 golden 不变；Windows 不为了凑相同符号而
引入 Linux wrapper。禁 inlining 的辅助 nm 构建可逐函数见证，但 ordinary release 构建
仍独立检查，不用空集合、仅 -run 编译或无关二进制充数。依赖 netsh/DNS fallback 的
不可达证明与本节 field 符号门分开，不能混淆“包可链接”与“调用被授权”。

必有 RED→GREEN/变异：无/过期 token 仍枚举或创建；同名/同 GUID 接管；绕过单用 CAS；
raw handle 泄漏；SetIP 后门；Flush/DNS/netsh；跳过逐项 readback/rollback；错误 PID
创建时间仍 kill；conntrack 填 0；Windows responder 意外启用；普通构建可达 field；
claim 崩溃后再用。测试缺权限不能声称变异已被 OS 证据拒绝。

#### 4.5.7 实证计划、预算与停止门

新 required workflow 名为 `Field C1c Windows Build Proof`，运行于管理员
`windows-latest`。真实测试须显式 `WINKYOU_FIELD_WINTUN_PROOF=1`；普通本地测试在
无门控/非管理员时干净 skip，required job 缺门控/权限必须 RED，不能静默 skip 或
continue-on-error。B1 先 pure RED→GREEN 与 fake 配置事务，再在获准环境运行相同真实
Wintun 测试；本 B0 不运行适配器创建、驱动安装或现场二进制部署；既有 architecture 的
离线构建/nm 检查不等于平台运行证明。

证明至少包含：独占 create/config/readback、authority 拒绝矩阵、部分配置失败回滚、
真实 kernel echo、一个预先指定的 owned controller kill、child 排水、Close 幂等与
全部 owned residue。每条终局失败也运行残留门；保留首个 RED，不 rerun 求绿。

**kernel echo 与合成控制报文是两条路径。** Linux `controlPacket` 当前识别固定 UDP
control tuple，不是 ICMP。Windows 保持同一合成 control 语义与 challenge 预算；测试
ICMP echo 走真实 Wintun kernel read/write、原 WireGuard 数据面与受控 test transport，
由 kernel 收到并返回，再以外部 witness 核对。不能让 `controlPacket` 伪造 echo success，
不能用 MemoryTestInterface 替代 kernel，也不授权对现场 peer 发送额外 ICMP。

先以独立、私有记录的校准首跑得到完整矩阵时长 T；冻结 workflow/harness budget 为
`ceil(1.25 * T)`（单位秒），后续 CI 首跑实测不得大于该 budget 的 80%。尚无 T，本节
不虚构数字。构建、driver readiness、矩阵/cleanup 分别计时并声明 T 的覆盖范围；预算
只属于测试外壳，绝不放宽 2s drain、candidate/active、3 datagram/3s 或 liveness 常量。

若托管 runner 不能创建适配器，保留确切 OS error code、失败阶段与全部 cleanup 结果在
私有归档；CI 首跑仍记录 RED，不改成 success。允许维护者 Windows PC 用**同一 SHA、
同一测试、同一显式门控**本地证明，不引入 self-hosted runner、不自动安装驱动；需主机
准备动作时先另行确认。公开只在后续 `docs/GATE-C1C-WINDOWS-FIELD-EVIDENCE.md` 发布
profile/stage/class、counts、duration/residue、SHA-256 与审查结论，原始错误/设备标识/
路径和日志不上 CI artifact。本地 PASS 不改写托管 RED；由独立复审确认替代验收，
否则 Windows 现场签发仍阻断。

#### 4.5.8 B0 复审栏（独立评审裁决 2026-09-23）

| 项目 | 冻结提案 / 接受结果 |
| --- | --- |
| preflight 只读 OS 查询；无效授权零能力 I/O | **接受**。零能力 I/O 的定义按 §4.5.1：读授权文件、构建见证、machine scope 与只读 OS 冲突查询属必要本地读取；DLL 加载、适配器枚举之外的驱动调用、地址/路由写入、child/socket 创建都在有效 authority 之后。 |
| A：winipcfg v0.5.3、逐项 IP Helper、禁止 Flush/DNS fallback | **接受"类型化 IP Helper、逐项 row、禁 Flush/SetRoutes/DNS/netsh"的方案本体；打包方式裁定为 A′：仓库内最小类型化子集**（`pkg/netif/field_iphlpapi_windows.go`，仅本节所需的 LUID/GUID 转换、单地址 Create/Get/Delete、单路由 Create/Get/Delete、接口 row 的 get/compare/set/restore 与 FreeMibTable），不新增 go.mod 模块。理由：与 Linux 侧自实现 netlink 而不引入库的先例一致；不存在的调用无需证明不可达（v0.5.3 包内 `os/exec` DNS/netsh fallback 与 Flush 系列从代码层面消失）；避免 Go 1.25 约束、旧版本安全审查与模块图膨胀。允许以 v0.5.3 的 `winipcfg` 为参考实现，逐 struct/函数记录上游文件与 commit，复制代码保留 MIT 版权声明；每个 struct 须有 `unsafe.Sizeof`/字段偏移 golden 对照 Microsoft 文档。若移植子集在实现中显著超出上述清单，先报数量与原因再定，不自行切回引入模块。 |
| identity 投影/GUID 与 Windows scope/路径、claim 持久化 | **接受**：`winkyou-c1c-wintun-identity/1` 投影、15 字符名、GUID 规范字符串往返与双 role golden；MachineGuid（64-bit view）+ canonical namespace 路径 + 独立 domain 的 Windows machine scope；KnownFolder Profile 定位、owner+SYSTEM DACL、reparse 拒绝、独占创建的 one-shot claim；golden/crash 实证在 B2。MachineGuid 不是密码学身份，该限制按原文登记。 |
| Windows initiator 优先；responder 和跨 OS 统一实例不冒充已闭合 | **接受**：本轮只做 Windows initiator；`RunFieldResponder` 在 Windows 保持拒绝；异构（Windows initiator + Linux responder）实例的路径归属、逐角色依赖摘要与是否需要 `/3`，连同跨机 attachment 一起归 C1c-2d 设计。**由此 Windows 现场实例的关键路径 = B1 + B2 + C1c-2d（设计与实现）**，§7 签发以此为前提。 |
| B1/B2 精确文件增补、Windows nm/Job/残留门 | **逐项接受 §4.5.5 表列出的文件**（B1 主体、B1 必要增补、B2 原清单、B2 parser/path 增补、B2 持久化增补、B2 WG 增补），无通配授权；A′ 使 B1 的 `go.mod`/`go.sum` 项失效，改为 `field_iphlpapi_windows.go`。修改共享的 `field_authority_fieldc1c.go`、`instance.go`、`validate.go` 时 Linux `/1`、`/2` golden 与拒绝回归逐项不变。`missing_reasons` 作为固定词表的可选公开字段接受，Linux 省略，须纳入 summary 白名单测试。Wintun DLL：B1 须写明所用 Go 模块的实际加载机制（嵌入内存加载还是磁盘文件），记录模块版本与嵌入 DLL 哈希；嵌入即由 exact-SHA 二进制覆盖。 |
| 托管 proof / 不可行时同测试本地替代 | **接受并补充合并纪律**：若托管 `windows-latest` 无法创建适配器，required job **收窄**为编译、nm、纯逻辑与 fake 配置事务（不创建适配器）并保持绿色；真实适配器矩阵改为维护者 PC 本地证明（同 SHA、同测试、同显式门控），私有归档，公开证据文档记一次托管 RED 的阶段与 error code 类别。main 不得长期携带必红的 required job；本地 PASS 不改写托管 RED 的记录，替代验收由独立评审确认。 |
| B0 接受 SHA / 复核日期 | **接受**：head `69d98e4`，2026-09-23；设计门关闭，B1 可开工；B1/B2/C1c-3 各自仍须独立复审。 |

本节不签发 Windows 实例，不做 SSH assembly/跨机 attachment，不改协议、冻结数字、
Governor/Promote/FINISH、loopback/stdio、service/firewall/scheduled task；NO-GO 继续有效。
设计 PR 通过只关闭 B0 文档门，不代表 B1/B2 或 C1c-3 已通过。

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
| C1c-3 运行授权；私有instance引用 | **授权**（维护者 2026-09-23，基线 `1386c36`）。范围：§3 七个场景全部授权，仍逐实例签发、两人签字、每个场景单独闭合；hard-16K 保持一次/24h 与 circuit 约束。**首轮布局修正**（对 §2 与本表首行的显式偏离）：单机三 namespace——router 与两端点全部位于维护者控制的一台 Linux 主机，形态同 `C1c Router Composition Proof`；跨机接线不在本轮。该主机为**非一次性共享主机**（承载其他服务、不重装）；补偿控制：`allow_global_conntrack_ceiling` 一律 false，全部实例运行于专用非 init 外层 network namespace，不修改主机 sshd/默认路由/全局 sysctl，kill switch 仅限 owned PID，第二人在开始前后各取一次主机状态快照且 diff 为空方可记"完好退出"；§4.3 三项硬化未做的 root 残余风险由此落在有其他服务的主机上，两人签字接受。**内核**：目标机 Ubuntu 22.04（5.15），CI 未实证；签发任何实例前须先在该主机、非 init netns 下以不改全局 ceiling 的维护者主机证明模式跑通现有完整实例证明（test-only 变更，另行 PR 复审），GuardianCrash 证明仍限 CI。**角色**：执行者为维护者授权的代理经 SSH 逐步执行，每步停在"复核通过"门；第二人为独立评审，凭只读访问核验并在私有 checklist 签字。SSH 目标、凭证、地址等私有值不进入仓库。 |
| Windows 端点优先级；C1c-2c/2d 实现授权 | **授权实现**（维护者 2026-09-23）：维护者明确产品目标是 Windows 端点的 P2P 直连，Windows 不能缺席现场；§2 首轮 Linux 基线不再是唯一路线。授权两个实现子阶段（均无现场 I/O）：**C1c-2c** Windows field 端点——密封 Wintun capability（实例绑定、独占适配器）、地址/路由精确回滚、Job Object kill switch、Windows 残留见证（无 conntrack 记 null+reason，不填 0）、Windows field 入口、普通 Windows 构建 nm 零命中；**C1c-2d** 远端端点接入 router anchor 的跨机接线（先设计后实现，设计经独立复审）。Wintun 真实适配器证明：先尝试 GitHub 托管 windows-latest；不可行时允许在维护者 Windows PC 本地证明并私有归档，不接 self-hosted runner。两者各自 docs → RED → 实现 → 变异 → 复审；Windows 实例仍须另行签发。 |
