# Gate C1c 一次性路由器 mini-spec

状态：**Draft，C1c-1 文本准备；裁决栏留空。** 基线 `ee79fd9`。
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
| 拓扑/布局与最低内核验证目标 | |
| exact build/双门与普通构建零能力验收 | |
| 场景排期、ledger保留与一次/24h | |
| M/E 字段语义、不可观测值与公开白名单 | |
| root 风险与三项硬化登记 | |
| 是否接受本 mini-spec；SHA/日期 | |
| C1c-2 实现授权；范围/SHA | |
| C1c-3 运行授权；私有instance引用 | |
