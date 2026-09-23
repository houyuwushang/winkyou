# Gate C1c 一次性路由器运行清单（Draft）

**仅 C1c-1 准备文档，所有步骤均未执行。** 本文不能授权构建、云账号操作、主机变更或现场
发包。先接受 [mini-spec](./adr/ADR-N3C-GATE-C1C-DISPOSABLE-ROUTER.md)，再分别取得 C1c-2
实现/构建和 C1c-3 单实例运行授权；C2 不继承本授权。

## 1. 私有副本与填写规则

字段目录为 [空模板](./templates/gate-c1c-authorization.template.json)。其中 `type`、
`description` 是说明，`value` 全空；它不是可直接加载的配置，不提供“填写后自动批准”入口。
真实值只在 `~/.winkyou-field/c1c.json` 的私有副本填写，访问限操作者与获准复核者。
原始日志、ledger封存、证据与后续实例私有归档也只在该仓库外受控目录树；不得上传 CI。

`<PLACEHOLDER>` 必须由两人核对后的私有值替换，本文命令**不可原样执行**；不是额外的新
CLI/API。凡 `<...COMMAND>` 均指 C1c-2 已审查的精确实现命令，没有实现就停止，不临时拼接。
原始验证输出可能含地址/路径等，全部私有保存；公开只用 §5 的白名单摘要。

- 一个 instance = 一个 scenario = 一个 credential = 一次 foreground invocation。
- exact SHA、二进制哈希、标签/依赖/配置改变即失效；私有记录不可当成可重用授权。
- 未 burn 的失败也不在同一实例自动 retry；burn 后绝不退款/reset ledger。
- hard-16K 一次/24h与失败 circuit 不因销毁/重建 VM 消失；先封存持久状态，不能换scope绕过。
- root 风险必须双方签字；三项硬化分别填已做证据或未做原因，不把待硬化写成已保护。

## 2. 分步清单

每步执行者为维护者，复核者为独立第二人；只有“复核通过”才进入下一步。部署与回滚必须
在私有授权中逐项覆盖，不以“跑一次测试”为由改维护者原有管理通道。

| 步 | 执行 / 第二人验证 | 私有验证命令模板 | 失败时回滚 / 停止 |
| --- | --- | --- | --- |
| 0 签发前置 | 核实 C1c-2 独立评审、原低成本负面门、exact SHA与本次唯一场景；复核者签时间窗和预算 | `git rev-parse <REVIEWED_COMMIT>`；`<PRIVATE_AUTHORIZATION_VALIDATOR>` | 任一门未闭合不创建环境、不生成credential、不发包。 |
| 1 创建一次性 VM | 在另行批准的云作用域创建唯一router；核对专属身份、资源清单、删除方式、供应商允许负载；选全VM布局时两端另列清单 | `<CLOUD_CREATE_EXACT_RESOURCE_COMMAND>`；`<CLOUD_DESCRIBE_EXACT_RESOURCE_COMMAND>` | 只撤销本次创建的资源；禁止按账号/区域批量删除。 |
| 2 离线能力检查 | 核实OS/内核/UID/TUN/工具、独立管理路径、router两NAT域及observer双地址双端口权限；核对namespace与全局ceiling的不同管理域；共享主机另遵守下述维护者证明模式 | `uname -r`；`id -u`；`test -c <TUN_DEVICE>`；`conntrack -V`；`<READ_ONLY_CAPABILITY_CHECK>`；`env WINKYOU_C1C_MAINTAINER_HOST_PROOF=1 TMPDIR=<PRIVATE_ROOT_0700_DIRECTORY> <ISOLATED_REVIEWED_PROOF_COMMAND>` | 能力/许可不足即停止；不换公网observer，不降低隔离要求。 |
| 3 安装受审构建 | 私有源取得同一exact build，验证双方哈希；普通构建零现场符号证明来自C1c-2；安装/私有文件owner-only、非symlink/hardlink | `sha256sum <EXACT_BINARY>`；`stat <OWNED_INSTALLATION>`；`<CHECK_INSTALLATION_OWNER_AND_LINKS>` | 哈希/权限不符拒绝；只移除本次安装，保留旧管理软件。 |
| 4 限定网络配置 | 只应用已批准的owned NAT/interface/route/observer/SSH forced-command配置；保存旧值、逐值回读，独立guardian保留恢复能力 | `<APPLY_EXACT_APPROVED_CONFIGURATION>`；`<READ_BACK_EXACT_CONFIGURATION>`；`<VERIFY_UNRELATED_STATE_UNCHANGED>` | 原子恢复本次差异；不得重配主机通用SSH服务或管理overlay。 |
| 5 安全和账本前检 | 两端trip clear、scope/lock可用、ledger determinate、admission/circuit允许、无pending/stalechild/冲突interface/route；任务Disabled/absent | `<READ_ONLY_GOVERNOR_LEDGER_CHECK>`；`ss -H -nup <OWNED_SOCKET_FILTER>`；`<CHECK_EXACT_TASK_AND_PROCESS_STATE>` | 不clear trip/reset账本求通过；不确定就停。 |
| 6 材料与SSH核对 | 另行获准后离线生成本场景一个credential；两人核对manifest、时效、roles、trusted peer、host pin、一个literal endpoint、observer permission | `<OFFLINE_MATERIAL_COMMAND>`；`<VERIFY_SECRET_FREE_MANIFEST>`；`<VERIFY_PIN_AND_EFFECTIVE_SSH_PROFILE>` | PSK不回显/不入argv；未开始的材料隔离作废，不跨窗口复用。 |
| 7 kill switch与采集就绪 | 独立的低成本演练已闭合；本实例只作readiness检查；核对进程启动身份、owned scope、witness容量和停止动作 | `<VERIFY_EXACT_STOP_TARGET_IDENTITY>`；`<VERIFY_WITNESS_READY_WITHOUT_PROBING>` | 控制或见证不可用时不启动attempt；不得在本credential内再演练一次。 |
| 8 单次前台运行 | 操作者执行已签发的一个invocation，复核者同步观察计数/阶段；不后台守护、不重连 | `<EXACT_REVIEWED_ONE_SHOT_INVOCATION>` | 达到任一停止条件，转§3；任何新代码/临时参数要求都使实例失效。 |
| 9 排水与封存 | 保留首个terminal、双端FINISH/circuit、各资源终值、private日志哈希；失败也执行所有残留门 | `<COLLECT_PRIVATE_TERMINAL_WITNESSES>`；`<VERIFY_DURABLE_LEDGER_WITHOUT_RESET>` | 不因提前失败跳过cleanup；未知残留记unknown/RED，不能填0。 |
| 10 回滚owned资源 | 关闭本次foreground/SSH child/TransportLease/WG；撤销本次TUN/route/address和flow；保存、恢复、回读配置 | `<ROLLBACK_EXACT_OWNED_STATE>`；`ss -H -nup <OWNED_SOCKET_FILTER>`；`conntrack -L <OWNED_FLOW_FILTER>` | 不执行全局flush或删除未知PID/接口；失败触发预先授权containment并保留first RED。 |
| 11 销毁VM | ledger/证据已持久封存且复核；销毁本次router及选定endpoint VM与附属资源，核对provider清单归零 | `<CLOUD_DELETE_EXACT_RESOURCE_COMMAND>`；`<CLOUD_VERIFY_OWNED_RESOURCE_COUNT_ZERO>` | 删除未确认就不关闭授权记录；不得靠丢掉ledger重新建立scope。 |
| 12 第二人关窗 | 核对全部witness、签字、失效credential、保留原管理路径；只发布脱敏摘要 | `<VERIFY_REDACTED_SUMMARY_AND_SHA256>` | 未完成项保持RED/unknown；不签发下一个窗口来掩盖它。 |

### 2.1 维护者主机证明模式（A0，test-only）

`WINKYOU_C1C_MAINTAINER_HOST_PROOF=1` 仅用于
`TestLinuxFieldC1cExactBuildProof` 和 `TestLinuxC1cRouterFullInstances`；不是生产开关，
不批准实例签发或现场发包。A0 独立复审合入前不得执行共享主机证明。

它与四个 CI attestation 环境变量互斥：`WINKYOU_GATE_B3_DISPOSABLE_RUNNER`、
`GITHUB_ACTIONS`、`RUNNER_ENVIRONMENT`、`WINKYOU_GATE_B3_HOST_CONNTRACK_CAP`。
任一同时存在（包括空值）即拒绝，不伪造 CI；各测试原有 `*_REQUIRED=1` 门仍须满足。
`TestLinuxC1cRouterGuardianCrash` 仍仅限原 CI 模式。

维护者须先在私有副本核对已审查的隔离命令：root、非 init netns、非 init mount namespace、
private mount propagation、独立挂载的 namespace 注册表，以及绝对路径、root owner、0700
的 `TMPDIR`。证明在创建任何测试 namespace 前检查这些前置；全局 `nf_conntrack_max`
只读，保存原值，每个子测试排水后与顶层 cleanup 均核对未变。不得运行会改写主机 ceiling
的 CI wrapper。三次 fresh、200×2 清理批次、所有预算/残留/终局断言保持原样。

第二人使用 `scripts/c1c-review-snapshot.sh` 取得开始前/结束后的只读主机快照。脚本不接受
参数，以固定系统命令在 init net/mount namespace 内采集，输出一个 JSON；需要受审路径的
`nsenter`、`python3`、`ip`、`nft`、`sysctl`、`lsmod`、`ss`，缺失即停止，不自动安装。
原始快照可能含真实身份，只能进入仓库外受控目录，不得粘贴 PR、日志或 CI artifact。
仅 `ss` 项标为 volatile；其余字段 diff 必须为空才能记“完好退出”。共享业务造成的差异也须
保留并停止复核，不能自行忽略、归因或改写快照。账号/sudoers 与证据读取权限另行确认；
A0 不创建账号，不授权自由参数或任意文件读取。

## 3. Kill switch 契约

触发条件：达到签发停止时刻、parent/consumer异常退出、任一额度/第二地址/第二attempt、
计数失去可信性、意外持续发包、ledger不确定、stage失败或操作者撤销。按已签发动作停止
**本次** controller/SSH child，不使用按名称杀所有进程、停sshd、断开管理overlay等捷径。

```sh
<VERIFY_EXACT_STOP_TARGET_IDENTITY>
kill -TERM -- <OWNED_CONTROLLER_PID>
<WAIT_FOR_OWNED_DRAIN_AND_VERIFY_COUNTER_STABILITY>
<VERIFY_OWNED_CHILD_SOCKET_LOCK_COUNTS_ZERO>
<VERIFY_INDEPENDENT_MANAGEMENT_CHANNEL_UNCHANGED>
```

PID须连同启动身份/owned进程容器核对，避免PID复用误杀。Windows若获单独授权，使用受审
Job Object退出路径，既有 `Killed=true` 预期不能误报新缺陷。未在原2s drain内完成就是RED，
不得延长产品budget；只执行事前另行批准的精确containment/rollback，不临时扩大权限。

## 4. 现场证据与 M/E 时间记录

每个命中tuple按 mini-spec §5填一行，保留所有失败和缺失值；记录`mapping_age_at_hit_ns`、
`mapping_age_at_winner_ns`、`mapping_idle_age_at_winner_ns`、`hit_to_stop_ns`、
`stop_to_winner_ns`、`winner_to_verify_ns`、`stop_to_verify_ns`、`kernel_flow_observation`、
`failure_stage`、`terminal_class`、`missing_reason`和`measurement_source`。

采用同一见证者本地单调差值，不对两机器墙钟做减法；非winner端缺少本地W时填null。
普通tuple mapping年龄不等于kernel flow剩余寿命；查询失败不等于absent。full schedule
仍完整执行，stop不是新E2消息；这次观察本身不授权E2/E1或额外探测/保活。

必须同时有：packet分账与PPS峰值、socket/target/five-tuple、process/SSH child、conntrack
peak/terminal/residue、ledger BURN→FINISH/circuit、TransportLease所有权、WG challenge与
OOB退出后的双向数据、interface/route/address回滚。无conntrack观测能力的平台不得借另一台
机器计数声称本机归零；由已审查替代见证或明确unknown阻断对应验收。

router、所有endpoint和云侧附属资源分别列owned residue；机器上的无关连接不要求清零。
所有场景都 teardown，nominal success也不是让session留后台运行的许可。

## 5. 公开摘要与双人签字

只公开 profile/stable stage/class、样本数/unknown数、资源计数/ceiling、duration、owned
residue、审核结论、代码/证据SHA-256。原始日志只留私有目录；不得粘贴模板实例、tuple、
IP/域名/hostname/用户名/路径/指纹、云账号/区域、设备属性、credential或machine ID。
先离线脱敏再由第二人人工复核；仓库隐私门不是自然语言隐私的完整证明。

| 检查 | 维护者签字 / 时间（私有） | 独立复核签字 / 时间（私有） |
| --- | --- | --- |
| exact build、C1c-2复审与本场景权限 | | |
| root风险接受 / 降权、syscall隔离、低权限parser三项硬化状态 | | |
| 预算、ledger/circuit、kill switch、observer与SSH pin | | |
| 双端terminal、M/E来源与unknown、FINISH/排水 | | |
| 主机owned residue、原管理通道、VM及附属资源销毁 | | |
| 脱敏摘要与证据哈希、实例关闭 | | |

没有两人完整签字就不记录窗口成功。单次direct success不等于总体穿透成功率、生产就绪，
也不改变 [事故后的暂停与NO-GO](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)。
