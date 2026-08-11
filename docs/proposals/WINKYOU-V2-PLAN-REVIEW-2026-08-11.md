# WinkYou v2 计划审查意见（基于代码核对）

- 状态：审查意见 / 供维护者修订计划使用
- 日期：2026-08-11
- 审查对象：[`WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./WINKYOU-V2-DIRECT-FIRST-PLAN.md)
- 审查方式：逐条将计划断言与当前 `main` 分支代码（`6baac4c`）核对；`go build ./...` 通过
- 维护者已澄清的前提：分发模型为 **GitHub 发布二进制优先**；外部接入求解器走 **plugin / 本地 API**，不以 Go 库 import 为主要通道

---

## 0. 结论摘要

计划整体方向成立，对现状的诊断诚实，事故根因描述与代码逐条吻合，可以作为 RFC 基础接受。

需要修订的不是方向，而是以下五类问题：

1. **一个安全架构决定没有写死**：ResourceGovernor 的强制点位置（§2.1，本文件最重要的一条）；
2. **两处 alpha 范围过大**：身份/成员模型、具名服务（§3.1、§3.2）；
3. **一处流程设计缺陷**：Phase 1 把工程时间和证据时间混在同一窗口（§3.3）；
4. **一处顺序问题**：PR #11 应先于 RFC 接受合并（§3.4）；
5. **若干措辞与现实的偏差**："两套运行时"实为三条执行路径、"保留求解器"的真实口径、"库嵌入"应改为"plugin/API 接入"（§2、§4）。

---

## 1. 已核实为准确的计划断言

以下断言逐一与代码核对，全部属实，接受计划时无需修改：

| 计划断言 | 核对结果 |
| --- | --- |
| `solver.Strategy`、`transport.PacketTransport`、路径评分存在且值得保留 | `pkg/solver/types.go`、`pkg/transport/transport.go`、`ScoreOutcomeWithPolicy` 等，接口干净 |
| 运行时在 coordinator/WG 与 autonomous mesh 之间分裂 | `pkg/client/engine.go` vs `pkg/client/autonomous_engine.go` + `pkg/meshruntime`（但见 §2.1，实际比"两套"更碎） |
| 缺少节点级资源治理 | 全库唯一预算机制是 per-session `solver.ExecutionBudget`（3 候选 / 60s），不覆盖 socket、包速率、五元组 |
| 事故根因（128 socket × 每轮 48 新目标、无 single-flight、无总预算） | 与 `pkg/nat/puncher/puncher.go`、`pkg/bootstrap/selfhosted/engine.go` 及事故文档一致 |
| 身份依赖共享 secret，需要重做 | `meshruntime` 信任模式为 `shared_secret` / trusted node IDs，无签名身份 |
| PREPARE/READY/FIRE、attempt epoch、PCP/UPnP、IPv6 策略均为新工作 | 现有策略仅 birthdaypunch / legacyice / relayonly / signalrelay / tcpframed；`birthdaypunch/sync.go` 只有基础时间同步 |
| 生日策略默认禁用 + §9 硬上限与事故规模匹配 | 事故量级（~40 万会话）出自 128×48×65 轮的机制推算，上限表（8 socket / 512 包 / 5s）比事故参数低 2–3 个数量级，合理 |
| v1/v2 断代成本最低 | 仓库无外部使用者证据（9 个 PR 全部来自维护者/机器人），此时断代最便宜 |
| "无冷启动神话"的网络事实（§4） | 表述正确，无需修改 |
| 保留 WireGuard 数据面与 `mesh` 包 | `pkg/mesh` 仅依赖 `peercontrol` + `transport`，是全库分层最干净的包 |

---

## 2. 结构性发现（代码层面，计划应补充或修正）

### 2.1 打洞执行路径实际是三条，governor 的强制点必须写死在最底层

计划 §2 说"旧运行时在 coordinator/WireGuard 路径和 autonomous mesh/userspace 路径之间分裂"。核对代码后，**主动 UDP 探测的执行路径是三条，且预算机制只覆盖其中一条**：

```text
路径①  pkg/session（coordinator 模式）
        selectAndExecute → executeCandidateLoop → strategy.Execute
        唯一受 ExecutionBudget 约束的路径 ✅

路径②  pkg/meshruntime（autonomous mesh 模式）
        runtime.go:232 直接 birthdaypunch.New(strategyConfig)
        经 mesh/shortcut 触发，完全绕过 session 的预算/评分/排序 ❌

路径③  pkg/bootstrap/selfhosted（cached self-bootstrap，事故元凶）
        engine.go 直接调用 pkg/nat/puncher 发包
        连 solver 策略框架都不经过 ❌
```

**推论（本审查最重要的一条意见）**：计划 §5 要求"所有 UDP 策略发送必须经过同一个节点级 ResourceGovernor"，但没有规定 governor 在架构中的强制位置。如果 v2 把 governor 实现在 strategy 层或 session/编排层（路径①的位置），路径②③形态的代码在未来仍然可以绕过它——事故会以新形式重演。

**建议在计划 §5 或 §8.6 增加一条硬性约束**（示例措辞）：

> ResourceGovernor 的强制点在探测 socket 的创建与发送原语本身。v2 中不存在任何不经过 governor 即可创建探测 socket 或发送主动探测包的公开或内部 API。`BudgetLease` 是发送函数的必要参数而不是调用方自觉遵守的约定。策略、恢复控制器、诊断工具共用同一强制点。

验证矩阵（§17.1）已有"任意输入下资源消耗不超过 BudgetLease 与发布硬上限"，建议追加一条：**"代码层面证明不存在绕过 governor 的发送入口（可用包依赖白名单 + 静态检查实现：只允许 governor 包 import 原始 UDP 发送原语）"**。

### 2.2 solver 核心存在对 rendezvous 协议的依赖泄漏

`pkg/solver/types.go` 直接 `import rproto "winkyou/pkg/rendezvous/proto"`，`SolveInput.LocalCapability` / `RemoteCapability` 使用 `rproto.Capability` 类型。

这违反了当前基线文档自己的约束（`CONNECTIVITY-SOLVER-BASELINE.md`："legacy protocol details must not leak into the solver core API"）。计划 §13 的新 API（`connectivity` 只暴露 observations/plans/result）隐式修复了此问题，但没有把它点名为现存债务。

**建议**：在计划 §13 明确列出"切断 `solver → rendezvous/proto` 依赖"为抽库的第一步验收项，防止 v2 实现时为了省事继续沿用旧类型。

### 2.3 同一概念的类型定义重复了三份

- `solver.Observation` 与 `rendezvous/proto.Observation` 字段几乎逐一相同，靠手工转换；
- `solver.ProbeScript`/`ProbeStep` 与 `rproto.ProbeScript`/`ProbeStep` 同样重复；
- probe 相关类型再存在一份变体。

改一个字段需要同步三处，是未来 bug 的温床。**建议**：v2 定义 `connectivity` 公共类型时一次性收敛为单一来源，信令层只做序列化包装，不再定义平行结构。

### 2.4 "保留现有连接求解器"的真实口径

可直接保留的部分与需要重写的部分比例如下：

| 部分 | 规模 | v2 处置 |
| --- | --- | --- |
| solver 接口层 + 路径评分/策略打分 | ~3–4k 行 | 可基本保留（改接口签名） |
| transport 抽象 | 很小 | 可保留 |
| session 编排层（planning.go ~32KB、strategy_portfolio.go ~16KB、selection.go ~11KB） | ~8.9k 行 | 与 rendezvous 会话/信封深度耦合，基本重写 |
| client / meshruntime 双运行时 | ~15k 行 | 计划已明确重做 |

计划把"保留求解器"作为工作量前提，但真正干活的编排机器要推倒重来。**建议**：Phase 1/3 排期按"重写编排层"估算；并在计划 §2 或 §13 中明确 `pkg/session` 的去留（当前计划全文未提及 session 包——它是现状中最大的单一编排组件）。

### 2.5 仓库卫生（招募外部测试者前）

根目录存在大量工作残留：`brainstorm.md`、`guess.md`、`question.md`、`manage.md`、`selfdev.md`、`selfhost.md`、`winkplan.md`、`codex_summary.md`、`implementation_plan.md`、`protocol.md`、`wink-protocol-v1.md`、未跟踪的 `wink.exe`/`netprobe.exe`/`e2e.test`/`.live-run`/`.stability-run` 等。

Phase 1 要向 10 位外部测试者展示仓库，第一印象影响留存。**建议**：Phase 0 增加一项低成本交付——历史文档归档到 `docs/legacy/` 或删除，构建产物入 `.gitignore`。

---

## 3. 对计划关键判断的异议

### 3.1 Phase 2 身份/成员模型对 alpha 过度设计（最强异议）

计划 §6 为 alpha 设计了完整能力体系：四种可分别授予的能力（invite / revoke / control_transit / data_transit）+ 委托链（获得 invite 的成员可背书新设备）+ 签名撤销 + 分区合并确定性收敛 + 撤销优先。

这是一个微型 PKI。委托链验证、重放防护、分区合并冲突收敛，每一项都是分布式系统中出名难做对、难测全的领域。而目标用户是 **2–20 台互相信任的设备**（§3.1），通常属于同一人或同一家庭。

计划自己的风险表（§18）已承认"去中心成员状态过于复杂"是风险，但正文没有据此裁剪范围——发现了问题，未执行结论。

**建议将 alpha 裁剪为"签名成员名册（signed roster）"模型**：

```text
alpha 保留：
  - Ed25519 节点身份、NodeID 派生、WG key binding（§6.1 不变）
  - 离线根密钥签名一份带单调版本号的成员名册
  - 名册列出成员 NodeID 与其能力位（是否允许 control transit / data transit）
  - 节点间同步名册，版本高者胜；撤销 = 根签发去掉该成员的新名册
  - 邀请文件 = 根预签的一次性加入凭证（含 nonce、有效期、目标身份）

推迟到 v2.1（各自独立 ADR）：
  - invite 能力委托与成员背书链
  - revoke 权下放
  - 分区合并的多写者收敛（单一根签名下版本号比较即收敛，无多写者问题）
```

效果：功能上覆盖 2–20 台自有设备的全部场景；实现与测试复杂度约为原方案 1/5；安全攻击面显著缩小；Phase 2 的 4–6 周才可能成立。计划 §6.4 的"能力分离"原则不受损——能力位仍在名册中分离，只是**授予动作收敛到根**。

### 3.2 具名服务不应与 L3 overlay 同级

计划 §3.1/§12 把"具名 TCP/UDP 服务"（签名服务记录 + 发布端 ACL + 默认拒绝）与 L3 overlay 列为 alpha 同等重要目标。

具名服务本质是叠在身份系统之上的**第二套授权系统**（服务注册、签名验证、按名解析、ACL 执行）。而 L3 打通后，homelab 用户用 `虚拟IP:端口` + 系统防火墙即可覆盖绝大多数需求。两套授权系统同时进 alpha，是 Phase 3（6–8 周内做统一运行时 + L3 + 服务 + ACL + 稀疏控制图 + 状态输出 + 迁移工具）超时的最大风险源。

**建议**：具名服务降级为 Phase 3.5 或 Phase 4 的独立增量；alpha 的服务访问故事改为"L3 直达 + 文档指导防火墙配置"。若维护者认为具名服务是核心差异化体验而必须保留，则应把 Phase 3 拆成 3a（运行时 + L3）与 3b（服务 + ACL），分别设退出门槛。

### 3.3 Phase 1 门槛混合了工程时间与证据时间

Phase 1（6–8 周）同时要求：

- 工程件：`wink diagnose`、`connect-test`、ResourceGovernor、NAT 模拟矩阵、报告流程——维护者可控；
- 证据件：10 位外部测试者实际运行、5 个独立部署两周留存——取决于招募与他人意愿，**不受工程进度控制**。

可预见的结局：第 7 周工程完成、测试者未凑齐，此时要么宣布 Phase 1 失败，要么放宽门槛。门槛被放宽一次，后续所有证据门槛的约束力都会失效。

**建议**：拆为两段——

```text
Phase 1a 构建期（6–8 周）：交付全部工程件，退出门槛 = 模拟矩阵连续 100 次通过等技术项
Phase 1b 证据期（≥4 周，可与 1a 尾部重叠启动招募）：外部测试者、留存、集成意向
```

"继续完整 v2"的决策点放在 1b 结束，且明确：1b 未达标时的动作是复盘定位与分发（计划 §15 已有此条款），不回退 1a 的技术成果。

### 3.4 Phase 0 顺序：PR #11 应作为前置而非并行事项

PR #11（fail: fail closed on paused autonomous recovery）在配置校验层拒绝 `autonomous_mesh.maintain_peers` 与 `recovery_card`，并在 `meshruntime.New` 公共入口前置同样的门禁——即焊死事故路径的全部已知入口。

当前 main 上，maintained-peers 路径仍可触发与事故相同的 128 socket × 48 新目标 profile。计划 §16 Phase 0 把"审查 PR #11"列为与 RFC 审查并行的事项，且强调"本文不等于批准其合并"。

**建议**：顺序改为"先合 #11（独立、纯防御性、只加拒绝逻辑），再进行 RFC 接受"。RFC 审查可能持续数周，期间 main 不应继续携带已知 P0 隐患。这与计划维持 NO-GO 的立场完全一致，只是执行顺序问题。

---

## 4. 分发模型澄清后的计划修订点（维护者已确认二进制优先）

维护者澄清：用户从 GitHub 获取打包二进制；外部接入求解器通过 **plugin / 本地 API**；能读源码的人自行处理 import 问题。基于此前提：

1. **模块名（`module winkyou` 不可 `go get`）从硬阻塞降级为低优先级卫生项。** 无需立即改名；若未来某天要支持源码级引用，改名是机械工作。
2. **但计划文本需要同步修订**，当前多处以"Go 库嵌入"为一等目标和门槛：
   - §8.1 "Go 库：供其他 P2P、游戏、远程控制或边缘项目嵌入"；
   - §13 整节以 Go 公共包为 API 边界；
   - §15 分发漏斗最后一级"其他项目嵌入 connectivity 库"；
   - Phase 1 门槛"至少一个最小外部嵌入示例""有明确外部集成意向，最好完成首个真实集成"。

   建议统一改写为："**求解器接入面 = 版本化的本地 plugin/API（如 JSON-RPC / gRPC over localhost 或 stdio 子进程协议）**；Go 包边界作为内部分层约束保留，不作为对外承诺"。相应地 Phase 1 的集成门槛改为"首个通过 plugin/API 完成的外部集成或集成意向"。
3. **plugin/API 方案的三条设计约束**（建议写入计划，避免后续踩坑）：
   - **API 消费者不能绕过 governor**：diagnose/connect-test 级别的 API 调用同样占用节点级预算租约，防止外部集成方把 WinkYou 变成打洞放大器；
   - **本地 API 必须有认证与默认仅回环监听**：否则任何本机进程/局域网进程都能驱动探测；
   - **API schema 版本化**：二进制分发下无编译期类型检查，schema 兼容性即产品兼容性，需进入发布检查清单。
4. **§13 的 `internal/` 策略照旧有效**：即使不承诺 Go API，`internal/` 仍阻止源码级用户依赖未稳定实现，维持"能读源码的人自行处理"的边界清晰。
5. 一个附带收益：plugin/API 面是**跨语言**的（Python/Node/Rust 集成同样可行），比 Go 库嵌入的潜在受众更广，与 §15 的第二采用渠道目标更契合。

---

## 5. 建议的计划修订清单（可直接照改）

| # | 位置 | 修订 | 优先级 |
| --- | --- | --- | --- |
| 1 | §5 / §8.6 | 写死 governor 强制点在 socket 创建/发送原语层，`BudgetLease` 为发送函数必要参数；§17.1 增加"无绕过入口"的静态验证项 | **最高** |
| 2 | §6 / Phase 2 | alpha 裁剪为根签名成员名册模型；委托链、revoke 下放、多写者分区合并推迟至 v2.1 独立 ADR | **高** |
| 3 | §16 Phase 0 | PR #11 合并改为 RFC 接受的前置条件 | **高** |
| 4 | §16 Phase 1 | 拆为 1a 构建期（6–8 周，技术门槛）+ 1b 证据期（≥4 周，留存门槛） | **高** |
| 5 | §8.1 / §13 / §15 / Phase 1 门槛 | "Go 库嵌入"统一改写为"版本化本地 plugin/API 接入"，并加入 §4 所列三条 API 设计约束 | 高 |
| 6 | §3.1 / §12 / Phase 3 | 具名服务降级为 L3 之后的独立增量（或 Phase 3 拆 3a/3b 分设门槛） | 中 |
| 7 | §2 / §13 | 把"两套运行时"更正为"三条探测执行路径"（session / meshruntime→shortcut / bootstrap→puncher），并明确 `pkg/session` 编排层按重写计；工时估算随之调整 | 中 |
| 8 | §13 | 抽库/抽 API 第一步验收项：切断 `solver → rendezvous/proto` 依赖；Observation/ProbeScript 等重复类型收敛为单一来源 | 中 |
| 9 | Phase 0 | 增加仓库卫生交付：根目录历史文档归档 `docs/legacy/`、构建产物入 `.gitignore` | 低 |
| 10 | go.mod | 模块名改名降级为可选卫生项，不阻塞任何 Phase | 低 |

---

## 6. 审查中确认无需修改的判断

为避免误伤，以下计划判断经核对后明确支持保留：

- `direct: required` + `relay: disabled` 默认值，以及 `relay: fallback` 必须配 `direct: preferred`；
- 生日策略 alpha 默认禁用、仅 manual、§9 硬上限表、持久化 safety trip 优先于一切恢复状态；
- cached self-bootstrap / autonomous birthday recovery 维持 NO-GO；
- §4 关于冷启动的网络事实表述；
- v1/v2 协议与配置断代、迁移工具只生成文件不启动节点；
- NAT 观测不写入永久标签（§8.3）；
- 公共 STUN 默认开启但明示、可关闭、可自托管；DHT 仅留接口；
- 遥测默认关闭、证据来自用户主动提交；
- 以留存/集成/跨网络稳定性为里程碑，不以 Star 数为工程决策标准；
- 保留 `mesh` 数据面与 WireGuard 数据面。
