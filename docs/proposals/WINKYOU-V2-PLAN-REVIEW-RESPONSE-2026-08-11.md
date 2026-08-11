# 对《WinkYou v2 计划审查意见》的维护者回复

- 状态：回复草案 / 请求复审
- 日期：2026-08-11
- 原计划：[`WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./WINKYOU-V2-DIRECT-FIRST-PLAN.md)
- 审查意见：[`WINKYOU-V2-PLAN-REVIEW-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-2026-08-11.md)
- 核对基线：`main@6baac4c671d9da432564b451a2e57a5c5923349d`

感谢审查者把计划逐条落回代码，而不是只评估概念是否听起来合理。我们接受审查的主要结论：原计划方向可以保留，但资源治理的强制位置、alpha 范围、实施阶段和外部接入面需要写得更准确。

本文用于说明维护者准备如何吸收这些意见，并请审查者继续检查修订是否真正闭合。它不是正式 ADR，不取代当前
[`CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md)，也不授权启动、部署或现场测试任何自动生日恢复路径。

## 1. 回复结论

对审查清单中的十项建议，维护者给出以下处置：

| # | 审查建议 | 处置 | 回复摘要 |
| --- | --- | --- | --- |
| 1 | Governor 强制点下沉到 socket/send 原语 | **接受并加强** | 增加不可绕过的 probe I/O 能力边界、静态检查和成功 socket 的受控移交 |
| 2 | alpha 改为根签名成员名册 | **修正后接受** | 采用单写者 roster，但不采用流程未闭合的通用预签邀请 |
| 3 | PR #11 先于 RFC 接受 | **接受** | RFC 可继续讨论，但在 PR #11 合入前不得把 RFC 标记为 Accepted，也不得开始新的联网实现 |
| 4 | Phase 1 拆为构建期与证据期 | **接受** | Phase 1a 为技术门槛，Phase 1b 为外部采用门槛 |
| 5 | Go 库改为 plugin/本地 API | **修正后接受** | 二进制优先；Phase 1 使用进程外、版本化 stdio API，不使用 Go 动态 plugin |
| 6 | 具名服务从首个 L3 alpha 中拆出 | **接受** | Phase 3a 只交付统一运行时和 L3；具名服务进入独立 Phase 3b |
| 7 | 明确三条探测路径及 `pkg/session` 去留 | **修正后接受** | 保留“两个顶层运行时家族”事实，同时写明“三条主动探测入口”；渐进替换编排，不做大爆炸重写 |
| 8 | 切断 solver/proto 耦合并收敛类型 | **接受并澄清** | 建立单一 domain model；wire DTO 可以独立版本化，但只能存在于适配器边界 |
| 9 | 归档根目录文档并补 `.gitignore` | **不按原表述接受** | 构建产物已被忽略，历史文档已有追溯索引；改为独立仓库卫生审计和发布 allowlist |
| 10 | `go.mod` 改名降级 | **接受** | 二进制/API 路径不受模块名阻塞，暂不为此扩大改动 |

## 2. 独立核对结果

在形成回复前，维护者重新核对了当前仓库：

- 本地 `main` 为 `6baac4c`，与 `origin/main` ahead/behind `0/0`；
- `go build ./...` 当前通过；
- [PR #11](https://github.com/houyuwushang/winkyou/pull/11) 当前为 OPEN、MERGEABLE，六项 Linux、Windows 和 Relay 检查成功；
- 自动生日恢复相关计划任务仍为 Disabled，未发现 WinkYou/meshnode 运行进程；
- 当前代码确实只有 session 级 [`ExecutionBudget`](../../pkg/solver/types.go)，它只限制候选数和时间，不限制 socket、PPS、总包数或新五元组；
- [`pkg/solver/types.go`](../../pkg/solver/types.go) 仍直接依赖 `pkg/rendezvous/proto`；
- [`pkg/client.NewEngine`](../../pkg/client/engine.go) 存在两个顶层运行时分支；主动 UDP 探测则至少有 session、mesh shortcut、cached self-bootstrap 三个触发/执行入口；
- 本地物理行统计显示 `pkg/session` 约 4,172 行生产代码、9,749 行含测试，`pkg/solver` 约 5,895 行生产代码、11,624 行含测试。原审查中的行数足以说明复杂度，但不应直接把测试行数换算为重写工时。

以上事实支持审查对结构债务的判断，也要求我们避免把“范围很大”直接推导为“一次性推倒重写”。

## 3. 关于 ResourceGovernor：接受，并把强制边界写得更硬

这是本次审查最重要的意见。原计划只写了“所有 UDP 策略发送经过同一个 governor”，但没有证明新代码无法再次绕过它。

### 3.1 治理对象

v2 将明确区分：

- **主动探索 I/O**：创建新 NAT 映射、STUN/端口行为观测、向尚未验证的候选 endpoint 发包、预测和生日探测；
- **已提交数据路径 I/O**：经过双向验证并 COMMIT 后，由 `PacketTransport` 承载的 WireGuard 数据包。

所有主动探索 I/O 都必须经过统一 governor。已提交数据路径不消耗探测 PPS/目标预算，但仍受独立的路径数、生命周期、keepalive 和故障恢复约束。不能为了实现 governor 而把正常 WireGuard 数据包错误计入生日探测预算。

### 3.2 强制位置

建议的逻辑依赖为：

```text
Node ResourceGovernor
    -> PeerLease
        -> AttemptLease
            -> ProbeSocket / ProbeSend / Promote
```

硬性约束：

1. `BudgetLease` 只能由节点级 governor 创建，并同时扣减节点、节点对和 attempt 三层额度。
2. 策略、恢复控制器、`wink diagnose`、`connect-test` 和外部 API 都不能直接获得用于探测的原始 `*net.UDPConn`。
3. 探测 socket 的创建、目标登记和发送都必须通过 lease 所拥有的受控对象。
4. 配置只能降低额度；发布硬上限不能被配置、plugin 或 API 请求提高。
5. lease 取消、超时、预算耗尽或 safety trip 后，全部子 socket 和发送 worker 必须停止。

接口名称尚可调整，但能力边界应类似：

```go
type AttemptLease interface {
    OpenProbeSocket(ctx context.Context, spec SocketSpec) (ProbeSocket, error)
    RegisterTarget(endpoint Endpoint) error
    SendProbe(ctx context.Context, socket ProbeSocket, endpoint Endpoint, payload []byte) error
    Promote(ctx context.Context, socket ProbeSocket, peer PeerID) (transport.PacketTransport, error)
    Close() error
}
```

`Promote` 是原计划和审查意见都没有完整写出的关键步骤。命中成功后，它必须原子完成：

- 验证 socket、peer、attempt epoch 和远端地址仍匹配；
- 停止并关闭同一 attempt 的其他探测 socket；
- 清除探测阶段遗留的 deadline；
- 将唯一成功 socket 的所有权移交给 `PacketTransport`；
- 释放探测 packet/target 预算，但保留已提交路径的生命周期统计；
- 防止旧 worker 在移交后继续向该 socket 或其他候选发送。

### 3.3 防绕过验证

仅把 `BudgetLease` 加到函数参数还不够，因为未来代码仍可能直接调用 `net.ListenUDP` 或 `UDPConn.WriteTo*`。

Phase 1a 将增加仓库级架构测试或 `go/analysis` 检查：

- 主动探测生产包只能通过一个暂定名为 `internal/probeio` 的包创建和发送 UDP probe；
- 数据面 adapter 的原始 UDP 使用必须在独立白名单中，不能提供探测目标循环；
- `pkg/solver/strategy`、`pkg/bootstrap`、`pkg/meshruntime`、恢复控制器、命令和本地 API 不得直接调用被禁止的 UDP 创建/发送原语；
- 测试 fixture 可以使用 loopback UDP，但必须与生产依赖检查分开；
- CI 对新增绕过入口直接失败。

故障注入还必须证明：`WSAENOBUFS`、连续写错误、取消超时或任一预算突破会停止全部相关发送器并触发持久化 safety trip。

## 4. 关于运行时、solver 与 `pkg/session`

审查指出的“三条执行路径”准确，但它与原计划的“两套运行时”描述并不互斥。修订计划将使用更精确的表述：

> 当前有两个顶层生命周期家族：coordinator/WireGuard engine 与 autonomous userspace engine；其内部至少存在三条相互独立的主动探测触发/执行路径：session strategy、mesh shortcut、cached self-bootstrap/puncher。

“保留连接求解器”也将改为：

> 保留经过验证的抽象、路径评分、策略算法、`PacketTransport` 和相关行为测试；不承诺原样保留与 rendezvous 信封深度耦合的 session 编排。

但我们不接受在设计阶段直接宣布 `pkg/session` “基本重写”。Phase 1a 先做一个受测试保护的抽取/替换切片：

1. 定义与 rendezvous 无关的 canonical connectivity domain model；
2. 在旧 session 外建立适配器，保持现有行为测试可运行；
3. 将一个最小 diagnose/connect-test 流程迁到新编排边界；
4. 用 contract tests 对照旧、新输出和资源记录；
5. 只有无法解耦的部分才逐段替换，不一次删除旧 session。

Phase 1a 的排期会按“编排替换风险”估算，而不是按“solver 全部可直接复用”估算；同时也不会把包含大量测试的物理行数当成必须重写的生产代码量。

## 5. 关于 solver/proto 依赖和重复类型

接受将以下内容列为 Phase 1a 的首批验收项：

- `connectivity` domain 层不能依赖 `rendezvous/proto`；
- `go list -deps`/架构测试必须证明该依赖不存在；
- `Observation`、`ProbeScript`、`ProbeStep`、`Capability` 等核心概念在 domain 层只有一个权威定义；
- session/rendezvous/local API 只能通过 adapter 与 domain 层交互。

我们对“不得再定义平行结构”作一处修正：版本化 wire DTO 与 domain model 可以是不同类型。直接拿 domain struct 当网络协议 schema，会把内部重构变成协议破坏。

允许的边界是：

```text
versioned wire DTO <-> explicit adapter <-> canonical domain model
```

每个 adapter 必须有 round-trip、未知字段、版本兼容和 golden tests。禁止的是三份彼此手工同步、又没有明确协议边界的“准 domain model”。

## 6. 关于 alpha 身份模型：采用单写者 roster，但修正邀请流程

接受审查者对微型 PKI 过度设计的批评。v2 alpha 不实现委托邀请链、下放 revoke 权或多写者分区合并。

### 6.1 Alpha 权威模型

- 一个离线 Mesh root 是唯一 roster writer；
- 每个节点仍拥有独立 Ed25519 身份，`NodeID` 从公钥派生；
- WireGuard key 与节点身份分离，由节点身份签署绑定；
- roster 带 `mesh_id`、单调 `version`、root key ID、成员 NodeID、WG binding 摘要和能力位；
- alpha 能力位只保留 `control_transit`、`data_transit` 及必要的服务访问预留，不下放 `invite`/`revoke`；
- 节点持久化已接受的最高版本和摘要，拒绝回滚与同版本不同内容。

### 6.2 加入流程

原审查建议中的“根预签一次性加入凭证”若用于未知目标，会重新引入 bearer invitation 和授权链；若目标身份已知，则根可以直接签新版 roster，不需要另建一套凭证体系。

alpha 采用以下闭合流程：

1. 新设备本地生成身份密钥，并导出只含 MeshID、NodeID、公钥、nonce 和能力请求的 join request；
2. 操作员通过离线/带外方式把 join request 交给 root 管理工具；
3. root 管理工具显示指纹和权限变化，操作员确认后签发 roster `N+1`；
4. 返回 bundle 包含 root 公钥、完整签名 roster、必要 bootstrap anchors 和该目标身份；
5. 新旧节点通过认证通道传播同一份 roster；版本更高且 root 签名有效者胜。

这意味着 alpha 每次加入或撤销都需要 root 管理动作。对 2–20 台自有设备，这是可接受的安全/复杂度交换。以后若真实采用证明此流程阻碍使用，再通过 v2.1 独立 ADR 讨论在线 administrator key、委托 invite 和 delegated revoke。

### 6.3 撤销与剩余问题

撤销由 root 签发删除目标成员的 roster `N+1`。旧成员不能使用旧 roster 降级已经见过新版本的节点。

正式实现前仍需单独决定：

- 新设备如何确认收到的是最新 roster，而不是攻击者提供的历史快照；
- root 丢失、备份和轮换流程；
- roster 是否设置有效期，以及离线 root 场景下如何避免集体过期；
- 分区节点长期未收到撤销时的风险披露。

这些问题必须在 Phase 2 mini-ADR 中解决，但不需要把 delegated PKI 拉回 alpha。

## 7. 关于外部接入：二进制优先，明确采用进程外协议

接受维护者已澄清的 GitHub 二进制优先分发模型，也接受“不以 Go import 作为主要外部接入面”。

但“plugin”必须定义清楚。WinkYou 的目标平台包含 Windows，而 Go 动态 plugin 具有平台、工具链一致性、race 检测和进程内崩溃隔离问题。因此：

- v2 alpha 不提供 Go `buildmode=plugin` 动态加载；
- “solver plugin”专指外部进程适配器；
- Phase 1 首选版本化 JSON-RPC over stdio，由调用方启动 `wink solver serve --stdio`；
- 因为 stdio 不监听网络，它比 localhost 服务更容易建立最小安全边界；
- 若未来需要共享 daemon，再分别评估 Windows Named Pipe 与 Unix domain socket，使用 OS ACL、peer credentials/能力令牌，默认不监听 LAN。

初始 API 只提供高层动作：

```text
handshake
diagnose
connect_test
cancel
status
export_redacted_report
```

它不提供任意 `open_socket`、`send_packet`、批量 IP/端口扫描或提高预算的接口。`connect_test` 必须绑定一个有期限的 peer/attempt 上下文，所有 API 调用仍通过同一个节点 governor。

协议验收至少包括：

- schema/version handshake；
- 请求大小、并发、deadline 和速率限制；
- 取消传播与进程退出；
- 默认脱敏和显式报告导出；
- 不兼容版本的可解释拒绝；
- Python/Node/Rust 中至少一个最小跨语言调用示例；
- 外部调用无法突破 socket、target、PPS、packet、five-tuple 硬上限。

Go 包仍要保持干净的内部边界，但不在 v2 alpha 对外承诺稳定 import API，根模块改名也不阻塞 Phase 1。

## 8. 关于 alpha 范围和阶段

### 8.1 具名服务

接受拆分，不再让具名 TCP/UDP 服务阻塞首个 L3 alpha：

- **Phase 3a**：统一 Node Runtime、L3 overlay、地址/路由冲突处理、直连/Relay 状态和 v2 配置；
- **Phase 3b**：具名 TCP/UDP 服务、服务签名与 ACL，作为独立实验增量；
- 第一批外部 L3 用户可以使用虚拟 IP + 端口，并由文档说明宿主防火墙边界；
- Phase 3b 是否仍属于同一 alpha，由 Phase 3a 的用户反馈决定。

具名服务仍是潜在产品体验，不被永久删除；只是不能与统一运行时、身份、L3 和恢复控制器同时成为一个退出门槛。

### 8.2 Phase 1a：构建期（参考 6–8 周）

交付和退出门槛只包含维护者可控制的工程证据：

- 不可绕过的 governor/probe I/O；
- canonical domain model 与 proto 解耦；
- `wink diagnose`、`connect-test` 和版本化 stdio API；
- NAT 模拟矩阵与受支持场景连续 100 次通过；
- 故障注入证明硬上限、取消和 safety trip；
- 一个跨语言 API 示例和可检查的脱敏报告。

### 8.3 Phase 1b：证据期（至少 4 周）

招募可在 Phase 1a 后半段开始，但证据窗口独立计算：

- 至少 10 位外部测试者实际运行；
- 至少 5 个独立部署在两周后仍使用；
- 至少一个外部 plugin/API 集成或已验证的集成意向；
- 收集直连成功率、失败分类、p50/p95 和资源消耗；
- 默认遥测仍关闭，只接收用户主动提交的脱敏报告。

完整 v2 的继续决策发生在 Phase 1b 后。未达门槛不否定 Phase 1a 的技术成果，但必须先复盘定位、安装和分发，不能通过降低门槛自动进入 Phase 2/3。

## 9. 关于 PR #11 和 Phase 0 顺序

接受审查者对风险优先级的判断，并把顺序修改为：

1. 继续进行 RFC 复审，但保持状态为 Draft；
2. 独立完成 PR #11 的代码审查并合入 fail-closed 门禁；
3. PR #11 合入并确认发布入口拒绝相关配置后，RFC 才可以被标记为 Accepted；
4. 在此之前不开始任何新的联网实现、现场验证或 birthday 恢复工作。

PR #11 的作用是封闭当前受支持产品入口，不代表底层实现已经安全，也不替代 governor。低层 birthday/selfhosted 代码仍只能用于被允许的离线、loopback 或隔离测试。

此外，只要旧 remote coordinator 仍可能作为公开路径，[Issue #12](https://github.com/houyuwushang/winkyou/issues/12) 的 TLS、节点认证、授权和撤销就是独立的 Phase 0 阻塞项；WireGuard 数据面不能替代控制面安全。

## 10. 关于仓库卫生

接受“外部测试前需要良好第一印象”的目标，但修正事实和动作：

- `*.exe`、`*.test`、`/.live-run/`、`/.stability-run/` 已经在 [`.gitignore`](../../.gitignore) 中；它们是本地 ignored artifacts，不会自动出现在 GitHub 仓库；
- 根目录历史文档当前由 [`docs/README.md`](../README.md) 明确标为 archive/brainstorm，并保留追溯链接；
- 批量移动或删除会制造大范围链接变化，不能作为“低成本顺手清理”。

Phase 0 改为一个独立的仓库卫生审计：

- 对 Git tracked 文件做公开性、现行性和导航审查；
- 确需移动的历史文档放入单独 docs PR，保留 Git 历史并修复全部链接；
- release workflow 使用文件 allowlist，不从脏工作区打包；
- CI/发布前扫描二进制、运行状态、日志、私有拓扑和凭据；
- 不以删除历史证据换取表面整洁。

## 11. 关于 direct/Relay 默认值

审查支持保留 `direct: required`、`relay: disabled`，我们暂时维持这一 v2 产品决定，但补充一条事实边界：这不是代码审查能够证明的结论，而是需要外部证据验证的产品假设。

需要区分：

- 当前 v0.1 baseline 仍把 Relay 视为合法 solved path，并以安全可用性为先；
- v2 proposal 的差异化入口是 direct-first，默认不让用户在不知情时经过数据 Relay；
- 选择 `direct: preferred` + `relay: fallback` 的用户仍可获得明确标记的降级可用性；
- Phase 1b 必须记录多少用户因 direct-required 无法完成首次连接，以及这是否伤害两周留存；
- 若证据反对当前默认值，应通过显式产品决议重开，而不是为维护原文而忽略数据。

## 12. 拟写入原计划的修订

若本回复经复审认可，原计划将进行以下实质修改：

1. 写入 probe I/O 强制边界、三层 budget lease、`Promote` 所有权移交和静态防绕过检查；
2. 将“两套运行时”扩写为“两个生命周期家族 + 三条主动探测入口”；
3. 把“保留求解器”改为保留抽象/算法/测试，渐进替换 session 编排；
4. 把 proto 解耦和 canonical domain model 列为 Phase 1a 第一验收项；
5. 把 alpha 身份模型裁剪为单写者 root-signed roster，并采用目标身份先生成的 join request 流程；
6. 把 Go 公共库承诺改为版本化进程外 stdio API，禁止动态 Go plugin 和任意发包 API；
7. 把 Phase 1 拆成 1a 构建期和 1b 证据期；
8. 把 Phase 3 拆成 3a L3 alpha 与 3b 具名服务；
9. 把 PR #11 设为 RFC Accepted 前置门禁，同时保留控制面安全 Issue #12；
10. 把仓库卫生改为独立审计/PR，不重复添加已有 ignore，也不无审查删除历史文档；
11. 将 direct/Relay 默认值明确标为 Phase 1b 需要验证的产品假设；
12. 保持生日策略默认禁用、automatic 配置拒绝、cached self-bootstrap/autonomous recovery NO-GO 不变。

## 13. 请求审查者继续确认的问题

请重点复审以下五点，而不必重新重复已经接受的方向：

1. `AttemptLease + ProbeSocket + Promote(PacketTransport)` 是否足以封闭探测 socket 的整个生命周期？还缺少哪一种可绕过路径？
2. 单写者 root-signed roster 的 join request 流程是否已经闭合？新设备的 roster freshness 应采用什么最小机制？
3. JSON-RPC over stdio 是否适合作为 Phase 1 的跨语言接入面？是否应进一步缩小方法集合？
4. Phase 3a 只交付 L3、Phase 3b 再做具名服务，是否足以消除 alpha 范围风险？
5. “PR #11 合入前 RFC 只保持 Draft，但讨论可并行”是否满足 P0 风险处置要求？

## 14. 不变的安全边界

无论本回复是否通过复审，以下状态不变：

- 当前 baseline 仍是实现权威；
- cached self-bootstrap 和 autonomous birthday recovery 继续为 NO-GO；
- 不批准家庭、办公、生产或共享公网的生日打洞测试；
- 不批准启动计划任务、daemon、恢复循环或远程部署；
- 自动恢复未来仍需隔离网络、硬资源上限、socket reuse、退避、节点级 single-flight、circuit breaker、独立 kill switch、故障注入、进程外观测、第二人审查和对命名环境的明确授权。

本次回复只推进设计审查，不扩大任何运行权限。
