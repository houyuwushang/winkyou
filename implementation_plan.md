# WinkYou 项目深度审查

> **审查基础**: 112 个 Go 源文件 (615KB), 30 个测试包全部通过, 30 次 commit 历史, 13 份架构文档
>
> **审查日期**: 2026-05-25

---

## 一、项目全貌

### 你在做什么

WinkYou 是一个 **P2P 虚拟局域网**，核心公式：

```
WinkYou = connectivity solver + WireGuard 数据平面
```

当前可运行路径：
- ICE/UDP 打洞 (via `pion/ice`) → `PacketTransport` → userspace `wireguard-go` → TUN/Wintun
- relay 模式通过 coturn TURN 中继
- `signal_relay` 可通过 coordinator signal stream 承载已加密 WireGuard packet，作为 direct/TCP/TURN 暂不可用时的低吞吐保活 fallback
- 协调服务器 (gRPC) 做节点发现、信令交换

### 当前阶段

| 阶段 | 状态 | 标签 |
|------|------|------|
| Phase 1 ~ 2D | ✅ 冻结 | `phase2d-freeze-2026-04-24` |
| Phase 3A (Strategy Portfolio Foundation) | ✅ 合并 | session portfolio resolver |
| Phase 3B code health | ✅ 完成 | CI、session 拆分、state validation、context 边界 |
| Phase 4A relay_only | ✅ 冻结 | `make test-phase4a` |
| Connectivity policy / fallback / scoring | ✅ 完成 | `auto` / `relay_only`、ordered fallback、observation ordering |
| `tcp_framed` alpha | ✅ 完成 | 显式 TCP PacketTransport 验证 |
| `signal_relay` coordinator fallback | 🟡 现场验证中 | 已能绑定并保留 path；依赖 coordinator，不是无 coordinator bootstrap |
| v0.1 运维闭环 | 🟡 进行中 | self-host quickstart、doctor、long-running workflow、release pipeline、控制面韧性补强 |
| v0.1 freeze gate | ✅ 已定义 | `docs/V0.1-FREEZE.md` |

2026-06-06 现场结论：
- local-live 与 inner-live 已能通过 `signal_relay` 绑定，`wink peers` 显示 `Path Strat: signal_relay`、`Path Plan: signalrelay/coordinator_signal`、`Path Deps: coordinator:...:coordinator_signal_stream`。
- `signal_relay` ready 信号需要在等待窗口内重发；一次性 ready 会在两端 session 启动错位时丢失，导致双方都 `remote ready timeout`。
- 后台 `tcp_framed` / `legacy_ice_udp` protected-direct improvement 失败时，不应清空已绑定的 `signal_relay` path；当前代码已增加保护。
- `tcp_framed` 现场验证暴露了外部 overlay 的边界：本机能访问 inner-gw 的 `10.6.22.1:22`，但 inner-gw 临时监听的随机 TCP 端口收不到本机连接，且 natpierce 抓包显示 SSH 来源是 `10.6.22.4` 而不是本机 `10.6.22.3`。因此 `tcp_framed` 后续应按“固定可达 TCP endpoint”验证，使用 `tcp_framed.role` / `tcp_framed.dial_addr` 固定监听/拨号方向，不能把随机端口失败解释为代码已经证明物理不可达。
- 断开 chen-win/coordinator/natpierce 这一整条 underlay 后，`signal_relay` 也会断，因为它明确依赖 coordinator signal stream。只有已经存在另一条不依赖该 underlay 的 bound `PacketTransport` 时，才可能维持会话。
- Windows Wintun 仍有独立待办：in-band `33435` 和 tunnel 计数可持续读写，但外部 `wink ping` / PowerShell UDP 到 `10.88.0.8:33434` 可能增加 `wink0` `OutboundDiscardedPackets`，却不进入 wink 的 TUN read，也不会出现在 inner-gw `tcpdump -i wink0`。已新增默认关闭的 `WINKYOU_TRACE_TUN_PACKETS=1` 用于区分 OS/Wintun ingress 问题和 solver/transport 问题。

Phase 3A 已交付：`PortfolioResolver`、`StrategyEntry`、strategy selection 测试覆盖、fake strategy 验证。session 不再硬编码 `legacy_ice_udp`。

### 代码规模

| 指标 | 数值 |
|------|------|
| Go 源文件 | 160 个 |
| 源码体积 | 约 845 KB |
| 核心包数量 | 14 个 (`pkg/*`) |
| 测试包 | 33 个（当前 `go test ./... -count=1` 通过） |
| 最大单文件 | `pkg/client/engine.go` |
| 根目录二进制跟踪 | 当前未跟踪 `wink.exe` / `netprobe.exe` / `e2e.test` |

---

## 二、架构上做对的事情

先说清楚哪些设计决策是正确的，以免改进时拆掉好的东西：

### ✅ 1. PacketTransport 抽象设计精准

[transport.go](file:///d:/workspace/winkyou/pkg/transport/transport.go) — 只有 21 行，却定义了系统最关键的边界。`ReadPacket/WritePacket` 的 packet-oriented 设计让 tunnel 层不关心底层是 UDP、TURN relay 还是 QUIC datagram。未来加 TCP framed stream、WebSocket 等传输路径时，tunnel 层**零修改**。这是 Tailscale 做不到的事（它的 DERP 和 WireGuard 绑定太深）。

### ✅ 2. Solver/Strategy 分层清晰

solver core（[types.go](file:///d:/workspace/winkyou/pkg/solver/types.go)）不知道 ICE、TURN、STUN 的存在。`Strategy` → `Plan` → `Execute` → `Result` 的流水线抽象正确。`PlanRefiner`、`PlanRanker`、`ProbePlanner` 作为可选接口(optional interface pattern) 而非必须实现——这比硬塞一个大接口要好。

### ✅ 3. Evidence-driven planning 有实际落地

Phase 2D 不是纸面设计。`SolveInput` 包含 `LocalObservations`、`RemoteObservations`、`LastProbeResult`，strategy 的 `Plan()` 和 `RefinePlans()` 真正消费这些数据。relay evidence 可以剪枝 `direct_prefer` plan——这在实际网络环境下会减少无意义的打洞等待。

### ✅ 4. Phase freeze 纪律

每个 phase 都有冻结 tag，有明确的 exit criteria 和 regression gate (`make test-phase2d`)。这在个人项目中很少见，说明你对架构演进有控制力。

### ✅ 5. Binder 模式解耦了 session 和 tunnel

[binder.go](file:///d:/workspace/winkyou/pkg/session/binder.go) — session 只调 `Binder.Bind(peerID, transport)`，不碰 WireGuard IPC 细节。这意味着将来换数据平面（比如你在 brainstorm.md 里设想的 Wink Protocol v1）时，只需要换 binder 实现。

### ✅ 6. peerTransportBind 是技术含量最高的组件

[tunnel_wggo.go](file:///d:/workspace/winkyou/pkg/tunnel/tunnel_wggo.go) 里的 `peerTransportBind` 是整个项目最精巧的部分。它同时实现 `wgconn.Bind` 接口和 per-peer `PacketTransport` 路由，让 wireguard-go 认为它在跟 UDP socket 通信，实际上数据走的是 ICE transport。rebind cycle 管理、transport stats 收集、endpoint 热更新都在这一层干净地解决。

### ✅ 7. PortfolioResolver 正确实现了 Phase 3A

[strategy_portfolio.go](file:///d:/workspace/winkyou/pkg/session/strategy_portfolio.go) — 92 行代码完成了 strategy registration、name 验证、mutual capability intersection、registration-order selection。测试覆盖了 nil strategy、duplicate name、name mismatch、no mutual strategy 等边界情况。

---

## 三、问题清单

### S0 — 必须立即处理

#### 已澄清 1: 根目录二进制当前未被 Git 跟踪（不再列为 S0）

**位置**: 仓库根目录  
**文件**: `wink.exe` (22.7MB) + `netprobe.exe` (3.4MB) + `e2e.test` (23.1MB)

当前 `git ls-files wink.exe netprobe.exe e2e.test` 无输出，说明这三个根目录二进制不在当前 tree 中被跟踪。不要再把它列为当前 S0 清理项。

**后续原则**:
1. 若未来再次出现，先用 `git ls-files` 确认是否被跟踪。
2. 只在确认当前 tree 跟踪这些文件时做 `git rm --cached`。
3. 不要为这个判断自动 rewrite history；历史清理必须单独决策。

---

#### 已处理 2: `session.go` 巨型文件已机械拆分

**当前状态**: `pkg/session` 已拆分为 lifecycle/selection/planning/probe/observation/envelope/helpers 等职责文件，`session.go` 只保留 `Session` 结构、构造和简单访问器。

**位置**: [session.go](file:///d:/workspace/winkyou/pkg/session/session.go)

这个文件承担了：
- Session 生命周期管理（Start/Close/transition）
- Capability 交换（send/wait/set）
- Strategy 选择（selectStrategy）
- Plan 生成/剪枝/排序（refinePlans/rankPlans）
- 候选执行循环（executeCandidateLoop/executeCandidate/executePlan）
- Probe 编排（runStrategyPreflightProbe/sendProbeScript/handleProbeScript/runProbeScript）
- Observation 报告（reportObservation/emitObservation/recordRemoteObservation）
- 消息路由（HandleMessage/handleEnvelopeMessage）
- 50+ 个工具函数（clone*/normalize*/parseIntParam/addrString/...）

**问题本质**: 不是"文件太长"的审美问题，而是 **单一文件内的关注点交叉导致修改影响范围无法预判**。改 probe 逻辑时可能不小心影响 capability 等待，因为它们共享 `metaMu` 锁和 `Session` struct 的内部状态。

**建议拆分**:
```
session/
├── session.go          (~300 行) lifecycle + Start/Close + transition
├── capability.go       (~100 行) send/wait/set capability
├── selection.go        (~50 行)  selectStrategy
├── planning.go         (~200 行) Plan/Refine/Rank/execute candidate loop
├── probe.go            (~250 行) preflight probe orchestration
├── observation.go      (~150 行) report/emit/record observations
├── envelope.go         (~200 行) message handling + marshal/unmarshal
├── helpers.go          (~200 行) clone/normalize/parse utilities
```

> [!IMPORTANT]
> 拆分时不要改接口，只移动代码。所有函数仍然是 `*Session` 的方法，只是分散到不同文件里。Go 允许同一个 package 内多个文件定义同一个 type 的方法。

---

### S1 — 严重但不紧急

#### 已处理 3: 状态机已加入合法转换验证

**当前状态**: `pkg/session/state_machine.go` 已包含合法转换表，非法转换会返回错误并通过 session error hook 可观测。

**位置**: [state_machine.go](file:///d:/workspace/winkyou/pkg/session/state_machine.go) — **只有 25 行**

```go
func (m *StateMachine) Transition(next State) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.state = next  // 任意状态 → 任意状态，无验证
}
```

当前可以从 `StateBound` 跳到 `StateNew`，从 `StateClosed` 跳到 `StateExecuting`。虽然在正常流程中调用顺序是正确的，但**没有防御性验证意味着 bug 不会被及早发现**——它会表现为一个远端 peer 连接莫名失败，而不是一个清晰的 "invalid state transition" panic。

**建议**: 添加合法转换表：
```go
var validTransitions = map[State][]State{
    StateNew:                {StateCapabilityExchange, StateFailed, StateClosed},
    StateCapabilityExchange: {StateProbing, StateSelecting, StateFailed, StateClosed},
    StateProbing:            {StatePlanning, StateFailed, StateClosed},
    StateSelecting:          {StatePlanning, StateFailed, StateClosed},
    StatePlanning:           {StateExecuting, StateFailed, StateClosed},
    StateExecuting:          {StateBinding, StateFailed, StateClosed},
    StateBinding:            {StateBound, StateFailed, StateClosed},
    StateBound:              {StateFailed, StateClosed},
    StateFailed:             {StateClosed},
}
```

---

#### 已处理 4: UDP address helper 已提取到公共包

**当前状态**: `pkg/netutil/addr.go` 提供 `UDPAddrFromAddr` 和 `CloneUDPAddr`，session/client 相关重复实现已替换。

**位置**:
- [session/binder.go L73-100](file:///d:/workspace/winkyou/pkg/session/binder.go#L73-L100): `udpAddrFromAddr()` + `cloneUDPAddr()`
- [client/peer_session.go L348-368](file:///d:/workspace/winkyou/pkg/client/peer_session.go#L348-L368): `udpAddrFromAddr()` — 完全相同的代码
- [client/engine.go L653-662](file:///d:/workspace/winkyou/pkg/client/engine.go#L653-L662): `cloneUDPAddr()` — 完全相同的代码

三处实现完全一致。如果将来修一个 bug（比如 IPv6 zone 处理），只修一处就会留下隐患。

**建议**: 提取到公共包，比如 `pkg/netutil/addr.go`。

---

#### 已处理 5: session 正常路径已改用有界 context

**当前状态**: Bind、path commit、observation、probe script/result 发送使用传入 context 或 session run context，并加短超时；cleanup 路径使用独立有界 cleanup context。

**位置**: [session.go](file:///d:/workspace/winkyou/pkg/session/session.go) 多处

```go
// L227: 在有 ctx 的 selectAndExecute 内部
s.emitObservation(context.Background(), ...)

// L337: 在 Bind 时
s.cfg.Binder.Bind(context.Background(), ...)

// L355: 在 sendPathCommit 时  
s.sendPathCommit(context.Background(), ...)

// L577: 在 Close 中
s.cfg.Binder.Unbind(context.Background(), ...)
```

当 session 被 cancel 时，这些 `context.Background()` 操作不会被取消。对于 `Unbind` 和 `Close` 中的清理逻辑，使用 `context.Background()` 是**刻意的**（清理不应被取消）。但 `Bind` 和 `sendPathCommit` 使用 `context.Background()` 就有问题——如果 coordinator 挂了，`Send` 会永远阻塞。

**建议**: 
- 清理路径（Close/Unbind）: 保持 `context.Background()` ✅
- 正常路径（Bind/sendPathCommit/emitObservation）: 使用 `s.runContext()` 或传入的 `ctx`，加合理超时

---

#### 已处理 6: 生产 resolver 已收敛到 session portfolio resolver

**当前状态**: `pkg/session` 提供 factory-based portfolio resolver；client 只组装 strategy factory entries，保留 lazy factory、implicit legacy fallback 和 production 注册顺序。

**位置**:
- [client/strategy_factory.go](file:///d:/workspace/winkyou/pkg/client/strategy_factory.go): `strategyResolver` struct
- [session/strategy_portfolio.go](file:///d:/workspace/winkyou/pkg/session/strategy_portfolio.go): `PortfolioResolver` struct

两个 struct 都实现了 `session.StrategyResolver` 接口，都做 capability intersection，都按注册顺序选择 strategy。区别在于：
- `strategyResolver` 有 lazy build（`func() solver.Strategy`工厂）和 compatibility fallback policy
- `PortfolioResolver` 直接持有 `solver.Strategy` 实例，无 fallback

`engine.newStrategyResolver()` 实际上用的是 `strategyResolver`，`PortfolioResolver` 只在 Phase 3A 测试中使用。这造成了困惑：**生产路径和测试路径用的是不同的 resolver 实现**。

**建议**: 
1. 确认 `PortfolioResolver` 是 Phase 3A 的测试基础设施还是未来的生产 resolver
2. 如果它是未来方向，就让 `engine` 逐步迁移到 `PortfolioResolver`
3. 如果只是测试用，在文档和命名中明确标注

---

### S2 — 中等

#### 已处理 7: Observation 截断已避免长期保留旧底层数组

**当前状态**: session observation history 和 `ObservationStore` 在超过 limit 时复制保留尾部到新 slice，不再通过简单切片长期持有旧数组。

**位置**: [session.go L989-995](file:///d:/workspace/winkyou/pkg/session/session.go#L989-L995)

```go
func appendObservation(list []solver.Observation, obs solver.Observation, limit int) []solver.Observation {
    list = append(list, obs)
    if limit > 0 && len(list) > limit {
        list = list[len(list)-limit:]  // 截断前面的元素
    }
    return list
}
```

当 `len(list)` 从 100 增长到 101 时，`list[1:]` 创建新的 slice header 但底层数组不释放（因为 list[0] 还被引用）。高频场景下会造成 **内存泄漏假象**——内存不增长但 GC 无法回收旧元素。

**建议**: 使用定长环形缓冲 `[100]solver.Observation` + write index。

---

#### 已处理 8: CI 已补基础质量门

**当前状态**: Makefile 和 Linux CI 已加入 `go vet ./...` 与核心包 race test gate；未引入新的 golangci-lint 框架。

**位置**: [ci.yml](file:///d:/workspace/winkyou/.github/workflows/ci.yml)

CI 只跑 `go test ./...`，没有：
- `go vet ./...`
- `golangci-lint run`（Makefile 里提到了 golangci-lint 但 CI 没用）
- race detector（`-race` flag）

**建议**: 至少加 `go vet ./...` 和 `go test -race ./... -short`。

---

#### 已处理 9: probe result 已增加 latest-result 缓存

**当前状态**: `handleProbeResult` 会按 script type 保存 latest result；`runStrategyPreflightProbe` 等待前和等待期间都会检查缓存，channel 满导致的非阻塞发送丢信号不再丢失最新结果。

**位置**: [session.go L95](file:///d:/workspace/winkyou/pkg/session/session.go#L95)

```go
probeResultCh: make(chan probeResultSignal, 8),
```

`handleProbeResult` 往 channel 发信号时用了非阻塞写：
```go
select {
case s.probeResultCh <- probeResultSignal{...}:
default:  // 满了就丢弃
}
```

如果 probe 结果在 `runStrategyPreflightProbe` 还没开始监听之前到达，信号会被丢弃。当前 preflight probe 的设计假设 probe result 总是在 script 发送之后到达，但在**高延迟重排序**场景下可能破裂。

**影响**: 非致命——probe 超时后继续，但无法利用已到达的 probe 结果优化 plan ordering。

---

#### 已处理 10: 关键 cleanup/report 忽略错误已有可观测性

**当前状态**: session observation 发送失败会进入 error hook，session cleanup 超时/取消可观测；client engine/peer session 的 cleanup close/remove/load 失败会记录 debug 日志。剩余 `_ =` 主要在测试、生成代码或明确忽略的 deadline/parse 场景。

全局搜索 `_ =` 在 session.go 和 engine.go 中有约 15 处。其中多数是清理路径上的 `Close()` 返回值（可接受），但有几处值得注意：

- [session.go L330](file:///d:/workspace/winkyou/pkg/session/session.go#L330): `_ = outcomes[i].Result.Transport.Close()` — 如果 close 失败（比如底层 fd 已被另一个 goroutine 关闭），这里不会有任何日志
- [session.go L986](file:///d:/workspace/winkyou/pkg/session/session.go#L986): `_ = s.reportObservation(ctx, obs)` — observation 发送失败被完全静默

**建议**: 至少 log.Debug 级别记录 close 错误。

---

### S3 — 轻微 / 改善

#### 已处理 11: `firstNonEmpty()` session dead helper 已删除

**位置**: [session.go L1466-1473](file:///d:/workspace/winkyou/pkg/session/session.go#L1466-L1473)

Dead code。应删除或加 `//nolint:unused` 注释说明保留原因。

#### 已处理 12: `Session.Start(nil)` 已返回错误

```go
func (s *Session) Start(ctx context.Context) error {
    if ctx == nil {
        return fmt.Errorf("session: nil context")
    }
```

Go 的惯例是 `context.Context` 参数永远不为 nil（参见 [context package doc](https://pkg.go.dev/context)）。防御性处理 nil ctx 会掩盖调用方的 bug。

#### 已处理 13: `winkplan.md` 已标记 Deprecated / Archive

`winkplan.md` 描述的目录结构（`pkg/node/`, `platform/`, `internal/`）、协议设计（`messages.proto`）、功能规划（TAP、MagicDNS、SOCKS5 proxy）与实际代码对应不上。这是早期的 brainstorm 文档；现在已在文件顶部和文档索引中标注为过时归档材料。

**当前状态**: `winkplan.md` 顶部已声明其为早期长期规划文档，并指向 `docs/CONNECTIVITY-SOLVER-BASELINE.md` 作为当前架构权威。

#### 已处理 14: 多份架构/brainstorm 文档已明确定位

仓库里有：
- `docs/ARCHITECTURE.md` (1.8KB)
- `docs/ARCHITECTURE-DEEP-ANALYSIS.md` (17.8KB)
- `docs/ARCHITECTURE-IMPROVEMENT-INDEX.md` (8.9KB)
- `docs/ARCHITECTURE-RISK-REGISTER.md` (12.4KB)
- `docs/ARCHITECTURE-ROADMAP.md` (12.3KB)
- `brainstorm.md` (20.8KB)
- `winkplan.md` (42.6KB)
- `selfdev.md` (30.2KB)
- `manage.md` (27.0KB)
- `guess.md` (15.9KB)
- `question.md` (10.9KB)
- `protocol.md` (15.9KB)
- `wink-protocol-v1.md` (28.9KB)
- `codex_summary.md` (9.9KB)
- `selfhost.md` (19.8KB)

超过 **270KB** 的 markdown 文档，但只有 `docs/CONNECTIVITY-SOLVER-BASELINE.md` 是真正的架构权威。其余文档之间有矛盾、有重叠、有过时内容。

**当前状态**: `docs/ARCHITECTURE-*`、`docs/improvements/*` 和根目录 brainstorm/proposal 文档均已加 Proposal/Archive/Brainstorm 标记；`docs/README.md` 已明确 Active baseline、Current roadmap、Proposals、Archive/Brainstorm 分级。当前选择保留原路径，避免破坏既有相对链接。

#### 已处理 15: NAT 超时配置已暴露到 config（不再列为硬编码问题）

**位置**:
- [config/config.go](file:///d:/workspace/winkyou/pkg/config/config.go)
- [client/nat_timeouts.go](file:///d:/workspace/winkyou/pkg/client/nat_timeouts.go)

ICE gather/connect/check timeout 已通过 `config.NATConfig` 暴露，并由 `client/nat_timeouts.go` 从 `e.cfg.NAT` 读取；默认值在 config defaults/validator 中维护。

**后续原则**: 如需调整高延迟网络行为，修改配置默认值或文档示例，不再把它作为“硬编码在 client 包内部”的架构缺陷。

---

## 四、下一步开发路线建议

Phase 3A (Strategy Portfolio Foundation) 已完成。以下是我基于代码现实给出的路线：

### Phase 3B: Code Health Sprint（已完成）

> **原则**: 不加功能，只还技术债

| 任务 | 状态 |
|------|------|
| 根目录二进制当前 tree 跟踪检查 | ✅ 当前未跟踪 |
| 拆分 session.go 为职责文件 | ✅ 完成 |
| 状态机添加转换验证 | ✅ 完成 |
| 提取 `cloneUDPAddr`/`udpAddrFromAddr` 到公共包 | ✅ 完成 |
| CI 加 vet + race detector | ✅ 完成 |
| 清理过时文档（加 deprecation notice） | ✅ 完成 |
| 修复 context.Background() 误用 | ✅ 完成 |

### Phase 4A: Second Strategy Skeleton（已完成）

> **目标**: 添加第一个 非 ICE/UDP 策略的骨架，证明 solver 的 multi-strategy 能力在运行时工作

已选择并实现 **`relay_only` 策略**。production resolver 注册顺序保持：

1. `legacy_ice_udp`
2. `relay_only`

旧 peer 空 capability 仍 fallback 到 `legacy_ice_udp`；远端只 advertise `relay_only` 时可选择 `relay_only`。

### Phase 4B: Ordered Fallback + Observation Strategy Ordering（已完成）

当前 session 支持 ordered strategy fallback；production resolver 可以根据 connectivity policy 产出有序候选。`auto` 模式下 scoped observation 会影响 strategy order，但不会直接删除可用 strategy。

### Phase 4C: Non-UDP PacketTransport Alpha（已完成）

`tcp_framed` 已作为 alpha strategy 加入，用显式可达 TCP 地址和 `transport/framedstream` 证明非 UDP path 仍能输出 `PacketTransport`。该 strategy 默认禁用，不承诺 NAT TCP 打洞。

### v0.1 Operations Track（进行中）

已完成 self-host quickstart、`wink doctor` 分层诊断、`wink logs`、长期运行客户端文档、release workflow 和 v0.1 freeze gate。下一步应按 freeze gate 做真实部署验证，而不是继续扩大架构范围。

### v0.1 Hardening: Control Plane Resilience（新增 TODO）

2026-06-04 真实双节点验证证明：本机 Windows 节点与 `inner-gw` Linux 节点可以通过 `legacy_ice_udp` direct path 建立 `10.88.0.0/24` 虚拟局域网，且两端未配置 TURN relay，双向 ping 成功。

同时暴露了两个必须记录的限制：

1. coordinator 部署在 `chen-win` 时，断开本机到 `chen-win` 的 natpierce 后，连接也会断。这里不能把两个 `10.6.22.1` 当成同一个直接可达节点：本机侧的 `10.6.22.1` 是 natpierce 虚拟网关，`inner-gw` 位于 `chen-win` 另一侧虚拟网内。断开 natpierce 同时会影响 coordinator、跳板和可能的 underlay candidate，不是纯 coordinator outage 测试。根因方向仍是控制面持续依赖 coordinator，以及 client 对 peer offline/control-plane loss 的处理可能拆掉已 bound 的 tunnel peer。
2. 当前 direct candidate 可能使用 Tailscale/peer-reflexive 地址或 Docker bridge host 地址。这证明没有走 `chen-win` TURN relay，但不能证明完全不借助已有 overlay。

当前已完成多层基础补强：

- peer offline update 到达时，如果本地 peer 仍有最近 WireGuard handshake、packet counters 且没有 transport error，client 不再立即 `cleanupPeer`。
- controlled side peer session 已允许主动启动和 retry，避免高 node id 一侧在远端 stale session 或远端未重新发起时长期停在 `data_state=connecting/failed`。
- runtime/peer status 已新增 `control_state`、`data_state` 和最近成功 path cache 字段，`wink peers` 文本输出和 JSON 输出都能展示这些状态。
- 已建立数据面后的 in-band peer control 消息模型已加入 `pkg/peercontrol`，覆盖 heartbeat、path health、endpoint update、capability refresh 和 re-ICE request 的校验与 JSON 编解码。
- NAT/ICE 已新增 candidate interface include/exclude 和 candidate CIDR include/exclude 配置，并传入 Pion ICE agent；`wink doctor` 会展示过滤配置并检查 runtime candidate 是否命中 excluded CIDR。
- coordinator client 已新增 heartbeat NotFound 恢复路径：当 coordinator 重启或持久化 store 恢复后发现当前 node 不存在时，client 会关闭旧 signal stream 并使用最近一次 register 请求重新注册。
- 2026-06-05 起，`legacyice/public_direct` 的 Pion ICE 配置会在收到 STUN Binding Request 并形成公网 peer-reflexive 候选对时切换 selected pair；relay、私网、`100.64.0.0/10`、loopback、link-local、multicast 和 `198.18.0.0/15` 地址不会触发该切换。这是对“natpierce 能打通则 WinkYou 也应继续尝试公网 UDP NAT piercing”的最小策略补强，但仍需要两端部署新版本后做真实验证。
- 2026-06-06 起，`legacyice/public_direct` 默认不在 natpierce、Tailscale、ZeroTier、Docker/vEthernet、Wintun/WinkYou 等疑似外部 overlay/虚拟接口上 gather candidate。普通 `direct_prefer` 仍可用这些路径先保活，但 `public_direct` 不再把外部 overlay 接口当作 protected-direct 证明来源。
- 2026-06-06 起，显式 `nat.candidate_interface_include` 会覆盖 `legacyice/public_direct` 对 natpierce/Tailscale/Wintun 等疑似 overlay 接口的自动排除，用于受控复现“另一套穿透工具能通”的同类路径；显式 `candidate_interface_exclude` 仍优先。这不等于证明断开该 overlay 后 WinkYou 仍能独立保活，protected-direct 证据仍需要公网候选或明确的 `nat.direct_trusted_cidrs`。
- 2026-06-06 起，显式 `nat.candidate_cidr_include` 会让 `legacyice/public_direct` 接受该 CIDR 内的非公网 host/peer-reflexive 候选和 endpoint hint 参与连接尝试，并会与 mapped `public_endpoint_hints` 的本地 base `/32` 合并使用，避免 endpoint hint 覆盖受控 underlay include；它不会自动消除 path dependency，只有 `nat.direct_trusted_cidrs` 才表示该 underlay 可作为 protected-direct 证据。
- 2026-06-06 起，`wink doctor` 的 STUN 检查会复用同一个本地 UDP socket 探测多个 public-direct STUN 来源，并报告 `nat_type` 与每个 mapped endpoint。如果同一 socket 到不同 STUN 目的地得到不同公网映射，会显示 `nat_type=symmetric`，用于解释为什么标准 STUN/srflx public-direct 可能无法复现 natpierce 的打洞路径。
- 2026-06-06 起，`wink doctor` 会把 STUN 观测到的公网映射整理成 `nat.public_endpoint_hints` 候选。稳定映射可作为配置候选；symmetric/endpoint-dependent 映射会继续标注为与 natpierce 实际公网端点对比的 best-effort 证据，不应直接视为已证明稳定。
- 2026-06-06 起，新增 `nat.auto_public_endpoint_hints`，默认开启。client 启动时会把 STUN 映射合入 `legacyice/public_direct` 的 runtime `public_endpoint_hints`；symmetric/endpoint-dependent 映射仍只是 best-effort 候选，不能视为已证明稳定。
- 2026-06-06 起，新增 `nat.public_endpoint_hint_port_window`，默认 `2`、最大 `512`。该字段只在 `legacyice/public_direct` 边界围绕每个公网 endpoint hint 追加有限相邻端口候选，用于复现 natpierce/路由器日志中可预测的端口漂移；`pkg/session` 和 `pkg/solver` 不感知该 NAT 细节。
- 2026-06-06 起，启动 STUN 观测生成的 runtime `public_endpoint_hints` 与手工 hint 使用同一 trust 语义：默认拒绝 CGN/overlay/benchmark 等非公网端点；配置 `nat.direct_trusted_cidrs` 或兼容的 `nat.public_direct_trusted_cidrs` 后，才允许这些已验证 underlay 自动进入 `legacyice/public_direct`。
- 2026-06-06 起，生产启动时的 STUN mapping detection 与 doctor/public-direct 使用同一有效 STUN 来源：显式 `nat.stun_servers` 加 UDP TURN URL 派生出的同 host/port STUN binding 入口。只配置 coturn 的自托管部署也能生成 runtime endpoint hint。
- 2026-06-06 起，`legacyice/public_direct` 的 `candidate_failed` observation 会附带最近本端/远端候选过滤摘要、hint 数量和 ICE 状态，避免真实环境只看到 timeout 而无法判断是本端未发布候选、远端候选被过滤，还是 ICE check 阶段失败。
- 2026-06-06 起，当 `legacyice/public_direct` 已有手工或运行时 endpoint hint 时，会使用较短 gather deadline 先拿到本地 socket 并尽快交换 hinted candidate，避免慢 STUN gather 消耗 natpierce 类映射的可用窗口；无 hint 时仍使用正常 gather timeout。
- 2026-06-06 起，生产 resolver 在 `connectivity.mode=auto`、本机检测为 `nat_type=symmetric` 且配置了 TURN 时，会优先尝试 `relay_only`，再保留 `legacy_ice_udp`。没有 TURN 时仍保持 `legacy_ice_udp` 优先，避免把不可用的 relay-only 放在 public-direct 打洞之前。这不会设置 `ForceRelay`，因此 legacy 内部的 `public_direct` 仍可作为后续 fallback/improvement 继续争取独立路径。
- 2026-06-06 起，生产 `legacy_ice_udp` 配置在无 TURN 且非显式 relay-only 模式下会禁用内部 `legacyice/relay_only` plan。这样旧 observation 中的 relay success 不会把当前不可用的 relay plan 排到 `public_direct` 前面，避免无 TURN 环境浪费 candidate budget。
- 2026-06-06 起，`wink doctor` 会在 strategy 层输出 `legacy_ice_udp` 内部 plan order，用于确认无 TURN 环境是否实际执行 `legacyice/direct_prefer -> legacyice/public_direct`，而不是先等待不可用的 relay plan。
- 2026-06-06 起，当手工或运行时 `public_endpoint_hints` 存在时，`legacyice/public_direct` 会排到普通 `legacyice/direct_prefer` 前面，避免 natpierce/路由器/STUN 观测到的 UDP 映射在真正打洞前过期；若 relay evidence 更强，relay 仍可先保活，但 hinted `public_direct` 会排在 `direct_prefer` 前继续争取 protected-direct standby。
- 2026-06-06 起，多个 mapped `public_direct_hint_N` 计划会在同一个 `legacyice/public_direct` 信令家族内并发执行。base `public_direct` 信令会广播给 active hint executor，精确 hint 信令优先送到对应 executor；任一 hint 成功会取消同 family 慢 hint 并立即进入 bind，全部失败时仍继续后续 fallback。这个改动用于缩小与 natpierce 类工具在“多个端口同时打洞”上的执行差距，但真实独立可达仍必须用 `path_role=protected_direct` 且无 dependency 的 selected path 证明。
- 2026-06-06 起，`legacyice/public_direct` 会在 offer/answer 后发送三轮短间隔、有界 `candidate` 信令 burst，并通过 `candidate_signaled` observation 暴露发送数量、总数、round/rounds 和是否 capped。第一轮会立即发送，后续 retry 在 executor lifecycle 内后台补发，不阻塞 ICE connect。candidate 消息如果乱序先到，只会缓存远端候选，不会在 remote ICE credentials 未到时提前启动 connect。这让 coordinator 和已建立虚拟网内的 `session_signal` 都能多保留候选信令，降低短窗口打洞时单次候选消息丢失或延迟的影响。
- 2026-06-06 起，早到的有效 `legacyice/public_direct` candidate 会在 remote ICE credentials 到达后与 offer/answer 内的候选合并去重；如果后续 offer/answer 本身只有会被过滤掉的私网/overlay 候选，已缓存的公网 candidate 仍可继续触发 ICE checks。这是对 natpierce 类短窗口打洞信令乱序的补强，仍需要真实 selected pair 证明独立路径。
- 2026-06-06 起，`legacyice/public_direct` 在 remote ICE credentials 先到但 offer/answer 候选全被过滤时，不再立即失败；executor 会短暂等待后续 `candidate` burst，并通过 `remote_candidates_waiting` observation 暴露 grace 窗口。窗口内收到可用候选后继续 ICE checks，窗口后仍无候选才让 plan 失败并继续 fallback。
- 2026-06-06 起，`legacyice/public_direct` 的额外 `candidate` burst 在候选数量超过每轮上限时会优先发送 `public_endpoint_hints`/端口窗口生成的候选，避免最关键的 hinted public UDP 端点因为普通 srflx/host 候选排在前面而被截断。
- 2026-06-06 起，生产配置在启动 STUN mapping 判定为 symmetric/endpoint-dependent 且本轮存在 `public_endpoint_hints` 时，会把 effective `public_endpoint_hint_port_window` 从默认 `2` 提高到 `512`；显式 `0` 仍表示关闭，用户配置大于 `512` 不会被降低。这个改动用于覆盖 natpierce 类工具常见的更宽端口漂移探测，但仍不会把 endpoint-dependent STUN 映射当作稳定 proof。
- 2026-06-06 起，`wink doctor` 的 `candidate filters` 会显示 symmetric NAT + endpoint hints 下的 `effective_public_endpoint_hint_port_window=512`，并让 observed endpoint hint 逻辑与生产 `candidate_cidr_include`/trusted CIDR allow-list 保持一致，避免排查时误把配置默认值 `2` 当成实际执行窗口。
- 2026-06-06 起，如果启动 STUN mapping 只有一个来源成功、NAT 类型仍为 `unknown`，但本轮已经生成 runtime/public endpoint hint，生产配置也会把 effective `public_endpoint_hint_port_window` 提高到 `512`，doctor 会显示 `effective_window_reason=unclassified_nat_endpoint_hints`。这覆盖了“证据不足以证明稳定映射”的常见自托管/单 STUN 场景，继续按 best-effort 打洞处理。
- 2026-06-06 起，当 `legacyice/public_direct` 的 mapped `public_endpoint_hints` 含有唯一的本地 base `ip:port` 时，NAT 层会为本轮 Pion ICE agent 创建固定 UDP mux，让 host candidate 和 STUN/server-reflexive candidate 共用同一个 socket。这进一步缩小了与 natpierce 类工具在“已知本地 socket + 公网映射”打洞模型上的差距；若仍失败，应继续排查对端端点、端口漂移、防火墙或目的地相关 NAT 映射，而不是判定物理不可达。
- 2026-06-06 起，`legacyice/public_direct` 在收到远端 public-direct candidate 后，会从同一个固定 UDP mux socket 对远端候选做 best-effort STUN pre-punch；candidate signal/pre-punch 普通候选每轮默认上限为 `1024`，当 endpoint hint/window 候选超过默认上限时会最多放宽到 `4096`，以覆盖完整受控 hint 窗口。候选按 endpoint hint 的端口偏移交错排序，避免多个 hint 时只覆盖第一个 hint 的大窗口。mapped hint 带本地 base 且本地端口不同于公网映射端口时，还会把“公网 IP + 本地固定 socket 端口”作为第二个预测中心，覆盖端口保持型或目的地相关 NAT 常见漂移。inner-gw 现场抓包已看到远端从 `172.29.7.111` 向本机公网 `117.48.146.2` 发出同 socket UDP punch，但未看到本机公网包入站到 inner-gw；这说明当前仍未证明 local-live 到 inner-gw 的独立公网 P2P 已打通，后续应继续补更强的端点学习/同步打洞，而不是把 natpierce 可达性误当作 WinkYou 已完成。
- 2026-06-06 最新 live 验证中，inner-gw 的 `legacyice/public_direct` 已生成 `2050` 个 public-direct 候选并向本机公网发出大量同 socket UDP punch，但 inner-gw tcpdump 仍显示来自本机公网 `117.48.146.2` 的入站 UDP 为 `0`，会话未进入 bound。因此当前问题已经不是单纯的控制面维持，也不是只发送前 1024 个候选；仍需要继续对齐 natpierce 的真实端点学习/同步打洞模型，或依赖 relay fallback 兜底。该验证还暴露了两个信令细节：完整 hint 窗口旁边的真实 srflx 候选不应被动态上限漏掉，且 2050 级别候选 burst 的单轮发送窗口需要放宽，避免 `context deadline exceeded` 导致候选消息未完整发出。
- 2026-06-06 起，收到远端 offer/answer 候选后的 same-socket remote-candidate pre-punch 不再只执行第一轮；executor 会按 `nat.connect_timeout` 在生命周期内做有界重试，并通过 `remote_candidates_punched` 的 `punch_round`/`punch_rounds` 暴露进度。这让 WinkYou 更接近 natpierce 类工具持续双向 punch 的行为，但仍需要 live 抓包证明对端公网入站和 ICE selected pair，不能仅凭重试次数宣称 P2P 已打通。
- 2026-06-06 起，`candidate` 信令 burst 和 same-socket pre-punch 的重试轮次会从上一轮实际成功发送/打洞后的候选 offset 继续，而不是每轮都从候选列表开头重发。这样在 2050 级别端口窗口遇到 `context deadline exceeded` 时，后续轮次会继续扫剩余端口，避免低偏移端口被重复覆盖而高偏移端口始终没进入信令或 punch。`candidate_signaled` 和 `remote_candidates_punched` 还会记录 `candidate_first`/`candidate_last`、`candidate_next_start` 和 `candidate_port_min`/`candidate_port_max`，用于下一次 inner-gw live 抓包时直接对照是否覆盖了 natpierce 观测到的端口段。
- 2026-06-06 起，NAT 层 `PublicDirectPunchReport` 会返回实际 pre-punch UDP socket 的本地地址，`remote_candidates_punched` observation 暴露为 `punch_local_addr`/`punch_local_port`。这用于确认 pre-punch 是否真的从固定 public-direct mux socket 发出，避免只看到候选覆盖范围却不知道底层 socket 是否对齐 `public_endpoint_hints` 的本地 base。
- 2026-06-06 起，`legacyice/public_direct` 的 `candidate_failed` 会携带最近一次 same-socket pre-punch 摘要，使用 `last_punch_*` 前缀暴露本地 punch socket、候选覆盖范围和 punch round。这样一次失败事件就能直接说明失败前是否真的从固定 socket 扫过目标端口窗口。
- 2026-06-06 起，client 创建新的 peer session 前，以及已 bound 的 relay/依赖路径发起 protected-direct improvement 前，会用短超时刷新 runtime STUN endpoint hint；刷新成功且有 usable hint 时会更新 runtime hint，刷新失败或刷新成功但无 usable hint 时保留上一轮 hint，同时仍更新本轮 NAT 类型。生产 strategy factory 也改为每次 build strategy 时读取当前 hint，避免 protected-direct improvement 继续使用 session 创建时冻结的旧公网映射。
- 2026-06-06 起，生产 legacy ICE 配置会从近期 `legacyice/public_direct` 本地 `candidate_gathered` observation 的 srflx kept sample 中恢复最多 8 条 endpoint hint，年龄超过 10 分钟或来自远端过滤 observation 的样本会被忽略。这让上一轮已观测映射能推动下一轮 hinted public-direct 更早执行；它仍只是 best-effort 候选，不会把路径标记为 protected-direct proof。
- 2026-06-06 起，Windows TUN 安装 WinkYou 后端网段 route 时会设置低 route/interface metric，降低 `10.6.22.0/24` 这类同前缀后端 route 被 natpierce/Tailscale 等外部 overlay 抢占的概率。若外部 overlay 安装的是更具体的 `/32` host route，仍会按 OS longest-prefix 规则优先，需要清理 stale route 或发布同样具体的 WinkYou 后端 route。
- 2026-06-06 起，protected-direct session 调度不再因为第一条 protected/direct outcome 成功就停止跨 strategy 搜索；只要 `connectivity.multipath.max_paths` 预算未填满，后续 `relay_only` 或其他候选仍会获得执行机会，让低延迟 primary 与 protected direct standby 能在同一个 multipath transport 中同时保留。
- 2026-06-05 起，client 在 peer 已 bound 但 path 不是 `protected_direct` 时，会保留现有数据面并后台继续尝试 protected-direct improvement；失败的临时 transport 会关闭，旧 path 不变，只有新结果明确为 `protected_direct` 时才替换 tunnel peer transport。

2026-06-04 后续验证中，已能通过 SSH 密码登录 `chen-win` 并确认 `wink-coordinator` 进程可被单独停止。排查中先发现本机验证版 client 重启后数据面未重新达到 bound/handshake，原因是 chen-win coordinator 使用 memory store，重启后 `ListPeers` 为空，旧 client 不会自动重新注册。随后 chen-win coordinator scheduled task 已切换到 SQLite store，并按原 public key 顺序恢复 `inner-b=node-000001/10.88.0.1`、`local-a=node-000002/10.88.0.2`。

2026-06-04 21:48 已执行基础 kill-coordinator 验证：本机和 `inner-b` 已处于 `State: connected`、WireGuard handshake 非空、transport counters 非零、`wink ping inner-b` 成功；随后只停止 `chen-win` 上的 coordinator 进程 15 秒，不断开 natpierce/underlay；停机期间 `wink peers --json` 仍显示 peer connected/bound，`wink ping inner-b` 仍成功；脚本随后通过 scheduled task 拉起 coordinator，重启后 `wink ping` 继续成功。

已新增 `scripts/verify-control-plane-outage.py` 作为安全回归脚本。它会先检查本机 `wink peers --json`、WireGuard handshake、transport error 和 overlay ping；只有确认数据面已 bound 后才会读取 SSH 密码并停止 `chen-win` 上的 coordinator。当前 runtime 未 bound 时，脚本会拒绝执行远端停进程动作。

本次排查还确认了一个部署层根因：`chen-win` 原 coordinator 以默认 memory store 启动，重启后 `ListPeers` 为空，已运行的旧 client 不会自动重新注册，导致本机 runtime 仍显示旧 peer、实际 coordinator 已不知道任何 peer。测试部署已切换到 `--store-backend sqlite --sqlite-path coordinator.db`；后续长期测试仍应让两端 client 都运行包含 NotFound 重注册修复的新版本。

这还没有覆盖所有 coordinator 进程退出、heartbeat 失败、signaling stream 断开、cached path 恢复或 in-band control 网络循环接入场景。

后续 TODO：

- 保持 natpierce/underlay 不断，并且先确认两端数据面已 bound/handshake 成功；随后只停止 `chen-win` 上的 coordinator 进程，做更长时间 outage 验证。
- 测试部署的 coordinator 使用持久化 SQLite store，避免重启后注册表为空；当前 chen-win scheduled task 已切到 SQLite。
- 已 bound 且 WireGuard handshake 正常的 peer 不应因 coordinator 短暂不可达、heartbeat 失败或 peer offline 事件被立即清理。
- 增加 coordinator outage / heartbeat/signaling failure 回归测试，确保已连接数据面不会被误拆。
- 后续把已缓存的 peer lease、最近成功 endpoint、strategy、path summary 和 last handshake 用于无外部信令时的恢复或 cached path 重试；当前只完成 bound 后 protected-direct improvement，仍需要可用 signaling。
- 使用 ICE interface/CIDR 过滤排除 Tailscale、Docker bridge、其他 VPN/TAP 后，做真实纯 NAT piercing 验证。
- 后续把 `pkg/peercontrol` 接入已建立虚拟网后的 client 网络循环；它可以承载 heartbeat、endpoint update、re-ICE request、capability refresh 和 path health，但首次 bootstrap 仍需要 coordinator、稳定 bootstrap 节点、静态 endpoint/端口映射、已有 overlay、手动交换信息或其他 rendezvous。

详见 [`docs/CONTROL-PLANE-RESILIENCE.md`](./docs/CONTROL-PLANE-RESILIENCE.md)。

---

## 五、已收敛的决策

> [!IMPORTANT]
> 以下问题曾影响后续开发方向；当前状态已按代码和文档现实收敛。

### 已决策 1: 生产 resolver 使用 session factory portfolio resolver

`pkg/session` 提供 resolver 权威实现，`engine.newStrategyResolver()` 只负责组装 strategy factory entries。

### 已决策 2: 当前数据平面继续使用 wireguard-go，Wink Protocol 文档归为 proposal/brainstorm

当前 active baseline 仍是 connectivity solver + WireGuard data plane。`brainstorm.md`、`protocol.md`、`wink-protocol-v1.md` 保留为历史 proposal，不作为当前实现路线。

### 已决策 3: Phase 3B 已先完成，再进入 Phase 4A

Phase 3B code health 已完成，随后实现了 Phase 4A 的 `relay_only`。

### 已决策 4: 第二策略选择 `relay_only`

第二个真实 strategy 已选择并冻结为 `relay_only`。`tcp_framed` 后续作为 alpha 非 UDP PacketTransport 验证加入；`quic_datagram` 仍不在 v0.1 实现范围内。

### 已决策 5: 大量 brainstorm/analysis 文档保留原路径并明确标记

为了避免破坏既有相对链接，当前保留原路径；所有非权威文档通过 Proposal/Archive/Brainstorm 顶部说明和 `docs/README.md` 分级降低误导风险。
