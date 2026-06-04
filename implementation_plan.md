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
| v0.1 运维闭环 | 🟡 进行中 | self-host quickstart、doctor、long-running workflow、release pipeline、控制面韧性补强 |
| v0.1 freeze gate | ✅ 已定义 | `docs/V0.1-FREEZE.md` |

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

当前已完成两层基础补强：

- peer offline update 到达时，如果本地 peer 仍有最近 WireGuard handshake、packet counters 且没有 transport error，client 不再立即 `cleanupPeer`。
- runtime/peer status 已新增 `control_state`、`data_state` 和最近成功 path cache 字段，`wink peers` 文本输出和 JSON 输出都能展示这些状态。
- 已建立数据面后的 in-band peer control 消息模型已加入 `pkg/peercontrol`，覆盖 heartbeat、path health、endpoint update、capability refresh 和 re-ICE request 的校验与 JSON 编解码。
- NAT/ICE 已新增 candidate interface include/exclude 和 candidate CIDR include/exclude 配置，并传入 Pion ICE agent；`wink doctor` 会展示过滤配置并检查 runtime candidate 是否命中 excluded CIDR。

这还没有覆盖所有 coordinator 进程退出、heartbeat 失败、signaling stream 断开、cached path 恢复或 in-band control 网络循环接入场景。

后续 TODO：

- 保持 natpierce/underlay 不断，只停止 `chen-win` 上的 coordinator 进程，做真实 outage 验证。
- 已 bound 且 WireGuard handshake 正常的 peer 不应因 coordinator 短暂不可达、heartbeat 失败或 peer offline 事件被立即清理。
- 增加 coordinator outage / heartbeat/signaling failure 回归测试，确保已连接数据面不会被误拆。
- 后续把已缓存的 peer lease、最近成功 endpoint、strategy、path summary 和 last handshake 用于恢复或 cached path 重试。
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
