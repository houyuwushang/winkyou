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
| Phase 3A (Strategy Portfolio Foundation) | ✅ 合并 | commit `bae1266` |
| Phase 3B+ | ❌ 未开始 | — |

Phase 3A 已交付：`PortfolioResolver`、`StrategyEntry`、strategy selection 测试覆盖、fake strategy 验证。session 不再硬编码 `legacy_ice_udp`。

### 代码规模

| 指标 | 数值 |
|------|------|
| Go 源文件 | 112 个 |
| 源码体积 | 615 KB |
| 核心包数量 | 14 个 (`pkg/*`) |
| 测试包 | 30 个（全部通过） |
| 最大单文件 | `session.go` — **1748 行** |
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

#### 问题 2: `session.go` 是 1748 行的巨型文件

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

#### 问题 3: 状态机没有转换验证

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

#### 问题 4: `cloneUDPAddr` 和 `udpAddrFromAddr` 在两个包中重复定义

**位置**:
- [session/binder.go L73-100](file:///d:/workspace/winkyou/pkg/session/binder.go#L73-L100): `udpAddrFromAddr()` + `cloneUDPAddr()`
- [client/peer_session.go L348-368](file:///d:/workspace/winkyou/pkg/client/peer_session.go#L348-L368): `udpAddrFromAddr()` — 完全相同的代码
- [client/engine.go L653-662](file:///d:/workspace/winkyou/pkg/client/engine.go#L653-L662): `cloneUDPAddr()` — 完全相同的代码

三处实现完全一致。如果将来修一个 bug（比如 IPv6 zone 处理），只修一处就会留下隐患。

**建议**: 提取到公共包，比如 `pkg/netutil/addr.go`。

---

#### 问题 5: `context.Background()` 在已有 context 的场景中被使用

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

#### 问题 6: `strategyResolver`（client 包）和 `PortfolioResolver`（session 包）存在职责重叠

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

#### 问题 7: Observation 列表采用 slice 截断而非环形缓冲

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

#### 问题 8: CI 没有 lint 和 vet 步骤

**位置**: [ci.yml](file:///d:/workspace/winkyou/.github/workflows/ci.yml)

CI 只跑 `go test ./...`，没有：
- `go vet ./...`
- `golangci-lint run`（Makefile 里提到了 golangci-lint 但 CI 没用）
- race detector（`-race` flag）

**建议**: 至少加 `go vet ./...` 和 `go test -race ./... -short`。

---

#### 问题 9: `probeResultCh` 容量只有 8，可能丢信号

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

#### 问题 10: `_ =` 忽略错误返回值

全局搜索 `_ =` 在 session.go 和 engine.go 中有约 15 处。其中多数是清理路径上的 `Close()` 返回值（可接受），但有几处值得注意：

- [session.go L330](file:///d:/workspace/winkyou/pkg/session/session.go#L330): `_ = outcomes[i].Result.Transport.Close()` — 如果 close 失败（比如底层 fd 已被另一个 goroutine 关闭），这里不会有任何日志
- [session.go L986](file:///d:/workspace/winkyou/pkg/session/session.go#L986): `_ = s.reportObservation(ctx, obs)` — observation 发送失败被完全静默

**建议**: 至少 log.Debug 级别记录 close 错误。

---

### S3 — 轻微 / 改善

#### 问题 11: `firstNonEmpty()` 函数定义了但从未使用

**位置**: [session.go L1466-1473](file:///d:/workspace/winkyou/pkg/session/session.go#L1466-L1473)

Dead code。应删除或加 `//nolint:unused` 注释说明保留原因。

#### 问题 12: `session.go:162-164` — 接受 nil ctx 不符合 Go 惯例

```go
func (s *Session) Start(ctx context.Context) error {
    if ctx == nil {
        ctx = context.Background()
    }
```

Go 的惯例是 `context.Context` 参数永远不为 nil（参见 [context package doc](https://pkg.go.dev/context)）。防御性处理 nil ctx 会掩盖调用方的 bug。

#### 问题 13: `winkplan.md` 与实际代码严重脱节

`winkplan.md` 描述的目录结构（`pkg/node/`, `platform/`, `internal/`）、协议设计（`messages.proto`）、功能规划（TAP、MagicDNS、SOCKS5 proxy）与实际代码对应不上。这是早期的 brainstorm 文档，但 README 没有标注它已过时。

**建议**: 在 `winkplan.md` 顶部加明确的 deprecation notice，指向 `docs/CONNECTIVITY-SOLVER-BASELINE.md` 作为当前架构权威。

#### 问题 14: 多份 "架构分析" 文档定位不清

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

**建议**: 非权威文档必须明确 Proposal/Archive/Brainstorm 定位；当前选择保留原路径并在 `docs/README.md` 中明确分级，避免破坏既有相对链接。

#### 已处理 15: NAT 超时配置已暴露到 config（不再列为硬编码问题）

**位置**:
- [config/config.go](file:///d:/workspace/winkyou/pkg/config/config.go)
- [client/nat_timeouts.go](file:///d:/workspace/winkyou/pkg/client/nat_timeouts.go)

ICE gather/connect/check timeout 已通过 `config.NATConfig` 暴露，并由 `client/nat_timeouts.go` 从 `e.cfg.NAT` 读取；默认值在 config defaults/validator 中维护。

**后续原则**: 如需调整高延迟网络行为，修改配置默认值或文档示例，不再把它作为“硬编码在 client 包内部”的架构缺陷。

---

## 四、下一步开发路线建议

Phase 3A (Strategy Portfolio Foundation) 已完成。以下是我基于代码现实给出的路线：

### Phase 3B: Code Health Sprint (1-2 周)

> **原则**: 不加功能，只还技术债

| 任务 | 优先级 | 工作量 |
|------|--------|--------|
| 从 git 移除二进制文件 | S0 | 0.5h |
| 拆分 session.go 为 6-8 个文件 | S0 | 4h |
| 状态机添加转换验证 | S1 | 2h |
| 提取 `cloneUDPAddr`/`udpAddrFromAddr` 到公共包 | S1 | 1h |
| CI 加 vet + race detector | S2 | 1h |
| 清理过时文档（加 deprecation notice） | S3 | 1h |
| 修复 context.Background() 误用 | S1 | 2h |

### Phase 4A: Second Strategy Skeleton (3-4 周)

> **目标**: 添加第一个 非 ICE/UDP 策略的骨架，证明 solver 的 multi-strategy 能力在运行时工作

候选方案（按实现难度从低到高）：

1. **`relay_only` 策略** — 跳过 ICE 打洞，直接用 TURN relay。最简单，可以从 `legacyice/relay_only` plan 提取为独立策略
2. **`tcp_framed` 策略** — 通过 TCP 连接承载 `PacketTransport`（你已有 `transport/framedstream` 适配器）。需要 coordinator 支持 TCP endpoint 协商
3. **`quic_datagram` 策略** — 通过 QUIC Datagram 承载。需要引入 `quic-go` 依赖

**建议从方案 1 开始**: 它的代码改动最小，但能端到端验证 `PortfolioResolver` → strategy selection → 不同 strategy 执行 → Bind 的完整流程。

### Phase 4B: Observation → Scoring Closed Loop

这是 Phase 2D 遗留的 "not in scope" 项。在有两个真实策略之后，observation history 才有比较意义——可以回答 "上次 direct 失败了，这次应该先试 relay" 这类问题。

---

## 五、需要你做的决策

> [!IMPORTANT]
> 以下问题会影响后续开发方向，请给出你的判断。

### 决策 1: `PortfolioResolver` vs `strategyResolver` 的定位

`PortfolioResolver` 是未来生产路径的 resolver，还是仅作为 Phase 3A 测试基础设施？如果是前者，`engine.newStrategyResolver()` 应该迁移到 `PortfolioResolver`，淘汰 `strategyResolver`。

### 决策 2: `brainstorm.md` / `wink-protocol-v1.md` 的 Wink Protocol 自研数据平面计划是否继续

你在 brainstorm.md 里设计了一个自研协议（Noise KK + AES-GCM 协商 + 短头部 + 0-RTT），这跟当前 wireguard-go 数据平面是两条完全不同的路。你是打算：
- (A) 继续用 wireguard-go，在 solver/transport 层做差异化？
- (B) 将来真的替换数据平面为自研 Wink Protocol？
- (C) 两个都支持，作为 solver strategy 的不同选项？

### 决策 3: Phase 3B 先做还是跳过直接进 Phase 4A

上面列的 code health 任务（拆文件、修状态机、移二进制）不增加功能但会大幅提升代码可维护性。你愿意花 1-2 周做这个还是直接上功能？

### 决策 4: 第二策略选哪个

`relay_only`（最简单） vs `tcp_framed`（最有实际价值） vs `quic_datagram`（最前沿但依赖最重）？

### 决策 5: 那些大量的 brainstorm/analysis 文档怎么处理

保留在仓库根目录还是归档到 `docs/archive/`？它们总共 270KB，比源码还大。
