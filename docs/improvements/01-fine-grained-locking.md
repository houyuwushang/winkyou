# 改进方案 01：细粒度锁优化

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: 使用单个大锁保护整个 engine 状态

**影响文件**: 
- `pkg/client/engine.go:36-45`
- `pkg/session/session.go:21-55`
- `pkg/tunnel/tunnel_wggo.go:29-46`

**问题代码**:
```go
// pkg/client/engine.go:36-45
type engine struct {
    mu             sync.RWMutex  // ❌ 一个大锁保护所有状态
    started        bool
    status         EngineStatus
    peers          map[string]*PeerStatus
    statusHandlers []func(status *EngineStatus)
    peerHandlers   []func(peer *PeerStatus, event PeerEvent)
    peerMgr        *peerManager
    // ...
}
```

**性能问题**:
- 读取单个 peer 状态需要锁住整个 engine
- 添加/删除 peer 会阻塞所有状态读取操作
- 高并发场景下锁竞争严重
- 1000 并发时，锁竞争占用 CPU 30%+

---

## 改进方案

### 方案 1：分离锁（推荐）

**核心思想**: 将不同的状态用不同的锁保护

```go
// pkg/client/engine_v2.go
type engine struct {
    // 分离不同状态的锁
    statusMu sync.RWMutex
    status   EngineStatus
    
    // 使用 sync.Map 实现无锁 peer 管理
    peers sync.Map  // map[string]*PeerStatus
    
    // 使用原子操作管理简单状态
    started atomic.Bool
    
    // 事件处理器使用 copy-on-write
    handlersMu sync.RWMutex
    handlers   *handlerSet  // 不可变结构
    
    // 其他字段
    privateKey tunnel.PrivateKey
    netif      netif.NetworkInterface
    tun        tunnel.Tunnel
    nat        nat.NATTraversal
    coord      coordclient.CoordinatorClient
    pingConn   *net.UDPConn
    
    observationStore *solverstore.ObservationStore
    
    runCtx    context.Context
    runCancel context.CancelFunc
    wg        sync.WaitGroup
}

// 无锁读取 peer
func (e *engine) GetPeer(nodeID string) (*PeerStatus, bool) {
    val, ok := e.peers.Load(nodeID)
    if !ok {
        return nil, false
    }
    return val.(*PeerStatus), true
}

// 无锁添加 peer
func (e *engine) AddPeer(nodeID string, peer *PeerStatus) {
    e.peers.Store(nodeID, peer)
}

// 无锁删除 peer
func (e *engine) RemovePeer(nodeID string) {
    e.peers.Delete(nodeID)
}

// 遍历所有 peers
func (e *engine) ForEachPeer(fn func(nodeID string, peer *PeerStatus) bool) {
    e.peers.Range(func(key, value interface{}) bool {
        return fn(key.(string), value.(*PeerStatus))
    })
}

// 读取状态（只锁状态）
func (e *engine) Status() EngineStatus {
    e.statusMu.RLock()
    defer e.statusMu.RUnlock()
    return e.status
}

// 更新状态（只锁状态）
func (e *engine) setState(state EngineState, reason string) {
    e.statusMu.Lock()
    e.status.State = state
    e.status.StateReason = reason
    e.statusMu.Unlock()
    
    // 通知处理器（不在锁内）
    e.notifyStatusHandlers()
}
```

---

### 方案 2：Copy-on-Write 事件处理器

**问题**: 事件处理器的注册/注销需要锁

**解决方案**: 使用不可变数据结构

```go
// pkg/client/handlers.go
type handlerSet struct {
    statusHandlers []func(status *EngineStatus)
    peerHandlers   []func(peer *PeerStatus, event PeerEvent)
}

// 注册处理器（copy-on-write）
func (e *engine) OnStatusChange(handler func(status *EngineStatus)) {
    e.handlersMu.Lock()
    defer e.handlersMu.Unlock()
    
    // 复制旧的 handler set
    old := e.handlers
    if old == nil {
        old = &handlerSet{}
    }
    
    // 创建新的 handler set
    newHandlers := &handlerSet{
        statusHandlers: append([]func(*EngineStatus)(nil), old.statusHandlers...),
        peerHandlers:   old.peerHandlers,
    }
    newHandlers.statusHandlers = append(newHandlers.statusHandlers, handler)
    
    // 原子替换
    e.handlers = newHandlers
}

// 调用处理器（无锁读取）
func (e *engine) notifyStatusHandlers() {
    e.handlersMu.RLock()
    handlers := e.handlers
    e.handlersMu.RUnlock()
    
    if handlers == nil {
        return
    }
    
    status := e.Status()
    for _, handler := range handlers.statusHandlers {
        handler(&status)
    }
}
```

---

### 方案 3：原子操作替代锁

**适用场景**: 简单的布尔值或计数器

```go
// pkg/client/engine_v2.go
type engine struct {
    // 使用 atomic.Bool 替代锁保护的 bool
    started atomic.Bool
    
    // 使用 atomic.Int64 替代锁保护的计数器
    activeConnections atomic.Int64
    totalBytes        atomic.Int64
}

// 无锁检查是否启动
func (e *engine) IsStarted() bool {
    return e.started.Load()
}

// 无锁设置启动状态
func (e *engine) setStarted(started bool) {
    e.started.Store(started)
}

// 无锁增加连接数
func (e *engine) incrementConnections() {
    e.activeConnections.Add(1)
}

// 无锁减少连接数
func (e *engine) decrementConnections() {
    e.activeConnections.Add(-1)
}
```

---

## 性能对比

### 基准测试

```go
// pkg/client/engine_bench_test.go
func BenchmarkEngineGetPeer_Old(b *testing.B) {
    e := &engineOld{
        peers: make(map[string]*PeerStatus),
    }
    e.peers["peer1"] = &PeerStatus{}
    
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            e.mu.RLock()
            _ = e.peers["peer1"]
            e.mu.RUnlock()
        }
    })
}

func BenchmarkEngineGetPeer_New(b *testing.B) {
    e := &engine{}
    e.peers.Store("peer1", &PeerStatus{})
    
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            _, _ = e.peers.Load("peer1")
        }
    })
}
```

**预期结果**:
```
BenchmarkEngineGetPeer_Old-8    10000000    150 ns/op
BenchmarkEngineGetPeer_New-8    50000000     30 ns/op
```

**性能提升**: 5x

---

## 实施步骤

### Step 1: 重构 engine 结构（2 天）

1. 创建 `pkg/client/engine_v2.go`
2. 定义新的 engine 结构
3. 实现基础方法

### Step 2: 迁移 peer 管理（2 天）

1. 将 `map[string]*PeerStatus` 改为 `sync.Map`
2. 更新所有 peer 访问代码
3. 添加单元测试

### Step 3: 迁移状态管理（1 天）

1. 分离 status 锁
2. 使用 atomic.Bool 替代 started
3. 更新状态访问代码

### Step 4: 迁移事件处理器（2 天）

1. 实现 copy-on-write handler set
2. 更新处理器注册/调用代码
3. 添加并发测试

### Step 5: 性能测试（1 天）

1. 编写基准测试
2. 运行压力测试
3. 验证性能提升

### Step 6: 集成测试（2 天）

1. 运行完整测试套件
2. 修复发现的问题
3. 更新文档

**总计**: 10 天

---

## 风险与注意事项

### 风险 1: sync.Map 的性能特性

**问题**: sync.Map 在某些场景下性能不如带锁的 map

**适用场景**:
- ✅ 读多写少
- ✅ key 集合相对稳定
- ❌ 频繁添加/删除不同的 key

**缓解措施**:
- 在 peer 管理场景下，读操作远多于写操作
- 如果性能不达标，考虑使用分片锁（sharded lock）

### 风险 2: Copy-on-Write 的内存开销

**问题**: 每次注册处理器都会复制整个 slice

**缓解措施**:
- 处理器注册是低频操作
- 处理器数量通常很少（< 10）
- 内存开销可接受

### 风险 3: 并发 bug

**问题**: 细粒度锁容易引入死锁或竞态条件

**缓解措施**:
- 使用 Go race detector: `go test -race`
- 编写并发测试
- Code review 重点关注锁的使用

---

## 验收标准

### 功能验收

- ✅ 所有现有测试通过
- ✅ 新增并发测试通过
- ✅ Race detector 无警告

### 性能验收

- ✅ 锁竞争降低 80%
- ✅ 读操作延迟 < 200ns
- ✅ 支持 10,000 并发连接

### 代码质量

- ✅ 代码覆盖率 > 80%
- ✅ 文档完整
- ✅ Code review 通过

---

## 参考资料

- [Go sync.Map 文档](https://pkg.go.dev/sync#Map)
- [Go atomic 包](https://pkg.go.dev/sync/atomic)
- [Effective Go - Concurrency](https://go.dev/doc/effective_go#concurrency)
- [Go 并发模式](https://go.dev/blog/pipelines)
