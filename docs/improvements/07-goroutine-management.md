# 改进方案 07：Goroutine 生命周期管理

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: Goroutine 启动散布各处，难以追踪和管理

**影响文件**:
- `pkg/client/engine.go`
- `pkg/session/session.go`
- `pkg/tunnel/tunnel_wggo.go`

**问题分析**:
1. ❌ 没有统一的 goroutine 管理
2. ❌ 难以追踪活跃的 goroutine 数量
3. ❌ context 取消后 goroutine 可能未退出
4. ❌ Panic 没有恢复，可能导致进程崩溃
5. ❌ 没有泄漏检测

**实际案例**:
```go
// 常见的问题代码
go func() {
    // 如果这里 panic，整个程序崩溃
    // 如果 context 取消，可能不会退出
    for {
        select {
        case <-someCh:
            // 处理
        }
    }
}()
```

---

## 改进方案

### 核心：Goroutine 池

```go
// pkg/runtime/pool.go
package runtime

import (
    "context"
    "errors"
    "fmt"
    "runtime/debug"
    "sync"
    "sync/atomic"
    "time"
)

var (
    ErrPoolClosed   = errors.New("goroutine pool closed")
    ErrPoolFull     = errors.New("goroutine pool full")
    ErrTimeout      = errors.New("shutdown timeout")
)

// Pool Goroutine 池
type Pool struct {
    name    string
    ctx     context.Context
    cancel  context.CancelFunc
    
    wg      sync.WaitGroup
    metrics *PoolMetrics
    
    closed atomic.Bool
    
    // 限流
    semaphore chan struct{}
    
    // Panic 处理器
    panicHandler PanicHandler
    
    // 活跃 goroutine 追踪
    mu        sync.RWMutex
    active    map[uint64]*GoroutineInfo
    nextID    atomic.Uint64
    
    // 日志
    logger Logger
}

// PoolMetrics 池指标
type PoolMetrics struct {
    Spawned   atomic.Int64  // 总启动数
    Active    atomic.Int64  // 当前活跃数
    Finished  atomic.Int64  // 完成数
    Panicked  atomic.Int64  // panic 数
    Timeout   atomic.Int64  // 超时数
}

// GoroutineInfo 协程信息
type GoroutineInfo struct {
    ID       uint64
    Name     string
    Started  time.Time
    Stack    []byte
}

// PanicHandler panic 处理器
type PanicHandler func(name string, panicVal interface{}, stack []byte)

// Logger 简单的日志接口
type Logger interface {
    Error(msg string, args ...interface{})
    Warn(msg string, args ...interface{})
}

// PoolOptions 池配置
type PoolOptions struct {
    Name         string
    MaxConcurrent int
    PanicHandler PanicHandler
    Logger       Logger
}

// NewPool 创建 goroutine 池
func NewPool(ctx context.Context, opts PoolOptions) *Pool {
    if opts.Name == "" {
        opts.Name = "default"
    }
    if opts.MaxConcurrent == 0 {
        opts.MaxConcurrent = 1000
    }
    
    ctx, cancel := context.WithCancel(ctx)
    
    p := &Pool{
        name:         opts.Name,
        ctx:          ctx,
        cancel:       cancel,
        metrics:      &PoolMetrics{},
        semaphore:    make(chan struct{}, opts.MaxConcurrent),
        panicHandler: opts.PanicHandler,
        active:       make(map[uint64]*GoroutineInfo),
        logger:       opts.Logger,
    }
    
    if p.panicHandler == nil {
        p.panicHandler = defaultPanicHandler
    }
    
    return p
}

// Go 启动一个 goroutine
func (p *Pool) Go(name string, fn func(context.Context)) error {
    return p.GoWithTimeout(name, 0, fn)
}

// GoWithTimeout 启动带超时的 goroutine
func (p *Pool) GoWithTimeout(name string, timeout time.Duration, fn func(context.Context)) error {
    if p.closed.Load() {
        return ErrPoolClosed
    }
    
    // 限流
    select {
    case p.semaphore <- struct{}{}:
    case <-p.ctx.Done():
        return p.ctx.Err()
    default:
        return ErrPoolFull
    }
    
    // 准备 context
    ctx := p.ctx
    var cancel context.CancelFunc
    if timeout > 0 {
        ctx, cancel = context.WithTimeout(ctx, timeout)
    }
    
    // 注册 goroutine
    id := p.nextID.Add(1)
    info := &GoroutineInfo{
        ID:      id,
        Name:    name,
        Started: time.Now(),
    }
    
    p.mu.Lock()
    p.active[id] = info
    p.mu.Unlock()
    
    p.wg.Add(1)
    p.metrics.Spawned.Add(1)
    p.metrics.Active.Add(1)
    
    go func() {
        defer func() {
            // 释放限流
            <-p.semaphore
            
            // 取消 context
            if cancel != nil {
                cancel()
            }
            
            // 移除注册
            p.mu.Lock()
            delete(p.active, id)
            p.mu.Unlock()
            
            // 更新指标
            p.metrics.Active.Add(-1)
            p.metrics.Finished.Add(1)
            
            // Panic 恢复
            if r := recover(); r != nil {
                stack := debug.Stack()
                p.metrics.Panicked.Add(1)
                p.panicHandler(name, r, stack)
            }
            
            p.wg.Done()
        }()
        
        fn(ctx)
    }()
    
    return nil
}

// Shutdown 优雅关闭，等待所有 goroutine 退出
func (p *Pool) Shutdown(timeout time.Duration) error {
    if !p.closed.CompareAndSwap(false, true) {
        return ErrPoolClosed
    }
    
    // 通知所有 goroutine 退出
    p.cancel()
    
    // 等待退出（带超时）
    done := make(chan struct{})
    go func() {
        p.wg.Wait()
        close(done)
    }()
    
    select {
    case <-done:
        return nil
    case <-time.After(timeout):
        // 记录泄漏的 goroutine
        active := p.ActiveGoroutines()
        if p.logger != nil {
            for _, info := range active {
                p.logger.Error("goroutine leaked",
                    "name", info.Name,
                    "duration", time.Since(info.Started),
                )
            }
        }
        p.metrics.Timeout.Add(int64(len(active)))
        return fmt.Errorf("%w: %d goroutines still active", ErrTimeout, len(active))
    }
}

// ActiveGoroutines 返回当前活跃的 goroutines
func (p *Pool) ActiveGoroutines() []GoroutineInfo {
    p.mu.RLock()
    defer p.mu.RUnlock()
    
    result := make([]GoroutineInfo, 0, len(p.active))
    for _, info := range p.active {
        result = append(result, *info)
    }
    return result
}

// Metrics 获取指标
func (p *Pool) Metrics() PoolMetricsSnapshot {
    return PoolMetricsSnapshot{
        Spawned:  p.metrics.Spawned.Load(),
        Active:   p.metrics.Active.Load(),
        Finished: p.metrics.Finished.Load(),
        Panicked: p.metrics.Panicked.Load(),
        Timeout:  p.metrics.Timeout.Load(),
    }
}

// PoolMetricsSnapshot 指标快照
type PoolMetricsSnapshot struct {
    Spawned  int64
    Active   int64
    Finished int64
    Panicked int64
    Timeout  int64
}

// defaultPanicHandler 默认 panic 处理器
func defaultPanicHandler(name string, panicVal interface{}, stack []byte) {
    fmt.Printf("goroutine panic: %s\nvalue: %v\nstack:\n%s\n", name, panicVal, stack)
}
```

---

## 在各组件中的应用

### Engine 组件

```go
// pkg/client/engine_v2.go
type engine struct {
    // ...
    pool *runtime.Pool
}

func NewEngine(cfg *config.Config, log logger.Logger, statePath string) (Engine, error) {
    e := &engine{
        cfg: cfg,
        log: log,
    }
    
    e.pool = runtime.NewPool(context.Background(), runtime.PoolOptions{
        Name:          "engine",
        MaxConcurrent: 1000,
        Logger:        log,
        PanicHandler: func(name string, panicVal interface{}, stack []byte) {
            log.Error("goroutine panic",
                "name", name,
                "panic", panicVal,
                "stack", string(stack),
            )
        },
    })
    
    return e, nil
}

func (e *engine) Start(ctx context.Context) error {
    // ...
    
    // 启动心跳
    e.pool.Go("heartbeat", func(ctx context.Context) {
        e.heartbeatLoop(ctx)
    })
    
    // 启动状态同步
    e.pool.Go("state-sync", func(ctx context.Context) {
        e.stateSyncLoop(ctx)
    })
    
    // 启动观察持久化
    e.pool.Go("observation-persist", func(ctx context.Context) {
        e.observationPersistLoop(ctx)
    })
    
    return nil
}

func (e *engine) Stop() error {
    // 优雅关闭，30 秒超时
    return e.pool.Shutdown(30 * time.Second)
}
```

### Session 组件

```go
// pkg/session/session_v2.go
type Session struct {
    // ...
    pool *runtime.Pool
}

func New(cfg Config) (*Session, error) {
    s := &Session{
        cfg: cfg,
    }
    
    s.pool = runtime.NewPool(context.Background(), runtime.PoolOptions{
        Name:          fmt.Sprintf("session-%s", cfg.SessionID),
        MaxConcurrent: 50,
    })
    
    return s, nil
}

func (s *Session) Start(ctx context.Context) error {
    // 启动消息处理
    s.pool.Go("message-loop", func(ctx context.Context) {
        s.messageLoop(ctx)
    })
    
    // 启动 probe 循环（带超时）
    s.pool.GoWithTimeout("probe-loop", 30*time.Second, func(ctx context.Context) {
        s.probeLoop(ctx)
    })
    
    return nil
}

func (s *Session) Close() error {
    return s.pool.Shutdown(10 * time.Second)
}
```

---

## 泄漏检测

```go
// pkg/runtime/leak_detector.go
package runtime

import (
    "context"
    "runtime"
    "time"
)

// LeakDetector 泄漏检测器
type LeakDetector struct {
    pool        *Pool
    threshold   time.Duration
    logger      Logger
    onLeak      func(GoroutineInfo)
}

// NewLeakDetector 创建检测器
func NewLeakDetector(pool *Pool, threshold time.Duration) *LeakDetector {
    return &LeakDetector{
        pool:      pool,
        threshold: threshold,
    }
}

// Run 运行检测器
func (d *LeakDetector) Run(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            d.check()
        case <-ctx.Done():
            return
        }
    }
}

// check 检查泄漏
func (d *LeakDetector) check() {
    active := d.pool.ActiveGoroutines()
    now := time.Now()
    
    for _, info := range active {
        if now.Sub(info.Started) > d.threshold {
            // 捕获栈
            stack := captureGoroutineStack(info.ID)
            info.Stack = stack
            
            if d.logger != nil {
                d.logger.Warn("potential goroutine leak",
                    "name", info.Name,
                    "duration", now.Sub(info.Started),
                    "stack", string(stack),
                )
            }
            
            if d.onLeak != nil {
                d.onLeak(info)
            }
        }
    }
}

// captureGoroutineStack 捕获指定 goroutine 的栈
func captureGoroutineStack(id uint64) []byte {
    buf := make([]byte, 1<<20)
    n := runtime.Stack(buf, true)
    return buf[:n]
}
```

---

## 测试

### 单元测试

```go
// pkg/runtime/pool_test.go
func TestPool_Go(t *testing.T) {
    pool := NewPool(context.Background(), PoolOptions{
        Name: "test",
    })
    
    var counter atomic.Int64
    
    // 启动 100 个 goroutine
    for i := 0; i < 100; i++ {
        err := pool.Go(fmt.Sprintf("worker-%d", i), func(ctx context.Context) {
            counter.Add(1)
        })
        if err != nil {
            t.Fatal(err)
        }
    }
    
    // 等待完成
    if err := pool.Shutdown(5 * time.Second); err != nil {
        t.Fatal(err)
    }
    
    if counter.Load() != 100 {
        t.Fatalf("counter = %d, want 100", counter.Load())
    }
}

func TestPool_PanicRecovery(t *testing.T) {
    var panicked atomic.Bool
    
    pool := NewPool(context.Background(), PoolOptions{
        Name: "test",
        PanicHandler: func(name string, panicVal interface{}, stack []byte) {
            panicked.Store(true)
        },
    })
    
    pool.Go("panic-worker", func(ctx context.Context) {
        panic("test panic")
    })
    
    pool.Shutdown(1 * time.Second)
    
    if !panicked.Load() {
        t.Fatal("panic not recovered")
    }
    
    if pool.Metrics().Panicked != 1 {
        t.Fatal("panic count incorrect")
    }
}

func TestPool_Shutdown(t *testing.T) {
    pool := NewPool(context.Background(), PoolOptions{
        Name: "test",
    })
    
    // 启动一个长时间运行的 goroutine
    pool.Go("long-runner", func(ctx context.Context) {
        select {
        case <-ctx.Done():
            return
        case <-time.After(10 * time.Second):
            t.Fatal("should be cancelled")
        }
    })
    
    // 关闭应该快速完成
    start := time.Now()
    err := pool.Shutdown(1 * time.Second)
    if err != nil {
        t.Fatal(err)
    }
    
    if time.Since(start) > 100*time.Millisecond {
        t.Fatal("shutdown too slow")
    }
}

func TestPool_LeakDetection(t *testing.T) {
    pool := NewPool(context.Background(), PoolOptions{
        Name: "test",
    })
    
    // 启动一个不会退出的 goroutine
    pool.Go("leaker", func(ctx context.Context) {
        time.Sleep(10 * time.Second)
    })
    
    // 等待泄漏
    time.Sleep(100 * time.Millisecond)
    
    active := pool.ActiveGoroutines()
    if len(active) != 1 {
        t.Fatalf("active = %d, want 1", len(active))
    }
    
    if active[0].Name != "leaker" {
        t.Fatalf("name = %s, want leaker", active[0].Name)
    }
}
```

---

## 实施步骤

### Step 1: 实现 Pool（2 天）
1. 创建 `pkg/runtime/pool.go`
2. 实现核心功能
3. 单元测试

### Step 2: 实现泄漏检测（1 天）
1. 创建 `pkg/runtime/leak_detector.go`
2. 集成到 Pool

### Step 3: 迁移 Engine（2 天）
1. 重构 engine 使用 Pool
2. 替换所有 `go` 语句

### Step 4: 迁移 Session（2 天）
1. 重构 session 使用 Pool
2. 替换所有 `go` 语句

### Step 5: 集成测试（1 天）
1. 完整测试套件
2. 压力测试

**总计**: 8 天

---

## 验收标准

- ✅ 所有 goroutine 通过 Pool 启动
- ✅ Panic 自动恢复
- ✅ 优雅关闭机制
- ✅ 泄漏检测有效
- ✅ 单元测试覆盖率 > 90%

---

## 参考资料

- [Go context 包](https://pkg.go.dev/context)
- [Go runtime 包](https://pkg.go.dev/runtime)
- [errgroup 包](https://pkg.go.dev/golang.org/x/sync/errgroup)
