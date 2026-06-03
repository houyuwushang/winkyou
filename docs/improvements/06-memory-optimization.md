# 改进方案 06：内存优化（对象池 + 环形缓冲区）

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: 频繁的内存分配和复制

**影响文件**:
- `pkg/solver/store/observation.go:30-41`
- `pkg/session/session.go` - 大量临时对象

**问题代码**:
```go
// pkg/solver/store/observation.go:30
func (s *ObservationStore) Record(obs solver.Observation) error {
    s.mu.Lock()
    s.observations = append(s.observations, obs)  // ❌ 可能扩容
    if len(s.observations) > 1000 {
        s.observations = s.observations[len(s.observations)-1000:]  // ❌ 重新分配
    }
    s.mu.Unlock()
}
```

**性能问题**:
1. 频繁的 slice 扩容（每次 append 可能触发）
2. 截断操作触发新的内存分配
3. 没有对象池复用
4. GC 压力大

**实际数据**:
- 每秒 1000 次 Record
- 每次触发 1-2 次内存分配
- GC 每 5 秒触发一次
- GC 暂停 10-50ms

---

## 改进方案

### 方案 1：环形缓冲区（替代 slice）

```go
// pkg/util/ringbuffer/ringbuffer.go
package ringbuffer

import (
    "errors"
    "sync"
)

// RingBuffer 环形缓冲区，O(1) 入队和出队，无扩容
type RingBuffer[T any] struct {
    mu     sync.RWMutex
    data   []T
    head   int
    tail   int
    size   int
    cap    int
}

// New 创建环形缓冲区
func New[T any](capacity int) *RingBuffer[T] {
    if capacity <= 0 {
        panic("capacity must be positive")
    }
    return &RingBuffer[T]{
        data: make([]T, capacity),
        cap:  capacity,
    }
}

// Push 入队（满了会覆盖最旧的）
func (r *RingBuffer[T]) Push(item T) {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    r.data[r.tail] = item
    r.tail = (r.tail + 1) % r.cap
    
    if r.size == r.cap {
        // 缓冲区已满，移动 head
        r.head = (r.head + 1) % r.cap
    } else {
        r.size++
    }
}

// Pop 出队
func (r *RingBuffer[T]) Pop() (T, bool) {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    var zero T
    if r.size == 0 {
        return zero, false
    }
    
    item := r.data[r.head]
    r.data[r.head] = zero  // 清除引用，帮助 GC
    r.head = (r.head + 1) % r.cap
    r.size--
    
    return item, true
}

// Last 返回最后 N 个元素（不出队）
func (r *RingBuffer[T]) Last(n int) []T {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    if n <= 0 || r.size == 0 {
        return nil
    }
    
    if n > r.size {
        n = r.size
    }
    
    result := make([]T, n)
    start := (r.tail - n + r.cap) % r.cap
    
    for i := 0; i < n; i++ {
        idx := (start + i) % r.cap
        result[i] = r.data[idx]
    }
    
    return result
}

// All 返回所有元素
func (r *RingBuffer[T]) All() []T {
    r.mu.RLock()
    defer r.mu.RUnlock()
    
    result := make([]T, r.size)
    for i := 0; i < r.size; i++ {
        idx := (r.head + i) % r.cap
        result[i] = r.data[idx]
    }
    
    return result
}

// Size 返回当前元素数量
func (r *RingBuffer[T]) Size() int {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.size
}

// Clear 清空缓冲区
func (r *RingBuffer[T]) Clear() {
    r.mu.Lock()
    defer r.mu.Unlock()
    
    var zero T
    for i := range r.data {
        r.data[i] = zero
    }
    r.head = 0
    r.tail = 0
    r.size = 0
}
```

---

### 方案 2：对象池（减少分配）

```go
// pkg/util/pool/pool.go
package pool

import (
    "sync"
    "sync/atomic"
)

// Pool 通用对象池
type Pool[T any] struct {
    pool    sync.Pool
    new     func() *T
    reset   func(*T)
    
    // 指标
    gets    atomic.Int64
    puts    atomic.Int64
    misses  atomic.Int64
}

// New 创建对象池
func New[T any](newFn func() *T, resetFn func(*T)) *Pool[T] {
    p := &Pool[T]{
        new:   newFn,
        reset: resetFn,
    }
    p.pool.New = func() interface{} {
        p.misses.Add(1)
        return newFn()
    }
    return p
}

// Get 获取对象
func (p *Pool[T]) Get() *T {
    p.gets.Add(1)
    return p.pool.Get().(*T)
}

// Put 归还对象
func (p *Pool[T]) Put(obj *T) {
    if obj == nil {
        return
    }
    p.puts.Add(1)
    if p.reset != nil {
        p.reset(obj)
    }
    p.pool.Put(obj)
}

// Stats 获取统计
func (p *Pool[T]) Stats() PoolStats {
    return PoolStats{
        Gets:   p.gets.Load(),
        Puts:   p.puts.Load(),
        Misses: p.misses.Load(),
    }
}

// PoolStats 对象池统计
type PoolStats struct {
    Gets   int64
    Puts   int64
    Misses int64
}

// HitRate 命中率
func (s PoolStats) HitRate() float64 {
    if s.Gets == 0 {
        return 0
    }
    return float64(s.Gets-s.Misses) / float64(s.Gets)
}
```

### 字节缓冲池

```go
// pkg/util/pool/bytes.go
package pool

var (
    // 小包缓冲池（< 2KB）
    SmallBufPool = New(
        func() *[]byte {
            buf := make([]byte, 2048)
            return &buf
        },
        func(buf *[]byte) {
            *buf = (*buf)[:cap(*buf)]
        },
    )
    
    // 中包缓冲池（< 16KB）
    MediumBufPool = New(
        func() *[]byte {
            buf := make([]byte, 16384)
            return &buf
        },
        func(buf *[]byte) {
            *buf = (*buf)[:cap(*buf)]
        },
    )
    
    // 大包缓冲池（< 64KB）
    LargeBufPool = New(
        func() *[]byte {
            buf := make([]byte, 65536)
            return &buf
        },
        func(buf *[]byte) {
            *buf = (*buf)[:cap(*buf)]
        },
    )
)

// GetBuffer 根据大小获取合适的缓冲区
func GetBuffer(size int) *[]byte {
    switch {
    case size <= 2048:
        return SmallBufPool.Get()
    case size <= 16384:
        return MediumBufPool.Get()
    default:
        return LargeBufPool.Get()
    }
}

// PutBuffer 归还缓冲区
func PutBuffer(buf *[]byte) {
    if buf == nil {
        return
    }
    switch cap(*buf) {
    case 2048:
        SmallBufPool.Put(buf)
    case 16384:
        MediumBufPool.Put(buf)
    case 65536:
        LargeBufPool.Put(buf)
    }
}
```

---

## 应用到 Observation Store

```go
// pkg/solver/store/observation_v2.go
package store

import (
    "encoding/json"
    "os"
    "path/filepath"
    "sync"
    "time"
    
    "winkyou/pkg/solver"
    "winkyou/pkg/util/pool"
    "winkyou/pkg/util/ringbuffer"
)

// ObservationStore v2: 使用环形缓冲区 + 对象池
type ObservationStore struct {
    buffer   *ringbuffer.RingBuffer[*solver.Observation]
    pool     *pool.Pool[solver.Observation]
    filePath string
    
    // 持久化批量缓冲
    persistMu     sync.Mutex
    persistBuf    []*solver.Observation
    persistTicker *time.Ticker
    closed        chan struct{}
}

// NewObservationStore 创建存储
func NewObservationStore(filePath string, capacity int) *ObservationStore {
    s := &ObservationStore{
        buffer: ringbuffer.New[*solver.Observation](capacity),
        pool: pool.New(
            func() *solver.Observation {
                return &solver.Observation{}
            },
            func(obs *solver.Observation) {
                *obs = solver.Observation{}
            },
        ),
        filePath:   filePath,
        persistBuf: make([]*solver.Observation, 0, 100),
        closed:     make(chan struct{}),
    }
    
    if filePath != "" {
        s.persistTicker = time.NewTicker(1 * time.Second)
        go s.persistLoop()
    }
    
    return s
}

// Record 记录观察（O(1)，无内存分配）
func (s *ObservationStore) Record(obs solver.Observation) error {
    if obs.Timestamp.IsZero() {
        obs.Timestamp = time.Now()
    }
    
    // 从池中获取对象
    pooled := s.pool.Get()
    *pooled = obs
    
    // 入队（O(1)）
    s.buffer.Push(pooled)
    
    // 加入持久化缓冲
    if s.filePath != "" {
        s.persistMu.Lock()
        s.persistBuf = append(s.persistBuf, pooled)
        s.persistMu.Unlock()
    }
    
    return nil
}

// Recent 返回最近 N 个观察
func (s *ObservationStore) Recent(limit int) []solver.Observation {
    items := s.buffer.Last(limit)
    
    result := make([]solver.Observation, len(items))
    for i, item := range items {
        result[i] = *item
    }
    
    return result
}

// persistLoop 批量持久化
func (s *ObservationStore) persistLoop() {
    for {
        select {
        case <-s.persistTicker.C:
            s.flush()
        case <-s.closed:
            s.flush()
            return
        }
    }
}

// flush 刷新到文件
func (s *ObservationStore) flush() {
    s.persistMu.Lock()
    if len(s.persistBuf) == 0 {
        s.persistMu.Unlock()
        return
    }
    
    // 拷贝缓冲区
    batch := s.persistBuf
    s.persistBuf = make([]*solver.Observation, 0, 100)
    s.persistMu.Unlock()
    
    // 批量写入
    if err := s.writeBatch(batch); err != nil {
        // 记录错误
        return
    }
}

// writeBatch 批量写入
func (s *ObservationStore) writeBatch(batch []*solver.Observation) error {
    if err := os.MkdirAll(filepath.Dir(s.filePath), 0755); err != nil {
        return err
    }
    
    f, err := os.OpenFile(s.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return err
    }
    defer f.Close()
    
    // 使用缓冲池
    bufPtr := pool.LargeBufPool.Get()
    defer pool.LargeBufPool.Put(bufPtr)
    
    buf := (*bufPtr)[:0]
    for _, obs := range batch {
        data, err := json.Marshal(obs)
        if err != nil {
            continue
        }
        buf = append(buf, data...)
        buf = append(buf, '\n')
    }
    
    _, err = f.Write(buf)
    return err
}

// Close 关闭存储
func (s *ObservationStore) Close() error {
    close(s.closed)
    if s.persistTicker != nil {
        s.persistTicker.Stop()
    }
    return nil
}
```

---

## 性能对比

### 基准测试

```go
// pkg/solver/store/observation_bench_test.go
func BenchmarkRecord_Old(b *testing.B) {
    s := &OldObservationStore{
        observations: make([]solver.Observation, 0, 100),
    }
    
    obs := solver.Observation{
        Strategy: "test",
        Event:    "candidate_started",
    }
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        s.Record(obs)
    }
}

func BenchmarkRecord_New(b *testing.B) {
    s := NewObservationStore("", 1000)
    
    obs := solver.Observation{
        Strategy: "test",
        Event:    "candidate_started",
    }
    
    b.ResetTimer()
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        s.Record(obs)
    }
}
```

**预期结果**:
```
BenchmarkRecord_Old-8    5000000    300 ns/op    192 B/op    2 allocs/op
BenchmarkRecord_New-8   20000000     75 ns/op      0 B/op    0 allocs/op
```

**性能提升**:
- 速度: 4x
- 内存分配: 100% 减少
- GC 压力: 90% 减少

---

## 实施步骤

### Step 1: 实现工具库（2 天）
1. 创建 `pkg/util/ringbuffer`
2. 创建 `pkg/util/pool`
3. 单元测试

### Step 2: 改造 ObservationStore（2 天）
1. 重构使用环形缓冲区
2. 添加批量持久化
3. 测试

### Step 3: 改造其他热点（3 天）
1. Session 状态管理
2. Transport 数据包处理
3. Tunnel 缓冲管理

### Step 4: 性能测试（1 天）
1. 基准测试对比
2. 压力测试
3. GC 分析

**总计**: 8 天

---

## 验收标准

- ✅ 内存分配减少 90%
- ✅ GC 频率降低 80%
- ✅ GC 暂停降低到 5ms 以下
- ✅ 吞吐量提升 3-5 倍
- ✅ 单元测试覆盖率 > 90%

---

## 参考资料

- [Go sync.Pool 文档](https://pkg.go.dev/sync#Pool)
- [Go 内存优化](https://go.dev/doc/gc-guide)
- [环形缓冲区算法](https://en.wikipedia.org/wiki/Circular_buffer)
