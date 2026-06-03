# 改进方案 09：增强的 Transport 接口

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: PacketTransport 接口过于简单，缺少高级特性

**影响文件**: `pkg/transport/transport.go`

**问题代码**:
```go
type PacketTransport interface {
    ReadPacket(ctx context.Context, dst []byte) (n int, meta PacketMeta, err error)
    WritePacket(ctx context.Context, pkt []byte) error
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    Close() error
}
```

**限制**:
1. ❌ 没有批量读写 - 每次只能读写一个包
2. ❌ 没有零拷贝支持 - 必须复制到 dst
3. ❌ 没有 QoS 控制 - 无法设置优先级
4. ❌ 没有统计信息 - 无法获取吞吐量、丢包率
5. ❌ 没有流量控制
6. ❌ 没有连接质量监控

**性能影响**:
- 单包读写有系统调用开销
- 数据复制浪费 CPU
- 无法应对突发流量

---

## 改进方案

### 增强的接口设计

```go
// pkg/transport/transport_v2.go
package transport

import (
    "context"
    "net"
    "time"
)

// PacketTransportV2 增强的传输接口
type PacketTransportV2 interface {
    // 基础操作（向后兼容）
    ReadPacket(ctx context.Context, dst []byte) (n int, meta PacketMeta, err error)
    WritePacket(ctx context.Context, pkt []byte) error
    
    // 批量操作（性能优化）
    ReadBatch(ctx context.Context, buffers [][]byte) ([]ReadResult, error)
    WriteBatch(ctx context.Context, packets [][]byte) error
    
    // 零拷贝（高级特性）
    ReadPacketZeroCopy(ctx context.Context) (Packet, error)
    WritePacketZeroCopy(ctx context.Context, pkt Packet) error
    
    // QoS 控制
    SetPriority(priority Priority) error
    SetBandwidthLimit(bytesPerSec int64) error
    
    // 统计信息
    Stats() TransportStats
    
    // 连接质量
    Quality() QualityMetrics
    
    // 生命周期
    LocalAddr() net.Addr
    RemoteAddr() net.Addr
    Close() error
}

// ReadResult 批量读取结果
type ReadResult struct {
    N    int
    Meta PacketMeta
    Err  error
}

// Packet 零拷贝数据包
type Packet interface {
    Data() []byte
    Meta() PacketMeta
    Release()  // 必须调用，归还到池
}

// Priority 优先级
type Priority int

const (
    PriorityLow Priority = iota
    PriorityNormal
    PriorityHigh
    PriorityCritical
)

// TransportStats 传输统计
type TransportStats struct {
    BytesSent       uint64
    BytesReceived   uint64
    PacketsSent     uint64
    PacketsReceived uint64
    PacketsLost     uint64
    PacketsDropped  uint64
    
    SendErrors    uint64
    ReceiveErrors uint64
    
    StartTime time.Time
    Uptime    time.Duration
}

// QualityMetrics 质量指标
type QualityMetrics struct {
    RTT            time.Duration  // 往返延迟
    Jitter         time.Duration  // 抖动
    PacketLossRate float64        // 丢包率（0-1）
    Bandwidth      int64          // 估计带宽（bytes/sec）
    LastUpdate     time.Time
}
```

---

## 批量读写实现

```go
// pkg/transport/iceadapter/transport_v2.go
package iceadapter

import (
    "context"
    "sync"
    "sync/atomic"
    "time"
    
    "winkyou/pkg/transport"
)

type transportV2 struct {
    inner transport.PacketTransport
    
    // 统计
    stats   transportStats
    quality qualityTracker
    
    // QoS
    priority      atomic.Int32
    bandwidth     atomic.Int64
    bandwidthCtl  *bandwidthLimiter
}

type transportStats struct {
    bytesSent       atomic.Uint64
    bytesReceived   atomic.Uint64
    packetsSent     atomic.Uint64
    packetsReceived atomic.Uint64
    packetsLost     atomic.Uint64
    packetsDropped  atomic.Uint64
    sendErrors      atomic.Uint64
    receiveErrors   atomic.Uint64
    startTime       time.Time
}

// ReadBatch 批量读取
func (t *transportV2) ReadBatch(ctx context.Context, buffers [][]byte) ([]transport.ReadResult, error) {
    results := make([]transport.ReadResult, len(buffers))
    
    // 简单实现：循环读取
    // 高级实现：使用 recvmmsg() 系统调用（Linux）
    for i := range buffers {
        n, meta, err := t.inner.ReadPacket(ctx, buffers[i])
        results[i] = transport.ReadResult{
            N:    n,
            Meta: meta,
            Err:  err,
        }
        
        if err != nil {
            t.stats.receiveErrors.Add(1)
            // 部分成功也返回
            return results[:i+1], nil
        }
        
        t.stats.bytesReceived.Add(uint64(n))
        t.stats.packetsReceived.Add(1)
    }
    
    return results, nil
}

// WriteBatch 批量写入
func (t *transportV2) WriteBatch(ctx context.Context, packets [][]byte) error {
    // 应用带宽限制
    if t.bandwidth.Load() > 0 {
        totalBytes := 0
        for _, pkt := range packets {
            totalBytes += len(pkt)
        }
        if err := t.bandwidthCtl.Wait(ctx, totalBytes); err != nil {
            return err
        }
    }
    
    // 简单实现：循环写入
    // 高级实现：使用 sendmmsg() 系统调用（Linux）
    for _, pkt := range packets {
        if err := t.inner.WritePacket(ctx, pkt); err != nil {
            t.stats.sendErrors.Add(1)
            return err
        }
        t.stats.bytesSent.Add(uint64(len(pkt)))
        t.stats.packetsSent.Add(1)
    }
    
    return nil
}
```

---

## 零拷贝实现

```go
// pkg/transport/zerocopy.go
package transport

import (
    "sync"
)

// poolPacket 池化的 Packet 实现
type poolPacket struct {
    data []byte
    meta PacketMeta
    pool *sync.Pool
}

func (p *poolPacket) Data() []byte {
    return p.data
}

func (p *poolPacket) Meta() PacketMeta {
    return p.meta
}

func (p *poolPacket) Release() {
    if p.pool != nil {
        p.data = p.data[:0]
        p.pool.Put(p)
    }
}

// PacketPool 数据包池
type PacketPool struct {
    pool sync.Pool
    size int
}

// NewPacketPool 创建池
func NewPacketPool(size int) *PacketPool {
    p := &PacketPool{size: size}
    p.pool.New = func() interface{} {
        return &poolPacket{
            data: make([]byte, 0, size),
            pool: &p.pool,
        }
    }
    return p
}

// Get 获取一个数据包
func (p *PacketPool) Get() Packet {
    return p.pool.Get().(*poolPacket)
}
```

---

## 带宽限制器

```go
// pkg/transport/bandwidth.go
package transport

import (
    "context"
    "sync"
    "time"
)

// bandwidthLimiter 令牌桶带宽限制器
type bandwidthLimiter struct {
    mu        sync.Mutex
    tokens    float64
    maxTokens float64
    rate      float64  // bytes/sec
    lastFill  time.Time
}

// newBandwidthLimiter 创建限制器
func newBandwidthLimiter(bytesPerSec int64) *bandwidthLimiter {
    return &bandwidthLimiter{
        tokens:    float64(bytesPerSec),
        maxTokens: float64(bytesPerSec),
        rate:      float64(bytesPerSec),
        lastFill:  time.Now(),
    }
}

// Wait 等待获取 n 字节的令牌
func (b *bandwidthLimiter) Wait(ctx context.Context, n int) error {
    for {
        b.mu.Lock()
        b.refill()
        
        if b.tokens >= float64(n) {
            b.tokens -= float64(n)
            b.mu.Unlock()
            return nil
        }
        
        // 计算等待时间
        needed := float64(n) - b.tokens
        waitDur := time.Duration(needed / b.rate * float64(time.Second))
        b.mu.Unlock()
        
        select {
        case <-time.After(waitDur):
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}

// refill 补充令牌
func (b *bandwidthLimiter) refill() {
    now := time.Now()
    elapsed := now.Sub(b.lastFill).Seconds()
    b.tokens += elapsed * b.rate
    if b.tokens > b.maxTokens {
        b.tokens = b.maxTokens
    }
    b.lastFill = now
}
```

---

## 质量监控

```go
// pkg/transport/quality.go
package transport

import (
    "sync"
    "time"
)

// qualityTracker 质量追踪器
type qualityTracker struct {
    mu sync.RWMutex
    
    // RTT 测量
    rttSamples    []time.Duration
    rttHead       int
    rttCount      int
    rttMaxSamples int
    
    // 丢包率
    sentSeqs   map[uint64]time.Time
    lostCount  int
    totalCount int
    
    // 带宽估计
    bandwidthSamples []int64
    bandwidthHead    int
    bandwidthMax     int
    
    lastUpdate time.Time
}

// newQualityTracker 创建追踪器
func newQualityTracker() *qualityTracker {
    return &qualityTracker{
        rttMaxSamples:    100,
        rttSamples:       make([]time.Duration, 100),
        sentSeqs:         make(map[uint64]time.Time),
        bandwidthMax:     10,
        bandwidthSamples: make([]int64, 10),
    }
}

// RecordRTT 记录 RTT
func (q *qualityTracker) RecordRTT(rtt time.Duration) {
    q.mu.Lock()
    defer q.mu.Unlock()
    
    q.rttSamples[q.rttHead] = rtt
    q.rttHead = (q.rttHead + 1) % q.rttMaxSamples
    if q.rttCount < q.rttMaxSamples {
        q.rttCount++
    }
    q.lastUpdate = time.Now()
}

// AvgRTT 平均 RTT
func (q *qualityTracker) AvgRTT() time.Duration {
    q.mu.RLock()
    defer q.mu.RUnlock()
    
    if q.rttCount == 0 {
        return 0
    }
    
    var total time.Duration
    for i := 0; i < q.rttCount; i++ {
        total += q.rttSamples[i]
    }
    return total / time.Duration(q.rttCount)
}

// Jitter 计算抖动（RTT 标准差的近似）
func (q *qualityTracker) Jitter() time.Duration {
    q.mu.RLock()
    defer q.mu.RUnlock()
    
    if q.rttCount < 2 {
        return 0
    }
    
    avg := q.AvgRTT()
    var sumDiff time.Duration
    for i := 0; i < q.rttCount; i++ {
        diff := q.rttSamples[i] - avg
        if diff < 0 {
            diff = -diff
        }
        sumDiff += diff
    }
    return sumDiff / time.Duration(q.rttCount)
}

// PacketLossRate 丢包率
func (q *qualityTracker) PacketLossRate() float64 {
    q.mu.RLock()
    defer q.mu.RUnlock()
    
    if q.totalCount == 0 {
        return 0
    }
    return float64(q.lostCount) / float64(q.totalCount)
}

// Snapshot 获取快照
func (q *qualityTracker) Snapshot() QualityMetrics {
    return QualityMetrics{
        RTT:            q.AvgRTT(),
        Jitter:         q.Jitter(),
        PacketLossRate: q.PacketLossRate(),
        LastUpdate:     q.lastUpdate,
    }
}
```

---

## 性能对比

### 基准测试

```go
func BenchmarkSinglePacket(b *testing.B) {
    t := newTransport()
    pkt := make([]byte, 1500)
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        t.WritePacket(ctx, pkt)
    }
}

func BenchmarkBatchPacket(b *testing.B) {
    t := newTransportV2()
    packets := make([][]byte, 32)
    for i := range packets {
        packets[i] = make([]byte, 1500)
    }
    
    b.ResetTimer()
    for i := 0; i < b.N/32; i++ {
        t.WriteBatch(ctx, packets)
    }
}
```

**预期结果**:
```
BenchmarkSinglePacket-8    500000    3000 ns/op
BenchmarkBatchPacket-8    5000000     800 ns/op
```

**性能提升**: 3-4x

---

## 实施步骤

### Step 1: 定义新接口（1 天）
1. 设计 PacketTransportV2
2. 设计辅助类型

### Step 2: 实现批量读写（3 天）
1. 通用实现
2. Linux recvmmsg/sendmmsg 优化
3. 基准测试

### Step 3: 实现零拷贝（2 天）
1. PacketPool
2. 集成到现有 transport

### Step 4: 实现 QoS（2 天）
1. 优先级队列
2. 带宽限制器

### Step 5: 实现质量监控（2 天）
1. RTT 测量
2. 丢包率统计
3. 带宽估计

### Step 6: 集成测试（2 天）
1. 性能测试
2. 兼容性测试

**总计**: 12 天

---

## 验收标准

- ✅ 批量操作吞吐量提升 3 倍以上
- ✅ 零拷贝降低 CPU 30%
- ✅ 带宽限制误差 < 5%
- ✅ 质量监控指标准确
- ✅ 向后兼容

---

## 参考资料

- [Linux recvmmsg](https://man7.org/linux/man-pages/man2/recvmmsg.2.html)
- [Token Bucket](https://en.wikipedia.org/wiki/Token_bucket)
- [QUIC 拥塞控制](https://datatracker.ietf.org/doc/html/rfc9002)
