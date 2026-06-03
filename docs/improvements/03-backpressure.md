# 改进方案 03：背压机制（Backpressure）

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: Channel 容量过小，没有溢出策略

**影响文件**: `pkg/session/session.go:94`

**问题代码**:
```go
// pkg/session/session.go:94
capabilityCh:  make(chan struct{}, 1),      // ❌ 只有 1 个缓冲
probeResultCh: make(chan probeResultSignal, 8),  // ❌ 只有 8 个缓冲
```

**严重问题**:
1. ❌ 没有溢出处理 - channel 满了就阻塞
2. ❌ 没有积压监控 - 不知道是否要降级
3. ❌ 没有流量控制 - 上游不知道下游处理能力
4. ❌ 缺少优雅降级机制

**实际影响**:
- 网络抖动时 probe 结果堆积，session 卡死
- 高负载下出现死锁
- 无法保护下游免于过载

---

## 改进方案

### 核心架构：带背压的事件总线

```go
// pkg/events/bus.go
package events

import (
    "context"
    "errors"
    "sync"
    "sync/atomic"
    "time"
)

// EventType 事件类型
type EventType string

const (
    EventCapability   EventType = "capability"
    EventProbeResult  EventType = "probe_result"
    EventObservation  EventType = "observation"
    EventStateChange  EventType = "state_change"
)

// Event 通用事件结构
type Event struct {
    Type      EventType
    Payload   interface{}
    Timestamp time.Time
    Priority  Priority
}

// Priority 优先级
type Priority int

const (
    PriorityLow Priority = iota
    PriorityNormal
    PriorityHigh
    PriorityCritical
)

// OverflowPolicy 溢出策略
type OverflowPolicy int

const (
    PolicyBlock      OverflowPolicy = iota // 阻塞发送者
    PolicyDropOldest                       // 丢弃最旧的事件
    PolicyDropNewest                       // 丢弃最新的事件
    PolicyDropLowest                       // 丢弃优先级最低的
)

// 错误定义
var (
    ErrEventDropped     = errors.New("event dropped due to overflow")
    ErrSubscriberClosed = errors.New("subscriber closed")
)

// EventBus 带背压的事件总线
type EventBus struct {
    mu          sync.RWMutex
    subscribers map[EventType][]*Subscriber
    metrics     *BusMetrics
    closed      atomic.Bool
}

// BusMetrics 总线指标
type BusMetrics struct {
    Published atomic.Int64
    Delivered atomic.Int64
    Dropped   atomic.Int64
    Blocked   atomic.Int64
}

// Subscriber 订阅者
type Subscriber struct {
    id       string
    ch       chan Event
    capacity int
    policy   OverflowPolicy
    
    // 指标
    received atomic.Int64
    dropped  atomic.Int64
    
    // 背压监控
    highWaterMark int  // 高水位（开始降级）
    lowWaterMark  int  // 低水位（恢复正常）
    degraded      atomic.Bool
    
    // 关闭控制
    closeOnce sync.Once
    closed    chan struct{}
}

// NewEventBus 创建事件总线
func NewEventBus() *EventBus {
    return &EventBus{
        subscribers: make(map[EventType][]*Subscriber),
        metrics:     &BusMetrics{},
    }
}

// Subscribe 订阅事件
func (b *EventBus) Subscribe(eventType EventType, opts SubscribeOptions) (*Subscriber, error) {
    if b.closed.Load() {
        return nil, errors.New("bus closed")
    }
    
    if opts.Capacity == 0 {
        opts.Capacity = 64
    }
    if opts.HighWaterMark == 0 {
        opts.HighWaterMark = opts.Capacity * 80 / 100
    }
    if opts.LowWaterMark == 0 {
        opts.LowWaterMark = opts.Capacity * 50 / 100
    }
    
    sub := &Subscriber{
        id:            opts.ID,
        ch:            make(chan Event, opts.Capacity),
        capacity:      opts.Capacity,
        policy:        opts.Policy,
        highWaterMark: opts.HighWaterMark,
        lowWaterMark:  opts.LowWaterMark,
        closed:        make(chan struct{}),
    }
    
    b.mu.Lock()
    b.subscribers[eventType] = append(b.subscribers[eventType], sub)
    b.mu.Unlock()
    
    return sub, nil
}

// SubscribeOptions 订阅选项
type SubscribeOptions struct {
    ID            string
    Capacity      int
    Policy        OverflowPolicy
    HighWaterMark int
    LowWaterMark  int
}

// Publish 发布事件
func (b *EventBus) Publish(ctx context.Context, event Event) error {
    if b.closed.Load() {
        return errors.New("bus closed")
    }
    
    b.metrics.Published.Add(1)
    
    if event.Timestamp.IsZero() {
        event.Timestamp = time.Now()
    }
    
    b.mu.RLock()
    subs := b.subscribers[event.Type]
    b.mu.RUnlock()
    
    for _, sub := range subs {
        if err := sub.send(ctx, event); err != nil {
            if errors.Is(err, ErrEventDropped) {
                b.metrics.Dropped.Add(1)
            }
        } else {
            b.metrics.Delivered.Add(1)
        }
    }
    
    return nil
}

// send 向订阅者发送事件
func (s *Subscriber) send(ctx context.Context, event Event) error {
    select {
    case <-s.closed:
        return ErrSubscriberClosed
    default:
    }
    
    // 检查背压状态
    s.checkBackpressure()
    
    // 尝试非阻塞发送
    select {
    case s.ch <- event:
        s.received.Add(1)
        return nil
    default:
        // Channel 满了，应用溢出策略
        return s.handleOverflow(ctx, event)
    }
}

// checkBackpressure 检查背压
func (s *Subscriber) checkBackpressure() {
    queueLen := len(s.ch)
    
    if queueLen >= s.highWaterMark && !s.degraded.Load() {
        s.degraded.Store(true)
        // 触发降级事件
    } else if queueLen <= s.lowWaterMark && s.degraded.Load() {
        s.degraded.Store(false)
        // 触发恢复事件
    }
}

// handleOverflow 处理溢出
func (s *Subscriber) handleOverflow(ctx context.Context, event Event) error {
    switch s.policy {
    case PolicyBlock:
        select {
        case s.ch <- event:
            s.received.Add(1)
            return nil
        case <-ctx.Done():
            return ctx.Err()
        case <-s.closed:
            return ErrSubscriberClosed
        }
        
    case PolicyDropOldest:
        // 丢弃最旧的事件
        select {
        case <-s.ch:
            s.dropped.Add(1)
        default:
        }
        // 重试发送
        select {
        case s.ch <- event:
            s.received.Add(1)
            return nil
        default:
            s.dropped.Add(1)
            return ErrEventDropped
        }
        
    case PolicyDropNewest:
        // 直接丢弃新事件
        s.dropped.Add(1)
        return ErrEventDropped
        
    case PolicyDropLowest:
        // 丢弃低优先级事件
        if event.Priority < PriorityHigh {
            s.dropped.Add(1)
            return ErrEventDropped
        }
        // 高优先级事件强制入队
        select {
        case <-s.ch:
            s.dropped.Add(1)
        default:
        }
        s.ch <- event
        s.received.Add(1)
        return nil
    }
    
    return ErrEventDropped
}

// Receive 接收事件
func (s *Subscriber) Receive(ctx context.Context) (Event, error) {
    select {
    case event := <-s.ch:
        return event, nil
    case <-ctx.Done():
        return Event{}, ctx.Err()
    case <-s.closed:
        return Event{}, ErrSubscriberClosed
    }
}

// Stats 获取订阅者统计
func (s *Subscriber) Stats() SubscriberStats {
    return SubscriberStats{
        ID:        s.id,
        QueueLen:  len(s.ch),
        Capacity:  s.capacity,
        Received:  s.received.Load(),
        Dropped:   s.dropped.Load(),
        Degraded:  s.degraded.Load(),
    }
}

// SubscriberStats 订阅者统计信息
type SubscriberStats struct {
    ID       string
    QueueLen int
    Capacity int
    Received int64
    Dropped  int64
    Degraded bool
}

// Close 关闭订阅者
func (s *Subscriber) Close() {
    s.closeOnce.Do(func() {
        close(s.closed)
    })
}

// Metrics 获取总线指标
func (b *EventBus) Metrics() BusMetrics {
    return BusMetrics{
        Published: atomic.Int64{},
        Delivered: atomic.Int64{},
        Dropped:   atomic.Int64{},
        Blocked:   atomic.Int64{},
    }
}

// Close 关闭事件总线
func (b *EventBus) Close() {
    b.closed.Store(true)
    
    b.mu.Lock()
    defer b.mu.Unlock()
    
    for _, subs := range b.subscribers {
        for _, sub := range subs {
            sub.Close()
        }
    }
}
```

---

## 在 Session 中的应用

```go
// pkg/session/session_v2.go
type Session struct {
    cfg     Config
    bus     *events.EventBus
    
    capabilitySub  *events.Subscriber
    probeResultSub *events.Subscriber
    observationSub *events.Subscriber
}

func (s *Session) Start(ctx context.Context) error {
    // 订阅 capability 事件（关键路径，使用阻塞策略）
    capSub, _ := s.bus.Subscribe(events.EventCapability, events.SubscribeOptions{
        ID:       "session-capability",
        Capacity: 4,
        Policy:   events.PolicyBlock,
    })
    s.capabilitySub = capSub
    
    // 订阅 probe 结果（可丢弃，丢最旧）
    probeSub, _ := s.bus.Subscribe(events.EventProbeResult, events.SubscribeOptions{
        ID:            "session-probe",
        Capacity:      32,
        Policy:        events.PolicyDropOldest,
        HighWaterMark: 25,
        LowWaterMark:  15,
    })
    s.probeResultSub = probeSub
    
    // 订阅 observation（按优先级丢弃）
    obsSub, _ := s.bus.Subscribe(events.EventObservation, events.SubscribeOptions{
        ID:       "session-observation",
        Capacity: 128,
        Policy:   events.PolicyDropLowest,
    })
    s.observationSub = obsSub
    
    return s.run(ctx)
}

// 监控背压状态
func (s *Session) monitorBackpressure(ctx context.Context) {
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            stats := s.probeResultSub.Stats()
            if stats.Degraded {
                // 触发降级处理：减少 probe 频率
                s.reducePrebeRate()
            }
        case <-ctx.Done():
            return
        }
    }
}
```

---

## 实施步骤

### Step 1: 实现事件总线（3 天）
1. 创建 `pkg/events/bus.go`
2. 实现订阅、发布、溢出策略
3. 单元测试

### Step 2: 重构 Session（2 天）
1. 替换 channel 为事件总线
2. 配置溢出策略
3. 测试

### Step 3: 监控集成（1 天）
1. 暴露指标到 Prometheus
2. 添加告警规则

### Step 4: 集成测试（1 天）
1. 压力测试
2. 故障注入测试

**总计**: 7 天

---

## 验收标准

- ✅ Channel 满时不阻塞关键路径
- ✅ 优先级机制正常工作
- ✅ 背压监控指标完整
- ✅ 高负载测试通过（1000 events/sec）
- ✅ 单元测试覆盖率 > 90%

---

## 参考资料

- [Reactive Streams 规范](https://www.reactive-streams.org/)
- [Go 并发模式 - 限流](https://go.dev/blog/pipelines)
- [Backpressure 策略](https://medium.com/@jayphelps/backpressure-explained-the-flow-of-data-through-software-2350b3e77ce7)
