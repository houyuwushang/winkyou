# 改进方案 10：混沌工程测试

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: 缺少混沌测试，生产环境表现不可预测

**当前测试覆盖**:
- ✅ 单元测试: 47 个文件
- ✅ 集成测试: 6 个文件
- ✅ E2E 测试: 6 个文件
- ❌ 混沌测试: 0
- ❌ 压力测试: 0

**问题分析**:
1. 当前测试都是正常路径
2. 没有测试网络抖动、丢包、延迟
3. 没有测试资源耗尽场景
4. 没有测试并发竞争条件

**实际风险**:
- 生产环境网络不稳定时可能崩溃
- 高负载下出现未知问题
- 边界条件未覆盖

---

## 改进方案

### 混沌工程框架

```go
// test/chaos/framework.go
package chaos

import (
    "context"
    "sync"
    "testing"
    "time"
)

// Scenario 混沌场景
type Scenario struct {
    Name        string
    Description string
    Faults      []Fault
    Duration    time.Duration
    Target      Target
    Assertions  []Assertion
    
    // 报告
    StartTime time.Time
    EndTime   time.Time
    Result    *Result
}

// Result 场景结果
type Result struct {
    Passed     bool
    Failures   []string
    Metrics    map[string]float64
    Events     []Event
}

// Event 事件
type Event struct {
    Timestamp time.Time
    Type      string
    Message   string
    Data      map[string]interface{}
}

// Fault 故障注入接口
type Fault interface {
    Name() string
    Inject(ctx context.Context, target Target) error
    Remove(ctx context.Context, target Target) error
}

// Target 目标系统
type Target interface {
    GetTransport() interface{}
    GetSession() interface{}
    GetEngine() interface{}
}

// Assertion 断言
type Assertion interface {
    Name() string
    Check(ctx context.Context, target Target) error
}

// Run 运行场景
func Run(t *testing.T, scenario *Scenario) {
    ctx, cancel := context.WithTimeout(context.Background(), scenario.Duration)
    defer cancel()
    
    scenario.StartTime = time.Now()
    scenario.Result = &Result{
        Metrics: make(map[string]float64),
        Events:  []Event{},
    }
    
    // 1. 注入故障
    for _, fault := range scenario.Faults {
        scenario.recordEvent("fault_injected", map[string]interface{}{
            "fault": fault.Name(),
        })
        
        if err := fault.Inject(ctx, scenario.Target); err != nil {
            t.Fatalf("inject fault %s: %v", fault.Name(), err)
        }
        
        defer func(f Fault) {
            f.Remove(ctx, scenario.Target)
        }(fault)
    }
    
    // 2. 持续验证断言
    var wg sync.WaitGroup
    for _, assertion := range scenario.Assertions {
        wg.Add(1)
        go func(a Assertion) {
            defer wg.Done()
            
            ticker := time.NewTicker(1 * time.Second)
            defer ticker.Stop()
            
            for {
                select {
                case <-ctx.Done():
                    return
                case <-ticker.C:
                    if err := a.Check(ctx, scenario.Target); err != nil {
                        scenario.Result.Failures = append(scenario.Result.Failures,
                            fmt.Sprintf("%s: %v", a.Name(), err))
                    }
                }
            }
        }(assertion)
    }
    
    // 3. 等待结束
    <-ctx.Done()
    wg.Wait()
    
    scenario.EndTime = time.Now()
    scenario.Result.Passed = len(scenario.Result.Failures) == 0
    
    if !scenario.Result.Passed {
        for _, failure := range scenario.Result.Failures {
            t.Errorf("assertion failed: %s", failure)
        }
    }
}
```

---

### 故障类型

#### 1. 网络故障

```go
// test/chaos/faults/network.go
package faults

import (
    "context"
    "math/rand"
    "time"
)

// NetworkFault 网络故障
type NetworkFault struct {
    PacketLoss   float64       // 丢包率 0.0-1.0
    Latency      time.Duration // 额外延迟
    Jitter       time.Duration // 抖动
    Bandwidth    int64         // 带宽限制
    Disconnect   bool          // 完全断开
    Duplicate    float64       // 重复率
    Reorder      float64       // 乱序率
}

func (f *NetworkFault) Name() string {
    return "network_fault"
}

func (f *NetworkFault) Inject(ctx context.Context, target Target) error {
    transport := target.GetTransport().(*FaultyTransport)
    transport.SetFault(f)
    return nil
}

func (f *NetworkFault) Remove(ctx context.Context, target Target) error {
    transport := target.GetTransport().(*FaultyTransport)
    transport.ClearFault()
    return nil
}

// FaultyTransport 包装 transport，注入故障
type FaultyTransport struct {
    inner transport.PacketTransport
    fault *NetworkFault
    mu    sync.RWMutex
}

func (t *FaultyTransport) WritePacket(ctx context.Context, pkt []byte) error {
    t.mu.RLock()
    fault := t.fault
    t.mu.RUnlock()
    
    if fault == nil {
        return t.inner.WritePacket(ctx, pkt)
    }
    
    // 完全断开
    if fault.Disconnect {
        return errors.New("disconnected")
    }
    
    // 丢包
    if fault.PacketLoss > 0 && rand.Float64() < fault.PacketLoss {
        return nil  // 静默丢弃
    }
    
    // 延迟
    if fault.Latency > 0 {
        delay := fault.Latency
        if fault.Jitter > 0 {
            delay += time.Duration(rand.Int63n(int64(fault.Jitter)))
        }
        select {
        case <-time.After(delay):
        case <-ctx.Done():
            return ctx.Err()
        }
    }
    
    // 重复
    if fault.Duplicate > 0 && rand.Float64() < fault.Duplicate {
        t.inner.WritePacket(ctx, pkt)
    }
    
    return t.inner.WritePacket(ctx, pkt)
}
```

#### 2. 资源故障

```go
// test/chaos/faults/resource.go
package faults

// ResourceFault 资源故障
type ResourceFault struct {
    MemoryPressure  bool          // 内存压力
    CPUSaturation   bool          // CPU 饱和
    GoroutineLeak   int           // 故意泄漏 N 个 goroutine
    FileDescriptor  int           // 文件描述符耗尽
}

func (f *ResourceFault) Inject(ctx context.Context, target Target) error {
    if f.MemoryPressure {
        go consumeMemory(ctx)
    }
    
    if f.CPUSaturation {
        go saturateCPU(ctx)
    }
    
    return nil
}

func consumeMemory(ctx context.Context) {
    var bigSlices [][]byte
    ticker := time.NewTicker(100 * time.Millisecond)
    defer ticker.Stop()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            bigSlices = append(bigSlices, make([]byte, 10*1024*1024))
        }
    }
}

func saturateCPU(ctx context.Context) {
    for i := 0; i < runtime.NumCPU(); i++ {
        go func() {
            for {
                select {
                case <-ctx.Done():
                    return
                default:
                    // 忙等待
                }
            }
        }()
    }
}
```

#### 3. 时钟故障

```go
// test/chaos/faults/clock.go
package faults

// ClockFault 时钟故障
type ClockFault struct {
    Skew      time.Duration  // 时钟偏移
    Frozen    bool           // 时钟冻结
    JumpForward time.Duration // 时钟跳跃
}

// 需要使用可控时钟接口
type Clock interface {
    Now() time.Time
    Sleep(d time.Duration)
}
```

---

### 标准断言

```go
// test/chaos/assertions/connectivity.go
package assertions

// SessionConnected 断言 session 连接正常
type SessionConnected struct {
    Timeout time.Duration
}

func (a *SessionConnected) Name() string {
    return "session_connected"
}

func (a *SessionConnected) Check(ctx context.Context, target Target) error {
    session := target.GetSession().(*session.Session)
    
    deadline := time.Now().Add(a.Timeout)
    for time.Now().Before(deadline) {
        if session.State() == session.StateBound {
            return nil
        }
        time.Sleep(100 * time.Millisecond)
    }
    
    return fmt.Errorf("session not connected after %v, state=%s",
        a.Timeout, session.State())
}

// ThroughputAbove 断言吞吐量
type ThroughputAbove struct {
    MinBytesPerSec int64
    Window         time.Duration
}

func (a *ThroughputAbove) Check(ctx context.Context, target Target) error {
    transport := target.GetTransport().(transport.PacketTransportV2)
    
    statsBefore := transport.Stats()
    time.Sleep(a.Window)
    statsAfter := transport.Stats()
    
    bytesPerSec := int64(float64(statsAfter.BytesReceived-statsBefore.BytesReceived) /
        a.Window.Seconds())
    
    if bytesPerSec < a.MinBytesPerSec {
        return fmt.Errorf("throughput %d B/s < %d B/s", bytesPerSec, a.MinBytesPerSec)
    }
    
    return nil
}

// NoGoroutineLeak 断言无 goroutine 泄漏
type NoGoroutineLeak struct {
    BaselineCount int
    Tolerance     int
}

func (a *NoGoroutineLeak) Check(ctx context.Context, target Target) error {
    current := runtime.NumGoroutine()
    if current > a.BaselineCount+a.Tolerance {
        return fmt.Errorf("goroutine count %d > %d (baseline=%d, tolerance=%d)",
            current, a.BaselineCount+a.Tolerance,
            a.BaselineCount, a.Tolerance)
    }
    return nil
}

// MemoryStable 断言内存稳定
type MemoryStable struct {
    MaxBytes  uint64
    Tolerance float64  // 0.1 = 10%
}

func (a *MemoryStable) Check(ctx context.Context, target Target) error {
    var stats runtime.MemStats
    runtime.ReadMemStats(&stats)
    
    if stats.HeapAlloc > a.MaxBytes {
        return fmt.Errorf("memory %d > %d", stats.HeapAlloc, a.MaxBytes)
    }
    
    return nil
}
```

---

### 测试场景示例

```go
// test/chaos/scenarios_test.go
package chaos_test

import (
    "testing"
    "time"
    
    "winkyou/test/chaos"
    "winkyou/test/chaos/assertions"
    "winkyou/test/chaos/faults"
)

func TestScenario_PacketLoss(t *testing.T) {
    scenario := &chaos.Scenario{
        Name: "Session resilience under 10% packet loss",
        Faults: []chaos.Fault{
            &faults.NetworkFault{
                PacketLoss: 0.1,
                Latency:    50 * time.Millisecond,
                Jitter:     20 * time.Millisecond,
            },
        },
        Duration: 60 * time.Second,
        Target:   setupTestTarget(t),
        Assertions: []chaos.Assertion{
            &assertions.SessionConnected{Timeout: 10 * time.Second},
            &assertions.ThroughputAbove{
                MinBytesPerSec: 1024 * 1024,  // 1 MB/s
                Window:         5 * time.Second,
            },
            &assertions.NoGoroutineLeak{
                BaselineCount: 50,
                Tolerance:     10,
            },
        },
    }
    
    chaos.Run(t, scenario)
}

func TestScenario_HighLatency(t *testing.T) {
    scenario := &chaos.Scenario{
        Name: "Session under high latency",
        Faults: []chaos.Fault{
            &faults.NetworkFault{
                Latency: 500 * time.Millisecond,
                Jitter:  100 * time.Millisecond,
            },
        },
        Duration: 60 * time.Second,
        Target:   setupTestTarget(t),
        Assertions: []chaos.Assertion{
            &assertions.SessionConnected{Timeout: 30 * time.Second},
        },
    }
    
    chaos.Run(t, scenario)
}

func TestScenario_NetworkPartition(t *testing.T) {
    scenario := &chaos.Scenario{
        Name: "Session recovery from network partition",
        Faults: []chaos.Fault{
            // 30s 后断开 10s
            &faults.TimedFault{
                Delay:    30 * time.Second,
                Duration: 10 * time.Second,
                Inner: &faults.NetworkFault{
                    Disconnect: true,
                },
            },
        },
        Duration: 90 * time.Second,
        Target:   setupTestTarget(t),
        Assertions: []chaos.Assertion{
            &assertions.SessionEventuallyReconnects{
                Within: 30 * time.Second,
            },
        },
    }
    
    chaos.Run(t, scenario)
}

func TestScenario_MemoryPressure(t *testing.T) {
    scenario := &chaos.Scenario{
        Name: "Session under memory pressure",
        Faults: []chaos.Fault{
            &faults.ResourceFault{
                MemoryPressure: true,
            },
        },
        Duration: 60 * time.Second,
        Target:   setupTestTarget(t),
        Assertions: []chaos.Assertion{
            &assertions.SessionConnected{Timeout: 10 * time.Second},
            &assertions.NoCrash{},
        },
    }
    
    chaos.Run(t, scenario)
}
```

---

### 压力测试

```go
// test/stress/load_test.go
package stress

import (
    "sync"
    "testing"
    "time"
)

func TestLoad_1000Connections(t *testing.T) {
    if testing.Short() {
        t.Skip("skipping in short mode")
    }
    
    const numConnections = 1000
    const duration = 5 * time.Minute
    
    engine := setupTestEngine(t)
    
    var wg sync.WaitGroup
    errors := make(chan error, numConnections)
    
    for i := 0; i < numConnections; i++ {
        wg.Add(1)
        go func(id int) {
            defer wg.Done()
            
            peerID := fmt.Sprintf("peer-%d", id)
            ctx, cancel := context.WithTimeout(context.Background(), duration)
            defer cancel()
            
            if err := engine.Connect(ctx, peerID); err != nil {
                errors <- fmt.Errorf("peer %d: %v", id, err)
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    var errCount int
    for err := range errors {
        t.Logf("error: %v", err)
        errCount++
    }
    
    successRate := float64(numConnections-errCount) / float64(numConnections)
    if successRate < 0.99 {
        t.Fatalf("success rate %.2f%% < 99%%", successRate*100)
    }
}
```

---

## CI 集成

```yaml
# .github/workflows/chaos.yml
name: Chaos Tests

on:
  schedule:
    - cron: '0 0 * * *'  # 每天运行
  workflow_dispatch:

jobs:
  chaos:
    runs-on: ubuntu-latest
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      
      - name: Run chaos tests
        run: |
          go test -v -timeout=60m ./test/chaos/...
      
      - name: Run stress tests
        run: |
          go test -v -timeout=60m ./test/stress/...
      
      - name: Upload results
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: chaos-results
          path: test-results/
```

---

## 实施步骤

### Step 1: 实现框架（3 天）
1. Scenario / Fault / Assertion 接口
2. Runner 实现
3. 基础测试

### Step 2: 实现故障类型（4 天）
1. 网络故障
2. 资源故障
3. 时钟故障

### Step 3: 实现断言（2 天）
1. 连接性断言
2. 性能断言
3. 资源断言

### Step 4: 编写场景（3 天）
1. 网络故障场景
2. 资源故障场景
3. 综合场景

### Step 5: CI 集成（1 天）
1. GitHub Actions
2. 报告生成

**总计**: 13 天

---

## 验收标准

- ✅ 至少 10 个混沌场景
- ✅ 在 10% 丢包下 session 能保持连接
- ✅ 在 500ms 延迟下能正常工作
- ✅ 网络分区后 30s 内恢复
- ✅ 1000 并发连接稳定运行
- ✅ 无 goroutine 泄漏
- ✅ 内存使用稳定

---

## 参考资料

- [Chaos Engineering 原则](https://principlesofchaos.org/)
- [Netflix Chaos Monkey](https://github.com/Netflix/chaosmonkey)
- [Go testing 包](https://pkg.go.dev/testing)
