# 改进方案 02：完整的状态机实现

## 问题描述

**当前状态**: 状态机过于简单，只有 25 行代码

**影响文件**: `pkg/session/state_machine.go`

**问题代码**:
```go
// pkg/session/state_machine.go - 只有 25 行！
type StateMachine struct {
    mu    sync.RWMutex
    state State
}

func (m *StateMachine) Transition(next State) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.state = next  // ❌ 没有任何验证！
}
```

**严重问题**:
1. ❌ 没有状态转换验证 - 可以从任意状态跳到任意状态
2. ❌ 没有转换历史 - 无法追踪状态变化
3. ❌ 没有转换钩子 - 无法在状态变化时执行清理
4. ❌ 没有超时机制 - 状态可能永久卡住

---

## 改进方案

### 完整的状态机设计

```go
// pkg/session/state_machine_v2.go
package session

import (
    "context"
    "fmt"
    "sync"
    "time"
)

// StateMachine 是一个完整的状态机实现
type StateMachine struct {
    mu          sync.RWMutex
    current     State
    history     []StateTransition
    transitions map[State][]State  // 允许的转换
    hooks       map[State][]TransitionHook
    timers      map[State]*time.Timer
    timeouts    map[State]time.Duration
    
    // 失败信息
    failureReason string
    
    // 配置
    maxHistory int
}

// StateTransition 记录状态转换
type StateTransition struct {
    From      State
    To        State
    Timestamp time.Time
    Reason    string
    Duration  time.Duration  // 在 From 状态停留的时间
}

// TransitionHook 是状态转换钩子
type TransitionHook func(from, to State) error

// StateMachineConfig 配置
type StateMachineConfig struct {
    InitialState State
    Transitions  map[State][]State
    Timeouts     map[State]time.Duration
    MaxHistory   int
}

// NewStateMachine 创建状态机
func NewStateMachine(cfg StateMachineConfig) *StateMachine {
    if cfg.MaxHistory == 0 {
        cfg.MaxHistory = 100
    }
    
    return &StateMachine{
        current:     cfg.InitialState,
        history:     make([]StateTransition, 0, cfg.MaxHistory),
        transitions: cfg.Transitions,
        hooks:       make(map[State][]TransitionHook),
        timers:      make(map[State]*time.Timer),
        timeouts:    cfg.Timeouts,
        maxHistory:  cfg.MaxHistory,
    }
}

// State 返回当前状态
func (m *StateMachine) State() State {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.current
}

// Transition 执行状态转换
func (m *StateMachine) Transition(next State, reason string) error {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    // 1. 验证转换是否合法
    if !m.isValidTransitionLocked(m.current, next) {
        return fmt.Errorf("invalid transition: %s -> %s", m.current, next)
    }
    
    // 2. 执行 pre-transition hooks
    for _, hook := range m.hooks[m.current] {
        if err := hook(m.current, next); err != nil {
            return fmt.Errorf("transition hook failed: %w", err)
        }
    }
    
    // 3. 计算在当前状态停留的时间
    var duration time.Duration
    if len(m.history) > 0 {
        lastTransition := m.history[len(m.history)-1]
        duration = time.Since(lastTransition.Timestamp)
    }
    
    // 4. 记录历史
    m.history = append(m.history, StateTransition{
        From:      m.current,
        To:        next,
        Timestamp: time.Now(),
        Reason:    reason,
        Duration:  duration,
    })
    
    // 限制历史长度
    if len(m.history) > m.maxHistory {
        m.history = m.history[len(m.history)-m.maxHistory:]
    }
    
    // 5. 取消旧状态的超时
    if timer, ok := m.timers[m.current]; ok {
        timer.Stop()
        delete(m.timers, m.current)
    }
    
    // 6. 执行转换
    old := m.current
    m.current = next
    
    // 7. 设置新状态的超时
    if timeout, ok := m.timeouts[next]; ok {
        m.timers[next] = time.AfterFunc(timeout, func() {
            m.onStateTimeout(next)
        })
    }
    
    return nil
}

// isValidTransitionLocked 检查转换是否合法（需要持有锁）
func (m *StateMachine) isValidTransitionLocked(from, to State) bool {
    // 允许转换到 Failed 和 Closed
    if to == StateFailed || to == StateClosed {
        return true
    }
    
    // 检查白名单
    allowed, ok := m.transitions[from]
    if !ok {
        return false
    }
    
    for _, s := range allowed {
        if s == to {
            return true
        }
    }
    
    return false
}

// onStateTimeout 处理状态超时
func (m *StateMachine) onStateTimeout(state State) {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    if m.current != state {
        return  // 已经转换到其他状态
    }
    
    // 根据状态决定超时行为
    switch state {
    case StateCapabilityExchange:
        m.current = StateFailed
        m.failureReason = "capability exchange timeout"
    case StatePlanning:
        m.current = StateFailed
        m.failureReason = "planning timeout"
    case StateExecuting:
        m.current = StateFailed
        m.failureReason = "execution timeout"
    case StateProbing:
        m.current = StateFailed
        m.failureReason = "probing timeout"
    default:
        m.current = StateFailed
        m.failureReason = fmt.Sprintf("timeout in state %s", state)
    }
    
    // 记录超时转换
    m.history = append(m.history, StateTransition{
        From:      state,
        To:        m.current,
        Timestamp: time.Now(),
        Reason:    "timeout",
    })
}

// OnEnter 注册进入状态时的钩子
func (m *StateMachine) OnEnter(state State, hook TransitionHook) {
    m.mu.Lock()
    defer m.mu.Unlock()
    m.hooks[state] = append(m.hooks[state], hook)
}

// History 返回状态转换历史
func (m *StateMachine) History() []StateTransition {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    result := make([]StateTransition, len(m.history))
    copy(result, m.history)
    return result
}

// FailureReason 返回失败原因
func (m *StateMachine) FailureReason() string {
    m.mu.RLock()
    defer m.mu.RUnlock()
    return m.failureReason
}

// Close 关闭状态机，取消所有定时器
func (m *StateMachine) Close() {
    m.mu.Lock()
    defer m.mu.Unlock()
    
    for _, timer := range m.timers {
        timer.Stop()
    }
    m.timers = make(map[State]*time.Timer)
}
```

---

## 状态转换图

```
StateNew
  ↓
StateCapabilityExchange (timeout: 2s)
  ↓
StateSelecting (timeout: 1s)
  ↓
StateProbing (timeout: 5s)
  ↓
StatePlanning (timeout: 3s)
  ↓
StateExecuting (timeout: 30s)
  ↓
StateBound
  ↓
StateClosed

任何状态都可以转换到 StateFailed
```

---

## 使用示例

### 初始化状态机

```go
// pkg/session/session.go
func New(cfg Config) (*Session, error) {
    // 定义允许的状态转换
    transitions := map[State][]State{
        StateNew: {
            StateCapabilityExchange,
        },
        StateCapabilityExchange: {
            StateSelecting,
        },
        StateSelecting: {
            StateProbing,
            StatePlanning,  // 如果不需要 probe
        },
        StateProbing: {
            StatePlanning,
        },
        StatePlanning: {
            StateExecuting,
        },
        StateExecuting: {
            StateBound,
            StateExecuting,  // 允许重试
        },
        StateBound: {
            StateClosed,
        },
    }
    
    // 定义状态超时
    timeouts := map[State]time.Duration{
        StateCapabilityExchange: 2 * time.Second,
        StateSelecting:          1 * time.Second,
        StateProbing:            5 * time.Second,
        StatePlanning:           3 * time.Second,
        StateExecuting:          30 * time.Second,
    }
    
    sm := NewStateMachine(StateMachineConfig{
        InitialState: StateNew,
        Transitions:  transitions,
        Timeouts:     timeouts,
        MaxHistory:   100,
    })
    
    // 注册钩子
    sm.OnEnter(StateClosed, func(from, to State) error {
        // 清理资源
        return nil
    })
    
    s := &Session{
        cfg: cfg,
        sm:  sm,
        // ...
    }
    
    return s, nil
}
```

### 执行状态转换

```go
// pkg/session/session.go
func (s *Session) Start(ctx context.Context) error {
    // 转换到 CapabilityExchange
    if err := s.sm.Transition(StateCapabilityExchange, "start"); err != nil {
        return err
    }
    
    // 发送 capability
    if err := s.sendCapability(ctx); err != nil {
        s.sm.Transition(StateFailed, fmt.Sprintf("send capability: %v", err))
        return err
    }
    
    // 等待远程 capability
    select {
    case <-s.capabilityCh:
        // 收到 capability，转换到 Selecting
        if err := s.sm.Transition(StateSelecting, "capability received"); err != nil {
            return err
        }
    case <-ctx.Done():
        s.sm.Transition(StateFailed, "context cancelled")
        return ctx.Err()
    }
    
    // ... 继续其他状态
    
    return nil
}
```

### 查询状态历史

```go
// pkg/session/session.go
func (s *Session) Snapshot() Snapshot {
    history := s.sm.History()
    
    return Snapshot{
        SessionID:       s.cfg.SessionID,
        State:           s.sm.State(),
        StateHistory:    history,
        FailureReason:   s.sm.FailureReason(),
        // ...
    }
}
```

---

## 测试

### 单元测试

```go
// pkg/session/state_machine_v2_test.go
func TestStateMachine_ValidTransition(t *testing.T) {
    sm := NewStateMachine(StateMachineConfig{
        InitialState: StateNew,
        Transitions: map[State][]State{
            StateNew: {StateCapabilityExchange},
            StateCapabilityExchange: {StateSelecting},
        },
    })
    
    // 合法转换
    err := sm.Transition(StateCapabilityExchange, "test")
    if err != nil {
        t.Fatalf("valid transition failed: %v", err)
    }
    
    if sm.State() != StateCapabilityExchange {
        t.Fatalf("state = %v, want %v", sm.State(), StateCapabilityExchange)
    }
}

func TestStateMachine_InvalidTransition(t *testing.T) {
    sm := NewStateMachine(StateMachineConfig{
        InitialState: StateNew,
        Transitions: map[State][]State{
            StateNew: {StateCapabilityExchange},
        },
    })
    
    // 非法转换
    err := sm.Transition(StatePlanning, "test")
    if err == nil {
        t.Fatal("invalid transition should fail")
    }
    
    // 状态不应该改变
    if sm.State() != StateNew {
        t.Fatalf("state = %v, want %v", sm.State(), StateNew)
    }
}

func TestStateMachine_Timeout(t *testing.T) {
    sm := NewStateMachine(StateMachineConfig{
        InitialState: StateNew,
        Transitions: map[State][]State{
            StateNew: {StateCapabilityExchange},
        },
        Timeouts: map[State]time.Duration{
            StateCapabilityExchange: 100 * time.Millisecond,
        },
    })
    
    // 转换到有超时的状态
    sm.Transition(StateCapabilityExchange, "test")
    
    // 等待超时
    time.Sleep(150 * time.Millisecond)
    
    // 应该自动转换到 Failed
    if sm.State() != StateFailed {
        t.Fatalf("state = %v, want %v", sm.State(), StateFailed)
    }
    
    if sm.FailureReason() != "capability exchange timeout" {
        t.Fatalf("reason = %v, want 'capability exchange timeout'", sm.FailureReason())
    }
}

func TestStateMachine_History(t *testing.T) {
    sm := NewStateMachine(StateMachineConfig{
        InitialState: StateNew,
        Transitions: map[State][]State{
            StateNew: {StateCapabilityExchange},
            StateCapabilityExchange: {StateSelecting},
        },
    })
    
    sm.Transition(StateCapabilityExchange, "reason1")
    sm.Transition(StateSelecting, "reason2")
    
    history := sm.History()
    if len(history) != 2 {
        t.Fatalf("history length = %d, want 2", len(history))
    }
    
    if history[0].From != StateNew || history[0].To != StateCapabilityExchange {
        t.Fatalf("first transition = %v -> %v, want %v -> %v",
            history[0].From, history[0].To, StateNew, StateCapabilityExchange)
    }
}
```

---

## 实施步骤

### Step 1: 实现新状态机（2 天）

1. 创建 `pkg/session/state_machine_v2.go`
2. 实现完整的状态机逻辑
3. 编写单元测试

### Step 2: 定义状态转换图（1 天）

1. 分析现有状态流程
2. 定义允许的转换
3. 设置合理的超时

### Step 3: 迁移 Session（2 天）

1. 更新 Session 使用新状态机
2. 添加状态转换调用
3. 处理超时情况

### Step 4: 集成测试（1 天）

1. 运行完整测试套件
2. 修复发现的问题
3. 验证超时机制

**总计**: 6 天

---

## 验收标准

### 功能验收

- ✅ 所有非法转换被拒绝
- ✅ 状态超时自动转换到 Failed
- ✅ 状态历史完整记录
- ✅ 钩子正确执行

### 测试验收

- ✅ 单元测试覆盖率 > 90%
- ✅ 集成测试通过
- ✅ 超时测试通过

---

## 参考资料

- [有限状态机](https://en.wikipedia.org/wiki/Finite-state_machine)
- [Go 状态机模式](https://github.com/looplab/fsm)
