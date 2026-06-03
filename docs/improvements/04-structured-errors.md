# 改进方案 04：结构化错误系统

## 问题描述

**当前状态**: 错误处理简陋，丢失上下文

**影响范围**: 整个代码库

**问题代码**:
```go
// pkg/session/session.go - 大量类似代码
if err != nil {
    return err  // ❌ 丢失上下文
}

// pkg/solver/strategy/legacyice/executor.go:64
if _, err := e.ensureAgent(ctx); err != nil {
    return solver.Result{}, err  // ❌ 没有包装
}
```

**严重问题**:
1. ❌ 错误传播时丢失调用栈
2. ❌ 无法区分错误类型（网络/认证/配置）
3. ❌ 难以定位问题根源
4. ❌ 用户看到的错误信息不友好
5. ❌ 无法判断是否可重试

---

## 改进方案

### 核心错误类型

```go
// pkg/errors/errors.go
package errors

import (
    "errors"
    "fmt"
    "runtime"
    "strings"
    "time"
)

// ErrorCode 错误代码
type ErrorCode string

const (
    // 网络相关
    CodeNetworkTimeout    ErrorCode = "NETWORK_TIMEOUT"
    CodeNetworkUnreachable ErrorCode = "NETWORK_UNREACHABLE"
    CodeConnectionRefused ErrorCode = "CONNECTION_REFUSED"
    CodeDNSFailure        ErrorCode = "DNS_FAILURE"
    
    // 认证相关
    CodeAuthFailed       ErrorCode = "AUTH_FAILED"
    CodeAuthExpired      ErrorCode = "AUTH_EXPIRED"
    CodeInvalidKey       ErrorCode = "INVALID_KEY"
    
    // 配置相关
    CodeInvalidConfig    ErrorCode = "INVALID_CONFIG"
    CodeMissingConfig    ErrorCode = "MISSING_CONFIG"
    
    // 权限相关
    CodePermissionDenied ErrorCode = "PERMISSION_DENIED"
    CodeRequiresAdmin    ErrorCode = "REQUIRES_ADMIN"
    
    // 协议相关
    CodeProtocolError    ErrorCode = "PROTOCOL_ERROR"
    CodeVersionMismatch  ErrorCode = "VERSION_MISMATCH"
    
    // 资源相关
    CodeResourceExhausted ErrorCode = "RESOURCE_EXHAUSTED"
    CodeTimeout           ErrorCode = "TIMEOUT"
    
    // 内部错误
    CodeInternal         ErrorCode = "INTERNAL"
    CodeNotImplemented   ErrorCode = "NOT_IMPLEMENTED"
    CodeAborted          ErrorCode = "ABORTED"
)

// Severity 错误严重程度
type Severity int

const (
    SeverityDebug Severity = iota
    SeverityInfo
    SeverityWarning
    SeverityError
    SeverityCritical
)

// Error 结构化错误
type Error struct {
    Code      ErrorCode              // 错误代码
    Message   string                 // 技术描述
    UserMsg   string                 // 用户友好的描述
    Cause     error                  // 原始错误
    Stack     []StackFrame           // 调用栈
    Context   map[string]interface{} // 上下文信息
    Timestamp time.Time              // 发生时间
    Severity  Severity               // 严重程度
    Retryable bool                   // 是否可重试
    Suggestion string                // 解决建议
}

// StackFrame 栈帧
type StackFrame struct {
    Function string
    File     string
    Line     int
}

// Error 实现 error 接口
func (e *Error) Error() string {
    if e.Cause != nil {
        return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
    }
    return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap 支持 errors.Is/As
func (e *Error) Unwrap() error {
    return e.Cause
}

// Is 比较错误代码
func (e *Error) Is(target error) bool {
    var t *Error
    if errors.As(target, &t) {
        return e.Code == t.Code
    }
    return false
}

// New 创建新错误
func New(code ErrorCode, message string) *Error {
    return &Error{
        Code:      code,
        Message:   message,
        Stack:     captureStack(2),
        Context:   make(map[string]interface{}),
        Timestamp: time.Now(),
        Severity:  SeverityError,
        Retryable: isRetryable(code),
    }
}

// Wrap 包装错误
func Wrap(err error, code ErrorCode, message string) *Error {
    if err == nil {
        return nil
    }
    
    // 如果已经是 *Error，保留原始信息
    var existing *Error
    if errors.As(err, &existing) {
        return &Error{
            Code:      code,
            Message:   message,
            Cause:     err,
            Stack:     captureStack(2),
            Context:   copyContext(existing.Context),
            Timestamp: time.Now(),
            Severity:  existing.Severity,
            Retryable: existing.Retryable,
        }
    }
    
    return &Error{
        Code:      code,
        Message:   message,
        Cause:     err,
        Stack:     captureStack(2),
        Context:   make(map[string]interface{}),
        Timestamp: time.Now(),
        Severity:  SeverityError,
        Retryable: isRetryable(code),
    }
}

// WithContext 添加上下文
func (e *Error) WithContext(key string, value interface{}) *Error {
    if e.Context == nil {
        e.Context = make(map[string]interface{})
    }
    e.Context[key] = value
    return e
}

// WithUserMessage 添加用户消息
func (e *Error) WithUserMessage(msg string) *Error {
    e.UserMsg = msg
    return e
}

// WithSuggestion 添加解决建议
func (e *Error) WithSuggestion(suggestion string) *Error {
    e.Suggestion = suggestion
    return e
}

// WithSeverity 设置严重程度
func (e *Error) WithSeverity(severity Severity) *Error {
    e.Severity = severity
    return e
}

// WithRetryable 设置是否可重试
func (e *Error) WithRetryable(retryable bool) *Error {
    e.Retryable = retryable
    return e
}

// Code 获取错误代码
func Code(err error) ErrorCode {
    var e *Error
    if errors.As(err, &e) {
        return e.Code
    }
    return CodeInternal
}

// IsRetryable 检查是否可重试
func IsRetryable(err error) bool {
    var e *Error
    if errors.As(err, &e) {
        return e.Retryable
    }
    return false
}

// UserMessage 获取用户消息
func UserMessage(err error) string {
    var e *Error
    if errors.As(err, &e) {
        if e.UserMsg != "" {
            return e.UserMsg
        }
        return defaultUserMessage(e.Code)
    }
    return "An unknown error occurred"
}

// captureStack 捕获调用栈
func captureStack(skip int) []StackFrame {
    const maxDepth = 32
    pcs := make([]uintptr, maxDepth)
    n := runtime.Callers(skip+1, pcs)
    
    frames := make([]StackFrame, 0, n)
    runtimeFrames := runtime.CallersFrames(pcs[:n])
    
    for {
        frame, more := runtimeFrames.Next()
        if !strings.Contains(frame.File, "runtime/") {
            frames = append(frames, StackFrame{
                Function: frame.Function,
                File:     frame.File,
                Line:     frame.Line,
            })
        }
        if !more {
            break
        }
    }
    
    return frames
}

// isRetryable 判断错误是否可重试
func isRetryable(code ErrorCode) bool {
    switch code {
    case CodeNetworkTimeout, CodeNetworkUnreachable, CodeConnectionRefused,
         CodeDNSFailure, CodeTimeout, CodeResourceExhausted:
        return true
    case CodeAuthFailed, CodeAuthExpired, CodeInvalidKey,
         CodeInvalidConfig, CodeMissingConfig,
         CodePermissionDenied, CodeRequiresAdmin,
         CodeNotImplemented:
        return false
    default:
        return false
    }
}

// defaultUserMessage 默认用户消息
func defaultUserMessage(code ErrorCode) string {
    switch code {
    case CodeNetworkTimeout:
        return "网络连接超时，请检查网络状态"
    case CodeNetworkUnreachable:
        return "无法访问目标网络"
    case CodeConnectionRefused:
        return "连接被拒绝，目标服务可能未启动"
    case CodeDNSFailure:
        return "域名解析失败"
    case CodeAuthFailed:
        return "认证失败，请检查凭据"
    case CodeAuthExpired:
        return "认证已过期，请重新登录"
    case CodeInvalidConfig:
        return "配置无效，请检查配置文件"
    case CodePermissionDenied:
        return "权限不足"
    case CodeRequiresAdmin:
        return "需要管理员权限"
    default:
        return "操作失败"
    }
}

// copyContext 深拷贝上下文
func copyContext(ctx map[string]interface{}) map[string]interface{} {
    if ctx == nil {
        return make(map[string]interface{})
    }
    out := make(map[string]interface{}, len(ctx))
    for k, v := range ctx {
        out[k] = v
    }
    return out
}
```

---

## 错误格式化

```go
// pkg/errors/format.go
package errors

import (
    "encoding/json"
    "fmt"
    "strings"
)

// Format 格式化错误（用于日志）
func Format(err error) string {
    var e *Error
    if !errors.As(err, &e) {
        return err.Error()
    }
    
    var sb strings.Builder
    sb.WriteString(fmt.Sprintf("[%s] %s\n", e.Code, e.Message))
    
    if e.UserMsg != "" {
        sb.WriteString(fmt.Sprintf("User Message: %s\n", e.UserMsg))
    }
    
    if e.Suggestion != "" {
        sb.WriteString(fmt.Sprintf("Suggestion: %s\n", e.Suggestion))
    }
    
    if len(e.Context) > 0 {
        sb.WriteString("Context:\n")
        for k, v := range e.Context {
            sb.WriteString(fmt.Sprintf("  %s = %v\n", k, v))
        }
    }
    
    if e.Cause != nil {
        sb.WriteString(fmt.Sprintf("Caused by: %v\n", e.Cause))
    }
    
    if len(e.Stack) > 0 {
        sb.WriteString("Stack:\n")
        for _, frame := range e.Stack {
            sb.WriteString(fmt.Sprintf("  %s\n    %s:%d\n",
                frame.Function, frame.File, frame.Line))
        }
    }
    
    return sb.String()
}

// ToJSON 序列化为 JSON
func (e *Error) ToJSON() ([]byte, error) {
    return json.Marshal(map[string]interface{}{
        "code":       string(e.Code),
        "message":    e.Message,
        "user_msg":   e.UserMsg,
        "suggestion": e.Suggestion,
        "severity":   e.Severity,
        "retryable":  e.Retryable,
        "timestamp":  e.Timestamp,
        "context":    e.Context,
        "stack":      e.Stack,
    })
}
```

---

## 使用示例

### 基础使用

```go
// pkg/solver/strategy/legacyice/executor.go
func (e *executor) ensureAgent(ctx context.Context) (nat.ICEAgent, error) {
    agent, err := e.cfg.NewICEAgent(ctx, AgentRequest{...})
    if err != nil {
        return nil, errors.Wrap(err, errors.CodeNetworkTimeout, "failed to create ICE agent").
            WithContext("strategy", StrategyName).
            WithContext("plan_id", e.plan.ID).
            WithContext("initiator", e.input.Initiator).
            WithUserMessage("无法建立连接代理").
            WithSuggestion("请检查 STUN/TURN 服务器配置")
    }
    return agent, nil
}
```

### 错误处理

```go
// pkg/client/peer_session.go
func (e *engine) handlePeerSessionError(nodeID string, s *peerSession, err error) {
    var winkErr *errors.Error
    if errors.As(err, &winkErr) {
        // 根据错误类型决定处理方式
        switch winkErr.Code {
        case errors.CodeNetworkTimeout:
            if errors.IsRetryable(err) {
                e.scheduleRetry(s, winkErr)
            }
        case errors.CodeAuthFailed:
            e.notifyUser("认证失败，请重新配置凭据")
        case errors.CodePermissionDenied:
            e.notifyUser("需要管理员权限")
        }
    }
    
    e.log.Error("peer session error",
        "node_id", nodeID,
        "error", errors.Format(err))
}
```

### 重试逻辑

```go
// pkg/client/retry.go
func (e *engine) retryWithBackoff(ctx context.Context, fn func() error) error {
    backoff := time.Second
    maxBackoff := 30 * time.Second
    
    for attempt := 0; ; attempt++ {
        err := fn()
        if err == nil {
            return nil
        }
        
        // 检查是否可重试
        if !errors.IsRetryable(err) {
            return err
        }
        
        // 退避
        select {
        case <-time.After(backoff):
            backoff *= 2
            if backoff > maxBackoff {
                backoff = maxBackoff
            }
        case <-ctx.Done():
            return ctx.Err()
        }
    }
}
```

---

## 实施步骤

### Step 1: 实现错误库（2 天）
1. 创建 `pkg/errors/` 包
2. 实现 Error 结构和方法
3. 单元测试

### Step 2: 迁移核心包（5 天）
1. 改造 `pkg/session`
2. 改造 `pkg/solver/strategy/legacyice`
3. 改造 `pkg/client`
4. 改造 `pkg/transport`

### Step 3: 用户界面（2 天）
1. CLI 错误显示
2. 日志格式化
3. 错误聚合

### Step 4: 测试（1 天）
1. 错误传播测试
2. 重试逻辑测试

**总计**: 10 天

---

## 验收标准

- ✅ 所有错误带有错误码和上下文
- ✅ 错误调用栈完整
- ✅ 用户错误消息友好
- ✅ 可重试错误自动重试
- ✅ 单元测试覆盖率 > 90%

---

## 参考资料

- [Go 错误处理最佳实践](https://go.dev/blog/error-handling-and-go)
- [pkg/errors 库](https://github.com/pkg/errors)
- [errors 包文档](https://pkg.go.dev/errors)
