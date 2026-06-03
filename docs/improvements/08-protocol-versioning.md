# 改进方案 08：协议版本化

## 问题描述

**当前状态**: 协议没有版本字段，无法平滑升级

**影响文件**: `pkg/rendezvous/proto/envelope.go`

**问题代码**:
```go
// 当前设计：❌ 没有版本字段
type SessionEnvelope struct {
    SessionID string          `json:"session_id"`
    FromNode  string          `json:"from_node"`
    ToNode    string          `json:"to_node"`
    MsgType   string          `json:"msg_type"`
    Seq       uint64          `json:"seq"`
    Ack       uint64          `json:"ack"`
    Payload   json.RawMessage `json:"payload,omitempty"`
}
```

**严重问题**:
1. ❌ 无法平滑升级协议
2. ❌ 新旧版本客户端无法互操作
3. ❌ 无法废弃旧字段
4. ❌ 无法添加新特性
5. ❌ 升级需要所有客户端同时停机

---

## 改进方案

### 协议版本化策略

```go
// pkg/rendezvous/proto/version.go
package proto

// ProtocolVersion 协议版本
type ProtocolVersion int

const (
    ProtocolV1 ProtocolVersion = 1
    ProtocolV2 ProtocolVersion = 2
    
    CurrentProtocolVersion = ProtocolV2
    MinSupportedVersion    = ProtocolV1
)

// VersionInfo 版本信息
type VersionInfo struct {
    Version      ProtocolVersion
    MinSupported ProtocolVersion
    Features     []string
}

// SupportedVersions 当前实现支持的版本
var SupportedVersions = []ProtocolVersion{
    ProtocolV1,
    ProtocolV2,
}

// Negotiate 协商版本（选择双方都支持的最高版本）
func Negotiate(local, remote []ProtocolVersion) (ProtocolVersion, error) {
    localSet := make(map[ProtocolVersion]bool)
    for _, v := range local {
        localSet[v] = true
    }
    
    var best ProtocolVersion
    found := false
    for _, v := range remote {
        if localSet[v] && v > best {
            best = v
            found = true
        }
    }
    
    if !found {
        return 0, ErrNoCompatibleVersion
    }
    
    return best, nil
}
```

### V2 信封设计

```go
// pkg/rendezvous/proto/envelope_v2.go
package proto

import (
    "encoding/json"
    "fmt"
    "time"
)

// SessionEnvelopeV2 v2 协议
type SessionEnvelopeV2 struct {
    Version   ProtocolVersion `json:"version"`
    SessionID string          `json:"session_id"`
    FromNode  string          `json:"from_node"`
    ToNode    string          `json:"to_node"`
    MsgType   string          `json:"msg_type"`
    Seq       uint64          `json:"seq"`
    Ack       uint64          `json:"ack"`
    Payload   json.RawMessage `json:"payload,omitempty"`
    
    // V2 新增字段
    Timestamp   time.Time `json:"timestamp,omitempty"`
    TTL         int64     `json:"ttl,omitempty"`         // 消息过期时间（毫秒）
    Compression string    `json:"compression,omitempty"` // "gzip", "zstd", ""
    Encryption  string    `json:"encryption,omitempty"`  // "aes256gcm", ""
    TraceID     string    `json:"trace_id,omitempty"`    // 分布式追踪
    SpanID      string    `json:"span_id,omitempty"`
    
    // 扩展字段（向前兼容）
    Extensions map[string]json.RawMessage `json:"ext,omitempty"`
}

// IsExpired 检查消息是否过期
func (e *SessionEnvelopeV2) IsExpired() bool {
    if e.TTL == 0 {
        return false
    }
    if e.Timestamp.IsZero() {
        return false
    }
    return time.Since(e.Timestamp) > time.Duration(e.TTL)*time.Millisecond
}

// GetExtension 获取扩展字段
func (e *SessionEnvelopeV2) GetExtension(name string, dst interface{}) error {
    raw, ok := e.Extensions[name]
    if !ok {
        return ErrExtensionNotFound
    }
    return json.Unmarshal(raw, dst)
}

// SetExtension 设置扩展字段
func (e *SessionEnvelopeV2) SetExtension(name string, value interface{}) error {
    if e.Extensions == nil {
        e.Extensions = make(map[string]json.RawMessage)
    }
    raw, err := json.Marshal(value)
    if err != nil {
        return err
    }
    e.Extensions[name] = raw
    return nil
}
```

### 版本兼容层

```go
// pkg/rendezvous/proto/codec.go
package proto

// Codec 协议编解码器
type Codec struct {
    version ProtocolVersion
}

// NewCodec 创建编解码器
func NewCodec(version ProtocolVersion) *Codec {
    return &Codec{version: version}
}

// Marshal 序列化
func (c *Codec) Marshal(env interface{}) ([]byte, error) {
    switch c.version {
    case ProtocolV1:
        return c.marshalV1(env)
    case ProtocolV2:
        return c.marshalV2(env)
    default:
        return nil, fmt.Errorf("unsupported version: %d", c.version)
    }
}

// Unmarshal 反序列化（自动检测版本）
func (c *Codec) Unmarshal(data []byte) (*UnifiedEnvelope, error) {
    // 先解析版本字段
    var probe struct {
        Version ProtocolVersion `json:"version"`
    }
    if err := json.Unmarshal(data, &probe); err != nil {
        // 没有 version 字段，假定为 V1
        probe.Version = ProtocolV1
    }
    
    if probe.Version == 0 {
        probe.Version = ProtocolV1
    }
    
    // 根据版本反序列化
    switch probe.Version {
    case ProtocolV1:
        var v1 SessionEnvelope
        if err := json.Unmarshal(data, &v1); err != nil {
            return nil, err
        }
        return c.upgradeV1ToUnified(&v1), nil
        
    case ProtocolV2:
        var v2 SessionEnvelopeV2
        if err := json.Unmarshal(data, &v2); err != nil {
            return nil, err
        }
        return c.v2ToUnified(&v2), nil
        
    default:
        return nil, fmt.Errorf("unsupported version: %d", probe.Version)
    }
}

// UnifiedEnvelope 统一信封（内部表示，向上兼容）
type UnifiedEnvelope struct {
    Version     ProtocolVersion
    SessionID   string
    FromNode    string
    ToNode      string
    MsgType     string
    Seq         uint64
    Ack         uint64
    Payload     json.RawMessage
    Timestamp   time.Time
    TTL         int64
    Compression string
    TraceID     string
    SpanID      string
    Extensions  map[string]json.RawMessage
}

// upgradeV1ToUnified 将 V1 升级为统一格式
func (c *Codec) upgradeV1ToUnified(v1 *SessionEnvelope) *UnifiedEnvelope {
    return &UnifiedEnvelope{
        Version:   ProtocolV1,
        SessionID: v1.SessionID,
        FromNode:  v1.FromNode,
        ToNode:    v1.ToNode,
        MsgType:   v1.MsgType,
        Seq:       v1.Seq,
        Ack:       v1.Ack,
        Payload:   v1.Payload,
        // V1 没有的字段使用零值
    }
}

// v2ToUnified V2 转换为统一格式
func (c *Codec) v2ToUnified(v2 *SessionEnvelopeV2) *UnifiedEnvelope {
    return &UnifiedEnvelope{
        Version:     v2.Version,
        SessionID:   v2.SessionID,
        FromNode:    v2.FromNode,
        ToNode:      v2.ToNode,
        MsgType:     v2.MsgType,
        Seq:         v2.Seq,
        Ack:         v2.Ack,
        Payload:     v2.Payload,
        Timestamp:   v2.Timestamp,
        TTL:         v2.TTL,
        Compression: v2.Compression,
        TraceID:     v2.TraceID,
        SpanID:      v2.SpanID,
        Extensions:  v2.Extensions,
    }
}

// Downgrade 降级到 V1（用于与旧客户端通信）
func (c *Codec) Downgrade(unified *UnifiedEnvelope) *SessionEnvelope {
    return &SessionEnvelope{
        SessionID: unified.SessionID,
        FromNode:  unified.FromNode,
        ToNode:    unified.ToNode,
        MsgType:   unified.MsgType,
        Seq:       unified.Seq,
        Ack:       unified.Ack,
        Payload:   unified.Payload,
    }
}
```

---

## 能力协商扩展

```go
// pkg/rendezvous/proto/capability_v2.go
package proto

// CapabilityV2 v2 能力描述
type CapabilityV2 struct {
    // V1 字段（向后兼容）
    Strategies []string `json:"strategies,omitempty"`
    Features   []string `json:"features,omitempty"`
    
    // V2 新增
    ProtocolVersions []ProtocolVersion `json:"protocol_versions,omitempty"`
    Compression      []string          `json:"compression,omitempty"`
    Encryption       []string          `json:"encryption,omitempty"`
    Extensions       map[string]bool   `json:"extensions,omitempty"`
}

// NegotiateProtocol 协商使用的协议版本
func NegotiateProtocol(local, remote *CapabilityV2) (ProtocolVersion, error) {
    if local == nil || remote == nil {
        return ProtocolV1, nil
    }
    
    localVersions := local.ProtocolVersions
    if len(localVersions) == 0 {
        localVersions = []ProtocolVersion{ProtocolV1}
    }
    
    remoteVersions := remote.ProtocolVersions
    if len(remoteVersions) == 0 {
        remoteVersions = []ProtocolVersion{ProtocolV1}
    }
    
    return Negotiate(localVersions, remoteVersions)
}
```

---

## 升级路径

### Phase 1: 引入 V2，但默认使用 V1

```go
// 客户端启动时
codec := proto.NewCodec(proto.ProtocolV1)  // 默认 V1

// 但能力广告中包含 V2
capability := proto.CapabilityV2{
    ProtocolVersions: []proto.ProtocolVersion{proto.ProtocolV1, proto.ProtocolV2},
}
```

### Phase 2: 协商使用 V2

```go
// 收到对端能力后
remoteCapability := receivedCapability
version, err := proto.NegotiateProtocol(localCapability, remoteCapability)
if err == nil {
    codec = proto.NewCodec(version)
}
```

### Phase 3: 全部升级到 V2 后废弃 V1

```go
// 6 个月后
// 移除 V1 支持
const MinSupportedVersion = ProtocolV2
```

---

## 向后兼容测试

```go
// pkg/rendezvous/proto/compat_test.go
func TestCompat_V1ClientToV2Server(t *testing.T) {
    // V1 客户端发送
    v1Env := &SessionEnvelope{
        SessionID: "test",
        MsgType:   "capability",
        Seq:       1,
    }
    v1Data, _ := json.Marshal(v1Env)
    
    // V2 服务端接收
    codec := NewCodec(ProtocolV2)
    unified, err := codec.Unmarshal(v1Data)
    if err != nil {
        t.Fatal(err)
    }
    
    if unified.Version != ProtocolV1 {
        t.Fatalf("version = %v, want V1", unified.Version)
    }
    
    if unified.SessionID != "test" {
        t.Fatalf("session_id = %v, want test", unified.SessionID)
    }
}

func TestCompat_V2ClientToV1Server(t *testing.T) {
    // V2 客户端
    v2Env := &SessionEnvelopeV2{
        Version:   ProtocolV2,
        SessionID: "test",
        MsgType:   "capability",
        TraceID:   "trace-123",
    }
    
    // 降级发送给 V1 服务端
    codec := NewCodec(ProtocolV1)
    unified := &UnifiedEnvelope{
        Version:   ProtocolV2,
        SessionID: v2Env.SessionID,
        MsgType:   v2Env.MsgType,
        TraceID:   v2Env.TraceID,
    }
    v1Env := codec.Downgrade(unified)
    v1Data, _ := json.Marshal(v1Env)
    
    // V1 服务端接收（不知道 V2 字段）
    var received SessionEnvelope
    json.Unmarshal(v1Data, &received)
    
    if received.SessionID != "test" {
        t.Fatalf("session_id = %v", received.SessionID)
    }
}
```

---

## 实施步骤

### Step 1: 设计 V2 协议（1 天）
1. 定义版本常量
2. 设计 V2 信封
3. Review

### Step 2: 实现 Codec（2 天）
1. 实现 Marshal/Unmarshal
2. 实现版本协商
3. 实现降级机制

### Step 3: 兼容性测试（1 天）
1. V1 ↔ V2 互通测试
2. 升级/降级测试

### Step 4: 集成（2 天）
1. 更新 session 使用 Codec
2. 更新 capability 协商
3. 集成测试

**总计**: 6 天

---

## 验收标准

- ✅ V1 和 V2 客户端互通
- ✅ 自动协商最高版本
- ✅ 未知字段被保留
- ✅ 协议升级文档完整
- ✅ 单元测试覆盖率 > 90%

---

## 参考资料

- [Protobuf 兼容性规则](https://developers.google.com/protocol-buffers/docs/proto3#updating)
- [API 版本化最佳实践](https://www.mnot.net/blog/2012/12/04/api-evolution)
