# 改进方案 05：分布式追踪

> [!IMPORTANT]
> **Proposal / Archive**: This improvement note is part of the 2026-05 architecture overhaul proposal set. It is historical reference material, not the active implementation plan. See [`../CONNECTIVITY-SOLVER-BASELINE.md`](../CONNECTIVITY-SOLVER-BASELINE.md) for the current baseline.

## 问题描述

**当前状态**: 缺少分布式追踪能力

**问题分析**:
一个连接请求涉及多个组件：
```
Coordinator ← Session ← Solver ← Strategy ← ICE ← Transport ← Tunnel
```

当前问题：
1. ❌ 无法追踪请求在各组件间的流转
2. ❌ 难以定位性能瓶颈
3. ❌ 无法分析端到端延迟
4. ❌ 调试困难

**实际案例**:
```
用户报告: "连接建立很慢（10 秒）"

当前定位流程:
1. 在每个组件加日志 (1h)
2. 重现问题 (30min)
3. 分析日志 (1h)
4. 定位到 STUN 响应慢
总耗时: 2.5 小时

如果有分布式追踪:
1. 查看 trace 火焰图 (1min)
2. 直接定位 STUN 阶段
总耗时: 1 分钟
```

---

## 改进方案

### 选用 OpenTelemetry

**理由**:
- 工业标准，跨语言
- 厂商无关（可对接 Jaeger, Zipkin, Datadog 等）
- Go 官方支持成熟

### 核心追踪框架

```go
// pkg/tracing/tracer.go
package tracing

import (
    "context"
    "fmt"
    "time"
    
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/codes"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/sdk/resource"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
    "go.opentelemetry.io/otel/trace"
)

// Config 追踪配置
type Config struct {
    ServiceName    string
    ServiceVersion string
    Environment    string
    Endpoint       string  // OTLP 端点
    SampleRate     float64
    Enabled        bool
}

// Tracer 追踪器
type Tracer struct {
    tp     *sdktrace.TracerProvider
    tracer trace.Tracer
}

// NewTracer 创建追踪器
func NewTracer(ctx context.Context, cfg Config) (*Tracer, error) {
    if !cfg.Enabled {
        return &Tracer{
            tracer: trace.NewNoopTracerProvider().Tracer(""),
        }, nil
    }
    
    // 创建 OTLP exporter
    exporter, err := otlptrace.New(
        ctx,
        otlptracegrpc.NewClient(
            otlptracegrpc.WithEndpoint(cfg.Endpoint),
            otlptracegrpc.WithInsecure(),
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("create OTLP exporter: %w", err)
    }
    
    // 创建资源
    res, err := resource.New(ctx,
        resource.WithAttributes(
            semconv.ServiceName(cfg.ServiceName),
            semconv.ServiceVersion(cfg.ServiceVersion),
            attribute.String("environment", cfg.Environment),
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("create resource: %w", err)
    }
    
    // 创建 TracerProvider
    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter),
        sdktrace.WithResource(res),
        sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRate)),
    )
    
    otel.SetTracerProvider(tp)
    
    return &Tracer{
        tp:     tp,
        tracer: tp.Tracer(cfg.ServiceName),
    }, nil
}

// Start 开始一个 span
func (t *Tracer) Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
    return t.tracer.Start(ctx, name, opts...)
}

// Shutdown 关闭追踪器
func (t *Tracer) Shutdown(ctx context.Context) error {
    if t.tp == nil {
        return nil
    }
    return t.tp.Shutdown(ctx)
}

// 全局追踪器
var globalTracer *Tracer

// SetGlobal 设置全局追踪器
func SetGlobal(t *Tracer) {
    globalTracer = t
}

// Global 获取全局追踪器
func Global() *Tracer {
    if globalTracer == nil {
        return &Tracer{
            tracer: trace.NewNoopTracerProvider().Tracer(""),
        }
    }
    return globalTracer
}
```

---

## 在各组件中的使用

### Session 组件

```go
// pkg/session/session.go
import "winkyou/pkg/tracing"

func (s *Session) Start(ctx context.Context) error {
    ctx, span := tracing.Global().Start(ctx, "session.Start",
        trace.WithAttributes(
            attribute.String("session.id", s.cfg.SessionID),
            attribute.String("peer.id", s.cfg.PeerID),
            attribute.Bool("initiator", s.cfg.Initiator),
        ))
    defer span.End()
    
    // 1. 能力交换
    if err := s.exchangeCapability(ctx); err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "capability exchange failed")
        return err
    }
    
    // 2. 策略选择
    if err := s.selectStrategy(ctx); err != nil {
        span.RecordError(err)
        span.SetStatus(codes.Error, "strategy selection failed")
        return err
    }
    
    // 3. 计划生成
    if err := s.plan(ctx); err != nil {
        span.RecordError(err)
        return err
    }
    
    // 4. 执行
    if err := s.execute(ctx); err != nil {
        span.RecordError(err)
        return err
    }
    
    span.SetStatus(codes.Ok, "")
    return nil
}

func (s *Session) exchangeCapability(ctx context.Context) error {
    ctx, span := tracing.Global().Start(ctx, "session.exchangeCapability")
    defer span.End()
    
    span.SetAttributes(
        attribute.StringSlice("local.strategies", s.localCapability.Strategies),
    )
    
    // 发送 capability
    if err := s.sendCapability(ctx); err != nil {
        span.RecordError(err)
        return err
    }
    
    // 等待远程 capability
    select {
    case <-s.capabilityCh:
        span.AddEvent("capability_received",
            trace.WithAttributes(
                attribute.StringSlice("remote.strategies", s.remoteCapability.Strategies),
            ))
        return nil
    case <-ctx.Done():
        span.RecordError(ctx.Err())
        return ctx.Err()
    }
}
```

### Strategy 组件

```go
// pkg/solver/strategy/legacyice/executor.go
func (e *executor) Execute(ctx context.Context, sess solver.SessionIO) (solver.Result, error) {
    ctx, span := tracing.Global().Start(ctx, "legacyice.Execute",
        trace.WithAttributes(
            attribute.String("plan.id", e.plan.ID),
            attribute.String("plan.mode", string(e.execCfg.Mode)),
            attribute.Bool("force_relay", e.execCfg.ForceRelay),
        ))
    defer span.End()
    
    // 创建 ICE Agent
    agent, err := e.ensureAgent(ctx)
    if err != nil {
        span.RecordError(err)
        return solver.Result{}, err
    }
    
    // 候选收集
    if err := e.gatherCandidates(ctx, agent); err != nil {
        span.RecordError(err)
        return solver.Result{}, err
    }
    
    // 连接建立
    transport, err := e.connect(ctx, agent)
    if err != nil {
        span.RecordError(err)
        return solver.Result{}, err
    }
    
    span.SetAttributes(
        attribute.String("transport.type", "ice_udp"),
        attribute.String("transport.local", transport.LocalAddr().String()),
        attribute.String("transport.remote", transport.RemoteAddr().String()),
    )
    
    return solver.Result{Transport: transport}, nil
}

func (e *executor) gatherCandidates(ctx context.Context, agent nat.ICEAgent) error {
    ctx, span := tracing.Global().Start(ctx, "legacyice.gatherCandidates")
    defer span.End()
    
    start := time.Now()
    candidates, err := agent.GatherCandidates(ctx)
    duration := time.Since(start)
    
    span.SetAttributes(
        attribute.Int("candidates.count", len(candidates)),
        attribute.Int64("duration.ms", duration.Milliseconds()),
    )
    
    for _, c := range candidates {
        span.AddEvent("candidate_gathered",
            trace.WithAttributes(
                attribute.String("type", c.Type.String()),
                attribute.String("address", c.Address),
            ))
    }
    
    return err
}
```

### Transport 组件

```go
// pkg/transport/iceadapter/transport.go
type tracedTransport struct {
    inner  transport.PacketTransport
    tracer *tracing.Tracer
}

func (t *tracedTransport) ReadPacket(ctx context.Context, dst []byte) (n int, meta transport.PacketMeta, err error) {
    ctx, span := t.tracer.Start(ctx, "transport.ReadPacket")
    defer span.End()
    
    n, meta, err = t.inner.ReadPacket(ctx, dst)
    
    span.SetAttributes(
        attribute.Int("bytes", n),
        attribute.String("path.id", meta.PathID),
    )
    
    if err != nil {
        span.RecordError(err)
    }
    
    return
}
```

---

## 跨进程追踪

### Coordinator 客户端注入

```go
// pkg/coordinator/client/grpc.go
import (
    "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
)

func NewClient(cfg *Config) (*GRPCClient, error) {
    conn, err := grpc.Dial(cfg.URL,
        grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
    )
    if err != nil {
        return nil, err
    }
    // ...
}
```

### Coordinator 服务端注入

```go
// pkg/coordinator/server/grpc.go
func NewServer(cfg *Config) *grpc.Server {
    return grpc.NewServer(
        grpc.StatsHandler(otelgrpc.NewServerHandler()),
    )
}
```

---

## 关键指标 + Metrics

### 集成 Prometheus

```go
// pkg/metrics/metrics.go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    // 连接建立时间
    ConnectionDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "winkyou_connection_duration_seconds",
            Help:    "Time to establish a connection",
            Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
        },
        []string{"strategy", "result"},
    )
    
    // 活跃连接数
    ActiveConnections = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "winkyou_active_connections",
            Help: "Number of active connections",
        },
    )
    
    // 数据传输
    BytesTransferred = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "winkyou_bytes_transferred_total",
            Help: "Total bytes transferred",
        },
        []string{"direction", "transport_type"},
    )
    
    // 错误计数
    ErrorCount = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "winkyou_errors_total",
            Help: "Total errors",
        },
        []string{"code", "component"},
    )
    
    // ICE 候选收集时间
    CandidateGatherDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "winkyou_ice_gather_duration_seconds",
            Help:    "ICE candidate gathering duration",
            Buckets: []float64{0.1, 0.5, 1, 2, 5, 10},
        },
        []string{"strategy"},
    )
)
```

---

## 部署架构

```
┌─────────────────┐
│  WinkYou Client │
│  (OTLP exports) │
└────────┬────────┘
         │
         ▼
┌─────────────────┐         ┌─────────────────┐
│ OTel Collector  │────────▶│   Jaeger/Zipkin │
│   (聚合/路由)    │         │    (追踪后端)   │
└────────┬────────┘         └─────────────────┘
         │
         ▼
┌─────────────────┐
│   Prometheus    │
│    (Metrics)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Grafana     │
│   (可视化)      │
└─────────────────┘
```

---

## 实施步骤

### Step 1: 集成 OpenTelemetry SDK（2 天）
1. 添加依赖
2. 创建 `pkg/tracing` 包
3. 配置 OTLP exporter

### Step 2: 核心组件追踪（4 天）
1. Session 追踪
2. Solver/Strategy 追踪
3. Transport 追踪
4. Tunnel 追踪

### Step 3: 跨进程追踪（2 天）
1. gRPC 客户端拦截器
2. gRPC 服务端拦截器
3. 上下文传播测试

### Step 4: Metrics 集成（2 天）
1. Prometheus exporter
2. 关键指标定义
3. Grafana 面板

### Step 5: 部署文档（1 天）
1. Docker Compose 部署 OTel + Jaeger + Prometheus + Grafana
2. 运维文档

**总计**: 11 天

---

## 验收标准

- ✅ 所有关键操作有 span
- ✅ 跨进程上下文正确传播
- ✅ 端到端 trace 完整
- ✅ 关键 metrics 暴露
- ✅ 性能开销 < 5%

---

## 参考资料

- [OpenTelemetry Go SDK](https://opentelemetry.io/docs/languages/go/)
- [Jaeger 部署](https://www.jaegertracing.io/docs/deployment/)
- [Prometheus 最佳实践](https://prometheus.io/docs/practices/)
