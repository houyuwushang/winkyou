# TASK-01: 基础设施模块

> 历史任务说明：本任务文档按 legacy MVP baseline 编写。当前 active architecture baseline 为 `docs/CONNECTIVITY-SOLVER-BASELINE.md`。
> 本文档描述的是 MVP 所需基础设施，不覆盖 GUI、移动端和自研协议路线。

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-01 |
| 任务名称 | 基础设施模块 |
| 难度 | 低 |
| 预估工作量 | 2-3天 |
| 前置依赖 | 无 |
| 后续依赖 | TASK-02, TASK-03, TASK-04, TASK-05, TASK-06, TASK-07 |

## 任务说明

### 背景

基础设施模块是整个项目的地基，为所有其他模块提供通用能力，包括：
- 配置文件解析与管理
- 日志系统
- CLI命令框架
- 版本信息管理

### 目标

构建一个可运行的CLI框架，支持配置加载和日志输出，为后续模块开发提供基础。

---

## 功能需求

### FR-01: 配置管理

**描述**: 实现配置文件的加载、解析、校验和热更新能力

**详细需求**:

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-01-1 | 支持YAML格式配置文件 | P0 |
| FR-01-2 | 支持环境变量覆盖配置 | P0 |
| FR-01-3 | 支持命令行参数覆盖配置 | P0 |
| FR-01-4 | 配置项校验，非法值报错 | P0 |
| FR-01-5 | 提供合理的默认值 | P0 |
| FR-01-6 | 配置文件热更新(可选) | P2 |

**配置优先级**: 命令行参数 > 环境变量 > 配置文件 > 默认值

**配置文件示例**:
```yaml
# ~/.wink/config.yaml
node:
  name: "my-laptop"           # 节点名称，默认为hostname

log:
  level: "info"               # debug|info|warn|error
  format: "text"              # text|json
  output: "stderr"            # stderr|stdout|file
  file: "/var/log/wink.log"   # 当output=file时有效

coordinator:
  url: "https://coord.wink.dev:443"
  timeout: 10s
  auth_key: ""
  
netif:
  backend: "auto"             # auto|tun|userspace|proxy
  mtu: 1280

wireguard:
  private_key: ""
  listen_port: 51820

nat:
  stun_servers:
    - "stun:stun.l.google.com:19302"
    - "stun:stun.cloudflare.com:3478"
  turn_servers:
    - url: "turn:relay.example.com:3478"
      username: "wink"
      password: "secret"
```

### FR-02: 日志系统

**描述**: 提供结构化日志能力

**详细需求**:

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-02-1 | 支持日志级别: debug/info/warn/error | P0 |
| FR-02-2 | 支持结构化字段 | P0 |
| FR-02-3 | 支持文本和JSON两种输出格式 | P1 |
| FR-02-4 | 支持输出到stderr/stdout/文件 | P1 |
| FR-02-5 | 日志文件轮转(可选) | P2 |

**日志格式示例**:
```
# 文本格式
2026-04-02T10:30:00.123Z INFO  [main] starting wink daemon version=0.1.0
2026-04-02T10:30:00.456Z DEBUG [netif] creating TUN device name=wink0 mtu=1280

# JSON格式
{"time":"2026-04-02T10:30:00.123Z","level":"INFO","module":"main","msg":"starting wink daemon","version":"0.1.0"}
```

### FR-03: CLI框架

**描述**: 实现命令行工具框架

**详细需求**:

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-03-1 | 实现 `wink` 根命令 | P0 |
| FR-03-2 | 实现 `wink version` 显示版本 | P0 |
| FR-03-3 | 实现 `wink up` 启动连接(占位) | P0 |
| FR-03-4 | 实现 `wink down` 断开连接(占位) | P0 |
| FR-03-5 | 实现 `wink status` 查看状态(占位) | P0 |
| FR-03-6 | 支持 `-c/--config` 指定配置文件 | P0 |
| FR-03-7 | 支持 `-v/--verbose` 详细输出 | P1 |
| FR-03-8 | 良好的帮助信息和错误提示 | P0 |

**命令示例**:
```bash
$ wink version
wink version 0.1.0 (commit: abc1234, built: 2026-04-02)

$ wink up
[INFO] Loading config from ~/.wink/config.yaml
[INFO] Starting wink...
[INFO] Connected to network

$ wink status
Status: connected
Virtual IP: 10.100.0.5
Peers: 3 online
Uptime: 2h 30m

$ wink down
[INFO] Disconnecting...
[INFO] Stopped

$ wink --help
WinkYou - P2P Virtual LAN

Usage:
  wink [command]

Available Commands:
  up          Start and connect to the network
  down        Disconnect and stop
  status      Show connection status
  version     Show version information
  help        Help about any command

Flags:
  -c, --config string   config file (default ~/.wink/config.yaml)
  -v, --verbose         verbose output
  -h, --help            help for wink

Use "wink [command] --help" for more information about a command.
```

### FR-04: 版本信息

**描述**: 编译时注入版本信息

**详细需求**:

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-04-1 | 版本号 (语义化版本) | P0 |
| FR-04-2 | Git Commit Hash | P0 |
| FR-04-3 | 构建时间 | P0 |
| FR-04-4 | Go版本 | P1 |

---

## 技术要求

### 技术栈

| 组件 | 选型 | 说明 |
|------|------|------|
| CLI框架 | [cobra](https://github.com/spf13/cobra) | 业界标准 |
| 配置管理 | [viper](https://github.com/spf13/viper) | 与cobra配合好 |
| 日志 | [zap](https://github.com/uber-go/zap) | 高性能结构化日志 |
| 配置格式 | YAML | gopkg.in/yaml.v3 |

### 目录结构

```
pkg/
├── config/
│   ├── config.go          # Config结构体定义
│   ├── loader.go          # 加载逻辑
│   ├── defaults.go        # 默认值
│   └── validator.go       # 校验逻辑
├── logger/
│   ├── logger.go          # Logger封装
│   └── options.go         # 配置选项
└── version/
    └── version.go         # 版本信息

cmd/
└── wink/
    ├── main.go            # 入口
    └── cmd/
        ├── root.go        # 根命令
        ├── up.go          # up命令
        ├── down.go        # down命令
        ├── status.go      # status命令
        └── version.go     # version命令
```

### 接口定义

```go
// pkg/config/config.go
package config

type Config struct {
    Node        NodeConfig        `yaml:"node"`
    Log         LogConfig         `yaml:"log"`
    Coordinator CoordinatorConfig `yaml:"coordinator"`
    NetIf       NetIfConfig       `yaml:"netif"`
    WireGuard   WireGuardConfig   `yaml:"wireguard"`
    NAT         NATConfig         `yaml:"nat"`
}

type NodeConfig struct {
    Name string `yaml:"name"`
}

type LogConfig struct {
    Level  string `yaml:"level"`  // debug|info|warn|error
    Format string `yaml:"format"` // text|json
    Output string `yaml:"output"` // stderr|stdout|file
    File   string `yaml:"file"`
}

type CoordinatorConfig struct {
    URL     string        `yaml:"url"`
    Timeout time.Duration `yaml:"timeout"`
    AuthKey string        `yaml:"auth_key"`
    TLS     TLSConfig     `yaml:"tls"`
}

type TLSConfig struct {
    InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
    CAFile             string `yaml:"ca_file"`
}

type NetIfConfig struct {
    Backend string `yaml:"backend"`
    MTU     int    `yaml:"mtu"`
}

type WireGuardConfig struct {
    PrivateKey string `yaml:"private_key"`
    ListenPort int    `yaml:"listen_port"`
}

type NATConfig struct {
    STUNServers []string           `yaml:"stun_servers"`
    TURNServers []TURNServerConfig `yaml:"turn_servers"`
}

type TURNServerConfig struct {
    URL      string `yaml:"url"`
    Username string `yaml:"username"`
    Password string `yaml:"password"`
}

// Load 加载配置
func Load(path string) (*Config, error)

// Validate 校验配置
func (c *Config) Validate() error
```

```go
// pkg/logger/logger.go
package logger

type Logger interface {
    Debug(msg string, fields ...Field)
    Info(msg string, fields ...Field)
    Warn(msg string, fields ...Field)
    Error(msg string, fields ...Field)
    With(fields ...Field) Logger
}

type Field struct {
    Key   string
    Value interface{}
}

// New 创建Logger
func New(cfg *config.LogConfig) (Logger, error)

// 便捷函数
func String(key, val string) Field
func Int(key string, val int) Field
func Error(err error) Field
```

---

## 验收标准

### AC-01: 配置管理验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | 能正确解析YAML配置文件 | 编写测试配置文件，验证解析结果 |
| AC-01-2 | 环境变量能覆盖配置 | `WINK_LOG_LEVEL=debug wink up` 应使用debug级别 |
| AC-01-3 | 命令行参数能覆盖配置 | `wink up -c ./test.yaml` 应使用指定配置 |
| AC-01-4 | 无效配置报错清晰 | 配置`log.level: invalid`应报明确错误 |
| AC-01-5 | 无配置文件时使用默认值 | 删除配置文件后程序仍可启动 |

**测试用例示例**:
```go
func TestConfigLoad(t *testing.T) {
    cfg, err := config.Load("testdata/valid.yaml")
    assert.NoError(t, err)
    assert.Equal(t, "my-node", cfg.Node.Name)
}

func TestConfigValidation(t *testing.T) {
    cfg := &config.Config{
        Log: config.LogConfig{Level: "invalid"},
    }
    err := cfg.Validate()
    assert.ErrorContains(t, err, "invalid log level")
}

func TestEnvOverride(t *testing.T) {
    os.Setenv("WINK_LOG_LEVEL", "debug")
    defer os.Unsetenv("WINK_LOG_LEVEL")
    
    cfg, _ := config.Load("testdata/valid.yaml")
    assert.Equal(t, "debug", cfg.Log.Level)
}
```

### AC-02: 日志系统验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | 日志级别过滤正确 | level=info时不输出debug日志 |
| AC-02-2 | 结构化字段正确输出 | `logger.Info("msg", String("key", "val"))` 输出包含key=val |
| AC-02-3 | JSON格式正确 | format=json时输出合法JSON |
| AC-02-4 | 文件输出正确 | output=file时写入指定文件 |

### AC-03: CLI框架验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | `wink version` 输出版本信息 | 执行命令，验证输出格式 |
| AC-03-2 | `wink --help` 输出帮助 | 验证包含所有命令 |
| AC-03-3 | `wink up` 命令可执行 | 当前阶段输出占位信息即可 |
| AC-03-4 | 未知命令报错友好 | `wink unknown` 提示可用命令 |
| AC-03-5 | `-c` 参数生效 | 指定配置文件能被加载 |

### AC-04: 版本信息验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | 版本号通过ldflags注入 | `go build -ldflags "-X ..."` |
| AC-04-2 | Commit Hash正确 | 与当前git commit一致 |

**构建命令示例**:
```makefile
VERSION := 0.1.0
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X 'winkyou/pkg/version.Version=$(VERSION)' \
           -X 'winkyou/pkg/version.Commit=$(COMMIT)' \
           -X 'winkyou/pkg/version.BuildTime=$(BUILD_TIME)'

build:
	go build -ldflags "$(LDFLAGS)" -o wink ./cmd/wink
```

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| 配置模块 | `pkg/config/` | 完整配置管理代码 |
| 日志模块 | `pkg/logger/` | 日志封装代码 |
| 版本模块 | `pkg/version/` | 版本信息代码 |
| CLI入口 | `cmd/wink/` | 命令行工具代码 |
| 单元测试 | `pkg/*/xxx_test.go` | 各模块单元测试 |
| Makefile | `Makefile` | 构建脚本 |

---

## 注意事项

1. **配置路径**: 
   - Linux/macOS: `~/.wink/config.yaml`
   - Windows: `%APPDATA%\wink\config.yaml`

2. **日志性能**: 使用 zap 的 `SugaredLogger` 在开发阶段，生产环境可切换到 `Logger`

3. **错误信息**: 所有错误信息应清晰指出问题所在和解决建议

4. **向后兼容**: 配置项新增时保持向后兼容，旧配置文件应能继续使用

---

## 参考资料

- [Cobra 文档](https://cobra.dev/)
- [Viper 文档](https://github.com/spf13/viper)
- [Zap 文档](https://pkg.go.dev/go.uber.org/zap)
- [12-Factor App: Config](https://12factor.net/config)
