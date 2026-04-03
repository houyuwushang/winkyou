# TASK-02: 网络接口抽象层

> 当前任务以 `docs/EXECUTION-BASELINE.md` 为准。
> MVP 范围包含 `TUN`、`userspace`、`proxy`，`TAP` 为 post-MVP 能力。

## 任务概述

| 属性 | 值 |
|------|-----|
| 任务ID | TASK-02 |
| 任务名称 | 网络接口抽象层 |
| 难度 | 中 |
| 预估工作量 | 5-7天 |
| 前置依赖 | TASK-01 |
| 后续依赖 | TASK-03, TASK-06 |

## 任务说明

### 背景

网络接口层是虚拟局域网的基础，负责创建虚拟网卡（TUN/TAP设备），使应用程序的网络流量能够被拦截并送入WireGuard隧道。

为了支持跨平台和无管理员权限运行，本模块需要实现**多后端架构**，根据运行环境自动选择最优的网络接口实现。

### 目标

- 定义统一的 `NetworkInterface` 抽象接口
- 实现多个后端：TUN、用户态网络栈、SOCKS5代理
- 实现自动后端选择逻辑
- 确保跨平台支持（Windows/Linux/macOS）

---

## 功能需求

### FR-01: 抽象接口定义

**描述**: 定义统一的网络接口抽象，所有后端必须实现此接口

```go
// NetworkInterface 虚拟网络接口抽象
type NetworkInterface interface {
    // 基本信息
    Name() string              // 接口名称 (如 wink0)
    Type() InterfaceType       // 接口类型 (TUN/TAP/Userspace/Proxy)
    MTU() int                  // MTU值
    
    // 数据读写
    Read(buf []byte) (int, error)   // 读取一个IP包
    Write(buf []byte) (int, error)  // 写入一个IP包
    
    // 生命周期
    Close() error
    
    // 网络配置
    SetIP(ip net.IP, mask net.IPMask) error
    AddRoute(dst *net.IPNet, gateway net.IP) error
    RemoveRoute(dst *net.IPNet) error
}

type InterfaceType string

const (
    TypeTUN       InterfaceType = "tun"
    TypeUserspace InterfaceType = "userspace"
    TypeProxy     InterfaceType = "proxy"
)
```

### FR-02: TUN后端实现

**描述**: 各平台的TUN设备实现

| 需求ID | 需求描述 | 平台 | 优先级 |
|--------|----------|------|--------|
| FR-02-1 | Linux TUN实现 (/dev/net/tun) | Linux | P0 |
| FR-02-2 | macOS TUN实现 (utun) | macOS | P0 |
| FR-02-3 | Windows TUN实现 (WinTUN) | Windows | P0 |

**Linux实现要点**:
```go
// 使用 /dev/net/tun
fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
// 使用 TUNSETIFF ioctl 创建设备
```

**macOS实现要点**:
```go
// 使用 utun (系统自带)
// 通过 socket + SYSPROTO_CONTROL 创建
```

**Windows实现要点**:
```go
// 使用 WinTUN 驱动
// 需要嵌入 wintun.dll 或要求用户安装
import "golang.zx2c4.com/wireguard/tun"
```

### FR-03: TAP后端实现（post-MVP）

**描述**: 二层网络接口，用于需要广播/组播的场景

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-03-1 | Linux TAP实现 | P1 |
| FR-03-2 | Windows TAP实现 (TAP-Windows) | P2 |
| FR-03-3 | macOS TAP实现 (需第三方驱动) | P2 |

### FR-04: 用户态网络栈后端

**描述**: 无需管理员权限的网络接口实现

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-04-1 | 集成 gVisor netstack | P0 |
| FR-04-2 | 实现 TCP 转发 | P0 |
| FR-04-3 | 实现 UDP 转发 | P0 |
| FR-04-4 | 实现 ICMP (ping) 支持 | P1 |

**架构说明**:
```
┌─────────────────────────────────────────────────────────────┐
│                    用户态网络栈架构                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  应用程序                                                    │
│     │                                                        │
│     ▼ (连接到虚拟IP)                                         │
│  ┌─────────────────┐                                        │
│  │  gVisor Netstack │  ← 用户态 TCP/IP 协议栈                │
│  │  (TCP/UDP/ICMP)  │                                        │
│  └────────┬────────┘                                        │
│           │ (IP包)                                           │
│           ▼                                                  │
│  ┌─────────────────┐                                        │
│  │  WireGuard 隧道  │  ← 加密封装                            │
│  └────────┬────────┘                                        │
│           │ (UDP)                                            │
│           ▼                                                  │
│       物理网络                                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### FR-05: SOCKS5代理后端（降级）

**描述**: 最低限度的网络接口实现，作为兜底方案

| 需求ID | 需求描述 | 优先级 |
|--------|----------|--------|
| FR-05-1 | 启动本地SOCKS5代理服务器 | P1 |
| FR-05-2 | TCP流量通过隧道转发 | P1 |
| FR-05-3 | UDP Associate 支持 | P2 |

### FR-06: 自动后端选择

**描述**: 根据运行环境自动选择最优后端

```go
// 选择策略
func New(cfg Config) (NetworkInterface, error) {
    // 1. 用户显式指定
    if cfg.Backend != "auto" {
        return createBackend(cfg.Backend)
    }
    
    // 2. 自动选择
    // 2.1 检测是否有管理员权限
    if hasAdminPrivilege() {
        // 优先使用TUN
        if tun, err := createTUN(); err == nil {
            return tun, nil
        }
    }
    
    // 2.2 尝试用户态网络栈
    if netstack, err := createNetstack(); err == nil {
        return netstack, nil
    }
    
    // 2.3 降级到SOCKS5代理
    return createSOCKS5Proxy()
}
```

**选择优先级**:

| 优先级 | 后端 | 条件 |
|--------|------|------|
| 1 | TUN | 有管理员权限 |
| 2 | Userspace | 无管理员权限 |
| 3 | SOCKS5 | 兜底 |

---

## 技术要求

### 技术栈

| 组件 | MVP选型 | 长期目标 | 说明 |
|------|---------|----------|------|
| TUN (全平台) | golang.zx2c4.com/wireguard/tun | **Phase 1 自研** | 直接系统调用，去掉封装层 |
| TAP (跨平台) | github.com/songgao/water | 视需求自研 | 备选方案 |
| 用户态协议栈 | gvisor.dev/gvisor/pkg/tcpip | Phase 4 精简/优化 | 长期研究 |
| SOCKS5 | github.com/armon/go-socks5 | 不替换 | 降级方案，非热路径 |

> **抽象层设计要求**: 第三方库代码必须隔离在独立实现文件中。
> TUN的MVP实现放在`tun_linux_wg.go`等文件，自研实现放在`tun_linux_native.go`，共用`NetworkInterface`接口和测试。
> 详见 [selfhost.md](../../selfhost.md)

### 目录结构

```
pkg/netif/
├── interface.go           # NetworkInterface 接口定义（永远不改）
├── types.go               # 类型定义
├── selector.go            # 后端选择逻辑
├── tun.go                 # TUN通用逻辑
├── tun_linux_wg.go        # Linux TUN: 基于wireguard/tun（MVP）
├── tun_linux_native.go    # Linux TUN: 自研syscall（Phase 1）
├── tun_darwin_wg.go       # macOS TUN: 基于wireguard/tun（MVP）
├── tun_darwin_native.go   # macOS TUN: 自研（Phase 1）
├── tun_windows_wg.go      # Windows TUN: 基于wireguard/tun（MVP）
├── tun_windows_native.go  # Windows TUN: 自研WinTUN调用（Phase 1）
├── userspace.go           # 用户态网络栈
├── userspace_gvisor.go    # 基于gVisor（当前）
├── userspace_stack.go     # netstack集成
├── proxy.go               # SOCKS5代理后端
└── route.go               # 路由管理工具
```

### 跨平台编译

```go
// tun_linux.go
//go:build linux

package netif

// tun_darwin.go
//go:build darwin

package netif

// tun_windows.go
//go:build windows

package netif
```

---

## 验收标准

### AC-01: TUN后端验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-01-1 | Linux下能创建TUN设备 | `ip link show wink0` 能看到设备 |
| AC-01-2 | macOS下能创建utun设备 | `ifconfig` 能看到utun设备 |
| AC-01-3 | Windows下能创建WinTUN设备 | 网络适配器中能看到 |
| AC-01-4 | 能设置IP地址 | `ip addr` / `ifconfig` 验证 |
| AC-01-5 | 能添加路由 | `ip route` / `netstat -rn` 验证 |
| AC-01-6 | Read/Write正确工作 | 两端ping测试 |

**集成测试示例**:
```go
func TestTUNReadWrite(t *testing.T) {
    if os.Getuid() != 0 {
        t.Skip("requires root")
    }
    
    tun, err := NewTUN("wink0", 1280)
    require.NoError(t, err)
    defer tun.Close()
    
    err = tun.SetIP(net.ParseIP("10.100.0.1"), net.CIDRMask(24, 32))
    require.NoError(t, err)
    
    // 在另一个goroutine发送ping
    // 验证能在TUN上读到ICMP包
}
```

### AC-02: 用户态网络栈验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-02-1 | TCP连接能建立 | `curl http://10.100.0.2:8080` 成功 |
| AC-02-2 | UDP能发送接收 | DNS查询或自定义UDP测试 |
| AC-02-3 | 无需root权限 | 普通用户运行测试 |
| AC-02-4 | 性能可接受 | 吞吐量 > 100Mbps |

### AC-03: 自动选择验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-03-1 | root用户选择TUN | 检查返回的Type() |
| AC-03-2 | 普通用户选择Userspace | 检查返回的Type() |
| AC-03-3 | 显式配置被尊重 | 配置backend=userspace时使用userspace |

### AC-04: 跨平台验收

| 验收项 | 验收条件 | 测试方法 |
|--------|----------|----------|
| AC-04-1 | Linux编译通过 | `GOOS=linux go build` |
| AC-04-2 | macOS编译通过 | `GOOS=darwin go build` |
| AC-04-3 | Windows编译通过 | `GOOS=windows go build` |
| AC-04-4 | 各平台功能正常 | CI矩阵测试 |

---

## 交付物清单

| 交付物 | 路径 | 说明 |
|--------|------|------|
| 接口定义 | `pkg/netif/interface.go` | NetworkInterface接口 |
| TUN实现 | `pkg/netif/tun_*.go` | 各平台TUN实现 |
| Userspace实现 | `pkg/netif/userspace*.go` | 用户态网络栈 |
| 选择器 | `pkg/netif/selector.go` | 自动选择逻辑 |
| 单元测试 | `pkg/netif/*_test.go` | 测试代码 |
| 集成测试 | `test/netif_integration_test.go` | 集成测试 |

---

## 注意事项

### 1. WinTUN驱动分发

Windows上WinTUN驱动有两种分发方式：

**方案A: 嵌入DLL**
```go
//go:embed wintun.dll
var wintunDLL []byte
```
- 优点：用户无需额外安装
- 缺点：二进制体积增加约200KB

**方案B: 要求用户安装**
- 检测驱动是否存在
- 不存在则提示用户下载安装

**建议**: 采用方案A，嵌入DLL

### 2. gVisor netstack内存占用

gVisor netstack初始化时会分配内存，需要注意：
- 合理设置接收/发送缓冲区大小
- 监控内存使用情况
- Windows下可能需要额外测试

### 3. 路由配置权限

添加系统路由通常需要管理员权限，用户态模式下需要：
- 不添加系统路由
- 使用策略路由或通过其他方式引导流量

### 4. MTU选择

| 场景 | 建议MTU |
|------|---------|
| 标准网络 | 1420 |
| PPPoE网络 | 1400 |
| 移动网络 | 1280 |
| 保守值 | 1280 |

建议默认使用1280，这是IPv6要求的最小MTU，兼容性最好。

---

## 待确认问题

> 以下问题需要在开发前或开发中确认

| 问题 | 状态 | 决策 |
|------|------|------|
| gVisor netstack是否支持Windows? | 待验证 | 需要原型测试 |
| WinTUN是否需要签名? | 待确认 | 官方DLL已签名 |
| TAP功能是否MVP必需? | 已确定 | 不进入MVP，后续版本再评估 |
| SOCKS5代理是否MVP必需? | 待确认 | 建议作为降级保留 |

---

## 参考资料

- [WireGuard TUN实现](https://git.zx2c4.com/wireguard-go/tree/tun)
- [gVisor Netstack文档](https://gvisor.dev/docs/user_guide/networking/)
- [WinTUN文档](https://www.wintun.net/)
- [Linux TUN/TAP文档](https://www.kernel.org/doc/Documentation/networking/tuntap.txt)
