# WinkYou 开发计划与管理文档

> 说明：本文件保留项目开发管理与长期排期视角。
> 对于当前 MVP 执行，如与 `docs/EXECUTION-BASELINE.md` 冲突，以执行基线为准。

## 一、技术决策与选型

### 1.1 开发语言选择

**主语言：Go**

| 考量因素 | Go | Rust | C/C++ |
|----------|-----|------|-------|
| 跨平台编译 | 极佳，单二进制 | 好 | 复杂 |
| 并发模型 | goroutine原生支持 | async/await | 手动管理 |
| WireGuard生态 | wireguard-go成熟 | boringtun | 内核模块 |
| 开发效率 | 高 | 中等 | 低 |
| 内存安全 | GC自动管理 | 编译期保证 | 手动管理 |
| 学习曲线 | 低 | 高 | 中 |
| 二进制体积 | 中等(~10-20MB) | 较小 | 最小 |

**选择理由**：
1. wireguard-go 是官方维护的用户态实现，直接可用
2. pion 项目提供了完整的 STUN/TURN/ICE Go 实现
3. gVisor netstack 是 Go 实现的用户态协议栈
4. 单二进制分发，部署简单
5. 团队上手快，招聘容易

**潜在问题** ⚠️：
- Go 的 GC 可能在高吞吐场景下引入延迟抖动
- 二进制体积较大（可通过 UPX 压缩缓解）
- cgo 跨平台编译复杂（尽量使用纯 Go 实现）

### 1.2 核心依赖确认

| 依赖 | 选择 | 备选 | 待验证 | 自研计划 |
|------|------|------|--------|----------|
| WireGuard | wireguard-go | boringtun(Rust) | 性能是否满足？ | **Phase 2 自研** |
| TUN驱动 | wireguard/tun | songgao/water | Windows兼容性？ | **Phase 1 自研** |
| 用户态协议栈 | gVisor netstack | lwip-go | Windows支持？内存占用？ | Phase 4 (长期) |
| STUN | pion/stun | - | - | **Phase 1 自研** |
| ICE | pion/ice | - | 国内NAT穿透率？ | Phase 3 自研 |
| TURN | pion/turn | - | - | Phase 3 自研 |
| 序列化 | protobuf | msgpack/json | - | 不替换 |
| RPC | gRPC | - | - | 不替换 |
| 数据库 | SQLite | PostgreSQL(服务端) | - | 不替换 |

> **重要**: 数据热路径上的依赖（WireGuard、TUN、STUN/ICE）均计划逐步自研替换。
> 详见 [selfhost.md](selfhost.md) — 自研路线图。
> 核心原则：MVP用第三方跑通，但抽象层从第一天就为替换而设计。

---

## 二、开发环境准备

### 2.1 硬件设备

#### 必需设备

| 设备 | 用途 | 数量 | 说明 |
|------|------|------|------|
| Windows开发机 | 主开发 + Windows测试 | 1 | Win10/11，建议16GB+ |
| Linux机器 | Linux测试 + 服务器开发 | 1 | 虚拟机可，Ubuntu 22.04+ |
| macOS机器 | macOS测试 | 1 | 有条件的话，或用GitHub Actions |
| 云服务器(公网IP) | 协调服务器 + 中继 + STUN | 1-2 | 1核1G起步，带宽重要 |

#### 建议设备（后期测试）

| 设备 | 用途 |
|------|------|
| Android手机 | 移动端测试 |
| 树莓派/软路由 | 边缘场景测试 |
| 不同ISP的网络环境 | NAT类型覆盖测试 |

### 2.2 网络环境

**NAT测试环境矩阵**（P2P穿透测试必需）：

```
┌─────────────────────────────────────────────────────────────────┐
│                      NAT 测试矩阵                                │
├─────────────┬─────────────┬─────────────┬───────────────────────┤
│             │ Full Cone   │ Restricted  │ Symmetric             │
├─────────────┼─────────────┼─────────────┼───────────────────────┤
│ Full Cone   │ ✅ 易通      │ ✅ 可通      │ ⚠️ 需TURN             │
│ Restricted  │ ✅ 可通      │ ✅ 可通      │ ⚠️ 需TURN             │
│ Symmetric   │ ⚠️ 需TURN    │ ⚠️ 需TURN    │ ❌ 必须TURN           │
└─────────────┴─────────────┴─────────────┴───────────────────────┘
```

**环境准备方案**：

| 方案 | 描述 | 成本 |
|------|------|------|
| 家庭路由器 | 大多数是 Cone NAT | 已有 |
| 手机热点 | 常见 Symmetric NAT | 已有 |
| 企业网络 | 复杂NAT/防火墙 | 需要权限 |
| Docker模拟 | 使用iptables模拟各种NAT | 免费 |
| 云服务器 | 公网IP，无NAT | ~50元/月 |

**Docker NAT模拟脚本**（待开发）：
```bash
# 模拟 Symmetric NAT
docker network create --driver bridge symmetric-nat
# 配置 iptables 规则...
```

### 2.3 开发工具链

```yaml
必需工具:
  - Go 1.22+
  - Git
  - Docker & Docker Compose
  - protoc (Protocol Buffers编译器)
  - Make 或 Task (任务运行器)
  - Wireshark (网络抓包分析)

推荐工具:
  - GoLand 或 VSCode + Go插件
  - golangci-lint (静态分析)
  - delve (Go调试器)
  - iperf3 (网络性能测试)
  - stun-client (STUN测试工具)

CI/CD:
  - GitHub Actions (跨平台构建)
  - goreleaser (发布管理)
```

---

## 三、模块开发顺序

### 3.1 开发路线图

```
阶段0: 基础设施        阶段1: 核心隧道        阶段2: P2P连接
    │                      │                      │
    ▼                      ▼                      ▼
┌─────────┐          ┌───────────┐          ┌───────────┐
│ 项目框架 │          │ TUN设备   │          │ STUN客户端│
│ 配置系统 │    →     │ WireGuard │    →     │ NAT检测   │
│ 日志系统 │          │ 封装      │          │ ICE协商   │
│ CLI框架  │          │ 点对点直连 │          │ TURN中继  │
└─────────┘          └───────────┘          └───────────┘
                                                  │
    ┌─────────────────────────────────────────────┘
    ▼
阶段3: 协调服务        阶段4: 完整组网        阶段5: 产品化
    │                      │                      │
    ▼                      ▼                      ▼
┌───────────┐          ┌───────────┐          ┌───────────┐
│ 节点注册  │          │ 多节点组网 │          │ GUI客户端 │
│ 密钥交换  │    →     │ 网络组    │    →     │ 自动更新  │
│ 节点发现  │          │ ACL控制   │          │ 安装包    │
│ 信令传递  │          │ DNS解析   │          │ 文档完善  │
└───────────┘          └───────────┘          └───────────┘
```

### 3.2 详细模块分解

#### 阶段 0：基础设施（建议 1 人）

```
pkg/
├── config/           # 配置管理
│   ├── config.go     # 配置结构体定义
│   ├── loader.go     # YAML/环境变量加载
│   └── validator.go  # 配置校验
├── logger/           # 日志系统
│   └── logger.go     # 基于 zap 的封装
└── version/          # 版本信息
    └── version.go    # 编译时注入版本号

cmd/
└── wink/             # CLI 入口
    ├── main.go
    └── cmd/
        ├── root.go   # cobra 根命令
        ├── up.go     # wink up
        ├── down.go   # wink down
        └── status.go # wink status
```

**产出物**：可运行的 CLI 框架，能解析配置文件

#### 阶段 1：核心隧道（建议 1-2 人）

**1.1 网络接口抽象层**
```go
// pkg/netif/interface.go
type NetworkInterface interface {
    Name() string
    MTU() int
    Read(buf []byte) (int, error)   // 读取IP包
    Write(buf []byte) (int, error)  // 写入IP包
    Close() error
    SetIP(ip net.IP, mask net.IPMask) error
}
```

**1.2 TUN后端实现**
```
pkg/netif/
├── interface.go      # 抽象接口
├── tun_linux.go      # Linux TUN
├── tun_darwin.go     # macOS utun
├── tun_windows.go    # Windows WinTUN
└── selector.go       # 自动选择
```

**1.3 WireGuard封装**
```
pkg/tunnel/
├── wireguard.go      # WireGuard Device 封装
├── peer.go           # Peer 管理
├── keypair.go        # 密钥对生成
└── config.go         # WireGuard 配置
```

**产出物**：
- 两台机器通过手动配置IP和公钥实现 WireGuard 直连
- 验证 ping 通、TCP/UDP 通信正常

#### 阶段 2：P2P 连接（建议 1-2 人，核心难点）

**2.1 NAT检测**
```
pkg/nat/
├── detector.go       # NAT类型检测
├── stun.go           # STUN客户端
├── types.go          # NAT类型定义
└── utils.go          # 工具函数
```

**2.2 ICE协商**
```
pkg/ice/
├── agent.go          # ICE Agent
├── candidate.go      # 候选地址
├── gather.go         # 候选收集
├── check.go          # 连通性检查
└── selector.go       # 最优路径选择
```

**2.3 TURN中继**
```
pkg/relay/
├── client.go         # TURN客户端
├── server.go         # 自建中继服务
└── allocation.go     # 中继分配管理
```

**产出物**：
- 两台跨NAT设备能自动发现并建立连接
- NAT穿透成功率统计
- 穿透失败时自动回退到中继

#### 阶段 3：协调服务（建议 1 人）

```
pkg/coordinator/
├── server.go         # gRPC服务器
├── registry.go       # 节点注册表
├── keyexchange.go    # 公钥交换
├── signaling.go      # 信令转发
└── storage.go        # 持久化存储

cmd/
└── wink-coordinator/ # 协调服务器入口
    └── main.go
```

**产出物**：
- 节点能自动注册到协调服务器
- 通过协调服务器获取对端信息
- 完整的两节点自动组网

#### 阶段 4：完整组网（建议 1-2 人）

- 多节点组网（Mesh 或 Hub-Spoke）
- 虚拟IP分配（IPAM）
- 网络组隔离
- ACL访问控制
- 路由管理

#### 阶段 5：产品化（建议 1 人）

- GUI客户端（Wails 或 Electron）
- 安装包制作
- 自动更新机制
- 文档和使用教程

---

## 四、开发计划排期

### 4.1 里程碑规划

| 里程碑 | 目标 | 核心产出 |
|--------|------|----------|
| **M0** | 项目初始化 | 代码框架、CI/CD、开发环境 |
| **M1** | 点对点直连 | 两节点手动配置WireGuard隧道 |
| **M2** | NAT穿透 | 跨NAT自动建立P2P连接 |
| **M3** | 协调服务 | 自动节点发现和组网 |
| **M4** | MVP发布 | 可用的命令行版本 |
| **M5** | V1.0 | 稳定版本，GUI客户端 |

### 4.2 详细任务分解

#### M0：项目初始化

| 任务 | 描述 | 依赖 | 产出 |
|------|------|------|------|
| T0.1 | Go项目初始化、目录结构 | - | go.mod, 目录结构 |
| T0.2 | 配置管理模块 | T0.1 | config包 |
| T0.3 | 日志系统 | T0.1 | logger包 |
| T0.4 | CLI框架搭建 | T0.2, T0.3 | wink命令行工具 |
| T0.5 | GitHub Actions CI | T0.1 | 自动构建、测试 |
| T0.6 | 开发文档 | - | CONTRIBUTING.md |

#### M1：点对点直连

| 任务 | 描述 | 依赖 | 产出 |
|------|------|------|------|
| T1.1 | NetworkInterface抽象接口设计 | M0 | interface.go |
| T1.2 | Linux TUN实现 | T1.1 | tun_linux.go |
| T1.3 | Windows TUN实现(WinTUN) | T1.1 | tun_windows.go |
| T1.4 | macOS TUN实现(utun) | T1.1 | tun_darwin.go |
| T1.5 | wireguard-go集成 | T1.2/T1.3/T1.4 | tunnel包 |
| T1.6 | 密钥生成工具 | T1.5 | wink genkey |
| T1.7 | 手动配置直连测试 | T1.5, T1.6 | 测试用例 |
| T1.8 | 用户态网络栈后端(可选) | T1.1 | userspace.go |

#### M2：NAT穿透

| 任务 | 描述 | 依赖 | 产出 |
|------|------|------|------|
| T2.1 | STUN客户端实现 | M1 | stun.go |
| T2.2 | NAT类型检测 | T2.1 | detector.go |
| T2.3 | 候选地址收集 | T2.1, T2.2 | gather.go |
| T2.4 | ICE连通性检查 | T2.3 | check.go |
| T2.5 | ICE协商状态机 | T2.4 | agent.go |
| T2.6 | TURN客户端实现 | T2.5 | turn_client.go |
| T2.7 | 自建TURN服务器 | - | turn_server.go |
| T2.8 | 打洞成功率测试 | T2.5, T2.6 | 测试报告 |

#### M3：协调服务

| 任务 | 描述 | 依赖 | 产出 |
|------|------|------|------|
| T3.1 | Protobuf协议定义 | - | messages.proto |
| T3.2 | gRPC服务框架 | T3.1 | server.go |
| T3.3 | 节点注册/心跳 | T3.2 | registry.go |
| T3.4 | 公钥交换 | T3.3 | keyexchange.go |
| T3.5 | 信令转发（ICE候选交换） | T3.4, M2 | signaling.go |
| T3.6 | 客户端集成 | T3.5 | 自动组网 |
| T3.7 | 协调服务器部署 | T3.6 | Docker镜像 |

#### M4：MVP发布

| 任务 | 描述 | 依赖 | 产出 |
|------|------|------|------|
| T4.1 | 完整CLI实现 | M3 | 所有命令 |
| T4.2 | 连接状态监控 | T4.1 | wink status |
| T4.3 | 自动重连机制 | T4.1 | 断线重连 |
| T4.4 | 安装脚本 | T4.1 | install.sh |
| T4.5 | 用户文档 | T4.1 | README, 使用指南 |
| T4.6 | 发布二进制 | T4.4 | GitHub Release |

---

## 五、关键技术问题与待验证事项

### 5.1 必须验证的问题 ⚠️

以下问题在正式开发前**必须通过原型验证**：

#### Q1: wireguard-go 性能是否满足需求？

**疑问**：
- wireguard-go 是用户态实现，性能是否足够？
- 在高吞吐场景（如大文件传输）下延迟表现如何？

**验证方案**：
```bash
# 搭建测试环境，使用 iperf3 测试吞吐量
# 对比：
# 1. 原生网络
# 2. 内核 WireGuard
# 3. wireguard-go
```

**接受标准**：
- 吞吐量达到原生网络的 70%+
- 延迟增加不超过 5ms

#### Q2: gVisor netstack 在 Windows 上是否可用？

**疑问**：
- gVisor 主要针对 Linux，Windows 支持情况不明
- 内存占用和性能如何？

**验证方案**：
```go
// 编写 Windows 测试程序
// 验证 netstack 基本 TCP/UDP 功能
```

**备选方案**：
- 如果 netstack 不可用，Windows 无权限场景降级为 SOCKS5 代理

#### Q3: 国内网络环境的 NAT 穿透成功率？

**疑问**：
- 国内运营商 NAT 类型分布如何？
- 对称型 NAT 占比多少？
- 不同运营商之间穿透成功率？

**验证方案**：
```bash
# 1. 收集多种网络环境的 NAT 类型
#    - 家庭宽带（电信/联通/移动）
#    - 手机热点（4G/5G）
#    - 企业网络
# 2. 交叉测试穿透成功率
```

**影响决策**：
- 如果对称NAT占比 > 30%，需要优先部署国内 TURN 中继服务器

#### Q4: WinTUN 驱动安装体验？

**疑问**：
- 是否需要用户手动安装驱动？
- 是否需要管理员权限？
- 杀毒软件是否会拦截？

**验证方案**：
- 在干净的 Windows 10/11 系统上测试安装流程
- 测试常见杀毒软件的反应

#### Q5: ICE/STUN 库的稳定性？

**疑问**：
- pion/ice 库在长时间运行下是否稳定？
- 是否有内存泄漏？
- 边界情况处理是否完善？

**验证方案**：
- 长时间运行测试（72小时+）
- 模拟各种网络中断场景

### 5.2 设计层面待决策

#### D1: 网络拓扑选择

| 选项 | Full Mesh | Hub-Spoke | 混合 |
|------|-----------|-----------|------|
| 连接数 | O(n²) | O(n) | 可变 |
| 延迟 | 最低 | 经过Hub增加 | 优化后最低 |
| 复杂度 | 高 | 低 | 中 |
| 适用规模 | <50节点 | 任意 | 任意 |

**建议**：小规模默认 Full Mesh，大规模自动切换 Hub-Spoke

#### D2: 协调服务器架构

| 选项 | 单点 | 多点主从 | P2P分布式 |
|------|------|----------|-----------|
| 复杂度 | 低 | 中 | 高 |
| 可用性 | 单点故障 | 高可用 | 极高 |
| 一致性 | 简单 | Raft/主从 | 最终一致 |

**建议**：MVP用单点，V1.0实现主从高可用

#### D3: 虚拟IP分配策略

| 选项 | 静态配置 | 协调服务器分配 | DHCP风格 |
|------|----------|----------------|----------|
| 冲突风险 | 用户负责 | 低 | 低 |
| 复杂度 | 低 | 中 | 中高 |
| 灵活性 | 高 | 中 | 高 |

**建议**：协调服务器集中分配，支持用户指定

#### D4: 是否兼容原生 WireGuard 客户端？

**优点**：
- 用户可以使用现有 WireGuard 客户端
- 降低用户学习成本

**缺点**：
- 功能受限（无法使用高级特性）
- 协议设计受约束

**建议**：不作为核心目标，但保持协议层面兼容可能性

### 5.3 运营层面待规划

#### O1: STUN/TURN 服务器部署

**问题**：
- 使用公共 STUN 服务器还是自建？
- TURN 服务器部署在哪里？带宽成本？
- 是否需要多地域部署？

**建议方案**：
```yaml
STUN服务器:
  - 使用公共服务器（Google/Cloudflare）作为备用
  - 自建主STUN服务器（成本低）

TURN服务器:
  - 必须自建（公共TURN不可控）
  - 初期：1台国内云服务器
  - 后期：按需多地域扩展
  - 成本预估：带宽为主，约 0.5-1元/GB
```

#### O2: 协调服务器托管

**选项**：
1. 提供官方托管服务（SaaS模式）
2. 完全自托管（Headscale模式）
3. 两者都支持

**建议**：优先支持自托管，后期考虑官方服务

---

## 六、团队分工建议

### 6.1 最小团队配置

```
┌─────────────────────────────────────────────────────────────┐
│                    最小团队（2-3人）                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  开发者A（核心开发）                                          │
│  ├── 网络接口层（TUN/TAP/Netstack）                          │
│  ├── WireGuard 集成                                         │
│  └── P2P连接（NAT穿透、ICE）                                 │
│                                                              │
│  开发者B（服务端 + 工具）                                     │
│  ├── 协调服务器                                              │
│  ├── CLI工具                                                 │
│  └── 部署和运维                                              │
│                                                              │
│  开发者C（可选：前端/测试）                                   │
│  ├── GUI客户端                                               │
│  ├── 测试和QA                                                │
│  └── 文档                                                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 技能要求

| 角色 | 必需技能 | 加分项 |
|------|----------|--------|
| 核心开发 | Go, 网络编程, Linux | WireGuard, 系统编程 |
| 服务端开发 | Go, gRPC, 数据库 | Kubernetes, 分布式系统 |
| 前端开发 | TypeScript/Go | Electron/Wails, 跨平台开发 |

---

## 七、风险与应对

### 7.1 技术风险

| 风险 | 可能性 | 影响 | 应对措施 |
|------|--------|------|----------|
| wireguard-go性能不足 | 低 | 高 | 提供内核模块可选支持 |
| netstack Windows不可用 | 中 | 中 | 降级为SOCKS5代理 |
| NAT穿透成功率过低 | 中 | 高 | 优化中继，多TURN节点 |
| WinTUN驱动兼容问题 | 中 | 中 | 提供TAP-Windows备选 |
| 移动端实现困难 | 高 | 中 | 延后移动端计划 |

### 7.2 进度风险

| 风险 | 可能性 | 影响 | 应对措施 |
|------|--------|------|----------|
| 跨平台适配超出预期 | 高 | 中 | 优先核心平台(Linux/Windows) |
| ICE实现复杂度高 | 高 | 高 | 充分利用pion库，减少自研 |
| 测试环境搭建困难 | 中 | 中 | Docker模拟NAT环境 |

---

## 八、P2P连接保证机制

### 8.1 连接建立策略

```
┌─────────────────────────────────────────────────────────────┐
│                   P2P 连接建立流程                           │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. 候选收集 (Gathering)                                     │
│     ├── Host Candidate (本地IP)                             │
│     ├── Server Reflexive (STUN映射IP)                       │
│     └── Relay Candidate (TURN中继IP)                        │
│                                                              │
│  2. 候选交换 (Signaling)                                     │
│     └── 通过协调服务器交换候选地址                            │
│                                                              │
│  3. 连通性检查 (Connectivity Check)                          │
│     ├── 按优先级尝试所有候选对                                │
│     ├── STUN Binding Request/Response                       │
│     └── 选择最优路径                                         │
│                                                              │
│  4. 连接建立                                                 │
│     ├── 成功：建立 WireGuard 隧道                            │
│     └── 失败：回退 TURN 中继                                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 连接保活机制

```go
// 保活策略
const (
    WireGuardKeepalive = 25 * time.Second  // WireGuard 原生心跳
    ICEKeepalive       = 15 * time.Second  // ICE 保活（防止NAT映射超时）
    ReconnectInterval  = 5 * time.Second   // 断线重连间隔
    MaxReconnectDelay  = 5 * time.Minute   // 最大重连退避
)
```

### 8.3 连接质量保证

| 机制 | 描述 |
|------|------|
| 路径探测 | 定期探测延迟，发现更优路径时切换 |
| 故障检测 | 连续丢包超阈值判定为断线 |
| 快速恢复 | 网络切换时主动重新协商 |
| 多路径 | 保留备用路径，主路径故障时快速切换 |

### 8.4 中继保底机制

```
┌─────────────────────────────────────────────────────────────┐
│                    中继回退策略                              │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  优先级排序：                                                │
│  1. P2P直连 (最低延迟)                                       │
│  2. 自建TURN中继 (可控)                                      │
│  3. 云厂商中继 (备用)                                        │
│                                                              │
│  自动回退触发条件：                                          │
│  - ICE协商超时 (10秒)                                        │
│  - 连通性检查全部失败                                        │
│  - 检测到对称NAT对                                           │
│                                                              │
│  回退后优化：                                                │
│  - 后台持续尝试打洞                                          │
│  - 打洞成功后自动切换到P2P                                   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 九、测试策略

### 9.1 测试金字塔

```
                    ┌───────────┐
                    │   E2E     │  跨平台组网测试
                    │   Tests   │
                   ┌┴───────────┴┐
                   │ Integration │  NAT穿透、协调服务
                   │    Tests    │
                  ┌┴─────────────┴┐
                  │  Unit Tests   │  各模块单元测试
                  └───────────────┘
```

### 9.2 关键测试场景

| 场景 | 描述 | 优先级 |
|------|------|--------|
| 同局域网直连 | 两节点在同一网络 | P0 |
| 跨NAT连接 | 不同NAT后的节点连接 | P0 |
| 对称NAT回退 | 对称NAT自动使用中继 | P0 |
| 网络切换 | WiFi/4G切换后重连 | P1 |
| 长时间运行 | 72小时稳定性测试 | P1 |
| 高吞吐测试 | 大文件传输性能 | P1 |
| 多节点组网 | 10+节点Mesh网络 | P2 |

---

## 十、附录

### A. 参考代码库

| 项目 | 参考价值 | 链接 |
|------|----------|------|
| tailscale | 整体架构、netstack实现 | github.com/tailscale/tailscale |
| headscale | 协调服务器实现 | github.com/juanfont/headscale |
| wireguard-go | WireGuard用户态实现 | golang.zx2c4.com/wireguard |
| pion/ice | ICE协商实现 | github.com/pion/ice |
| pion/turn | TURN服务器实现 | github.com/pion/turn |
| netbird | 类似项目参考 | github.com/netbirdio/netbird |

### B. 关键RFC文档

| RFC | 标题 |
|-----|------|
| RFC 5389 | STUN |
| RFC 5766 | TURN |
| RFC 8445 | ICE |
| RFC 8656 | TURN Allocation |

### C. 调试工具命令

```bash
# STUN测试
stun stun.l.google.com:19302

# NAT类型检测
pystun3

# WireGuard调试
wg show
wg showconf

# 网络抓包
tcpdump -i any udp port 51820
wireshark -k -i any

# 性能测试
iperf3 -s              # 服务端
iperf3 -c <ip>         # 客户端
```

---

*文档版本：v0.1*
*创建日期：2026-04-02*
*作者：WinkYou Team*
