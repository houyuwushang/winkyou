# WinkYou 项目文档索引

> 欢迎来到 WinkYou 项目！本文档将帮助你快速了解项目文档结构，并指导你如何开始。

> 当前 MVP 执行以 `docs/EXECUTION-BASELINE.md` 为准。
> 当其他规划文档与其冲突时，优先采用执行基线。

---

## 项目概述

WinkYou 是一个 **P2P 内网穿透虚拟局域网** 项目，让任意设备之间能够安全、高效地直接通信，无需中心服务器转发。

**核心特性**:
- P2P 直连优先，自动 NAT 穿透
- 基于 WireGuard 的端到端加密
- 跨平台支持 (Windows/Linux/macOS)
- 无管理员权限也能使用 (降级模式)
- 完全开源，支持自托管

---

## 当前开发进度

> 截至 2026-04-11

### 已完成

- Git 仓库已初始化，并已按阶段打多次 checkpoint。
- MVP 执行基线、架构文档、任务文档和受信节点中继扩展设计已收敛并回写到文档体系。
- 基础工程已建立：`go.mod`、配置加载、日志、版本信息、CLI 主入口均已可用。
- coordinator 控制面已具备真实 gRPC 传输能力，包含 proto 代码生成、server adapter、client、streaming signal 和测试。
- NAT 模块已具备第一版真实能力：STUN Binding、`XOR-MAPPED-ADDRESS` / `MAPPED-ADDRESS` 解析、host/srflx candidate 收集、保守型 NAT 检测。
- `pkg/netif` 已有可测试的内存后端，支持内存包队列、IP 设置、路由维护和关闭语义。
- `pkg/tunnel` 已有可测试的内存后端，支持生命周期、peer 状态维护、事件流和统计快照。
- `pkg/client` 已有第一版 engine 骨架，已串起 `config + coordinator + nat + netif + tunnel`，并能写入/清理本地 runtime state 文件。
- CLI 已具备 `wink up / down / status / peers / genkey / debug`。
- 测试层已覆盖单元测试、集成测试和 CLI e2e 测试；当前仓库可通过 `go test ./...` 和 `go build ./...`。

### 当前处于骨架阶段的部分

- `pkg/client` 的 `ConnectToPeer` / `DisconnectToPeer` 仍未完成真正的 peer 编排。
- signal payload、候选交换后的隧道 peer 下发、真实连接建立流程还未闭环。
- 当前 `netif` 和 `tunnel` 仍是内存实现，不是 OS 级 TUN / 真实 WireGuard 数据面。
- 当前 NAT 模块尚未完成完整 ICE、TURN 连接和锥形 NAT 细分识别。

### 尚未完成的 MVP 关键项

- 真实 WireGuard 后端接入。
- 真实网络接口后端接入。
- 客户端 peer 自动连接编排闭环。
- TURN relay 服务与回退链路。
- 后台常驻进程/守护化模型收敛。

---

## 本地联调与验收（coordinator + 两客户端 + 可选 TURN）

### 启动顺序（MVP 推荐）

1. 启动 coordinator：`wink-coordinator`（或容器化部署）。  
2. （可选）启动 TURN：`deploy/relay` 下的 coturn 示例。  
3. 启动客户端 A：`wink up --config alpha.yaml`。  
4. 启动客户端 B：`wink up --config beta.yaml`。  
5. 验证状态与连通：`wink peers`、`wink ping <peer>`，并结合集成/e2e 测试目标做 TCP/UDP 连通检查。

### Makefile 测试/构建目标

- `make build-wink`：构建客户端二进制。  
- `make build-wink-coordinator`：构建 coordinator 二进制。  
- `make build-wink-relay`：构建仓库内 TURN relay 二进制。  
- `make build-all`：一次构建上述三个产物。  
- `make test-unit`：仅跑非 `test/` 目录包测试（快速单元/包级）。  
- `make test-integration`：运行 `test/integration`。  
- `make test-e2e`：运行默认 e2e（无特权，memory backend）。  
- `make test-e2e-privileged`：运行需要特权/真实网络条件的 e2e（`privileged_e2e` tag）。

### 如何运行 privileged tests

```bash
WINKYOU_E2E_PRIVILEGED=1 go test -tags=privileged_e2e ./test/e2e/... -count=1
# 或
make test-e2e-privileged
```

运行前建议确认：
- 主机具备 TUN 与网络管理权限；
- 可创建并配置虚拟网卡；
- `wg`、`ip`（Linux）等依赖可用。

---

## 文档结构

```
winkyou/
├── winkplan.md              # 项目规划文档
├── manage.md                # 开发管理文档
├── question.md              # 待确认问题清单
├── guess.md                 # 问题解决方案
├── selfhost.md              # 自研路线图 — 渐进式替换策略
├── selfdev.md               # 完全自研开发计划 — 按WireGuard协议实现
├── protocol.md              # 自研协议设计 — 突破WireGuard协议本身
├── brainstorm.md            # 头脑风暴 — WireGuard缺陷分析
├── wink-protocol-v1.md      # Wink Protocol v1 详细设计 (字节级)
└── docs/
    ├── README.md            # 本文档 - 文档索引
    ├── EXECUTION-BASELINE.md # MVP 执行基线（当前最高优先级）
    ├── PEER-RELAY-DESIGN.md # 受信节点中继扩展设计（post-MVP）
    ├── ARCHITECTURE.md      # 系统架构文档
    └── tasks/               # 任务规格文档
        ├── TASK-01-infrastructure.md
        ├── TASK-02-netif.md
        ├── TASK-03-wireguard.md
        ├── TASK-04-nat-traversal.md
        ├── TASK-05-coordinator.md
        ├── TASK-06-client-core.md
        └── TASK-07-relay.md
```

---

## 文档阅读顺序

### 对于新加入的开发者

建议按以下顺序阅读:

```
1. EXECUTION-BASELINE.md (15分钟) - 了解当前 MVP 的冻结决策
      ↓
2. winkplan.md          (30分钟) - 了解项目背景、长期目标和技术选型
      ↓
3. ARCHITECTURE.md      (20分钟) - 理解当前架构和模块关系
      ↓
4. manage.md            (20分钟) - 了解开发计划和关键问题
      ↓
5. selfhost.md          (20分钟) - 理解自研战略和抽象层设计原则
      ↓
6. question.md          (15分钟) - 了解当前待解决的问题
      ↓
7. guess.md             (15分钟) - 了解问题的解决方案
      ↓
8. 你负责的 TASK-XX.md  (30分钟) - 深入了解具体任务
```

### 对于项目管理者

```
1. EXECUTION-BASELINE.md - 当前 MVP 执行基线
2. ARCHITECTURE.md      - 任务分解和依赖关系
3. manage.md            - 开发管理和风险
4. winkplan.md          - 长期规划
5. question.md          - 待决策事项
```

### 对于快速了解项目

只需阅读:
```
1. EXECUTION-BASELINE.md 第一至四章 (10分钟)
2. ARCHITECTURE.md 第一至三章 (10分钟)
```

如果你关心“节点 A 作为 B 到 C 的受信中继”这种扩展场景，再补读:

```
3. PEER-RELAY-DESIGN.md (10分钟)
```

---

## 各文档详细说明

### EXECUTION-BASELINE.md - MVP 执行基线

**内容概要**:
- MVP 范围冻结
- 模块依赖和执行顺序
- 目录结构和配置模型
- 模块接口契约冻结
- 发布门禁

**适合人群**: 所有直接参与 MVP 开发的成员（**必读**）

---

### PEER-RELAY-DESIGN.md - 受信节点中继扩展设计

**内容概要**:
- 节点 `A` 作为 `B <-> C` 单跳中继的可行性结论
- `TURN relay` 与 `peer relay` 的边界
- 控制面、数据面和路由编排建议
- 安全、性能和验证场景

**适合人群**: 关心自有节点中继、拓扑增强和 post-MVP 扩展的开发者

---

### winkplan.md - 项目规划文档

**内容概要**:
- 项目背景和定位
- 竞品分析 (frp, Tailscale, ZeroTier)
- 核心技术调研 (NAT穿透, WireGuard, 虚拟网卡)
- 系统架构设计
- 功能规划 (MVP → V1.0 → V2.0 → V3.0)
- 技术选型和依赖

**适合人群**: 所有团队成员

---

### manage.md - 开发管理文档

**内容概要**:
- 技术决策和选型理由
- 开发环境准备
- 模块开发顺序
- 详细任务分解和里程碑
- 关键技术问题和待验证事项
- 团队分工建议
- 风险与应对

**适合人群**: 技术负责人、项目经理、核心开发者

---

### selfhost.md - 自研路线图

**内容概要**:
- 数据热路径 vs 控制平面的依赖分类
- 每个第三方依赖的自研难度、价值和优先级
- 抽象层设计原则（第三方类型不泄漏、面向替换设计接口）
- 分阶段自研路线（TUN/STUN → WireGuard → ICE → 协议栈）
- 替换准入条件和质量保证

**适合人群**: 所有开发者（**必读** — 这是项目的技术灵魂）

---

### selfdev.md - 完全自研开发计划

**内容概要**:
- 每个自研模块的具体实现方案（代码骨架级别）
- 协议报文格式、加密流程的逐步拆解
- 各模块的代码量估计和工作顺序
- 每个阶段的验证检查点
- 必读的RFC和参考文档清单
- 渐进式路线 vs 完全自研的对比

**适合人群**: 负责自研模块的核心开发者

---

### protocol.md - 自研协议设计

**内容概要**:
- 为什么按相同协议实现打不过原作者
- 协议层可以动的地方（密码套件、握手简化、批量加密、零拷贝DMA）
- 安全性保证方法（原语安全、协议验证、实现安全）
- 具体的 Wink Protocol v1 设计方案
- PSK直连模式（0-RTT）
- 实现路线和风险评估

**适合人群**: 有密码学背景的架构师、想追求极致性能的团队

---

### ARCHITECTURE.md - 系统架构文档

**内容概要**:
- 项目目标定义 (G1-G7)
- 系统架构总览图
- 任务模块总览和依赖图
- 目标-模块耦合矩阵
- 数据流图
- 模块间接口契约
- 测试策略
- 开发规范

**适合人群**: 所有开发者

---

### question.md - 待确认问题清单

**内容概要**:
- 技术验证类问题 (必须在开发前验证)
- 架构设计决策问题
- MVP 范围确认问题
- 运维和部署问题
- 安全相关问题
- 文档一致性问题

**适合人群**: 技术决策者、架构师

---

### guess.md - 问题解决方案

**内容概要**:
- 每个问题的调研结论
- 推荐的解决方案
- 实现代码示例
- 验证计划
- MVP 功能清单
- 部署建议
- 开发优先级建议

**适合人群**: 所有开发者

---

### TASK 文档 (docs/tasks/)

每个 TASK 文档包含:
- 任务概述和难度评估
- 详细功能需求 (FR-XX)
- 技术要求和选型
- 验收标准 (AC-XX)
- 交付物清单
- 接口契约
- 注意事项
- 待确认问题

| 任务 | 文件 | 难度 | 依赖 | 简述 |
|------|------|------|------|------|
| TASK-01 | infrastructure.md | 低 | 无 | 配置、日志、CLI 框架 |
| TASK-02 | netif.md | 中 | 01 | 网络接口抽象层 |
| TASK-03 | wireguard.md | 中 | 02 | WireGuard 隧道封装 |
| TASK-04 | nat-traversal.md | **高** | 01,05 | NAT 穿透 (STUN/ICE) |
| TASK-05 | coordinator.md | 中 | 01 | 协调服务器 |
| TASK-06 | client-core.md | **高** | 02,03,04,05 | 客户端核心集成 |
| TASK-07 | relay.md | 中 | 04 | 中继服务 (TURN) |

---

## 快速入门指南

### 如果你是后端开发者

1. 阅读 winkplan.md 了解项目技术栈 (Go)
2. 根据你的技能选择任务:
   - **网络编程经验**: TASK-02, TASK-04, TASK-07
   - **服务端开发经验**: TASK-05
   - **系统编程经验**: TASK-03
   - **通用 Go 开发**: TASK-01, TASK-06

### 如果你是新手

建议从 TASK-01 (基础设施) 开始:
- 难度最低
- 无外部依赖
- 是所有其他任务的基础
- 涉及常见技术 (CLI, 配置, 日志)

### 开始开发前

1. **确认开发环境**:
   ```bash
   go version    # 需要 Go 1.22+
   git --version
   docker --version
   ```

2. **克隆项目**:
   ```bash
   git clone <repo-url>
   cd winkyou
   ```

3. **阅读你负责的 TASK 文档**

4. **创建功能分支**:
   ```bash
   git checkout -b feature/task-XX-description
   ```

5. **开发并提交**:
   ```bash
   git add .
   git commit -m "feat(task-XX): implement feature description"
   ```

---

## 关键技术参考

### 必读参考

| 主题 | 链接 |
|------|------|
| WireGuard 协议 | [wireguard.com](https://www.wireguard.com/) |
| NAT 穿透原理 | [Tailscale: How NAT Traversal Works](https://tailscale.com/blog/how-nat-traversal-works) |
| ICE 协议 | [RFC 8445](https://tools.ietf.org/html/rfc8445) |
| STUN 协议 | [RFC 5389](https://tools.ietf.org/html/rfc5389) |

### 代码参考

| 项目 | 参考价值 |
|------|----------|
| [tailscale](https://github.com/tailscale/tailscale) | 整体架构、netstack 实现 |
| [headscale](https://github.com/juanfont/headscale) | 协调服务器实现 |
| [wireguard-go](https://git.zx2c4.com/wireguard-go/) | WireGuard 用户态实现 |
| [pion/ice](https://github.com/pion/ice) | ICE 协商实现 |
| [netbird](https://github.com/netbirdio/netbird) | 类似项目参考 |

---

## 常见问题

### Q: 任务之间的依赖关系是什么？

```
TASK-01 (基础设施)
    ├── TASK-02 (网络接口) ─► TASK-03 (WG) ────┐
    └── TASK-05 (协调服务器) ─► TASK-04 (NAT穿透) ─┼──► TASK-06 (客户端核心)
                                              └──► TASK-07 (中继)
```

当前执行基线补充:
- TASK-04 的 MVP 完成依赖 TASK-05 的信令能力
- TASK-07 不是 TASK-06 的开发启动前置依赖，但属于 MVP 发布门禁依赖

### Q: 哪些任务可以并行开发？

建议按执行基线推进:
- TASK-01 完成后，优先并行推进 TASK-02 和 TASK-05
- TASK-03 在 TASK-02 之后推进
- TASK-04 可先做 STUN/NAT 原型，但完整 MVP 交付依赖 TASK-05 信令
- TASK-07 在 TASK-04 之后推进
- TASK-06 在 TASK-02,03,04,05 可用后启动，TASK-07 作为 MVP 发布门禁补齐

### Q: MVP 需要完成哪些任务？

所有 7 个任务都需要完成 MVP 版本，但各任务的 MVP 范围有所精简:
- TASK-02: 仅 TUN + netstack (不含 TAP)
- TASK-05: 单点协调服务器
- TASK-07: 基本 TURN 中继

补充说明:
- TASK-06 可先完成“直连版集成”
- 但没有 TASK-07 时，不能宣称 MVP 完整完成，因为中继保底能力未闭合

### Q: 有问题应该问谁？

1. 首先查看相关 TASK 文档的 "待确认问题" 部分
2. 查看 question.md 和 guess.md
3. 在项目 Issue 中讨论

---

## 贡献指南

### 提交规范

```
<type>(<scope>): <subject>

type:
  - feat:     新功能
  - fix:      修复 bug
  - docs:     文档更新
  - refactor: 重构
  - test:     测试
  - chore:    构建/工具

scope: task-01 | task-02 | ... | all

示例:
feat(task-02): implement Linux TUN backend
fix(task-04): handle STUN timeout correctly
```

### 代码规范

- 遵循 [Effective Go](https://golang.org/doc/effective_go)
- 使用 `golangci-lint` 检查
- 核心模块测试覆盖率 > 80%

---

## 联系方式

- 项目仓库: [待填写]
- Issue 追踪: [待填写]
- 讨论组: [待填写]

---

*文档版本: v1.0*
*创建日期: 2026-04-02*
*维护者: WinkYou Team*
