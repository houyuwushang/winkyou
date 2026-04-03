# WinkYou 项目文档索引

> 欢迎来到 WinkYou 项目！本文档将帮助你快速了解项目文档结构，并指导你如何开始。

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
1. winkplan.md          (30分钟) - 了解项目背景、目标和技术选型
      ↓
2. ARCHITECTURE.md      (20分钟) - 理解系统架构和模块关系
      ↓
3. selfhost.md          (20分钟) - 理解自研战略和抽象层设计原则
      ↓
4. manage.md            (20分钟) - 了解开发计划和关键问题
      ↓
5. question.md          (15分钟) - 了解当前待解决的问题
      ↓
6. guess.md             (15分钟) - 了解问题的解决方案
      ↓
7. 你负责的 TASK-XX.md  (30分钟) - 深入了解具体任务
```

### 对于项目管理者

```
1. winkplan.md          - 项目整体规划
2. manage.md            - 开发管理和风险
3. ARCHITECTURE.md      - 任务分解和依赖关系
4. selfhost.md          - 自研路线和长期战略
5. question.md          - 待决策事项
```

### 对于快速了解项目

只需阅读:
```
1. winkplan.md 第一、二章  (10分钟)
2. ARCHITECTURE.md 第一、二章 (10分钟)
```

---

## 各文档详细说明

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
| TASK-04 | nat-traversal.md | **高** | 01 | NAT 穿透 (STUN/ICE) |
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
    ├── TASK-02 (网络接口) ─────┐
    │       └── TASK-03 (WG) ──┤
    ├── TASK-04 (NAT穿透) ─────┼──► TASK-06 (客户端核心)
    │       └── TASK-07 (中继) ┤
    └── TASK-05 (协调服务器) ──┘
```

### Q: 哪些任务可以并行开发？

在 TASK-01 完成后，以下任务可以并行:
- TASK-02, TASK-04, TASK-05, TASK-07

### Q: MVP 需要完成哪些任务？

所有 7 个任务都需要完成 MVP 版本，但各任务的 MVP 范围有所精简:
- TASK-02: 仅 TUN + netstack (不含 TAP)
- TASK-05: 单点协调服务器
- TASK-07: 基本 TURN 中继

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
