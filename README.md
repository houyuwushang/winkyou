# WinkYou

WinkYou 是一个正在演进中的 P2P 虚拟局域网项目。当前架构定义是：

```text
WinkYou = connectivity solver + secure WireGuard data plane
```

项目不再以固定 ICE/TURN 流程作为架构中心。ICE、TURN relay、未来的 QUIC/TCP/proxy 路径都应被视为连接求解器可选择的候选路径；真正承载数据的是统一的 `transport.PacketTransport` 边界和 userspace `wireguard-go` 数据平面。

## 当前状态

- v2 直连优先计划已经 **Accepted**；接受范围、证据与不授权事项见 [`docs/PHASE0-EXIT-RECORD.md`](./docs/PHASE0-EXIT-RECORD.md)，完整计划见 [`docs/proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./docs/proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md)。
- 项目处于 **Phase 1a 构建期**。当前树已包含 machine-wide governor、`probeio` 网络能力边界、保持不变的 stdio API v1、显式版本的 N3b stdio v2 候选，以及 Gate A/B 的 OOB handoff 与困难 NAT 隔离证明。v2 direct 目前仍只由 literal loopback、memory/natsim 和 Linux 隔离 namespace 验证；Gate C 的 SSH/产品装配仅有 Draft 设计，真实 LAN/公网、正式身份、产品 session 与数据面接线仍未授权。
- [`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md) 仍是当前实现权威；Accepted v2 计划不会在正式 ADR 合入前取代它。
- 当前版本仍是开发中的 alpha，不应被描述为 production-ready、零信任网络或已经完成真实公网验收的 v2 产品。

## 安全边界

- cached self-bootstrap / autonomous birthday recovery 继续维持 **NO-GO 与暂停决定**；当前二进制会 fail-closed 拒绝相关配置，不得重新部署或绕过门禁。
- 历史部署的计划任务保持 `Disabled`，不得因文档重构而启用；本仓库的普通构建和测试也不授权真实家庭网、办公网或公网探测。
- 事故根因、影响与恢复门禁见 [`docs/INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./docs/INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)；已去除个人部署细节的停机原则归档在 [`docs/RUNBOOK-EMERGENCY-STOP-HISTORICAL-WINDOWS.md`](./docs/RUNBOOK-EMERGENCY-STOP-HISTORICAL-WINDOWS.md)。
- v2 计划 Accepted 只授权其明确列出的本地、模拟器与安全基础设施工作，不授权自动恢复、公共 coordinator/DHT/relay、遥测收集或生产发布。
- N3b 提供代码入口不等于现场许可：`winkyou.stdio/v2` direct arm、`wink-rendezvous` 和离线配对命令在独立安全评审闭合并签发具名窗口前，均不得用于真实 LAN/公网。
- Gate B3 隔离实现合入也不等于产品或现场许可；Gate C1 Draft、空白模板、确认 flag、CI 或构建均不能授权 SSH、非回环 UDP、WireGuard handoff 或真实设备 attempt。

## 快速开始

### 无发包的首次检查

仓库要求 Go 1.23.1 或兼容工具链。第一次接触项目时，建议先运行 Phase 1a 的被动诊断；它读取本机安全 namespace、配置、接口和路由状态，但不会打开 socket 或发送探测包：

```bash
go run ./cmd/wink diagnose
go run ./cmd/wink diagnose --json
```

机器级安全 namespace 的准备、非特权用户的显式降级边界与输出解释见：

- [`docs/PASSIVE-DIAGNOSE.md`](./docs/PASSIVE-DIAGNOSE.md)
- [`docs/MACHINE-SAFETY-NAMESPACE.md`](./docs/MACHINE-SAFETY-NAMESPACE.md)
- [`docs/USER-ACKNOWLEDGED-SCOPE.md`](./docs/USER-ACKNOWLEDGED-SCOPE.md)

`wink doctor` 是现有 legacy runtime 的联网诊断入口，会检查 coordinator、STUN/TURN 和路径候选；只有在明确授权的网络中才应运行。它与无发包的 `wink diagnose` 不是同一个安全级别。

### 自托管两节点路径

当前可复现的端到端路径仍是默认 legacy 模式：一台 Linux 公网服务器运行 coordinator + coturn，两台 client 通过连接求解器建立 direct 或 relay path，再由 WireGuard 数据面承载流量。完整证书生成、密钥权限、Compose 启动、client 配置和 direct/relay 验收步骤见 [`docs/SELFHOST-QUICKSTART.md`](./docs/SELFHOST-QUICKSTART.md)。

完成 quickstart 中的 TLS 证书、共享凭证和 `.env` 准备后，服务端使用：

```bash
docker compose --env-file deploy/quickstart/.env \
  -f deploy/quickstart/docker-compose.yml up -d --build
```

这里的 Docker 路径只容器化 coordinator 与 coturn；需要 TUN/Wintun 的 client 仍在宿主机运行。远程 coordinator 必须使用 `grpcs://`、匹配 IP/DNS SAN 的证书和部署级共享凭证；明文 `grpc://` 或无 scheme 地址只允许数值 loopback（`127.0.0.0/8`、`::1`），`localhost` 也不会被当作显式 loopback。共享凭证只证明部署成员资格，不提供每节点身份隔离。

## 当前可运行路径

| 入口 | 当前定位 | 关键边界 |
| --- | --- | --- |
| `wink diagnose` | Phase 1a 被动首次检查 | 不开 socket、不发包；主动探测仍受 governor 与安全门禁约束 |
| `wink solver serve --stdio` + `winkyou.stdio/v1` | Phase 1a 一次性回环连通证明 | v1 schema/golden 保持不变；仅 canonical 数值 loopback，每端最多 3 包，成功后立即关闭 |
| `wink solver serve --stdio` + `winkyou.stdio/v2` direct arm | N3b 一次性 direct-attempt 候选 | 显式 exact-version、单 credential、无重试；只获准在回环/隔离 netns 验证，真实 LAN/公网仍为 NO-GO |
| `wink solver pair direct --out-dir <new-dir>` | 离线生成一对 N2 OOB artifact | 目录必须不存在；manifest 最后写入；PSK 不进终端或日志，使用后即焚 |
| `wink-rendezvous serve ...` | one-shot 有界密文转发器 | 构建存在不等于部署授权；单 association、双 slot、TLS 1.3、零持久化，不是 coordinator/relay |
| 默认 `wink up` | legacy coordinator + ICE/TURN + WireGuard 端到端路径 | 会进行真实网络通信；远程 coordinator 强制 TLS + auth |
| `connectivity.mode: relay_only` | TURN relay 保活与验收路径 | 仍使用同一 WireGuard 数据面；需要正确开放 coturn relay 端口 |
| `autonomous_mesh` | 默认关闭的历史实验路径 | birthday recovery 相关配置 fail-closed；不是当前 quickstart，也不得重新启用历史任务 |

常用 client 生命周期命令：

```bash
wink --config <config.yaml> up
wink --config <config.yaml> status
wink --config <config.yaml> peers
wink --config <config.yaml> logs
wink --config <config.yaml> down
```

长期运行、强制停止差异和日志位置见 [`docs/LONG-RUNNING-CLIENT.md`](./docs/LONG-RUNNING-CLIENT.md)。

## 构建与验证

使用 Makefile：

```bash
make build-wink
make build-wink-coordinator
make build-wink-relay
make check
make test-race
make test-loopback-connect
```

Windows 或已安装 PowerShell 7 的环境也可直接运行
`./scripts/verify-loopback-connect.ps1`。该入口只执行受限的回环测试与架构门禁；证据组成、
预期包数和它没有证明的边界见
[`docs/LOOPBACK-CONNECT-TEST.md`](./docs/LOOPBACK-CONNECT-TEST.md)。

也可以直接使用 Go 构建当前平台的二进制：

```bash
go build -o bin/wink ./cmd/wink
go build -o bin/wink-coordinator ./cmd/wink-coordinator
go build -o bin/wink-relay ./cmd/wink-relay
go build -o bin/wink-rendezvous ./cmd/wink-rendezvous
```

跨平台 release 构建与校验流程见 [`docs/RELEASE.md`](./docs/RELEASE.md)。构建产物写入 `bin/` 或 `dist/`，不应提交到源码树。

## 架构边界

- `pkg/solver` 是 strategy-agnostic 的连接求解 domain，负责通用 capability、observation、plan ordering/refinement 与结果模型，不依赖 wire DTO。
- `pkg/session` 负责 session 生命周期、状态机、rendezvous adapter、probe/observation 协调与 binder 编排；NAT/ICE 专属细节不应回流到这里。
- `pkg/transport` 提供稳定的 `PacketTransport` 边界；不同连接策略通过它向上层交付统一的 packet transport。
- `pkg/tunnel` 使用 userspace `wireguard-go` 和 `PacketTransport` 承载数据，不拥有路径求解逻辑。
- strategy 专属实现位于 `pkg/solver/strategy/*` 或 client 组装边界；安全预算与实际网络 I/O 必须经过 `internal/governor` / `internal/probeio` 门禁。

## 目录导览

- [`cmd/`](./cmd)：`wink`、coordinator、relay、one-shot rendezvous 与开发工具入口
- [`pkg/solver`](./pkg/solver)：连接求解器 domain 与 strategy portfolio
- [`pkg/session`](./pkg/session)：session 编排和 wire/domain adapter 边界
- [`pkg/transport`](./pkg/transport)：统一 packet transport 抽象与适配器
- [`pkg/tunnel`](./pkg/tunnel)：userspace WireGuard 数据面
- [`pkg/rendezvous`](./pkg/rendezvous)：coordinator-backed rendezvous 通道和 wire protocol
- [`pkg/probe`](./pkg/probe)：probe model 与受控实验支持
- [`internal/governor`](./internal/governor)：机器级资源预算、owner lock 与持久 safety trip
- [`internal/probeio`](./internal/probeio)：受 governor 约束的网络 I/O 能力
- [`internal/architecture`](./internal/architecture)：依赖方向与网络能力回归门禁
- [`deploy/quickstart`](./deploy/quickstart)：coordinator + coturn Compose 与 client 配置模板
- [`docs/`](./docs)：架构权威、路线图、运维文档、事故记录和历史归档

## 文档定位

- 当前实现权威：[`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- Accepted v2 计划：[`docs/proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./docs/proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md)
- Phase 0 出口记录：[`docs/PHASE0-EXIT-RECORD.md`](./docs/PHASE0-EXIT-RECORD.md)
- Phase 1a 回环 connect-test 与本地验证入口：[`docs/LOOPBACK-CONNECT-TEST.md`](./docs/LOOPBACK-CONNECT-TEST.md)
- N3b 显式 stdio v2 协议与实现证据：[`docs/STDIO-API-V2.md`](./docs/STDIO-API-V2.md)、[`docs/N3B-PRODUCT-ENTRY-EVIDENCE.md`](./docs/N3B-PRODUCT-ENTRY-EVIDENCE.md)
- Accepted N3a 设计与空白现场授权模板：[`docs/adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./docs/adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)、[`docs/N3-LIVE-AUTHORIZATION-TEMPLATE.md`](./docs/N3-LIVE-AUTHORIZATION-TEMPLATE.md)
- Draft Gate C1 SSH/OOB 与产品 handoff 设计（docs-only、无现场权限）：[`docs/adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md`](./docs/adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md)、[`docs/N3C-GATE-C-LIVE-AUTHORIZATION-TEMPLATE.md`](./docs/N3C-GATE-C-LIVE-AUTHORIZATION-TEMPLATE.md)
- 自托管 quickstart：[`docs/SELFHOST-QUICKSTART.md`](./docs/SELFHOST-QUICKSTART.md)
- 分层排障：[`docs/TROUBLESHOOTING.md`](./docs/TROUBLESHOOTING.md)
- 事故记录：[`docs/INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./docs/INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)
- 完整文档索引：[`docs/README.md`](./docs/README.md)

历史 ICE/TURN-centric baseline 保留在 tag `legacy-ice-turn-baseline-2026-04-15`，仅用于回溯和 rollback 分析。当前代码应按 connectivity solver baseline 和已接受的 v2 阶段边界评估。
