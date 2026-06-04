# WinkYou

WinkYou 是一个正在演进中的 P2P 虚拟局域网项目。当前架构定义是：

```text
WinkYou = connectivity solver + secure WireGuard data plane
```

项目不再以固定 ICE/TURN 流程作为架构中心。ICE、TURN relay、未来的 QUIC/TCP/proxy 路径都应被视为连接求解器可选择的候选路径；真正承载数据的是统一的 `transport.PacketTransport` 边界和 userspace `wireguard-go` 数据平面。

## 当前状态

当前代码已经完成 Phase 3B code health，并已进入 Phase 4A 的第一个真实扩展点：`relay_only` 作为第二个真实 strategy。

- 活跃架构权威：[`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- Phase 2D 已冻结：`phase2d-freeze-2026-04-24`
- Phase 3A strategy portfolio foundation 已落地
- Phase 3B code health 已完成，包括 CI 质量门、session 机械拆分、状态转换校验、resolver 统一、context 边界修复和若干小型清理
- Phase 4A 已新增 `relay_only` strategy
- 当前生产注册顺序保持兼容：`legacy_ice_udp` -> `relay_only`
- `connectivity.mode: relay_only` 会把生产 strategy 顺序切到 `relay_only` -> `legacy_ice_udp`
- 旧的 `nat.force_relay: true` 仍兼容映射到 relay-only 行为
- 旧 peer 空 capability 仍会隐式 fallback 到 `legacy_ice_udp`

当文档发生冲突时，以 [`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md) 作为 session、solver、strategy 和 transport 边界的判断依据。部分历史架构文档已标记为 proposal/archive，不能覆盖 active baseline。

## 当前可运行路径

当前可部署的主路径仍是：

- Windows client 使用 TUN/Wintun
- Linux client / peer
- Linux coordinator
- coturn 作为公网部署推荐 TURN relay
- userspace `wireguard-go` 作为安全数据平面
- `PacketTransport` 负责把选中的 packet path 绑定给 tunnel
- rendezvous v2 envelope 负责 capability、observation、probe、path_commit 等 session 消息

当前真实 strategy：

- `legacy_ice_udp`：兼容现有 ICE/UDP 路径，内部支持 `direct_prefer` 和 `relay_only` execution plan
- `relay_only`：第二个真实 strategy，是 `legacyice` 的 thin wrapper，强制 relay，并对外以 `relay_only` 出现在 capability、observation 和 path_commit 中

默认连接策略：

```yaml
connectivity:
  mode: auto
  strategy_order:
    - legacy_ice_udp
    - relay_only
```

显式验证 relay-only 路径时，优先使用连接策略入口：

```yaml
connectivity:
  mode: relay_only
  strategy_order:
    - relay_only
    - legacy_ice_udp

nat:
  turn_servers:
    - url: turn:your-turn.example.com:3478?transport=udp
      username: winkdemo
      password: winkdemo-pass
```

旧配置仍兼容：

```yaml
nat:
  force_relay: true
  turn_servers:
    - url: turn:your-turn.example.com:3478?transport=udp
      username: winkdemo
      password: winkdemo-pass
```

在 relay-only 模式下，如果双方都支持 `relay_only`，生产 resolver 会优先选择 `relay_only`。如果远端是旧 peer 且没有上报 capability，仍会 fallback 到 `legacy_ice_udp`，但 legacy ICE agent 会继续使用 relay-only candidate gathering。

尚未完成：

- no-admin mode
- proxy/userspace-only 产品路径
- TCP framed、QUIC datagram、HTTP CONNECT、WebSocket 等真实 transport strategy
- 完整 observation -> scoring -> learning 闭环
- GUI 或桌面常驻 daemon

## 架构边界

- `pkg/session` 负责 session 生命周期、状态机、capability 交换、rendezvous envelope、probe/observation 消息和 binder 协调；不要把 NAT/ICE 细节重新引入这里。
- `pkg/solver` 保持 strategy-agnostic，只处理通用 `Strategy`、`Plan`、`Result`、observation 和 plan ordering/refinement 输入。
- `pkg/transport` 提供稳定的 `PacketTransport` 边界；当前不要把它改成新的 V2 接口。
- `pkg/tunnel` 使用 `wireguard-go` 和 `PacketTransport` 消费 packet 数据，不拥有路径求解逻辑。
- strategy 专属逻辑放在 `pkg/solver/strategy/*` 或 client 组装边界中。

## 目录导览

- [`pkg/session`](./pkg/session)：session lifecycle、state machine、strategy selection、planning、probe、observation、envelope 和 binder 协调
- [`pkg/client`](./pkg/client)：客户端 engine、生产 resolver 组装、peer session 和运行时状态
- [`pkg/solver`](./pkg/solver)：连接求解器核心抽象
- [`pkg/solver/strategy/legacyice`](./pkg/solver/strategy/legacyice)：当前 ICE/UDP 兼容 strategy
- [`pkg/solver/strategy/relayonly`](./pkg/solver/strategy/relayonly)：relay-only strategy
- [`pkg/transport`](./pkg/transport)：packet transport 抽象及适配器
- [`pkg/tunnel`](./pkg/tunnel)：userspace WireGuard 数据平面和 per-peer transport bind
- [`pkg/rendezvous`](./pkg/rendezvous)：coordinator-backed rendezvous 通道与 v2 envelope 类型
- [`pkg/probe`](./pkg/probe)：probe model/lab
- [`deploy/quickstart`](./deploy/quickstart)：快速部署素材
- [`deploy/coturn`](./deploy/coturn)：TURN relay 部署素材
- [`docs/README.md`](./docs/README.md)：文档分级索引

## 常用命令

```bash
go fmt ./...
go vet ./...
go test ./... -count=1
go test -race ./pkg/session ./pkg/client ./pkg/solver/... -count=1
```

Makefile 中也提供了等价入口：

```bash
make check
make test-race
make test-phase2d
make test-phase3a
make test-phase4a
make build-all
```

Windows 本机跑 race test 需要可用的 cgo/GCC 环境。可以使用 MSYS2、MinGW-w64、w64devkit 或等价工具链，并在当前 shell 中临时启用：

```powershell
$env:PATH='<gcc-bin-dir>;' + $env:PATH
$env:CGO_ENABLED='1'
$env:CC='gcc'
go test -race ./pkg/session ./pkg/client ./pkg/solver/... -count=1
```

## 构建

```bash
make build-wink
make build-wink-coordinator
make build-wink-relay
make build-all
```

跨平台构建入口：

```bash
make build-windows-client
make build-linux-client
make build-linux-coordinator
make build-linux-relay
```

构建产物输出到 `bin/`。根目录下的 `wink.exe`、`netprobe.exe`、`e2e.test` 当前不应作为源码树的一部分跟踪。

## Relay 握手排障

当预期走 relay 时，先使用 `wink peers` 或 `wink peers --json`。CLI 会展示从 ICE 选择、transport attach 到 WireGuard handshake 的链路状态。

示例：

```text
Peer 1
  Name:        beta
  Node ID:     node-000002
  Virtual IP:  10.77.0.2
  Public Key:  BRWDltpykmj7xkz5mscwH82XtleebmfOtYvvaIxIRVQ=
  State:       connected
  Endpoint:    127.0.0.1:65042
  Conn Type:   relay
  ICE State:   connected
  Local Cand:  relay:127.0.0.1:65040
  Remote Cand: relay:127.0.0.1:65042
  Tx:          1.2 KiB
  Rx:          304 B
  Xport Tx:    13 pkts / 1.2 KiB
  Xport Rx:    4 pkts / 304 B
  Xport Err:   -
  Handshake:   2026-04-22T16:04:34Z
  Last Seen:   2026-04-22T16:04:34Z
```

排查顺序：

- `ICE State` 不是 `connected` 或 `completed`：问题仍在 ICE/TURN 或 candidate exchange。
- `Local Cand` / `Remote Cand` 未出现 `relay`：没有选中 relay path，或 relay candidate 没有成功 gather。
- candidate 显示 relay，但 `Xport Tx` / `Xport Rx` 始终为 `0`：ICE transport 已选中，但 `PacketTransport` 未 attach 或未保持存活。
- `Xport Tx` / `Xport Rx` 增长且 `Xport Err` 非空：transport/bind 读写失败。
- `Xport Tx` / `Xport Rx` 增长但 `Handshake` 仍为 `-`：relay packet 在流动，但 WireGuard 握手没有完成。
- `Handshake` 非 `-` 但业务流量失败：检查 `AllowedIPs`、路由、防火墙和 MTU。

## 文档定位

- Active baseline：[`docs/CONNECTIVITY-SOLVER-BASELINE.md`](./docs/CONNECTIVITY-SOLVER-BASELINE.md)
- 文档索引：[`docs/README.md`](./docs/README.md)
- Phase 2D freeze gate：[`docs/PHASE2D-FREEZE.md`](./docs/PHASE2D-FREEZE.md)
- Phase 3A entry：[`docs/PHASE3A-STRATEGY-PORTFOLIO.md`](./docs/PHASE3A-STRATEGY-PORTFOLIO.md)
- Phase 3B+ working plan：[`implementation_plan.md`](./implementation_plan.md)
- legacy execution baseline notice：[`docs/EXECUTION-BASELINE.md`](./docs/EXECUTION-BASELINE.md)

历史 ICE/TURN-centric baseline 保留在 tag `legacy-ice-turn-baseline-2026-04-15`，仅用于回溯和 rollback 分析。当前代码应按 connectivity solver baseline 评估。
