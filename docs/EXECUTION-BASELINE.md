# WinkYou MVP 执行基线

> 目的：把当前仓库中分散且互相冲突的规划，收敛为一份可以直接执行的 MVP 基线。
>
> 适用范围：MVP 到首个可用命令行版本发布前。
>
> 优先级：当本文件与 `winkplan.md`、`manage.md`、`docs/ARCHITECTURE.md`、各 TASK 文档冲突时，以本文件为准；旧文档后续应回改到与本文件一致。

---

## 一、基线结论

本执行基线冻结以下决策：

1. MVP 只覆盖 `Windows/Linux/macOS`，不包含 `Android/iOS`。
2. MVP 只交付 `CLI`，不包含 `GUI`。
3. MVP 只支持 `IPv4`，不包含 `IPv6`。
4. MVP 的加密隧道实现固定为 `wireguard-go`，不把 `Wink Protocol v1` 纳入 MVP 交付范围。
5. MVP 的网络接口能力包含 `TUN`、`userspace netstack`、`SOCKS5 fallback`，不包含 `TAP`。
6. MVP 的中继能力只做 `UDP TURN`，不做 `TCP TURN`。
7. MVP 的控制平面采用 `单协调服务器 + SQLite`，不做多实例同步。
8. MVP 的网络模型采用 `单网络`，不做网络组、多租户、OIDC、ACL。
9. Go 版本基线统一为 `Go 1.22+`。
10. 代码目录和接口命名从本文件开始冻结，后续不再出现第二套版本。

---

## 二、MVP 范围

### 2.1 包含项

- 节点注册与节点发现
- TUN 虚拟网卡
- userspace netstack 无权限模式
- SOCKS5 降级模式
- 两节点及多节点虚拟网组网
- STUN 获取公网映射
- ICE 候选交换与连通性检查
- TURN 中继回退
- `wink up / down / status / peers / genkey / debug`
- 单协调服务器自托管
- 单中继服务器自托管

### 2.2 明确不在 MVP 内

- GUI 客户端
- Android/iOS
- Wink Protocol v1
- AES-GCM/`cipher_suite` 协商
- TAP 二层模式
- IPv6
- 多协调服务器
- OIDC / 用户账户体系
- 网络组 / 多租户 / ACL
- TCP TURN
- 受信节点中继（`peer relay / transit node`）

---

## 三、依赖图收敛

### 3.1 模块依赖

| 模块 | 硬依赖 | 说明 |
|------|--------|------|
| TASK-01 基础设施 | 无 | 初始化仓库、配置、日志、CLI、版本信息 |
| TASK-02 网络接口 | TASK-01 | 提供 TUN / userspace / proxy |
| TASK-03 隧道层 | TASK-02 | 对接 `NetworkInterface` |
| TASK-05 协调服务器 | TASK-01 | 注册、发现、信令 |
| TASK-04 NAT 穿透 | TASK-01, TASK-05 | STUN 本地原型可先行，但 MVP 完成必须依赖 TASK-05 信令 |
| TASK-07 中继服务 | TASK-04 | TURN 候选与回退逻辑建立在 NAT 模块之上 |
| TASK-06 客户端核心 | TASK-02, TASK-03, TASK-04, TASK-05 | 可先完成直连版集成 |

### 3.2 TASK-06 与 TASK-07 的关系

冻结决策：

- `TASK-07` 不是 `TASK-06` 的“开发启动前置依赖”。
- `TASK-07` 是 `TASK-06` 的“MVP 发布门禁依赖”。

也就是：

- 没有 `TASK-07`，可以做出“直连版客户端集成”。
- 没有 `TASK-07`，不能宣称完成 MVP，因为 G3“穿透失败自动回退中继”仍未实现。

---

## 四、执行顺序

MVP 主执行线按以下顺序推进：

| 里程碑 | 模块 | 目标 | 完成标志 |
|--------|------|------|----------|
| M0 | 仓库初始化 | 建立代码骨架与工具链 | 存在 `go.mod`、`cmd/`、`pkg/`、`api/`、`test/`、`deploy/`、CI |
| M1 | TASK-01 | 基础设施可用 | `wink version`、配置加载、日志输出可运行 |
| M2 | TASK-02 + TASK-03 | 手动直连 | 两节点手工配置可通过隧道互通 |
| M3 | TASK-05 | 控制平面可用 | 注册、发现、信令可用 |
| M4 | TASK-04 | 自动直连 | 通过协调服务器交换候选并建立 P2P 连接 |
| M5 | TASK-07 | 中继保底 | 对称 NAT 场景能回退 TURN |
| M6 | TASK-06 | 客户端整合 | `wink up/down/status/peers` 完整打通 |

冻结说明：

- 不再采用“先做完整 NAT/ICE，再做协调信令”的顺序。
- 信令属于 NAT/ICE 的硬依赖，协调服务器必须先于 TASK-04 MVP 交付。

---

## 五、目录结构冻结

MVP 统一采用以下目录结构：

```text
winkyou/
├── cmd/
│   ├── wink/
│   ├── wink-coordinator/
│   └── wink-relay/
├── pkg/
│   ├── config/
│   ├── logger/
│   ├── version/
│   ├── netif/
│   ├── tunnel/
│   ├── nat/
│   ├── coordinator/
│   │   ├── client/
│   │   └── server/
│   ├── relay/
│   │   ├── client/
│   │   └── server/
│   └── client/
├── api/
│   └── proto/
│       └── coordinator.proto
├── deploy/
│   ├── coordinator/
│   └── relay/
├── test/
│   ├── integration/
│   └── e2e/
├── docs/
└── Makefile
```

### 5.1 明确排除的目录版本

以下布局不进入 MVP 基线：

- `cmd/winkd`
- `cmd/wink-ui`
- `pkg/node`
- `pkg/network`
- `pkg/protocol`
- 顶层 `platform/`

平台差异代码统一放在对应包内，使用 build tags 组织，而不是另起一套顶层结构。

---

## 六、配置模型冻结

### 6.1 配置根结构

MVP 配置文件不使用 `wink:` 根节点，统一采用扁平顶层结构。

### 6.2 配置字段

```yaml
node:
  name: "my-node"

log:
  level: "info"
  format: "text"
  output: "stderr"
  file: ""

coordinator:
  url: "https://coord.example.com:443"
  timeout: 10s
  auth_key: ""
  tls:
    insecure_skip_verify: false
    ca_file: ""

netif:
  backend: "auto"      # auto|tun|userspace|proxy
  mtu: 1280

wireguard:
  private_key: ""
  listen_port: 51820

nat:
  stun_servers:
    - "stun:stun.l.google.com:19302"
  turn_servers:
    - url: "turn:relay.example.com:3478"
      username: "wink"
      password: "secret"
```

### 6.3 配置冻结说明

- `relay:` 顶层配置不进入客户端配置模型。
- TURN 服务器列表统一放在 `nat.turn_servers`。
- `cipher_suite` 不进入 MVP 配置。
- `tap` 不进入 `netif.backend` 的 MVP 可选值。

### 6.4 MVP 认证冻结

MVP 不做用户体系，采用最小化接入模型：

- 协调服务器可配置一个可选的 `auth_key`
- 客户端通过 `coordinator.auth_key` 传入
- 若服务器未启用 `auth_key`，则允许开放注册

MVP 不包含：

- OIDC
- 用户名密码
- 多角色权限模型

---

## 七、接口契约冻结

本节只定义 MVP 的收敛接口，不追求长期最优，只追求能稳定集成。

### 7.1 netif

```go
package netif

type Config struct {
    Backend string
    MTU     int
}

type NetworkInterface interface {
    Name() string
    Type() string
    MTU() int
    Read(buf []byte) (int, error)
    Write(buf []byte) (int, error)
    Close() error
    SetIP(ip net.IP, mask net.IPMask) error
    AddRoute(dst *net.IPNet, gateway net.IP) error
    RemoveRoute(dst *net.IPNet) error
}

func New(cfg Config) (NetworkInterface, error)
```

冻结说明：

- MVP 统一使用 `netif.New(...)`，不再出现 `Select(...)` 与 `SelectBackend(...)` 两套构造器。
- 自动后端选择逻辑内聚在 `netif.New(...)` 内部。

### 7.2 tunnel

```go
package tunnel

type Config struct {
    Interface  netif.NetworkInterface
    PrivateKey PrivateKey
    ListenPort int
}

type Tunnel interface {
    Start() error
    Stop() error
    AddPeer(peer *PeerConfig) error
    RemovePeer(publicKey PublicKey) error
    UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error
    GetPeers() []*PeerStatus
    GetStats() *TunnelStats
    Events() <-chan TunnelEvent
}

func New(cfg Config) (Tunnel, error)
```

冻结说明：

- MVP 交付文件名统一使用 `tunnel_wggo.go`。
- `tunnel_native.go` / `tunnel_wink.go` 属于后续轨道，不进入 MVP。

### 7.3 coordinator

`coordinator.proto` 的 MVP RPC 只冻结以下接口：

- `Register`
- `Heartbeat`
- `ListPeers`
- `GetPeer`
- `Signal`

明确不进入 MVP proto 的接口：

- `GetTURNCredentials`

`RegisterResponse` 在 wire format 中冻结为：

```protobuf
message RegisterResponse {
  string node_id = 1;
  string virtual_ip = 2;
  int64 expires_at = 3;
  string network_cidr = 4;
}
```

冻结说明：

- 客户端必须从 `network_cidr` 推导出掩码。
- 客户端不得期待 `network_mask` 字段。

### 7.4 nat

```go
package nat

type ICEAgent interface {
    GatherCandidates(ctx context.Context) ([]Candidate, error)
    SetRemoteCandidates(candidates []Candidate) error
    Connect(ctx context.Context) (net.Conn, *CandidatePair, error)
    Close() error
}

type NATTraversal interface {
    DetectNATType(ctx context.Context) (NATType, error)
    NewICEAgent(cfg ICEConfig) (ICEAgent, error)
}

func MarshalCandidate(c Candidate) ([]byte, error)
func UnmarshalCandidate(data []byte) (Candidate, error)
```

冻结说明：

- MVP 不再让客户端直接等待 `Connected()` channel。
- `ICEAgent.Connect(ctx)` 阻塞直到连接建立、超时或失败。
- 候选序列化由 `nat` 包负责，`coordinator` 只转发 `[]byte payload`。

### 7.5 client

客户端核心按以下顺序集成：

1. `netif.New`
2. `coordinator.NewClient`
3. `Register`
4. 从 `network_cidr` 解析掩码并调用 `SetIP`
5. `tunnel.New`
6. `nat.NewICEAgent`
7. 候选序列化后通过 `SendSignal` 发送
8. `ICEAgent.Connect`
9. `tunnel.AddPeer`

---

## 八、中继策略冻结

MVP 的 TURN 认证策略冻结为：

- 中继服务器使用长期凭证
- 客户端从 `nat.turn_servers` 读取静态用户名密码
- 协调服务器不负责下发 TURN 临时凭证

因此：

- `TASK-07` 可独立于协调服务器的 TURN 凭证 API 完成 MVP
- `GetTURNCredentials` 保留为后续增强项，不进入当前执行线

术语补充：

- 当前 MVP 文档中的“中继”默认指 `TURN server relay`
- “节点 A 作为 B 到 C 的受信转发节点”定义为 `peer relay / transit node`
- `peer relay` 设计可行，但不纳入当前 MVP 冻结范围，见 [PEER-RELAY-DESIGN.md](PEER-RELAY-DESIGN.md)

---

## 九、发布门禁

以下门禁不通过，则对应能力不得写进 MVP 宣传口径。

| 门禁 | 阻塞项 | 失败时的冻结动作 |
|------|--------|------------------|
| G1 | Windows `netstack` 原型验证 | Windows 无管理员模式降级为 `proxy`，不宣称 `userspace` |
| G2 | WinTUN 打包与安装验证 | Windows TUN 延后，MVP 仅宣称 Windows userspace/proxy |
| G3 | NAT 类型与穿透率采样 | 不对外声明穿透成功率指标 |
| G4 | TURN 中继稳定性与并发验证 | 不宣称“100% 连通”，仅保留实验性回退 |
| G5 | 72 小时稳定性测试 | 不发布 MVP 版本，只保留开发预览版 |

### 9.1 能开工但不能越级宣传的内容

以下工作可以先做，但在门禁通过前不能算“完成交付”：

- Windows 无权限模式
- Windows TUN 支持
- NAT 成功率指标
- “100% 连通”表述
- 稳定版发布

---

## 十、现有文档如何回改

本执行基线被接受后，旧文档按以下顺序回改：

1. `docs/README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/tasks/TASK-01..07.md`
4. `manage.md`
5. `winkplan.md`

回改原则：

- 只保留一套依赖图
- 只保留一套目录结构
- 只保留一套配置模型
- 只保留一套构造器命名
- 自研协议路线继续保留，但明确标注为 `post-MVP`

---

## 十一、执行起点

从今天开始，默认执行起点是：

1. 建立 M0 仓库骨架
2. 完成 TASK-01
3. 直推 TASK-02 + TASK-03
4. 完成 TASK-05
5. 再推进 TASK-04
6. 补上 TASK-07
7. 最后做 TASK-06 总集成

这条线是当前仓库内最短、最自洽、可落地的 MVP 执行路径。
