# WinkYou 计划审阅总结

本文件只收录我能直接从当前仓库内容证实的事实，不收录无法在仓库内复核的推断。
结论基于以下范围：`winkplan.md`、`manage.md`、`question.md`、`guess.md`、`selfhost.md`、`selfdev.md`、`protocol.md`、`wink-protocol-v1.md`、`docs/README.md`、`docs/ARCHITECTURE.md`、`docs/tasks/TASK-01..07.md`。

## 一、我对项目的确认理解

WinkYou 当前定义的是一个基于 Go 的 P2P 虚拟局域网方案，主线能力包括：
- 客户端网络接口抽象层（TUN/TAP/userspace/proxy）
- WireGuard 隧道
- NAT 穿透（STUN/ICE）
- 协调服务器
- TURN 中继
- 后续的自研替换路线（`selfhost.md` / `selfdev.md`）与自研协议路线（`protocol.md` / `wink-protocol-v1.md`）

仓库当前实际状态是“文档规划仓库”，不是“已初始化的代码仓库”。

## 二、当前项目状态的确定事实

### 1. 当前仓库只有文档，没有代码骨架

已确认事实：
- 当前仓库只有 18 个文件，且全部是 Markdown 文档。
- 当前目录下不存在 `go.mod`、`Makefile`、`cmd/`、`pkg/`、`api/`、`deploy/`、`test/`。
- 当前目录下不存在 `.git`。

这与计划中的 M0/T0.1 初始化产物不一致：
- `manage.md:313-318` 明确把 `go.mod`、目录结构、GitHub Actions、`CONTRIBUTING.md` 作为 M0 产出。
- `docs/tasks/TASK-01-infrastructure.md:330-342` 明确把基于 git commit 的版本注入和 `go build` 作为验收/构建方式。

结论：
当前项目还处在“计划设计阶段”，连 M0 初始化产物都还没有落地。

## 三、已确认的问题

### 2. TASK-07 的依赖关系在文档之间互相矛盾

已确认事实：
- `docs/ARCHITECTURE.md:78` 写明 `TASK-07 | 依赖 | TASK-04`。
- `docs/README.md:318-319` 写明 “在 TASK-01 完成后，TASK-02、TASK-04、TASK-05、TASK-07 可以并行”。
- `docs/ARCHITECTURE.md:574-576` 也写明 “TASK-02、TASK-04、TASK-05、TASK-07 可以并行（依赖TASK-01）”。

结论：
同一个任务 `TASK-07` 同时被写成“依赖 TASK-04”与“只依赖 TASK-01 即可并行”，依赖图没有收敛。

### 3. TASK-06 是否依赖 TASK-07，没有统一答案

已确认事实：
- `docs/ARCHITECTURE.md:77` 写明 `TASK-06` 依赖 `TASK-02,03,04,05`。
- `docs/tasks/TASK-06-client-core.md:11` 写明 `TASK-06` 前置依赖为 `TASK-02, TASK-03, TASK-04, TASK-05, TASK-07`。
- `question.md:386-390` 也已把这一点明确列为文档一致性问题。

结论：
`TASK-06` 对中继模块到底是“硬依赖”还是“软依赖”尚未定稿。

### 4. 模块开发顺序与模块依赖不一致

已确认事实：
- `manage.md:135-154` 把“阶段2: P2P连接（STUN/NAT检测/ICE/TURN）”放在“阶段3: 协调服务（节点注册/密钥交换/节点发现/信令传递）”之前。
- `manage.md:346-355` 进一步把信令传递放到 M3 的 `T3.5`。
- 但 `docs/tasks/TASK-04-nat-traversal.md:379-388` 明确写明 ICE 候选交换依赖 `TASK-05` 提供的信令通道。

结论：
当前排期把 NAT/ICE 的实现阶段排在协调信令之前，但 TASK-04 自己又声明依赖协调信令，开发顺序没有闭合。

### 5. 配置模型没有统一，基础配置与上层调用不兼容

已确认事实：
- `docs/ARCHITECTURE.md:430-460` 定义了带根节点 `wink:` 的统一配置结构，并包含 `wireguard`、`relay`、`cipher_suite`。
- `docs/tasks/TASK-01-infrastructure.md:50-60` 的配置示例使用的是扁平结构，没有 `wink:` 根节点。
- `docs/tasks/TASK-01-infrastructure.md:215-221` 的 `Config` 结构体只包含 `Node`、`Log`、`Coordinator`、`NetIf`、`NAT`，没有 `WireGuard`、`Relay`。
- `docs/tasks/TASK-06-client-core.md:326-343` 的引擎示例却直接读取 `e.cfg.WireGuard.PublicKey()` 和 `e.cfg.WireGuard.PrivateKey`。

结论：
当前配置模型至少存在三种版本，TASK-01 的配置定义无法直接支撑 TASK-06 的调用示例。

### 6. TASK-06 的示例代码与 TASK-02/03/04/05 的接口契约对不上

已确认事实：
- `docs/tasks/TASK-02-netif.md:160` 定义的是 `SelectBackend(...)`，但 `docs/tasks/TASK-06-client-core.md:314` 调用的是 `netif.Select(...)`。
- `docs/tasks/TASK-03-wireguard.md:115-129` 定义的是 `TunnelConfig` 与 `NewTunnel(cfg *TunnelConfig)`，但 `docs/tasks/TASK-06-client-core.md:340` 使用的是 `tunnel.NewTunnel(&tunnel.Config{...})`。
- `docs/tasks/TASK-05-coordinator.md:50-55` 的 `RegisterResponse` 只有 `node_id`、`virtual_ip`、`expires_at`、`network_cidr`，但 `docs/tasks/TASK-06-client-core.md:335` 使用了 `resp.NetworkMask`。
- `docs/tasks/TASK-04-nat-traversal.md:368-375` 的 `ICEAgent` 接口没有 `Connected()` 方法，但 `docs/tasks/TASK-06-client-core.md:398` 在等待 `iceAgent.Connected()`。
- `docs/tasks/TASK-05-coordinator.md:175` 规定 `SendSignal` 需要 `SignalType` 和 `[]byte payload`，但 `docs/tasks/TASK-06-client-core.md:386` 直接传入了 `nat.SIGNAL_ICE_CANDIDATE` 和候选对象 `c`。

结论：
当前顶层集成示例不是按现有接口契约写出来的，说明各模块接口还没有真正冻结。

### 7. 协调服务器与 TURN 凭证接口没有闭环

已确认事实：
- `docs/tasks/TASK-07-relay.md:415-416` 要求协调服务器新增 `rpc GetTURNCredentials(...)`。
- `docs/tasks/TASK-05-coordinator.md:224-239` 给出的 `Coordinator` service 只有 `Register`、`Heartbeat`、`ListPeers`、`GetPeer`、`Signal`，没有 `GetTURNCredentials`。

结论：
中继模块已经把 TURN 凭证下发设计成协调服务器职责，但协调服务器任务文档没有同步收口。

### 8. 目录结构和交付物路径没有统一版本

已确认事实：
- `winkplan.md:347-390` 的顶层布局包含 `cmd/winkd`、`cmd/wink-ui`、`pkg/node`、`pkg/network`、`pkg/protocol`、`internal/config`、`internal/logger`、`platform/`。
- `docs/ARCHITECTURE.md:519-533` 的代码组织写成 `cmd/wink`、`cmd/wink-coordinator`、`pkg/config`、`pkg/logger`、`pkg/client`、`api/`。
- `manage.md:163-178` 的阶段 0 布局又是 `pkg/config`、`pkg/logger`、`pkg/version`、`cmd/wink`。
- `docs/tasks/TASK-05-coordinator.md:199-211` 把 proto 放在 `pkg/coordinator/proto/`，但同一文档 `docs/tasks/TASK-05-coordinator.md:321` 的交付物又写成 `api/proto/coordinator.proto`。
- `docs/ARCHITECTURE.md:519-521` 的命令入口没有 `cmd/wink-relay`，但 `docs/tasks/TASK-07-relay.md:297` 要求交付 `cmd/wink-relay/`。
- `docs/tasks/TASK-03-wireguard.md:183` 的目录使用 `tunnel_wggo.go`，但 `docs/tasks/TASK-03-wireguard.md:326` 的交付物写成 `pkg/tunnel/wireguard.go`。

结论：
项目的目录结构、入口程序、proto 存放位置、实现文件命名都还没有统一。

### 9. 平台范围和版本基线没有统一，移动端/GUI 也没有任务拆解

已确认事实：
- `winkplan.md:31` 把 Android/iOS 列入核心目标。
- `docs/README.md:14` 只写了 `Windows/Linux/macOS`。
- `docs/ARCHITECTURE.md:15` 的 G5 目标也只写了 `Windows/Linux/macOS`。
- `winkplan.md:539` 写的是 `Go 1.21+`。
- `manage.md:109` 和 `docs/README.md:254` 写的是 `Go 1.22+`。
- `winkplan.md:566-567` 把 GUI 客户端和移动端支持列入 V2.0。
- 当前 `docs/tasks/` 只有 `TASK-01` 到 `TASK-07`，没有 GUI 或移动端任务文档。
- `question.md:394-406` 已把“移动端任务文档缺失”和“GUI 客户端任务文档缺失”列为文档缺口。

结论：
平台支持范围、Go 版本基线和中长期功能拆解都还没有统一版本。

### 10. “开发前必须验证”的事项没有闭环，计划还不具备开发就绪性

已确认事实：
- `manage.md:373-430` 明确写明 Q1-Q5 “正式开发前必须通过原型验证”。
- `question.md:9-70` 继续把这些问题列为 “Must Verify Before Development”。
- `guess.md:69` 已给出“gVisor netstack 在 Windows 上可用”等结论性表述。
- 但 `guess.md:692-720` 的 Pre-Development 验证清单仍全部未勾选。
- 当前仓库没有任何原型代码、测试代码、测试报告或验证产物可供复核。

结论：
计划文档已经给出若干方向性答案，但验证闭环没有完成，因此当前计划不能视为“开发前关键前提已全部验证完毕”。

### 11. 项目元信息仍存在占位符

已确认事实：
- `docs/README.md:368-370` 的“项目仓库 / Issue 追踪 / 讨论组”仍为 `[待填写]`。
- `docs/README.md:261` 的克隆命令仍是 `git clone <repo-url>` 占位形式。

结论：
对外协作入口信息还没有补齐。

## 四、总体判断

当前最大问题不是“方向缺失”，而是“文档尚未收敛成单一可执行版本”。

更具体地说：
- 技术路线已经写得很多，但模块依赖、阶段顺序、配置模型、接口契约、目录结构还没有统一。
- 一部分问题其实已经在 `question.md` 中被项目自己识别出来，但这些问题还没有反向修正到 `winkplan.md`、`ARCHITECTURE.md` 和 TASK 文档。
- 以当前仓库状态来看，最合理的下一步不是直接编码，而是先做一次“计划收敛”：冻结依赖图、冻结配置模型、冻结接口契约、冻结目录结构，然后再进入 M0 初始化。

## 五、建议的收敛顺序

这里不是不确定推断，而是基于上面已确认问题所对应的最短修复路径：

1. 先统一任务依赖图，明确 `TASK-06` 对 `TASK-07` 的依赖性质，并修正 `TASK-07` 的并行开发表述。
2. 再统一配置模型，至少确定：是否有 `wink:` 根节点、`wireguard` 是否属于 MVP 配置、`relay` 与 `cipher_suite` 是否进入基础配置。
3. 再统一接口契约，让 `TASK-06` 的引擎示例完全按 `TASK-02/03/04/05` 已定义接口可实现。
4. 最后统一目录结构和交付物路径，再开始 M0 初始化。
