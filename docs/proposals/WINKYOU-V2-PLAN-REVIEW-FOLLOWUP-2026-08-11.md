# 对维护者回复的复审意见（第二轮）

- 状态：复审意见 / 针对 §13 五个问题的回答
- 日期：2026-08-11
- 复审对象：[`WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md)
- 首轮意见：[`WINKYOU-V2-PLAN-REVIEW-2026-08-11.md`](./WINKYOU-V2-PLAN-REVIEW-2026-08-11.md)
- 核对基线：`main@6baac4c`

## 0. 复审结论

回复对十项建议的处置全部合理，其中四处"修正后接受"的修正本身是改进（见 §1）。
§13 的五个问题逐一回答如下：**Q2、Q4、Q5 可以闭合**（各附小补充）；
**Q1、Q3 存在同一个尚未覆盖的绕过面**——第三方库自行开 socket 与多进程多 governor——
需要在计划修订中补上两条硬约束后才算闭合。

## 1. 接受维护者的四处修正

以下修正比首轮意见的原表述更好，复审无异议：

1. **行数口径**（回复 §2）：`pkg/session` 生产代码约 4.2k 行而非含测试的 8.9k 行。
   接受更正。行为测试本身是资产，渐进抽取时可直接复用为 contract tests——这反而强化了
   "抽取/替换切片"优于"宣布重写"的论点。
2. **wire DTO 与 domain model 分离**（回复 §5）：首轮"收敛为单一来源"的本意是消除三份
   互相手工同步的准 domain model，不是要求 domain struct 直接当协议 schema。
   `versioned DTO <-> adapter <-> domain` 的边界是正确形态，接受并支持 golden tests 要求。
3. **仓库卫生事实**（回复 §10）：已核实 `.gitignore` 覆盖 `*.exe`/`*.test`/`.live-run`/
   `.stability-run`，`docs/README.md` 已提供归档索引。首轮该项事实有误，撤回原表述，
   接受"独立审计 + 发布 allowlist"方案。
4. **direct/Relay 默认值标为待验证假设**（回复 §11）：这是首轮复审未要求的加强，支持。
   Phase 1b 记录"因 direct-required 无法完成首连"的比例作为假设检验数据，正确。

另外已核实 [Issue #12](https://github.com/houyuwushang/winkyou/issues/12)（coordinator 无 TLS、
`Heartbeat`/`ListPeers`/`Signal` 不认证调用方）真实且描述准确，同意其作为独立 Phase 0 阻塞项。

## 2. Q1：AttemptLease + ProbeSocket + Promote 能否封闭探测生命周期？

**形态正确，但按当前写法仍有六条可绕过路径。前两条是硬缺口，必须写进计划；后四条是
接口契约级别的补充。**

### 2.1 硬缺口一：第三方库在 probeio 之外自行开 socket

已核实的依赖链：

```text
pkg/solver/strategy/legacyice -> pkg/nat -> github.com/pion/ice/v2 + github.com/pion/stun
go.mod 还包含 github.com/quic-go/quic-go（QUIC datagram 提案的基础）
```

pion/ice 在库内部自行 gather candidates、创建 UDP socket、发送 STUN/连通性检查包——
**全部发生在 probeio 强制点之外**。quic-go 同样自行管理 UDP socket。

回复 §3.3 的静态检查方案（"禁止直接调用 UDP 创建/发送原语"）抓不住这类绕过：
策略代码没有任何一行直接调用 `net.ListenUDP`，探测流量却照发不误。

**建议的修订**（三选一，按优先级）：

1. v2 alpha 的探测路径**不引入 pion/ice**。原计划 Phase 4 本就要做"多 STUN/普通 ICE"
   原生策略，STUN 客户端很小，可直接实现在 probeio 之上；legacyice 作为 v1 遗产不迁移。
2. 若必须复用 pion：以"粗粒度租约"包装——策略执行前声明 pion 的最坏成本
   （socket 数上界、并发检查数、STUN 目标数），governor 按声明预扣，进程内计数器
   （socket 打开数）越界即取消整个 attempt。精度差但保底。
3. 静态检查规则改为**传递闭包**：任何传递依赖包含"会开 socket 的库"（pion/*、quic-go、
   miekg/dns 直连模式等）的包都必须出现在白名单，白名单条目必须注明治理方式。

无论选哪条，§17.1 验收项应加一句："依赖图中所有能创建 UDP socket 的第三方库均有
明确治理声明"。

### 2.2 硬缺口二：多进程 = 多 governor

governor 是进程内对象，而节点预算是**机器级**语义。两个具体场景会破坏它：

- 外部集成方启动 N 个 `wink solver serve --stdio` 子进程，每个子进程一个 governor，
  预算被乘以 N——这恰好是 stdio API 模型下最自然的误用；
- daemon 运行期间，操作员手动执行 `wink diagnose`，两个进程各自持有"节点级"预算。

代码库已有单实例锁的先例（`pkg/client/runtime_lock_*.go`），建议直接写进计划：

> 节点级 governor 与机器状态目录绑定单实例锁。持锁进程是唯一预算权威；后续进程
> 要么拒绝启动主动探测（明确报错"governor held by PID"），要么将请求代理给持锁进程。
> `wink solver serve --stdio` 的每个实例必须先取得或代理到该锁，才能创建 AttemptLease。

不解决这条，回复 §7 的"外部调用无法突破硬上限"验收项在多进程下不成立。

### 2.3 接口契约级补充（四条，写入接口文档与测试即可）

1. **接收环路的回复包**：打洞协议需要响应入站包（HELLO/ACK）。`ProbeSocket` 不得暴露
   raw write；对入站包的回复也是发送，必须计入 PPS/总包预算（不新增五元组，可不扣
   target 预算）。当前接口草图未说明 ProbeSocket 的读取和回复路径，需补。
2. **SendProbe 必须拒绝未注册 endpoint**：否则 `RegisterTarget` 只是装饰。契约应为：
   新五元组预算在 RegisterTarget 扣减，PPS/包数在 SendProbe 扣减，向未注册 endpoint
   发送直接返回错误并计入违规指标。
3. **Promote/Close 后句柄失效**：Promote 移交所有权后，旧 `ProbeSocket` 句柄上的一切
   操作必须返回 `ErrLeaseClosed` 类错误（毒化句柄），防止残留 worker 持引用继续发送。
   回复 §3.2 列了"防止旧 worker 继续发送"的目标，建议把"句柄毒化"作为实现该目标的
   显式契约并配测试。
4. **非 UDP 主动连接的范围声明**：TCP 拨号（tcpframed/信令）与 DNS 解析也是主动网络
   行为。建议 alpha 明确：TCP dial 经粗粒度租约（并发数+频率），DNS 由 discovery
   provider 层限速；不必进 probeio，但要写明"为什么不进"，防止将来被当成漏洞报告。

### 2.4 Q1 结论

`AttemptLease + ProbeSocket + Promote` 的能力边界设计**方向正确且优于首轮建议**
（Promote 的原子移交清单是重要补充）。补上 §2.1/§2.2 两条硬约束、§2.3 四条契约后，
可以认为探测 socket 生命周期封闭。

## 3. Q2：单写者 roster 的加入流程是否闭合？freshness 最小机制？

**基本闭合。**"目标身份先生成、root 后签发"的顺序正确消除了 bearer invitation——
凭证不再是"谁持有谁能加入"，而是"roster 里有你的公钥你才是成员"。撤回首轮
"根预签一次性凭证"的建议，回复 §6.2 的流程更好。

三处需要补充：

### 3.1 信任锚交付通道（唯一的真缺口）

bundle 里含 root 公钥，而新设备此刻**没有任何先验来验证这份公钥**。若 bundle 经不可信
通道（网盘、IM）传输，中间人可整体替换为攻击者的 mesh。需在计划写明二选一：

- bundle 与 join request 走同一操作员控制的带外通道（U 盘/二维码/局域网直传），
  信任锚随物理信道建立；或
- 任意通道传输 + 双端指纹确认：root 工具签发时显示 root key 指纹，新设备导入时
  显示同一指纹，操作员人工比对。

对 2–20 台自有设备，指纹确认一次即可，成本可接受。

### 3.2 freshness 的最小机制（回答 §6.3 的提问）

新设备的 freshness 由构造保证：**root 工具是唯一 writer，签发时刻的 roster 就是全网
最新版**——这一点值得在计划里写成一句话，它消除了"新设备如何确认最新"的大半焦虑。
剩余的是在网节点的持续 freshness，最小机制三件套：

1. roster 携带 `issued_at`；`wink status` 展示 roster 年龄，超过可配置阈值仅告警
   **不硬过期**（与回复 §6.3 对离线 root 集体过期的担忧一致）；
2. 反熵同步：每条已认证 peer 连接建立时交换 `(version, digest)`，低者拉取高者——
   回复 §6.2 第 5 步已隐含，建议升格为显式验收项；
3. 文档披露撤销传播窗口 = 被撤销者与其余节点的连通间隔，alpha 规模下可接受，
   不引入第二种记录类型。

另加一条防御：节点收到**同版本、root 签名均有效、内容不同**的两份 roster 时，
除拒绝外应产生最高级别告警——这是 root 私钥泄露或签发工具 bug 的直接信号。

### 3.3 WG binding 建议不进 roster

回复 §6.1 让 roster 携带"WG binding 摘要"。若 WG 密钥轮换要求 root 重签 roster，
root 就从"仅成员变更时出场"变成"例行运维依赖"，与离线 root 的设计初衷冲突。
建议维持原计划 §6.1 的分层：roster 只钉身份公钥与能力位；WG binding 由节点身份
自签、带有效期、随控制记录传播。若维护者有意用 roster 钉 binding 来抵御
"身份密钥被盗后静默换 WG key"，请显式写出这个威胁与运维成本的取舍。

## 4. Q3：JSON-RPC over stdio 是否合适？方法集是否要再缩？

**合适。** stdio 免网络监听、进程边界即安全边界、跨语言成本最低（LSP 已验证此模式）。
不建议再缩方法集——六个方法已是"能演示价值"的下限，再删 `export_redacted_report`
只会把导出逻辑逼进各语言客户端重复实现。需要补五件事：

1. **framing 立即定死并纳入 handshake 版本**：LSP 式 `Content-Length` 头或 NDJSON
   二选一。这是二进制分发下最难事后改的决定。
2. **单 governor 约束**（同 §2.2）：`serve --stdio` 多实例必须共享机器级预算权威。
   这是 API 面唯一可能突破硬上限的路径，应作为回复 §7 协议验收项的第一条。
3. **handshake 返回内容明确化**：schema 版本、构建版本、当前硬上限表、
   **safety trip 状态**。外部集成方必须能在调用前发现节点已 trip，而不是收到
   语义模糊的失败。
4. **进度通知语义现在定义**：`connect_test` 可运行数十秒，server→client 的
   notification（绑定请求 id）需进 v1 schema；事后加是破坏性变更。
5. **负面清单写进协议文档**：无 raw socket/fd 传递、无批量目标接口、无预算提升
   接口——回复 §7 已列，建议从"回复"升格为协议规范的固定章节，方便外部集成方
   引用作为安全依据。

## 5. Q4：Phase 3a/3b 拆分是否消除 alpha 范围风险？

**消除了"双授权系统并行"这一最大风险，但 3a 内还藏着一个未分配的大件：**
**恢复控制器（原计划 §10）在回复中没有出现在任何阶段的交付清单里。**

原计划 Phase 3 的"稀疏控制图"在回复 §8.1 的 3a 清单（运行时、L3、冲突处理、状态、
配置）中也未出现。governor（1a）管的是"发送侧额度"，恢复控制器管的是
"谁、何时、以何种状态机触发重求解"——长期链路一旦存在（3a 交付 L3 时），
没有恢复控制器的 L3 就会退回事故前的形态。

建议明确：

- 恢复控制器状态机（STABLE→SUSPECT→…→CIRCUIT_OPEN）与稀疏控制图**归属 Phase 3a**，
  并把 §17.3 的"20 节点无 N² 重型恢复"测试挂为 3a 退出门槛；
- 或者若维护者认为 3a 先以"手动重连"交付，也可以——但必须写明"3a 无自动恢复"
  是有意为之的范围声明，避免默认继承 v1 行为。

3b 的"是否仍属同一 alpha 由 3a 用户反馈决定"——同意，这是正确的证据驱动姿态。

## 6. Q5："PR #11 合入前 RFC 保持 Draft"是否满足 P0 处置？

**满足。**"讨论并行、Accepted 门禁、合入前不开始联网实现"三条合在一起，
既不阻塞设计迭代，又保证 main 的已知隐患有明确的收敛动作。两点小补充：

1. PR #11 带入的拒绝逻辑测试（`pkg/config`、`pkg/meshruntime` 的 fail-closed 用例）
   应标记为**永久回归门禁**：v2 重构无论怎么改配置层，这些用例删除或放宽都需要
   独立 ADR。防止"重构时顺手清理了旧测试"复活入口。
2. 在 #11 合入前不从 main 打 tag/release（当前本就没有发布流程，写一句话成本为零，
   收益是杜绝"从带隐患的 commit 出二进制"）。

同意 Issue #12 与 #11 并列为 Phase 0 阻塞项；已核实 issue 内容与代码现状相符
（coordinator 明文 gRPC、Signal 流不认证调用方）。

## 7. 复审后的状态

| 项 | 状态 |
| --- | --- |
| Q2 roster 流程 | 闭合，需补信任锚通道、freshness 三件套、WG binding 分层（§3） |
| Q4 3a/3b 拆分 | 闭合，需给恢复控制器一个明确归属（§5） |
| Q5 PR #11 顺序 | 闭合，附两条零成本加固（§6） |
| Q1 探测封闭性 | **待补两条硬约束**：第三方 socket 库治理、机器级单 governor（§2） |
| Q3 stdio API | **待补一条硬约束**：多实例共享预算权威（§4.2，与 Q1 同源） |

Q1/Q3 的缺口同源（"强制点以进程为界，而威胁以机器为界"），一并解决即可。
补齐后，本复审同意回复 §12 的十二条修订进入原计划正文；RFC 状态推进仍以
PR #11 合入为门禁，与回复 §9 一致。
