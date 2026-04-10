# Trusted Peer Relay Design

> 状态: `post-MVP` 扩展设计
>
> 目的: 当 `B` 无法直连 `C`，但 `A` 能同时连通 `B` 和 `C` 时，允许 `A` 作为受信转发节点，为 `B <-> C` 提供单跳中继路径。

---

## 一、结论

这个设计是可行的，但它的本质不是“继续给 `B` 和 `C` 打洞”，而是：

- 让 `A` 成为 `B` 到 `C` 的 `transit node`
- 在覆盖网内部建立 `B -> A -> C` 的单跳转发路径
- 把原本需要走专用 `TURN` 服务的保底流量，改为优先走你自己控制的节点

确定结论：

- `高把握度`：单跳受信节点中继在当前项目架构下是可落地的。
- `高把握度`：它不要求协调服务器进入数据面，协调服务器仍只做注册、发现和信令。
- `高把握度`：它应被定义为独立于 `TURN server relay` 的第二类中继，而不是替换 `TASK-07` 的 MVP 交付。
- `高把握度`：第一版必须要求 `A` 显式开启“允许转发”，不能默认把任意在线节点都当成中继。

需要验证的点：

- `中把握度`：`TUN` 后端下的跨平台转发实现细节，需要在 Windows/Linux/macOS 分别验证。
- `中把握度`：MTU、分片和路径切换的稳定性，需要专项测试。
- `中把握度`：直连恢复后的自动回切策略，需要实测避免震荡。

---

## 二、术语冻结

- `TURN relay / server relay`：由 `wink-relay` 提供的专用中继服务，这是当前 MVP 的中继定义。
- `peer relay / trusted transit node`：由业务节点自己承担的中继能力，例如 `A` 为 `B <-> C` 转发。
- 第一版 `peer relay` 只做 `single-hop`，不做多跳路由。

---

## 三、适用场景

典型场景：

- `A`、`B`、`C` 都是你自己的节点
- `A <-> B` 可连通
- `A <-> C` 可连通
- `B <-> C` 因 NAT 或网络策略无法直接打洞

此时可以建立：

```text
B ---- encrypted hop ----> A ---- encrypted hop ----> C
 \_______________________ no direct path _______________________/
```

注意：

- 这条路径是“经 A 转发”，不是“B 和 C 最终建立了直接链路”。
- 如果采用最简单实现，链路加密是逐跳的，即 `B-A` 一层、`A-C` 一层。
- 在这种模式下，`A` 具备看到转发后明文 IP 流量的能力，因此只适合“你信任 A”的场景。

---

## 四、边界

第一版建议只覆盖以下范围：

- 单网络内的节点
- 单跳中继
- 显式配置或显式授权的受信节点
- 失败后仍可回退到 `TURN`

第一版明确不做：

- 多跳网状路由
- 任意节点自动成为中继
- 向不受信中继隐藏流量内容
- 取代 `TASK-07` 的标准 `TURN` 保底能力

---

## 五、推荐实现方式

### 5.1 控制面

推荐复用现有五个 RPC，不新增新的服务面：

- `Register`
- `ListPeers`
- `GetPeer`
- `Heartbeat`
- `Signal`

建议新增的是“元信息”和“信令类型”，而不是新增 RPC 方法。

建议扩展：

- 在节点注册元信息中声明 `peer_relay.allow_transit=true`
- 在 peer 信息中暴露 `relay_capable`、`relay_load`、`relay_policy`
- 通过 `Signal` 分发 `via_node_id`、建立/撤销受信中继路径

推荐的路由记录模型：

```go
type PeerRelayRoute struct {
    SrcNodeID  string
    DstNodeID  string
    ViaNodeID  string
    Mode       string // manual | auto
    ExpiresAt  time.Time
}
```

第一版建议使用以下信令语义：

- `SIGNAL_PEER_RELAY_PROPOSE`
- `SIGNAL_PEER_RELAY_ACCEPT`
- `SIGNAL_PEER_RELAY_REJECT`
- `SIGNAL_PEER_RELAY_TEARDOWN`

---

### 5.2 数据面

推荐把它实现成“覆盖网内部的受信转发”，而不是在第一版做复杂的“对等透明包转发器”。

也就是：

- `B` 保持到 `A` 的隧道
- `C` 保持到 `A` 的隧道
- `B` 到 `C` 的目的路由改成“via A”
- `C` 到 `B` 的回程路由也同步改成“via A”
- `A` 根据已建立的转发关系，在本地做单跳转发

这里的关键不是“B 能否把 UDP 包直接打到 C”，而是：

- `B` 是否能稳定把到 `C` 的覆盖网流量送到 `A`
- `A` 是否能稳定把这批流量再送到 `C`

因此这个功能成立的前提是：

- `A` 同时在线
- `A` 对 `B`、`C` 都有可用路径
- `B` 和 `C` 都接受 `A` 作为中继下一跳

---

### 5.3 路径选择策略

建议把策略做成显式模式，而不是隐式魔法。

推荐模式：

- `off`：关闭 peer relay
- `manual`：只对明确配置的目标节点使用指定 `via_node`
- `auto`：直连失败后，先尝试可用的受信节点中继，再回退到 `TURN`

推荐默认优先级：

1. `Direct`
2. `PeerRelay`
3. `TURNRelay`

这个顺序只在启用了 `peer relay` 时生效；未启用时仍是当前的 `Direct -> TURN`。

---

### 5.4 状态展示

客户端状态里不应再把所有“非直连”都混成一个 `relay`。

推荐区分：

- `direct`
- `peer-relay(via=node-a)`
- `turn-relay`

---

## 六、建议配置模型

这是 `post-MVP` 的建议配置，不修改当前 MVP 配置冻结：

```yaml
peer_relay:
  mode: "manual"              # off | manual | auto
  allow_transit: false        # 节点自身是否允许转发别人流量
  max_transit_sessions: 8
  preferred_paths:
    - dst_node: "node-c"
      via_node: "node-a"
```

约束：

- `allow_transit` 只在节点愿意充当中继时开启
- `preferred_paths` 只允许单跳
- 若 `via_node` 不在线或不可达，客户端应继续尝试 `TURN`

---

## 七、安全与性能影响

安全影响：

- 第一版是逐跳加密，不是 `B <-> C` 端到端透明中继
- `A` 可以观察到转发后的明文覆盖网流量
- 因此必须是显式信任模型，不能默认开启

性能影响：

- 时延大致接近 `RTT(B,A) + RTT(A,C)`
- 吞吐受 `A` 的带宽、CPU、NAT 和在线稳定性约束
- `A` 既消耗入站也消耗出站带宽，成本接近自建小型中继

工程影响：

- 需要回环与路由环检测
- 需要失效回收和直连恢复回切
- 需要对中继节点负载做基本保护

---

## 八、对现有任务的影响

- `TASK-05`：增加“谁愿意做受信中继”和“via 哪个节点”的控制面表达
- `TASK-06`：增加 `peer-relay` 连接状态、路由编排、失败回退和状态展示
- `TASK-07`：不替代 `TURN`，而是与 `TURN relay` 并列存在
- `TASK-02/TASK-03`：需要验证转发路径、AllowedIPs/路由更新和跨平台行为

这意味着它不是只改一个模块的功能，而是一个跨 `TASK-05 + TASK-06 + TASK-02/03` 的扩展。

---

## 九、建议验收场景

- 场景 1：`A <-> B`、`A <-> C` 可连，`B <-> C` 不可直连，配置 `B/C via A` 后可正常互通
- 场景 2：撤销 `A` 的转发许可后，`B <-> C` 自动降级到 `TURN`
- 场景 3：`B <-> C` 直连恢复后，路径从 `peer-relay` 自动回切到 `direct`
- 场景 4：`A` 离线后，过期的 `via A` 路由能被清理，不产生黑洞
- 场景 5：状态输出能明确显示 `peer-relay(via=...)`

---

## 十、落地建议

建议按下面顺序推进，而不是直接塞进当前 MVP 主线：

1. 保持当前 MVP 的 `TURN relay` 范围不变
2. 先把 `peer relay` 作为 `post-MVP` 扩展设计冻结
3. 先做 `manual single-hop` 版本
4. 验证稳定后，再考虑 `auto` 策略和负载选择

这样能保留你要的能力，同时不把当前已经收敛好的执行基线重新打散。
