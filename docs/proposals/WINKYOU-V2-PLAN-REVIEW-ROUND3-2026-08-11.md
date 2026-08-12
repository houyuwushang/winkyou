# 修订版计划复核（第三轮）

- 状态：复核意见 / 修订版验收
- 日期：2026-08-11
- 复核对象：修订后的 [`WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./WINKYOU-V2-DIRECT-FIRST-PLAN.md)（470 行版）
- 前序：[首轮审查](./WINKYOU-V2-PLAN-REVIEW-2026-08-11.md) ·
  [维护者回复](./WINKYOU-V2-PLAN-REVIEW-RESPONSE-2026-08-11.md) ·
  [第二轮复审](./WINKYOU-V2-PLAN-REVIEW-FOLLOWUP-2026-08-11.md)

## 0. 复核结论

前两轮达成的全部修订项已忠实写入正文，多处强于协商结果（§1）。
**发现两个此前各方都没注意到的新缺口（§2），建议在 Phase 1a 开工前补入文本**；
它们不影响"PR #11 合入后可标记 Accepted"的门禁安排。另有三条注记（§3）与
若干措辞级小项（§4），可顺手处理或忽略。

## 1. 修订落实核对

| 协商项 | 落实位置 | 评价 |
| --- | --- | --- |
| governor 强制点在 socket/send 原语层 | §8.6 探测 I/O 强制点 | 完整：Open/Register/Send/Promote/毒化五契约齐备 |
| 机器级唯一预算权威 | §8.6 机器级唯一预算权威 | **强于要求**：覆盖多数据目录/多 Mesh；明确威胁边界不含恶意本地用户；无法建立 scope 时 fail-closed |
| 第三方 socket 库治理 | §8.6 第三方 socket 库治理 | 完整：alpha 排除 pion/quic-go、legacyice 留在 v1、依赖闭包 CI、粗粒度租约需双重观测证明 |
| 回复包计预算 / SendProbe 拒绝未登记 endpoint / 句柄毒化 | §8.6 + §17.1 | 完整，且"回复不重复扣 target 额度"的细化正确 |
| TCP/DNS/QUIC 范围声明 | §8.6 非 UDP 主动网络行为 | 完整，含"不进 probeio 的原因写入文档" |
| 单写者 roster + join request + 信任锚 | §6.2–6.3 | 完整：带外通道或双端指纹确认二选一 |
| freshness 三件套 + 同版本冲突告警 | §6.4 | 完整，撤销传播窗口要求文档披露 |
| WG binding 不进 roster | §6.1 + §17.1 + §18 风险表 | 完整，测试项"WG 轮换不要求 root 重签"到位 |
| stdio API：framing 定死、通知进 v1、handshake 内容、负面清单 | §13.1 | 完整：Content-Length 定死；"不能等未来版本再补通知语义"表述到位 |
| Phase 1a/1b 拆分 | §16 | 完整，招募可在 1a 后半启动、证据窗独立计算 |
| 恢复控制器归属 | Phase 3a + §17.3 标题 | 完整，且加了"恢复控制器不得自动启用未过资源证明的策略" |
| PR #11 门禁三件套 + Issue #12 | Phase 0 + §20 + 文档头 | 完整：Draft 门禁、永久回归测试、合入前不打 tag |
| 两个生命周期家族 + 三条探测入口 | §2 + §5 | 完整 |
| proto 解耦 + DTO/adapter/domain + session 渐进抽取 | §13 + Phase 1a | 完整 |
| direct 默认值标为待验证假设 | §11 + §15 + §18 + §19 | 完整，量化指标（direct-required 首连失败比例）进了公开数据清单 |
| 硬上限表加计量范围列 | §9 | 改进：attempt/machine/peer-pair 归属清晰 |

## 2. 本轮新发现的两个缺口

### 2.1 非特权用户的机器锁故事缺失（影响价值漏斗第一级）

§8.6 规定：canonical machine-safety namespace 无法建立时，"官方二进制必须禁用
主动探测并明确报错，不能悄悄退化成每用户或每目录 governor"。

fail-closed 方向正确，但与 §15 的价值漏斗正面冲突：漏斗第一级是
`wink diagnose`（含 STUN 观测 = 主动探测）。在以下常见场景中，
真正的机器级锁可能无法建立：

- Linux 非 root 用户直接解包运行 tarball（无 installer 预建 `/var/lib` 或
  `/run` 下的锁目录）；多用户共享目录（如带 sticky bit 的 `/tmp`）有符号链接/
  抢占攻击面，不能作为可信 namespace；
- 受限企业环境或容器内，Windows `Global\` 命名对象或系统目录不可写。

后果：外部测试者第一次运行 `wink diagnose` 就得到"拒绝探测"——Phase 1b 的
留存门槛直接被入口 UX 打穿。

建议二选一写入 §8.6（不改变 fail-closed 原则）：

1. **安装器职责**：官方安装包/一键脚本负责预建 namespace（目录属组、权限、
   Windows 全局对象 ACL）；文档明确"tarball 免安装模式需先执行
   `wink setup-machine-scope`（可能需要一次提权）"；或
2. **显式降级**：保留一个需要用户明确确认的降级开关（如
   `--scope=user-acknowledged`），启用时打印醒目警告、写入报告元数据、
   在 status/handshake 中标记 scope=user。禁止的是**静默**退化，
   显式知情降级与 §8.6 的威胁模型（防误配置，不防恶意本地用户）并不矛盾。

不补这条，Phase 1b 大概率把"锁建不起来"当成最高频失败反馈。

### 2.2 Phase 1a 的 connect-test 缺少信令与认证原语的说明

§8.4 的协调尝试协议（DISCOVER→…→COMMIT）要求**经过认证的** attempt epoch；
§13.1 要求 `connect_test`"绑定有期限、经过认证的 peer/attempt 上下文"。

但身份体系（Ed25519、roster、SignalingChannel provider）全部在 Phase 2 交付。
Phase 1a 的两节点 connect-test 用什么交换 PLAN/READY 消息、又如何"认证"？
按当前文本，Phase 1a 隐藏了一小块 Phase 2 依赖，实施时会被迫临时发明。

建议在 Phase 1a 交付清单加一段（示例）：

> connect-test 使用一次性临时密钥对 + 操作员带外交换的短期 pairing token
> （或双方静态地址直连信令）建立本次测试的认证上下文；该机制明确标记为
> 测试专用，不进入 v2 正式身份/成员体系，Phase 2 交付后替换。

这既解锁 1a 实施，也防止临时机制悄悄长成第二套身份。

## 3. 三条注记（不要求改文本，要求有意识地决策）

1. **Phase 1a 范围较首稿增长约三分之一，参考时长未变**（新增：机器锁、
   probeio 全套契约、依赖治理清单、多进程压力测试、TCP/DNS 租约）。
   文档已声明"由证据门槛推进，不因日历自动进入"，可接受；建议内部排序为
   governor/probeio → diagnose → NAT 矩阵 → stdio API（API 最后，
   它依赖前三者稳定），并预期 1a 实际可能到 10–12 周，避免第 8 周产生
   "落后即放宽门槛"的压力。
2. **"代理给持锁权威"隐含 IPC**：§8.6 允许"代理或失败"二选一，而进程间代理
   所需的 Named Pipe/UDS 安全工作已被 §13.1 推迟到"未来共享 daemon"。
   建议 Phase 1a 验收明确：alpha 最小实现 = 后续进程 fail-closed 并提示
   持锁 PID；代理属于可选增强，与共享 daemon 一起评估。
3. **Phase 0 含 Issue #12 的"修复或排除"**：若选修复（coordinator TLS +
   全接口认证），1–2 周内完成 PR #11 + #12 + 卫生审计偏紧；"明确排除"
   逃生门存在即可，注意别让 Phase 0 静默膨胀。

## 4. 措辞级小项（可忽略）

- §8.6 首段仍用 `BudgetLease` 一词，层级图与 §13 接口已统一为
  `MachineGovernor→PeerLease→AttemptLease`，建议统一术语；
- §14 配置键 `invitation_anchors` 与 §7/§6 的"加入 bundle anchor"叫法
  不一致，实现前统一即可；
- §6.3 join request 含 MeshID，新设备获知 MeshID 的方式（操作员输入/扫码）
  可在 Phase 2 mini-ADR 里带一句，不必进主文档。

## 5. 验收声明

补入 §2 两项后，本轮复核对修订版计划**无保留异议**：
前两轮全部协商结果已闭合，新文本没有引入与基线、事故 NO-GO 或
威胁模型冲突的内容。RFC 状态推进依旧以 PR #11 合入（含永久回归门禁）
为前置，与文档头部声明一致。
