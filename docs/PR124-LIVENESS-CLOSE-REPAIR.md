# PR #124：liveness CLOSE 完成见证修复

2026-09-12，维护者在诊断后授权修复；沿用原 Draft PR，不合并、不运行现场 I/O。
约束：[session liveness ADR §8](./adr/ADR-N3C-SESSION-LIVENESS.md#8-结果取消与兼容)。

## 原始 RED 与归因边界

[Windows idle 首跑](https://github.com/houyuwushang/winkyou/actions/runs/34685361094/job/103531312495)
的 predictive 在约 225s 返回 `session_liveness_timeout`：PING=10、PONG=9、proof=8、
pending expired=2、inner injected=19；另两 profile 通过。全部 58 checks 中 56 成功，
实际失败及其 required 聚合共 2 项失败，run_attempt=1，未 rerun。

已确认 `bestEffortClose` 把任意 `ActiveWrites` 增量当成本次 CLOSE 完成。纯内存反例中，
无关 data / empty keepalive / rekey 都使 `CloseWritten=1`，但 CLOSE inner 注入为 0。
完整真实 WG + governor + memory NAT 组合中，暂缓 CLOSE inner 注入至多 250ms，并插入
一次无关 active write，CLOSE 在 25.127ms 被过早关闭撤销；对端重现 225s 及上述全部核心计数。
这证明缺陷足以造成该签名，**原 CI 没有逐 CLOSE 轨迹，仍不声称复原其唯一历史原因**。

| 私有原始证据（只公布摘要和 SHA-256） | SHA-256 |
| --- | --- |
| 首次 CI RED | `eff278f881117639c6eaf13cd976f3cb662186bacaf52f9bdf58ab9819cfba36` |
| 三类无关 write 反例 RED | `d767e2b6a848709c0e98de0f25e34b424ce26d094b7daaac1597189a35cf16d0` |
| 完整组合受控 interleaving RED | `b2c647bf23bd938d57067e66961ac013a1c0914d815c9bf3609dd3ecf7dcd749` |
| 原 180s observer-only 三 profile PASS（不能抵销 RED） | `45b6eaf6fec632babec65deb4a6d7007a078d22ce37caea9e730d9f247cfc8a5` |

## 修复契约

- 同一个 teardown intent 的 admission 与完整 inner 注入分开记数。`InjectPacket` 只是
  内层队列接纳，不是 WireGuard 加密或 outer UDP write completion，不得换名后继续冒充。
- liveness 路径不再由 aggregate `ActiveWrites` 推断 CLOSE；没有逐 CLOSE outer 见证，
  `Echo.CloseWritten` 保守为 0，本地取消使用已有 `canceled`，不再报
  `authenticated_close_sent`。接收方经原 WYCE parser 认证后仍可报 `authenticated_close`。
  新增的可选计数只在 liveness witness 内，旧无 policy 路径、原 parser/wire/error golden 不变。
- 只尝试一次，沿用从 intent admission 起的原 1s 出站窗，给异步 WG 发送机会；计数不提前
  截断该窗。许可/absolute/revocation 优先，不能从 inner 注入成功起重新计时。没有新 timer、
  ACK、重传、target、socket 或授权；1s 到期后仅原 2s drain。写硬故障仍保留 terminal/trip。
- 健康 idle 必须在取消**之前**读双端当前许可与 proof/rekey 见证，两端都满足完整 180s
  健康期后才由 fixture 显式取消两端。取消后必须干净排水，不接受提前发生的 timeout。
- teardown 单独验证：真实 WG 下 CLOSE 交付；无关 write + 暂缓 inner 注入不得提前关停；
  丢失 CLOSE 时对端保持原许可到期并干净结束，不退款/重试/持久 trip，不要求 best-effort 必达。

K=20s、R=5s、M=2/3、L=45/65s、write=1s、drain=2s、原 absolute ceiling 与所有建立预算不变。
普通 observation 修复的历史 RED/证据继续保留；不顺手处理其他 flake。

## 验证状态

待实现与首跑验证；未推送新 head，不能宣称当前 CI 已恢复。
