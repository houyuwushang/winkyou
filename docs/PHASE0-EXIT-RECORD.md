# Phase 0 出口记录（v2 直连优先计划）

- 状态：**已完成 / 出口门槛全部满足**
- 日期：2026-08-13
- 记录人：维护者 @houyuwushang（专家审查协助核验）
- 对应计划：[`proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md) §16 Phase 0
- 本记录的效力：确认 Phase 0 退出门槛已满足，v2 计划自本记录合入起由 **Draft 标记为 Accepted**。

## 1. 退出门槛逐项核验

计划 §16 Phase 0 的退出门槛为："PR #11 已合入且永久测试通过；Issue #12 已修复或相关远程路径被明确排除；架构决策、威胁边界、禁止事项和回滚责任均有记录。"

| # | 交付项 | 状态 | 证据 |
| --- | --- | --- | --- |
| 1 | PR #11 fail-closed 产品门禁独立审查并合入 | ✅ | [PR #11](https://github.com/houyuwushang/winkyou/pull/11) 经 Copilot 审查三项意见修复（`feede2b`：暂停门禁前移至旧校验之前、双分支独立测试覆盖）后合入 main（`d6d8567`），CI 6/6 |
| 2 | PR #11 拒绝逻辑测试设为永久回归门禁 | ✅ | `pkg/config/autonomous_mesh_test.go` 的 `TestValidateAutonomousMeshRejectsPausedBirthdayRecovery`（maintain-only / card-only / 组合三用例）与 `pkg/meshruntime/api_test.go` 的 `TestNewRejectsPausedAutonomousBirthdayRecovery`（两分支独立覆盖）。**删除或放宽这些用例必须有独立 ADR** |
| 3 | PR #11 合入前不从 main 打 tag/release | ✅ | 最后一个 tag 为 `phase2d-freeze-2026-04-24`；#11 合入（2026-08-12）前后均未新建 tag |
| 4 | Issue #12 coordinator 安全 | ✅ 修复 | [PR #27](https://github.com/houyuwushang/winkyou/pull/27) 合入 main（`b755802`），[Issue #12](https://github.com/houyuwushang/winkyou/issues/12) 自动关闭。非回环监听强制 TLS+共享凭证（启动前 fail-closed）；元数据为唯一 RPC 认证源，body 凭证被服务层覆盖；unary+stream 拦截器常时比较；客户端明文仅限数字回环。经真机 fail-closed 五场景实测与 `-race` / 20 次 TLS 集成测试验证，Docker Smoke CI 覆盖 Compose/TLS/auth 全流程 |
| 5 | 保持 baseline 权威直到正式 ADR 合入 | ✅ 持续有效 | [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md) 仍是实现权威；本记录不改变该状态（见 §4） |
| 6 | 固化 incident NO-GO、发布硬预算、machine lock、kill-switch、回滚责任 | ✅ | 见 §2、§3 |
| 7 | 仓库卫生审计与 release artifact allowlist | ✅ | `.gitignore` 覆盖二进制/测试产物/现场目录；根目录历史文档由 [`docs/README.md`](./README.md) 标注为 archive 并保留追溯链接；`release.yml` 从干净 checkout 构建并按显式文件列表打包，不从脏工作区取物 |

## 2. 已固化的安全边界（本记录再次确认，均不因 RFC Accepted 而放宽）

- **Incident NO-GO**：cached self-bootstrap 与 autonomous birthday recovery 维持 NO-GO；`wink` 拒绝 `autonomous_mesh.maintain_peers`/`recovery_card`，`meshnode` 拒绝对应参数（永久回归测试见 §1.2）。解除需满足 [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md) 记录的全部资源安全条件并另立 ADR。
- **发布硬预算**：Phase 1a governor 已合入编译期硬上限（`internal/governor/limits.go`；受限 user profile：1 peer / 1 attempt / 0 heavyweight / 15s / 4 sockets / 8 targets / 8 PPS / 64 packets）。配置只能降低、不能突破。
- **Machine lock**：canonical machine-safety namespace 与 OS 级单实例锁已合入（`internal/governor/namespace_*.go`），多进程/多数据目录不放大预算（`internal/architecture` 门禁 + 多进程测试覆盖）。
- **Kill-switch**：持久化 safety trip 与 `wink safety status/reset`（CAS 序列号 + 操作员备注）已合入；进程重启不自动清除。
- **网络能力冻结**：`internal/architecture` 的生产网络能力清单与 probeio 旁路门禁已合入,新增绕过入口会使 CI 失败。

## 3. 回滚责任

- **回滚责任人**：维护者 @houyuwushang。
- **回滚单位**：main 全部以 merge commit 合入,单个 PR 可独立 `git revert -m 1 <merge-sha>`。
- **安全回滚约束**：任何回滚不得移除 §1.2 的永久回归门禁与 §2 的安全边界；若回滚涉及这些文件,必须在回滚 PR 中说明并保留等效门禁。

## 4. 本记录生效后的状态

1. [`proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md) 状态由 Draft 变更为 **Accepted**（随本记录同一提交更新其文档头）。
2. 按计划 §20,Accepted 仅代表：可以据此编写正式 ADR、issue 拆分和 Phase 1a 实施计划；可以开发本地、模拟器内的 domain model、machine governor、probeio、stdio API 与安全基础设施。
3. Accepted **不代表**：批准自动生日恢复、真实家庭/办公/公网探测、启用被暂停的 scheduled task、部署公共 coordinator/DHT/Relay、收集遥测,或发布 production-ready 声明。
4. [`CONNECTIVITY-SOLVER-BASELINE.md`](./CONNECTIVITY-SOLVER-BASELINE.md) 何时被取代,仍须由后续明确提交（正式 ADR）决定。
5. Phase 1a 进行中交付的额外证据（先于本记录完成）：governor/probeio/architecture 门禁栈（PR #13–#23）、test-only 配对 mini-spec 与模拟器（PR #24/#25）、solver/domain 解耦（PR #29,Closes #28,本记录合入后解除其最后一个门禁）。

## 5. Phase 1a 剩余入口条件

本记录不改变 Phase 1a 的既有门槛。当前明确的下一步：

- 合并 PR #29（其"#27 + Phase 0 出口记录"门禁随本记录满足）；
- 按计划 §16 Phase 1a 清单继续:canonical domain model 扩展（Observation/ProbeScript 收敛）、session 编排渐进抽取、diagnose/connect-test、stdio API、NAT 模拟矩阵；
- 已隔离的测试观察类 flake 跟踪于 [#31](https://github.com/houyuwushang/winkyou/issues/31)、[#33](https://github.com/houyuwushang/winkyou/issues/33),不阻塞主线。
