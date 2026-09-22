# C1c-2b router/observer 实现证据

基线 `efc160e`；实现分支 `feat/gate-c1c-router`。依据
[mini-spec §4.4](./adr/ADR-N3C-GATE-C1C-DISPOSABLE-ROUTER.md#44-c1c-2b-统一实例裁决2026-09-22)
及 #167 的统一 `/2` 维护者裁决。本文不签发 C1c-3，也不预填验证成功。

## 验收顺序

1. docs：统一实例、三角色 authority、owned 资源和清理语义先冻结。
2. RED：旧实现拒绝新的合法 `/2`；缺字段/误授 ceiling/清理遗漏/unknown=0/公开地址泄漏
   的负向回归不改成宽松期望。
3. 实现：独立 field-only 工具、router witness 与端点显式 schema 分流；普通构建不含能力。
4. 变异：权限、版本、资源归属、排水及输出边界；旧 `/1` 全部原测试保持。
5. 验收：Go 1.23.1、普通/tagged vet、architecture×20、受影响包 race×20、#116 全仓
   分区与独立 relay race×20、nm 正负门；required netns 三个 fresh 完整实例及零残留。

## 状态

设计提交；实现、验收、CI 均待执行。第一份 RED 与后续 GREEN 分开保留，不 rerun 求绿。
公开仅收录稳定类、计数、duration、SHA-256；原始值与证据在仓库外。
