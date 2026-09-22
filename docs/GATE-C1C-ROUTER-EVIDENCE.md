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

## 实现与证据边界

`linux && fieldc1c` 的独立 router 工具已实现；普通端点构建不能导入。`/2` 三角色显式
解析，旧 `/1` 原测试不改。编译期工具上限与根权限残余风险见 mini-spec §4.3/§4.4。
没有改变任何端点预算、selection、liveness、完成阶段或重试规则。

- 只有两个新建且逐一记录 inode 的 NAT namespace；外层三个 attachment namespace 是
  已存在、已授权、non-init、专属资源。只添加本实例 veth/nft/路由；不接管同名对象。
- 明确 false 不写共同 ceiling。true 的独立 guardian 持锁保存/回读原值，在 worker 崩溃
  后清理并恢复；guardian 自身被不可捕获信号杀死时须显式 teardown，不声称自动恢复。
- 每次 journal 更新使用新的 owner-only O_EXCL 临时文件。中断字节保留为私有证据，
  不能成为恢复 authority，也不会阻断 guardian 写入后续清理见证。
- observer 复用 RFC 5780 codec；每次查询都是精确 conntrack GET。查询失败或取消不是
  absent。未经端点认证事件关联的 hit/W/VERIFY 时间始终 null + reason；当前不提供自动
  跨见证源关联器，因此不声称已经测得 M/E 的 authenticated mapping 年龄。
- stdout 只有稳定枚举、数值与证据摘要。原始 tuple、进程身份和日志只留私有目录；
  required job 不上传它们。未知残留不能写成零，清理表的第二人签字栏保持空白。

## 本地首跑与修正记录

Go 1.23.1，`GOMAXPROCS=4`，Windows。这里的 tagged 单测只覆盖可移植 schema/模型；
Linux 工具代码的交叉 vet 不是 namespace/socket/guardian 的实测证明。

| 批次 | 命令或结果 | 实测 |
| --- | --- | --- |
| runtime RED | `go test -tags=fieldc1c ./internal/v2/fieldc1c -run '^TestRouterV2ThreeRolesAndExplicitFalse$' -count=1 -v`，旧实现拒绝合法 `/2` | FAIL，0.211s |
| 首轮 field race | `go test -race -tags=fieldc1c ./internal/c1crouter ./internal/v2/fieldc1c -count=20 -failfast` | PASS，外层 52,259ms |
| 首轮 architecture×20 | 缺少新 guardian 在既有 Gate B3 ceiling 门中的精确登记 | RED，53,165ms；不是既有 flake |
| 登记修正后 architecture×20 | Go 默认整批 10m alarm 到期，尚未跑完；停在符号隔离测试 | RED，603,796ms；不是单次 build 的 120s deadline |
| 普通 vet | `go vet ./...` | PASS，32,679ms |
| #116 全仓分区 | `go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | PASS，88 包，331,415ms |
| 独立 relay | `go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast` | PASS，包 166.936s，外层 196,265ms |
| Linux 全标签 vet | `GOOS=linux CGO_ENABLED=0 go vet -tags=fieldc1c,natlab,c1bproof ./...` | PASS，12,765ms |
| 最后 production 修正后的 field race×20 | 同上述 field race 命令 | PASS，模型 1.278s、schema 38.179s，外层 44,135ms |
| 相对链接 | 本 PR 三个 Markdown 文件中的相对文件目标 | 113 个，0 broken |

ceiling 门修正只允许两个精确文件和各自完整 build tag；改名或移除 tag 的变异仍拒绝。
原 Gate B3 guardian、ceiling、预算均未修改。源码检查同时拒绝普通产品导入 router、工具
取得 planner executor、未授权构造 token、缺少清理步骤与 false permission 写路径。

全仓分区测得单轮 architecture 为 **58.758s**；20 轮包含 80 次构建。最终批次改为
`go test ./internal/architecture -count=20 -timeout=25m -failfast`，整批预算按
`ceil(58.758 × 20 × 1.25 / 60) = 25min`。每次构建原有 120s deadline 不变、count 不减，
此前默认 10m 的 RED 保留；这是验证命令总预算修正，不是协议窗口或产品预算变更。
该批次及 Linux 首次 CI 状态在 PR 中逐项报告，未完成前不能宣称全部验收通过。

### 私有原始日志摘要

| 记录 | stdout SHA-256 |
| --- | --- |
| 初次 architecture 门拒绝 | `e676be8d0f9eebf044fccb0821f43a607d86ac78c8b2af0d41ebc3976f266d05` |
| 默认 10m 整批超时 | `f0f349db747991768082ac0d11a5e11a75e3d4f54865ca09e234fc0757c94152` |
| #116 全仓 | `d5f544f308eecda7490993e51fce75c0dddbcf0b4a63a6ef1e876c1733acabe3` |
| relay race×20 | `5a895d609d41ce477ca1085eba8bab5e8f30b9a6b6d6a1db686aec8c7d8805cf` |
| 最后 field race×20 | `4b34259e6fa53aed708ad7ed015dbcd186c6b52e792ffb478d30dabe03b93b41` |

## 符号与 required Linux 实证门

普通、单独 natlab、单独 c1bproof 的符号排除与 field 构建正向门在全仓首跑通过。
另外实际 cross-build 优化 router ELF 并执行 nm：`runGuardian` 相关符号 5 个、
`fieldc1c.loadRouter` 相关符号 2 个；薄包装 `LoadRouter` 被内联为 0，故新 workflow
正向门锁定实际校验函数，不能把编译器内联误报为能力缺失。普通构建另断言 router 包零命中。

新 **C1c Router Three Instances (required)** job 预算：
`ceil((63 + 56 + 46 + 35 + 420 + 60) × 1.25 / 60) = 15min`。
各项依次为准备、符号、构建、focused race、三实例矩阵、guardian crash；无 advisory、
无静默 skip、无原始 artifact 上传。`WINKYOU_C1C_ROUTER_REQUIRED=1` 是硬前置。

| 必过门 | 必需证据，不预填成功 |
| --- | --- |
| 三次 predictive 完整实例 | 三套不同 synthetic credential/attempt/channel；真实 field 端点二进制与 router 二进制，双端 data-plane ready、真实 kernel echo、FINISH 与 release。失败即停，不清空 ledger 复用材料。 |
| OS 计费与字段 | 独立 helper 读取两域 nft counters 和 socket；outbound 与端点 probe/WG/liveness 见证精确相等；真实 conntrack 查询与 §5 nullable 字段存在。 |
| teardown | 工具 summary 的 socket/process/conntrack/netns/veth/nft 全部为已验证的零；独立 helper 再检查两个 owned namespace 和全部三个 attachment 的链路残留。 |
| worker crash + true ceiling | 单独一次性 CI scope，真实 guardian 原值保存、40,000 回读、杀精确 child 后恢复原值；独立测试清理若被迫恢复，仍计 RED。 |

本机没有运行中的 Linux namespace 环境，以上 OS 门只由 CI 实测，不通过启动现场环境补齐。
首次 CI 失败原样记录；本 PR 不混修已登记的其它 flake。保持 Draft，不合并、不签发 C1c-3。
