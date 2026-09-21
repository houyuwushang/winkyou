# SSH endpoint authority 具体值封装（#160）

## 范围与裁决

基线 `47fd5d7bcc1433a81ad5c8b4a1f4aca46bcadde0`。维护者选择 opaque concrete token：
独立修复既有 SSH capability，再继续 C1c-2a；不在本 PR 增加 field authority、现场 I/O
或任何新网络权限。普通构建仍仅 literal loopback，`linux && natlab` 仍只接受已验证的
固定 TEST-NET namespace 拓扑。

## 根因与影响

旧 `SSHEndpointAuthority` 是导出接口。包外结构可以嵌入合法接口值，继承其私有方法，
同时覆盖公开 `Endpoint()`。这样 `validate()` 验证内层 loopback 地址，`BindClientConfig`
却使用另一动态方法返回的地址。私有 marker 不能证明接口动态值属于原包。

已有零网络复现仅调用 `BindClientConfig`，返回 nil；没有调用 `OpenClient`、创建 socket、
启动 SSH child 或申请 governor。原始 RED 日志 SHA-256：
`8c7dc8fb3d0b5bbcf7b1d533d3a9083ff12e5b67a6cec59568d85762bdf0c70a`。
现有 architecture 门没有拒绝相同包装，日志 SHA-256：
`d759503d5486b352acece2147c81e941ac677144bae6862f484ed8d12cff319b`。
这是本地 Go API 的能力封装缺口，不是已证实的不可信 JSON/远端报文利用，也没有真实流量证据。

## 修复契约

1. `SSHEndpointAuthority` 改为具体 struct，字段全部私有；零值无效。调用方可保存、复制
   已签发 token，但包装类型不再能作为 token 参数。无 public setter 或反序列化授权入口。
2. endpoint 和私有 scope 一起保存在值内；scope 只验证传入的同一个 endpoint，不提供
   第二个地址来源。包内 `validatedEndpoint` 同时完成 canonical 检查、scope 核验和取值。
3. bind、构造 argv、spawn 前重新校验均使用该函数。外部 `Endpoint()` 仅用于精确比对，
   不作为实际 spawn 的独立动态地址来源。tagged namespace 在每次核验时仍检查当前归属。
4. orchestrator 的 nil 判定迁移为零值判定；responder 仍不得携带 SSH authority。
5. SSH argv/environment golden、固定命令、child/TCP/DNS 数、deadline、重试与 drain
   原样保持；不更改 governor、probeio、Gate B/C completion、配置或工作流。
6. architecture 门锁定具体私有 token、构造点、validated snapshot 消费点，并包含变异自检。
   包外 embedding/覆写回归必须从旧 RED 转为拒绝；有效 loopback 值与 tagged netns 行为保留。

## 验证计划

先提交文档与红回归，再实现并补变异门。使用 Go 1.23.1，保留每个首跑输出；不通过 rerun
换取绿色。新问题单独登记，不混修。

- 零网络包外覆写、零值、canonical/端口/地址不符的负面用例。
- `sshassembly`、`gatecorchestrator`、`architecture` 的 `-race -count=20`。
- ordinary argv/environment golden；`linux && natlab` namespace 校验与 required netns CI。
- `go vet ./...`、全仓 #116 分区、独立 relay race×20。
- `GOOS=linux CGO_ENABLED=0 go vet -tags=natlab,c1bproof ./...`。
- 隐私扫描、相对链接、`git diff --check`；生产差异只涉及 authority 及既有消费者迁移。

## 实测证据

### 本机首跑（2026-09-20 至 2026-09-21）

Go 1.23.1 / Windows；各重批次串行，没有并行负载、降低 count 或 rerun 求绿。

| 命令 / 检查 | 首跑结果 |
| --- | --- |
| `go test -race ./internal/v2/sshassembly -run '^TestExternalAuthorityEndpointOverrideRejected$' -count=1 -json`，旧接口 | RED，1个预期失败；包输出0.819s，报告接受包外覆写；socket/child调用0。 |
| `go test -race ./internal/v2/sshassembly ./internal/v2/gatecorchestrator -count=1 -json`，具体 token | GREEN；assembly6.178s、orchestrator1.753s；同一外部覆写在类型边界被拒绝。 |
| `go test -race ./internal/v2/sshassembly ./internal/architecture -run 'Authority\|GateC1a\|GateC1bBoundaryIsExactAndCapabilityNarrow' -count=1 -json` | PASS，1.784s / 8.121s；后加的global issuer变异另被完整race批次覆盖。 |
| `go test -json -race ./internal/v2/sshassembly -count=20 -failfast` | PASS，380个顶层实例，94.206s。 |
| `go test -json -race ./internal/v2/gatecorchestrator -count=20 -failfast` | PASS，700个顶层实例，4.913s。 |
| `go test -json -race ./internal/architecture -count=20 -failfast -timeout=30m` | PASS，2,700个顶层实例；13类变异×20=260次拒绝；1,508.659s。30m仅为整批测试watchdog，不修改产品窗口。 |
| `go vet ./...` | PASS，wall20.570s。 |
| `go test -json ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'` | PASS，88个测试包、1,866个顶层PASS；wall283.778s，11包无测试文件。仅沿用#116分区，没有新skip。 |
| `go test -json -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20 -failfast` | PASS，20/20，165.358s。 |
| `GOOS=linux CGO_ENABLED=0 go vet -tags=natlab,c1bproof ./...` | PASS，首批wall22.266s；追加required harness断言后再验PASS，wall11.403s。 |
| 追加required harness断言后的 `go test ./internal/architecture -count=1` | PASS，wall17.414s，含两道隐私门。 |
| `GOOS=linux CGO_ENABLED=0 go test -c -tags=natlab,c1bproof ./test/natlab`（输出到仓库外） | 编译PASS，wall28.525s；不将cross-compile写作Linux OS执行。 |

最后一个测试提交只给 `TestLinuxGateC1bProductProof` 增加
`ssh-authority-unproven-namespace` 子用例：两个无效namespace输入×两个side，必须返回无效
token；输出固定计数 `SSH_AUTHORITY_UNPROVEN_NAMESPACE rejected=4`。它位于既有 required
选择器内，不增加workflow、不改原成功/fault场景、count或预算。Windows无法执行该分支，
实际正反向namespace行为以Linux required首跑为准。包内tagged namespace单测另经cross-vet
编译检查，不宣称在Windows执行。

普通 `./cmd/wink` 构建PASS，未运行。`go tool nm` 对显式非空集合
`NewNATLabAuthority|natlabScope|RunNATLabInitiator|RunNATLabResponder|ExecuteGateCNATLabProof|OpenMemoryProofClient|ExecuteGateCMemoryProof`
的 `winkyou/` 符号匹配为0；这不是未来fieldc1c正向符号门的替代。

### 原始输出摘要

原始日志保留在仓库外，不上传含本机上下文的输出；以下为对应文件SHA-256。

| 批次 | SHA-256 |
| --- | --- |
| 永久回归旧接口RED | `14fe2c56a043b06643ff7084ac0427da260a6096dca67625aef864c7c5f5cc15` |
| 实现后同回归及消费者GREEN | `4bc375b0fc2b0d9dfe551d8125ca91e0f9d81225c49af7e5b8e41f98b35885b1` |
| 聚焦authority与旧门首跑 | `89c58f616abeec037b3988415f1e33d08de9a26b6e39ea52c2f556c5815f6903` |
| assembly race×20 | `e7817dcb94f1b5df71ee79620bffe9f197e8721e98df5b61bfdb8852742a09b7` |
| orchestrator race×20 | `4fe7644d720a44e164c81227ebe6308745b212a5105f04452a7cd41784bde1e9` |
| architecture race×20 | `296d44e773c0035d8c4b0e9e7a5214b8e151daba763b9bf8365af9ea0fa2df21` |
| 全仓#116分区 | `89a4497b5437cb1bba76d12ebbc14cbd28df29735c36232bfd75dfe6bbb5895b` |
| relay race×20 | `1eb36007b6875346bbd1239eb5b527f0bb6f3000bde7311a30414d9ff98b342d` |
| 最终architecture | `6b1aa06aeb77caeb0a8221e4f3e4fdeaf56645db8744ddf8ac3c0a64ba06fdbf` |
| 普通构建nm | `6c7e8245c7aeafe6036ddbc5aac05a9f2affd4a858a265267b0d8316ef7f0c71` |

CI首跑结果在本修复PR独立记录；没有本机新flake或未授权修复。生产差异仅六个既有文件
（+53/−34）；配置、workflow、governor、probeio、Gate B/C完成阶段和golden文件无差异。
无现场I/O、主机配置、部署或计划任务改动。C1c-2a仍须在本前置独立复审后继续接线，
本修复不签发C1c-3权限。
