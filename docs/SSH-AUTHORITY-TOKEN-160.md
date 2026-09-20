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

待本分支独立验证后填写。首跑 RED 与后续 GREEN 分别保留，CI 与本机证据分开记录。
