# 全仓当前树隐私收口

基线 `02a3932`。本批只清理当前树，不改写历史、不删除事故结论、不增加现场权限。
旧文档门仅覆盖 `docs/`，根目录规划、脚本与 Go 夹具不在其边界内；本次扩展两个独立扫描集合。
静态门报告相对文件名、行号和错误类，不输出匹配值。人工复核使用仓库外清单，仓库中没有真实值 denylist 或其哈希。

## 已确认范围

- 维护者选择 B：`IPV6_20` 在 `cmd/meshecho/main.go` 的五处可执行字面量及对应测试统一替换；
  地址仍属于 ULA，角色与相等关系不变。该文件另两处拓扑注释改为角色占位符，无控制流修改。
- `HOSTNAME_3/4` 的夹具使用通用节点角色；`IPV4_13` 使用 TEST-NET。输入与期望值同步替换。
- 私有清单的八个误报不作真实身份批量替换，公共 STUN 默认服务保持不变。
- 22 个既有 `testdata` golden 文件核对未命中需脱敏的 21 项；不修改冻结向量。
- 十二份 2026-06 规划在同一个提交内移动、脱敏，归档不是删除；保留历史时限、计数、事故与结论。

## 脚本与合成语料

现场 SSH 目的地与跳板由调用方显式参数提供，不从仓库默认值推断；原始资料留在仓库外。
`monitor-three-node-soak.ps1` 未提供角色登录参数时在启动监测前拒绝；`-SelfTest` 不建网络连接。
控制面中断脚本移除部署 host/user/ping 默认值，保留既有参数名兼容性；多路径脚本仍需原有确认开关。
本次不执行这些现场命令。

非 TEST-NET 的额外合成 IPv4 夹具归一到文档地址，保持地址之间的差异和输入/断言一致性；
只断言 IPv6 地址类别的夹具改用文档 IPv6。私网、ULA、link-local 与 shared/benchmark 分类夹具保留。
纯测试的非法身份、密钥样式和 Windows 路径由合成片段构造，运行时测试字节不变；
不把真实标识拆成片段来绕过检查，不按整文件豁免负向测试。

公开语法例外是逐 token 的 PowerShell/Bash 操作符、Python 字段插值和 u32 位移表达式，
不是主机/用户名白名单；同一行混入身份仍须拒绝。两个 IncludesEveryFile 门覆盖未来文件、深层目录、
隐藏文件和 CRLF 行号，并拒绝 symlink/非 UTF-8 数据。

## RED 与验证

Go 1.23.1，Windows。首次完整扩展扫描：文档 165 文件、257 条候选；源码 829 文件、178 条候选，
两道门均 RED。候选包含语言语法、合成反例与未脱敏项，不等于真实身份数量；首轮日志保存在仓库外。
语法规则与遍历正负测试先通过，再提交 RED 门禁。后续开发扫描与正式验收分别保留，不覆盖首轮日志。

### 开发阶段首次失败保留

- 受影响包的首次 race 批次失败：替换字符串后，`net.IPv4` 构造参数、IPv6 展开拼写和
  动态 portfolio 分组地址尚未同步。随后只修夹具输入/期望；未放宽任何断言、产品预算或控制流。
  首次日志 SHA-256：`d18b9d3dcfb39f6a6013669ca46b32da02f6889af11190f7c9feb3bd844502c1`。
- 语法变异曾发现 here-string 例外会放过同一行的额外身份；按 token 位置收紧后正负例通过。
  原 RED SHA-256：`6735c8c46cfe86fa242ec303b351c40944099409e9f7a1f78efb735489f702b6`。
- 自加的规则 race×20 首轮达到 10 分钟测试超时（600.509s），不是产品时限失败。
  原日志 SHA-256：`82f88a6da2e09708b48d6c393dcfc8423299632b47fbefae927a462cd96a95cb`。
  源码扫描增加 IP 必需语法的预筛选，不少扫文件、不降低 count、不延长该超时；修改后的同一批次
  PASS409.559s，SHA-256：`68a8eddd4504d23f6b343ac2f99425cb5592f131481354d9b3113046e0abf007`。
  此批次不包括尚待裁决的全量文档扫描，不能据此称完整架构门已绿。

### 当前验证快照（未推送）

| 项目 | 实测结果 |
| --- | --- |
| 私有清单复核 | 21 项均零命中；八个排除项未作部署标识替换 |
| 冻结 golden | 22 文件；零命中、零修改 |
| 相对文件链接 | 490 条，零失效；排除 fenced code 和外链，不声称验证页内锚点 |
| 生产 Go 差异 | 仅 `cmd/meshecho/main.go`，7 增/7 删：五个已授权字面量、两行拓扑注释 |
| 配置/工作流/依赖 | 零差异；公共 STUN 默认值不变 |
| 受影响包 race×1 | 提示词要求的 13 包，加实际改到的 4 包；合并验证 17/17 PASS |
| 脚本离线自测 | soak 41、supervisor 5、installer 4、Python 输入契约 5，全部 PASS；无现场命令 |
| `go vet ./...` | 当前实现开发批次 PASS，空诊断；最终验收前再执行 |
| 完整 architecture 首跑 | RED21.381s；只剩文档扫描 167 文件中的 3 处既有配置 token |
| `git diff --check` | PASS |
| 全仓 #116 分区 / 独立 relay race×20 / CI | 待边界确认；未完成、不计作 PASS |

17 包合并验证日志 SHA-256：`6a798161d7f391138b3c01a274750494b78a0b262e64ab241b570b9e2a646b38`。
命令（Go 1.23.1）：

```text
go test -race ./cmd/wink/cmd ./pkg/client ./pkg/config ./pkg/mesh ./pkg/meshruntime ./pkg/nat ./pkg/solver/... ./pkg/bootstrap/selfhosted ./pkg/tunnel ./internal/diagnose ./internal/v2/sshassembly -count=1
go test -race ./internal/architecture -run 'TestSourceTreePrivacy|TestPublicDocumentationPrivacySyntax|TestPublicDocumentationPrivacyIncludesEveryFile|TestPrivacyLanguageOperators' -count=20 -timeout=10m
go test ./internal/architecture -count=1
```

### 待维护者确认的精确配置例外

扩围后命中 quickstart 的现有 `WINK_NETWORK_CIDR` 默认配置：`.env.example` 第 6 行、
`docker-compose.yml` 与 `start-coordinator.sh` 各第 20 行。它们未在旧门覆盖范围内，旧 #144
白名单也未收录该精确 CIDR。当前未修改默认配置，未擅自扩充白名单或豁免这三个文件。

待确认方向：仅允许该默认 CIDR 的完整配置 token，仍拒绝其中的主机地址、其他掩码与伪装后缀；
不把整个网段放行。维护者确认前保留 RED，不推送。完整架构日志 SHA-256：
`0a13a8421241c0afbf2a2b8a345a331ea52b5ec971dbe7829f37005fe711e04f`。

后续验证与 CI 首跑另行补充；不覆盖上述首轮结果，不 rerun 求绿，不自行合并。
