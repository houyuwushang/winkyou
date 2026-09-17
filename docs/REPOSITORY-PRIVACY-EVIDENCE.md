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
  此批次不包括当时尚待裁决的全量文档扫描，不能据此称完整架构门已绿。

### 裁决前本地快照（历史记录）

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

### 维护者批准的精确配置例外

扩围后命中 quickstart 的现有 `WINK_NETWORK_CIDR` 默认配置：`.env.example` 第 6 行、
`docker-compose.yml` 与 `start-coordinator.sh` 各第 20 行。它们未在旧门覆盖范围内，旧 #144
白名单也未收录该精确 CIDR。首次扫描保留 RED 后暂停，未修改默认配置或豁免这三个文件。

维护者随后明确同意：仅允许该默认 CIDR 的完整配置 token，仍拒绝其中的主机地址、其他掩码与
伪装后缀，不把整个网段放行。新增 5 个精确 token 正例、12 个负例固定边界；旧规则下正例
确实 RED，再实现这个窄例外。默认配置仍零差异。此前完整架构日志 SHA-256：
`0a13a8421241c0afbf2a2b8a345a331ea52b5ec971dbe7829f37005fe711e04f`。

### 裁决后正式本地验收

仍为 Go 1.23.1 / Windows，串行执行。以下为该授权后批次的首次结果，不覆盖上面的开发 RED。
时间为命令外层墙钟毫秒（包括工具启动），不是产品时限或新的预算。

| 批次 | 结果 / 外层毫秒 | 日志 SHA-256 |
| --- | --- | --- |
| 全仓 vet | PASS / 13540，空诊断 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| 完整 architecture | 126 PASS / 0 FAIL / 0 SKIP，27989 | `5840f940327535c47f48ff4a37e03dda0735848e2d6180ed6149a4feebec4e68` |
| 17 个受影响包 race×1 | 全 PASS / 38226 | `1c7eaefe1308886ee25be010b3b7b59f0066ed57f7b72be4b47abe7e27c818f3` |
| 全仓 #116 主分区 | 88 个有测试的包 PASS / 291637 | `a7529ebb08de425fb061c67ec691d8f95fa6b9c00eb0e9e562e878e80b6d038a` |
| #116 独立 relay×1 | PASS / 19458 | `7d1ccff95fd9743d4b99829a539b4a8163ef6e69c4ed33402ac6ccd5a5205b5e` |
| 独立 relay race×20 | PASS / 179685 | `e961cfdcdeb5324bd9885b7a9f83873d66255fc5a973c7affcc52ec4ad3158dd` |
| Python 离线输入契约 | 5 PASS / 489 | `1a575bac5f2bf48aa50adaa58b5be3afb6a9a9d90acc3b8cdffce57ce519e99a` |

完整架构报告：文档扫描 167 文件 / 0 命中、源码扫描 829 文件 / 0 命中，两个 IncludesEveryFile
门与规则正负例全部通过。没有整文件豁免，没有为了通过而减少测试次数或修改任何产品硬上限。
当前批次未命中其它已登记 flake 签名。新增精确 CIDR 契约单独 race×20 PASS1.686s，
日志 SHA-256：`b06f8350c20affd8970056410971bc6b7ceaca0e6a72a0697bcb68d04637f8b9`。

窄 CIDR 例外的新增正例在旧规则下 RED 日志 SHA-256：
`7f7478c1e0b634db88dff5f97bf5ec445fdefe799890407c6584973558925d6e`；
实现后全量隐私门 GREEN 日志 SHA-256：
`bfd297ee33733ee07fcbcdaea8afa4ac47a2995f758b4f4cee88c272450aa35c`。

本阶段补充命令（受影响包完整命令见前表）：

```text
go vet ./...
go test ./internal/architecture -count=1 -v
go test ./... -count=1 -skip '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$'
go test ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=1
go test -race ./pkg/client -run '^TestRelayWGGoTwoEnginesExchangeIPv4Packets$' -count=20
go test -race ./internal/architecture -run '^TestPublicDocumentationPrivacyProductNetworkToken$' -count=20 -timeout=1m
python -m unittest discover -s scripts -p test_field_script_inputs.py -v
```

CI 首跑结果记录于 PR，推送仅一次；不覆盖首轮结果、不 rerun 求绿、不自行合并。
