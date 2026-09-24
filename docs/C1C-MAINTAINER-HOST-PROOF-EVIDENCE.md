# C1c 维护者主机证明模式（A0）

基线 `bf8ba21`。共享主机不得改写全局 conntrack ceiling，也不得通过伪造 CI attestation
运行既有证明。仅两处 test-only 入口增加互斥模式；生产代码、workflow、guardian crash
与全部冻结预算不变。[私有操作契约](./GATE-C1C-RUNBOOK.md#21-维护者主机证明模式a0test-only)。

## 验证顺序

1. 纯函数表先 RED：CI/维护者模式、混用变量、权限、namespace、独立注册表挂载、TMPDIR。
2. 实现只读采集和子测试/顶层 ceiling 不变断言；同一张表 GREEN。
3. 门禁核对校验先于 namespace 创建、两入口唯一消费、guardian 保持 CI-only、快照命令
   固定且只读、隐私扫描覆盖脚本；变异不得绕过这些条件。
4. Go 1.23.1：纯函数 race×20、所有标签 Linux vet、architecture（包括既有 CI 预算门）。
5. 两个 required Linux 证明的首跑 CI 单列；本机不能运行 Linux namespace 时明确记未执行。

所有首次 RED 原样私有保留，只公开脱敏结果与 SHA-256。A0 推送不授权远端操作；必须等待
独立复审合入。Windows mini-spec 单独 PR，不把尚未进行的 OS 证明写为通过。

## 实测结果

Go 1.23.1，GOMAXPROCS=4；本机只运行无 namespace 的测试，Linux tagged vet 为交叉检查，
不等同于 Linux OS 证明。没有执行共享主机证明，没有实例签发或现场 I/O。

| 批次 | 原始结果 |
| --- | --- |
| `16af272` 纯函数未实现，36 行表驱动用例 | RED 36/36；统一断言位于 `c1c_maintainer_proof_test.go:124`，class=`c1c_proof_unimplemented`。 |
| 同表实现后 `-count=1` / `-race -count=20 -failfast` | GREEN 36/36 / 720/720。 |
| 固定快照无主机 I/O 模拟 | 13 条命令，11 项 nonvolatile、2 项 volatile；拒绝非 root/读取失败；真实主机调用 0。 |
| `bash -n scripts/c1c-review-snapshot.sh` | PASS，仅语法检查，不执行快照。 |
| 首次 `go test ./internal/architecture -count=1` | RED：既有 Gate B3 文本扫描把新快照脚本及其契约测试中的 ceiling key 判为 writer。原日志保留。 |
| 只读例外修复后的 focused architecture | GREEN；仅允许精确脚本路径且固定只读 argv 契约成立。改为 `sysctl -w`、移除 init 约束、改名均仍拒绝。原 writer 权限和 CI wrapper 不变。 |
| `go vet ./...` | PASS。 |
| 最终 `go test ./internal/architecture -count=1` | PASS，命令墙钟 51.665s。 |
| 最终 focused attestation/architecture `-race -count=20 -failfast` | PASS，命令墙钟 12.235s；36 行表与 17 个负向变异各重复 20 次。 |
| 最终 `GOOS=linux CGO_ENABLED=0 go vet -tags=fieldc1c,natlab,c1bproof ./...` | PASS，命令墙钟 14.404s。 |

纯函数首 RED 日志 SHA-256：
`f6a6685f9fc61d64d94960c281e44d53a69902bb30b1e7596ae296df330f95fb`。
首次 architecture RED 日志 SHA-256：
`e732b5ee608c96f95948259e7301719e4113617bf98f9b047c92844b29895f30`。

本地 tagged vet 首次采集遇到空输出日志处理错误，不能当成有记录的验收；修正私有采集器后
重新执行并记录 exit=0。另一次 shell 语法检查因工具定位失败未执行，按实际安装位置调用后
PASS；两者都不是测试 flake 或 CI rerun。首次失败没有覆盖或删除。

CI 首跑在 PR 验证表单列；CI 未完成时不得把待跑项目写为通过。两项 required OS 证明仍须
走原 CI attestation 路径，GuardianCrash 未放宽。

## 2026-09-24 复审修订（两项 must-fix）

依据 [独立评审](https://github.com/houyuwushang/winkyou/pull/173#issuecomment-5794396105)：
原 11/2 快照口径把主机连接数、倒计时和流量计数作为严格结构，可能因无关业务变化误报。
修订为 10 项 nonvolatile / 3 项 volatile，并按类别递归剔除精确动态键；所有其它结构保留。
第二人证据读取独立为无参数脚本，固定目录白名单、nofollow、进程内哈希与 4 MiB 文本上限。

验证顺序：更新契约并在旧实现记录首 RED → 修复两个脚本 → 同一回归 GREEN、变异、
race×20 → vet/architecture/隐私/语法与相对链接 → 原两个隔离证明首跑 CI。使用模拟命令
和内存文件树测试读取器，不执行主机快照、不读取真实私有证据。此前首跑记录不覆盖。
本节不授权 A1、账号或 sudoers；生产、workflow、原 netns budget/场景均不变。
