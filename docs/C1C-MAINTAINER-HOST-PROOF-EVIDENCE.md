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

待填写；没有执行共享主机证明，没有实例签发或现场 I/O。
