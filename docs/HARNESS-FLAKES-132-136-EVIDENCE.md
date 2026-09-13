# Harness flake 收尾证据：#132–#136

基线 `ed9522b`，test/docs-only；生产、配置、工作流、冻结预算和所有现场权限均不变。
本批按 #133 → #135 → #132 → #134 → #136 串行处理，完成后一次推送，Draft 等独立复审。

- #133：维护者接受仅补 Fresh100 测量回归、原窗口不变、`Refs #133`；见
  [C1b 证据 §7.5](GATE-C1B-PRODUCT-COMPOSITION-EVIDENCE.md#75-133连续-fresh100-窗口校准先测量未宣称修复)。
- #135 / #132：等待预算与尾包分段见证见
  [Gate B3 证据](GATE-B3-HARD16-ISOLATED-EVIDENCE.md)。#132 未定位 OS 丢失点前仅 `Refs`。

## #134：expiry 观察顺序不改变持久不变量（设计先行）

原始 [Linux race RED](https://github.com/houyuwushang/winkyou/actions/runs/34561468857/job/103144896471)
保留：`ConsumeForCarrier` 返回 nil authorization / `ErrCommittedAttemptInvalid`，却未包含
测试要求的 `ErrPairingCredentialExpired`。watcher 先选 expired 终局时，生产
`terminalChosen` 分支返回前者；validate 先观察过期时同时包含后者。两者均无授权，
credential 都以 expired FINISH，不能把生产错误身份的现有差异判成权限泄漏。

先保留旧断言并记录实际 ordering，再改为裁决的不变量：authorization=nil、
`errors.Is(err, ErrCommittedAttemptInvalid)`、该 credential FINISH reason=expired、
journal sequence=3。类型化 expiry cause 只决定日志 `validate_first` / `watcher_first`，
不决定 PASS。原因为 cancelled/carrier_error、额外 journal 记录或非 nil authorization
仍必须拒绝；不加生产 hook、不改 watcher 或错误面。

验证预定：旧判据 race×200 首批、修订判据 race×200 首批，分别保留原日志与 ordering
计数；新批次两种顺序都必须实际覆盖，不以纯合成错误值代替真实持久 FINISH。
如果自然调度未覆盖某一顺序，只能补 test-only 调度控制，不能改生产去制造顺序。

P1 仍待维护者另行裁决：`terminalChosen` 按 `terminalReason` 拼接类型化 cause。
本批不实现 P1；issue 评论继续保留该待决项，不能把测试修复当成错误面已统一。

### #134 实测与修复

旧判据自然调度首批 race×200 **200/200 PASS（3.915s）**，但全部是 validate_first，
没有覆盖另一条路径；不把它称作根因修复。随后 `78bf98c` 增加两种顺序的确定性
test-only 控制：复用既有 beforeReturn hook，最终 postcheck 的一次时钟读取之后，
在唯一生产 watcher 首次读取测试时钟前设置屏障；不增加 watcher、不修改 committed
对象，也不伪造 FINISH。释放屏障与 Consume 的顺序决定谁先观察 expiry。

该控制首次 RED（0.612s）：validate_first PASS，watcher_first 被旧的类型化 cause
断言拒绝；**两条路径的真实 journal 都是 expired、sequence=3、authorization=nil、
ErrCommittedAttemptInvalid=true**。日志 SHA-256：
`50766fe3fdcbda542ed52422f58e3056fb2c85d5f47a5e29f6b6340e1ee89856`。

修复 `7231f72` 只把公共断言改为 `ErrCommittedAttemptInvalid`；原自然顺序用例仍在，
追加 FINISH reason 与 sequence=3 的精确检查。P1 生产错误身份没有改变。

```text
go test -race ./internal/governor -run '^TestCommittedAttempt(InvalidatesBeforeFirstEmission|ExpiryObserverOrderings)$/^(credential_expiry|validate_first|watcher_first)$' -count=200 -v -failfast -timeout=5m
```

修复后首批 PASS（12.773s），自然用例 200 次 + 两个受控顺序各 200 次；实际日志
validate_first=400、watcher_first=200，600 次真实 expired FINISH 的 sequence 均为 3。
绿日志 SHA-256：`0904a37fb7ab7b014c3d70502a5ed1a05268abfaee7f82a241e99f32c4dc77e5`。
全部控制在 `_test.go`，5s 只界定测试屏障等待，不变更任何产品 timer 或资源预算。
