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
