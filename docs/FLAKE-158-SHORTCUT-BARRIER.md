# #158：shortcut barrier 夹具见证与收敛

## 范围与首个 RED

基线 `f30a456`，仅测试与证据，不改生产、配置、工作流、probation、keepalive 或 peer timeout。
Windows 首跑的 `TestShortcutReconcilesDroppedPacketBarrierSignal/first_stable_after_initial_delivery_window`
在约 1.66s 报 `dropped stable count = 0, want 1`。
原始记录见 [#158](https://github.com/houyuwushang/winkyou/issues/158)。

源码核对：原 `dropFirstShortcutSignalTransport` 已使用原子 CAS 丢弃第一次匹配，
没有按墙钟关闭的武装窗口。尚不能把问题归因为“武装太晚”。
先用测试侧 `NodeConfig.OnEvent`、`Config.OnEvent` 及 transport 包装记录双向 barrier
的固定 type/hop、相对时间、dropper 武装与三个 manager 首次 stable 时刻。
不输出消息正文、attempt ID、地址或路径。失败保留完整见证。

## 验证计划

1. 保留原断言和执行顺序，`GOMAXPROCS=2`、两个 busy goroutine、Go 1.23.1，
   `go test -race ./pkg/mesh/shortcut -run '^TestShortcutReconcilesDroppedPacketBarrierSignal$' -count=200 -json`。
   测试侧压力开关 `WINKYOU_FLAKE_158_CPU_STRESS=1`，实际 0 次失败也照录。
2. 仅依据见证修改夹具顺序；首个指定跳信号必须丢弃，随后等待三方收敛。
   默认保持 `dropped == 1 && matched >= 2`。只有实际见证合法绕路时才评估提示词授权的替代断言。
3. 同 profile 新代码 200 次、`go test ./pkg/mesh/... -race -count=50`、
   `go vet ./...`、architecture、全仓 #116 分区与独立 relay 验证。
4. 原始日志留仓库外，仅发布计数、相对时间与 SHA-256。CI 首跑单列，不 rerun 求绿。

## 测量与结论

待首次测量；当前没有宣称复现或修复。
