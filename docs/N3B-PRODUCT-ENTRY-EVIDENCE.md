# N3b 产品入口实现证据

状态：**Draft 评审证据；不签发 LAN、公网、部署或现场运行授权。**

本文件记录基于 `main=320dce5` 实现
[`ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md`](./adr/ADR-N3A-PRODUCT-ENTRY-LIVE-WINDOW.md)
的可复核证据。实现包含显式 `winkyou.stdio/v2`、one-shot `wink-rendezvous` 与离线
`wink solver pair direct`，但测试权限仍只覆盖 literal loopback 和 Linux 隔离 network
namespace。它没有签发任何
[`N3-LIVE-AUTHORIZATION-TEMPLATE.md`](./N3-LIVE-AUTHORIZATION-TEMPLATE.md) 实例。

## 1. 验收门映射

| N3a §6 门 | 实现证据 | 当前边界 |
| --- | --- | --- |
| 1. v1 不变、v2 exact-version/tagged union | v1/v2 handshake 分立 golden；跨版本、unknown field、双 arm、未知 profile 在 authority 与 I/O 前拒绝 | v1 parser 与 `non_loopback_blocked` 未放宽 |
| 2. error/progress/result | 34 个 direct class golden；固定 stage/category；成功结果 golden；底层 cause 与 secret 扫描 | 不返回 endpoint、ID、fingerprint、transcript 或 transport |
| 3. one-shot server | loopback TLS 1.3 双 slot；第二 slot 后 listener 关闭；第三连接被拒且不影响在途 attempt；frame/byte/deadline、半 TLS、半帧、取消和 crash drain | 未部署；无非回环测试监听 |
| 4. pair generator | RNG/时效/五 ID、严格 manifest、manifest-last、平台权限、O_EXCL/symlink、partial crash、clipboard 双确认与 secret scan | 只离线写入调用方指定的新目录 |
| 5. architecture boundary | v2 stdio 是 N2 能力唯一产品消费者；`wink-rendezvous` 禁止导入 governor/probeio/noisecore/`wink-signal`；raw socket inventory 与 mutation 自检 | runtime、legacy、scheduler、WireGuard 仍被拒绝 |
| 6. unit/loopback/netns | 常规 Go 测试覆盖 literal loopback；required Linux natlab 用两个真实 stdio 子进程走完整 v2 管线并沿用 N2d OS witness | TEST-NET/netns 不是现场网络授权 |

## 2. v2 进程级组合证明

`linux && natlab` harness 在两个 endpoint namespace 中分别启动真实 stdio 子进程；每个
进程取得独立临时 machine governor namespace，并通过 Content-Length framing 显式完成
v2 handshake 与 direct `connect_test`。它组合的顺序是：

```text
artifact/routing validation
  -> read-only admission precheck
  -> exact N2 reservation
  -> TLS carrier presence
  -> durable burn
  -> ACTIVATE
  -> NNpsk0 handshake
  -> PREPARE
  -> one wildcard-ephemeral ProbeSocket
  -> same-socket STUN
  -> READY / FIRE / encrypted punch
  -> bidirectional VERIFY
  -> terminal promotion / FINISH / drain
```

该用例复用 N2d 的真实 STUN、受控 NAT 与 packet/conntrack/socket/process/ledger 见证，不另开
第二个 UDP socket、不提高 `N2AttemptCost()`，也不加入 retry、candidate rotation 或数据面。
结束后重新取得同一临时 machine authority，证明进程锁与未完成 reservation 均未残留。

## 3. 冻结输出

- v2 handshake：`internal/solverstdio/testdata/handshake-v2.golden.json`；
- 34 个 direct error class：
  `internal/solverstdio/testdata/direct-error-classes.golden.json`；
- direct success：`internal/v2/directconnect/testdata/direct-success.golden.json`；
- pair manifest：测试逐字段对照 ADR §4.1 的完整 JSON，且固定 basename 顺序；
- rendezvous terminal log：仅一个聚合 JSON record，字段均为计数或稳定 class。

v1 的 `handshake.golden.json` 和 loopback tests 继续原样执行。v2 没有版本协商或 fallback；
在 v1 发送 direct arm、在 v2 发送未标记旧 envelope、混入两个 arm 或提供未知字段时，均在
authority 调用前 fail-closed。

## 4. 验证命令与结果

提交前的本地复核使用：

```text
git diff --check
go vet ./...
go test ./... -count=1
go test -race <affected packages>
go test -count=20 <affected packages>
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -tags=natlab ./test/natlab
```

本地结果（Windows，2026-08-25）：

| 检查 | 结果 |
| --- | --- |
| `git diff --check`、相对链接检查 | 通过 |
| `go vet ./...` | 通过 |
| N3b 全部新增/受影响包单次测试 | 通过 |
| N3b 全部新增/受影响包 `-race -count=20` | 通过；one-shot server、carrier、stdio、CLI、golden 与 mutation gate 均包含在内 |
| governor 全包 `-race` + 新 Preflight `-race -count=20` | 通过 |
| Linux `natlab` tagged vet + cross-compile | 通过 |
| `go test ./... -count=1` | 第二轮全绿；既知隔离的 Windows relay-wggo #33 首轮曾停滞，原命令单测复跑与第二轮全仓均通过；未修改该隔离问题 |

上述结果不替代 Linux required job；PR 只有在该 job 与常规 CI 全绿后才可交给专家审查。

Windows 本地环境没有 Linux netns、`ip`、iptables 或 conntrack，因此只执行 unit/loopback、
race、重复测试与 Linux natlab cross-compile；required CI job 使用 Linux + sudo 实际运行
`WINKYOU_N2D_REQUIRED=1` 运行 `TestLinuxN2DEndToEndProof`；N3b 是该 required matrix 中的
固定子测试，不能单独静默 skip。总 job timeout 不超过 6 分钟，任何 required 环境检查失败
都是失败。最终提交与 required CI 结果在 Draft PR 中按 exact SHA 记录。

## 5. 未证明与下一道门

这些证据只证明实现符合 N3a 冻结合同及隔离拓扑内的有界行为。它没有证明家庭路由器、
运营商 CGNAT、企业防火墙或公网部署可用，也没有授权运行 `wink-rendezvous`、生成现场
credential、修改 firewall/service/scheduled task 或发起真实 attempt。

下一步只能是独立安全评审本 Draft。评审接受后，维护者与第二复核人仍须为每个真实场景
分别签发具名授权实例、exact build SHA/checksum、时间窗、kill switch、见证与 teardown；
失败矩阵不得共享 credential，也不得被实现为自动重试。
