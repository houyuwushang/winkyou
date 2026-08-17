# Linux netns NAT lab（Phase 1a）

- 状态：**隔离实验室基础已实现；不代表真实家庭/运营商设备覆盖完成**
- 实现：`test/natlab`
- 对应计划：[`WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md) §17.2、§17.5
- 安全边界：仅 Linux root 网络 namespace；没有公共 STUN 地址，也不接入 host 外部接口

## 1. 三层验证体系

| 层级 | 作用 | 能证明什么 | 不能证明什么 |
|---|---|---|---|
| `internal/natsim` | 纯内存、确定性状态机 | mapping/filtering/端口分配/行为变化的算法与资源不变量 | Linux 内核 conntrack、iptables 与真实 socket 行为 |
| `test/natlab` | Linux netns + veth + iptables + 真实 UDP socket | `stunobserve.Client` 经 `probeio` 穿过内核 NAT 后的映射、超时与规则切换 | 某款消费级路由器、CGNAT 厂商设备或公网路径的全部怪癖 |
| Phase 1b 现场验证 | 经具名授权的受控真实网络 | 指定设备、运营商和部署版本的可复现证据 | 对所有网络环境的泛化承诺 |

三层不能互相冒充。natsim 是快速、可重复的策略基线；natlab 是不离开本机的内核语义
验证；现场测试用于补齐具体设备证据。本 lab 不把一次映射观测写成永久 NAT 标签。

## 2. 拓扑与隔离

基础拓扑为：

```text
clientA -- natA -- internet -- natB -- clientB
```

CGNAT 配方在 `natA` 与 `internet` 之间增加 `natA2`：

```text
clientA -- natA -- natA2 -- internet -- natB -- clientB
```

每条链路都是 veth pair，两个端点都会立即移动到命名 namespace；host 不保留桥、地址、
默认路由或接入外部网卡的 veth 端。地址只使用文档/测试用途的 `192.0.2.0/24`、
`198.51.100.0/24`、基准测试网段 `198.18.0.0/15` 和共享地址空间
`100.64.0.0/10`。internet namespace 内的合成 STUN responder 固定监听实验室地址，
不做 DNS，也不联系公网。

`RunInNamespace(name, body)` 会把当前 goroutine 锁定在一个 OS thread，进入目标 network
namespace，运行任意 Go 测试体，再恢复原 namespace。调用体必须同步创建 socket；socket
创建后可由自己的 goroutine 继续读写。被测客户端始终是 `stunobserve.Client`，生产 UDP
能力仍只来自 `probeio.UDPFactory` 的显式 unicast scope。

## 3. 场景与配方

| 场景 | 内核配方 | 当前断言 | §17.2 映射 |
|---|---|---|---|
| EIM / 端口保持 | `POSTROUTING MASQUERADE` | STUN 外层地址正确，mapped port 等于 client socket port | EIM 基础证据 |
| 随机端口 | `MASQUERADE --random-fully` | 最多 3 个独立观测内出现 translated port | 随机 EDM 失败/适配基础 |
| UDP 阻断 | `FORWARD -p udp -j DROP` | 3 次有界发送后稳定 `timeout/binding_timeout`，responder 收包为 0 | UDP 完全阻断 |
| CGNAT | `natA` 与 `natA2` 两层 MASQUERADE | STUN 看到最外层地址，且两层规则 packet counter 都增加 | CGNAT 级联 |
| 中途行为变化 | 初始普通 MASQUERADE；随后用 `iptables-restore` 原子替换完整 nat table 为 `--random-fully` | 前后从 `preserved` 变为 `translated` | attempt 中 NAT 行为变化 |

所有目标按场景一次性创建。即使断言失败，defer 也会先关闭 responder，再逆序删除 namespace，
随后检查计划内每个 namespace 和临时 host veth 的精确名称；任何残留都会使测试失败。设置
中途失败也会调用同一清理和泄漏见证路径。

## 4. 本地运行

平台无关的配方、拓扑和清理计划测试不需要 root，也不会创建 socket：

```bash
go test ./test/natlab ./internal/stunobserve/testkit -count=20
```

真实矩阵需要 Linux、root、`iproute2`、`iptables` 和可用的 network namespace：

```bash
go test -c -tags=natlab -o /tmp/winkyou-natlab.test ./test/natlab
sudo /tmp/winkyou-natlab.test -test.v -test.run '^TestLinuxNATMatrix$' -test.timeout=2m
```

非 root 会明确 skip；非 Linux 的 `natlab` tag 入口也会明确 skip。普通 `go test ./...`
不会运行真实矩阵。

Windows 开发者可在 WSL2 的 Linux 文件系统中克隆仓库，然后安装并运行：

```bash
sudo apt-get update
sudo apt-get install -y iproute2 iptables
go test -c -tags=natlab -o /tmp/winkyou-natlab.test ./test/natlab
sudo /tmp/winkyou-natlab.test -test.v -test.run '^TestLinuxNATMatrix$' -test.timeout=2m
```

如果 WSL2 内核或组织策略禁止 namespace/iptables，应视为环境不具备条件，不应退化到
host 或公网测试。

## 5. CI 与已知边界

`.github/workflows/nat-lab.yml` 是独立的 Ubuntu advisory workflow：PR 与 push 都触发，
job 超时 3 分钟。它不属于现有 `CI` workflow，也不应配置为合并所需检查；失败用于收集
内核/runner 差异，不遮蔽既有必需检查结果。

当前 lab 刻意不覆盖：

- 消费级路由器的 endpoint filtering、hairpin、短 TTL、重启和固件怪癖；
- 运营商 CGNAT 的多用户端口池、级联设备和时序抖动；
- IPv6 防火墙、NAT64/464XLAT、MTU/分片和 ICMP；
- coordinator、relay、配对加密、`connect_test` 或完整 v2 策略选择。

这些项目只能在相应策略落地后扩充 natsim/natlab，或在 Phase 1b 按现场授权补证；不得通过
把 lab 接上真实公网来“补覆盖”。
