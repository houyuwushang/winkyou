# NAT 模拟矩阵

- 状态：**Phase 1a 基础设施；策略覆盖仍在进行中**
- 实现：`internal/natsim`
- 权威计划：[`proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md`](./proposals/WINKYOU-V2-DIRECT-FIRST-PLAN.md) §17.2、§17.4
- 安全边界：纯内存，不打开 socket，不访问 DNS，不启动 daemon，不发送真实网络包

## 1. 目的与边界

本 harness 为 v2 策略和未来 `connect_test` 提供可注入的 `net.PacketConn` 语义，使 NAT 映射、过滤、端口分配和故障可以在同一进程内确定性复现。它用于验证状态机、资源上限、取消和失败分类，不声称复刻某个具体路由器内核、运营商设备或真实网络时序。

`internal/architecture` 把 `internal/natsim` 设为永久零网络能力区：直接或传递引入 `net.Listen*`、`net.Dial*`、raw socket、Pion 或 quic-go 主动网络能力都会使测试失败。本文中的地址仅为文档保留地址或协议示例，不对应个人实验环境。

## 2. 模型语义

### 2.1 映射

| 模式 | 映射键 | 语义 |
|---|---|---|
| EIM | 内部 endpoint | 同一内部 endpoint 访问不同目的端时复用外部 endpoint |
| EDM | 内部 endpoint + 目的 endpoint | 每个目的 endpoint 使用独立映射 |

映射由第一次 `WriteTo` 创建；`Network.MappedAddr` 只读取既有映射，不会隐式创建。没有虚拟接收者的写入仍按 UDP 语义返回成功，但计入 `PacketsDropped`，因此可作为纯内存 observation endpoint 的建图步骤。

### 2.2 端口分配

| 策略 | 语义 |
|---|---|
| `preserving` | 优先保留内部端口；冲突时按配置范围递增回退 |
| `increment` | 在闭区间端口范围内确定性递增并回绕 |
| `random` | 使用显式 seed 选择确定性起点，再线性探测空闲端口；相同配置得到相同序列 |

所有策略都拒绝端口池耗尽，不会覆盖仍存活的映射。Network 还独立限制 PacketConn、映射、队列和单包字节数。

### 2.3 过滤

| 模式 | 允许的入站来源 |
|---|---|
| endpoint-independent | 任意来源均可使用已有映射 |
| address-dependent | 仅允许内部 endpoint 曾发送过的来源地址 |
| address+port-dependent | 仅允许内部 endpoint 曾发送过的完整来源 endpoint |

过滤拒绝模拟 UDP 丢包：发送方仍得到成功写入，接收方在自己的 deadline 内得到超时。测试必须对这种“不送达但无写错误”的语义作显式断言。

### 2.4 阻断、级联与中途变化

- `UDPBlocked` 在映射创建前返回稳定的 `ErrUDPBlocked`，不消耗映射额度；
- `EndpointConfig.NATChain` 按 inner-to-outer 顺序串联任意层，CGNAT 使用两层即可；
- `BehaviorChange.AfterOutboundPackets=N` 表示前 N 次 outbound attempt 使用旧行为，第 N+1 次前切换；
- 切换可同时替换 mapping/allocation/filtering/UDP-block 模型与虚拟公网地址；旧映射原子失效，端口分配器按新 generation 重置；
- 公网地址与其他 NAT 冲突时返回稳定错误，不静默合并两个虚拟边界。

## 3. PacketConn 与资源语义

`*natsim.PacketConn` 完整实现 `net.PacketConn`，可作为未来 transport adapter 的注入对象：

- `ReadFrom`/`WriteTo` 复制 payload 所有权，不共享调用方切片；
- read/write deadline 使用本地时钟并返回 `os.ErrDeadlineExceeded`；
- `Close` 唤醒阻塞读、删除该连接的全部映射并排空队列；
- 队列满、无路由和过滤拒绝都是有界丢包，不创建后台重试；
- `Counters` 同时报告 active、peak、written、delivered、dropped 和 rejected。

当前实现没有 fake clock、映射 TTL、分片、ICMP、MTU/带宽/抖动模型，也不模拟内核 socket buffer。这些能力只能在有具体策略测试需求时增补，不能通过引入真实网络 I/O 解决。

## 4. 重复 harness

`RunScenario` 为每次 repetition 创建全新的 Network，并执行以下固定顺序：

1. 执行同一场景；
2. 读取 peak 与 active 资源计数；
3. 验证场景声明的 PacketConn、mapping、queued-packet 上限；
4. 要求场景在返回前主动关闭所有 PacketConn；
5. defensive cleanup 后再次要求 active 资源为零；
6. 任一失败立即停止，不继续掩盖首个失败 repetition。

因此“100 次通过”同时意味着每次从空状态开始、峰值不越界且 teardown 无残留，不只是收到了预期 payload。

## 5. §17.2 九类场景映射

| # | 计划场景 | 模型表达 | 当前覆盖 |
|---:|---|---|---|
| 1 | LAN | 两个空 NAT chain 的直接 PacketConn | TODO：等待 v2 strategy adapter |
| 2 | 双方全局 IPv6 | IPv6 `netip.AddrPort` + 空 NAT chain | TODO：等待 v2 strategy adapter |
| 3 | EIM × EIM | 双 NAT、EIM、endpoint-independent filter | **参考场景及受控同步 punch 均连续 100 次成功；后者还覆盖 address+port-dependent filter** |
| 4 | EIM × EDM | 两侧分别选择 EIM/EDM | N2 direct-attempt 对 4 种 address/address+port filtering 组合各 100 次稳定有界失败；不做 candidate replacement |
| 5 | 可预测 EDM × EDM | EDM + preserving/increment allocation | N2 direct-attempt 对 4 种 filtering 组合各 100 次稳定有界失败；端口预测策略仍 TODO |
| 6 | 随机 EDM × EDM，预期有界失败 | EDM + seeded random allocation | TODO：随机确定性单测已覆盖，等待失败分类策略 |
| 7 | CGNAT | inner-to-outer 两层 NAT chain | 模型双向转换单测已覆盖；策略场景 TODO |
| 8 | UDP 完全阻断 | 任一层 `UDPBlocked=true` | **参考场景已覆盖，连续 100 次稳定 `ErrUDPBlocked`** |
| 9 | attempt 中 NAT/接口/公网 IP 变化 | `BehaviorChange` + mapping reset + `PublicAddr` | generation/地址切换单测已覆盖；策略重求解 TODO |

只有表中明确标为“参考场景已覆盖”的行满足当前连续 100 次门槛。其余行不得因为模型类型已存在就宣称策略已经支持。

## 6. §17.4 故障注入映射

本切片提供以下纯内存故障基础：

- UDP 完全阻断；
- filtering drop 与无路由 drop；
- 队列、映射、PacketConn、payload 上限；
- read/write deadline 与 Close 唤醒；
- attempt 中映射行为和公网地址变化；
- harness 首错即停、peak 越界和 teardown 泄漏见证。

N2 direct-attempt 另在 delivery seam 覆盖 SYN/SYN_ACK/ACK 丢包、乱序与重复，以及
control replay、跨 AD domain、oversize、认证篡改和 CANCEL 前后语义；详见
[`N2-DIRECT-ATTEMPT-SIMULATION.md`](./N2-DIRECT-ATTEMPT-SIMULATION.md)。这些注入不增加
sender emission，也不产生重试。

`WSAENOBUFS`、真实 OS socket 数、governor cancellation drain 和持久化 safety trip 属于 `probeio` 生产 adapter 的验证范围，不由纯内存 NAT 模拟器伪装为已覆盖。签名重放、machine lock、路由安装冲突、Relay 中断和真实进程外指标仍是后续独立故障注入项。
