# N2c governed rendezvous carrier 与 same-socket STUN 证据

状态：**Draft implementation evidence；不授权产品入口、非回环收发或现场测试。**

本切片实现 ADR 第 9 节第 4 步。它只允许进程内、literal loopback 测试，不接入
`wink-signal`、stdio、CLI、runtime、daemon、scheduler 或 legacy strategy。

## Carrier 边界

`internal/v2/rendezvouscarrier` 接受 caller 已取得的完整 heavyweight attempt lease；包内
不存在 governor 获取方法，也不接收 pairing secret。carrier 在任何 DNS/TCP I/O 前由该
lease 消费一次性 exclusive claim，失败或排水后也不释放，因此同一 attempt 无法重连。
自托管档与最低信任档共享同一窄
接口、同一 Noise profile、同一 carrier-domain binding 和同一资源上限。server TLS 或运营者
身份只能在未来保护 transport，不能替代端到端 pairing 证明。

固定顺序为：

```text
one preconnect
  -> secret-free presence (<= 3s)
  -> caller durable BURN_AND_ADMIT
  -> BeforeFirstEmission
  -> two empty-payload Noise handshake frames
  -> rendezvous-control frames only
  -> terminal close + registered drain
```

presence 仅携带用于本次 rendezvous 的随机关联标识、slot 与固定 profile，不携带 pairing
secret、pairing context、direct endpoint 或 secure-channel byte。burn 前收到 handshake/control
frame 不会排队，而是立即终局。认证成功的 `direct-punch` frame 若从 rendezvous stream 到达，
同样立即关闭 protocol 与 carrier。server 只转发有界 opaque frame，并看到不可避免的
rendezvous association/slot 与 transport metadata；它拿不到 pairing secret、明文控制
payload、raw stream 或跨 attempt mailbox。

## 冻结成本

| 项目 | hard ceiling |
| --- | ---: |
| TCP connection / rendezvous target | 1 / 1 |
| DNS | literal 0；package-test 注入式 resolver 最多 1 |
| DNS coarse reservation | 1 socket / 1 target / 1 five-tuple |
| application frame | 每方向 8 |
| application bytes | 每方向 8,256；双向合计 16,512 |
| presence | 3 seconds |
| active carrier | 13 seconds |
| attempt / drain margin | 15 seconds / 2 seconds |
| reconnect / polling / offline queue / cross-attempt reuse | 0 |

完整 attempt 同时预留 3 sockets、4 targets、4 five-tuples、5 UDP packets、5 PPS，且
`Heavyweight=true`；机器级 compiled limit 同时最多接纳 1 个 heavyweight attempt。TCP 的
OS packet 数不从 application frame 数推导，也不占用这里的 UDP packet 计数。

## Same-socket STUN

`stunobserve.NewSameSocket` 只接受 caller 已经通过 `probeio` 打开的 `ProbeSocket`。它没有
Factory，不能打开第二个 socket。STUN target 必须先登记，最多发送 3 个 Binding request；
成功且 generation 仍一致后，才可登记一个来自认证 READY 的 peer target。STUN target 与
peer target 一起占用同一 attempt 的 2 targets / 2 five-tuples。静默、源不匹配、协议错误、
generation 漂移或顺序错误都会关闭该 socket，使本 attempt 直接终局。

## 自动化证据

- 两个部署档均在真实 loopback TCP 上完成空 payload NNpsk0 与加密 PREPARE 往返；
- presence 超时未调用 durable authorization，且 drain 完成；
- burn 前 handshake、application bytes 超限、deadline、writer failure 均有界终止；
- carrier-domain 变异证明 direct-punch frame 即使认证打开成功仍因来源错误而终局；
- 真实 loopback UDP STUN 后向 peer 发送合成 punch，接收端观察到同一个源端口，Factory
  open 计数严格为 1；第三个 target fail-closed；
- 父测试进程强制终止 carrier 子进程后，独立 test server 的 active connection 回到 0；
- carrier 将底层网络错误折叠为无地址的稳定错误类；same-socket 默认 JSON 明确排除 raw
  Observation 与 endpoint；
- architecture 变异测试证明 product/stdio/runtime/legacy 导入 carrier 或调用 same-socket
  入口均失败，`stunobserve` 没有新增 raw network capability；
- Linux required CI 继续执行 N1 netns job，并另外对 N2c 受影响包执行 race 与 20 次
  mutation/stability matrix；普通 Linux/Windows 全仓测试仍覆盖 literal-loopback 路径。

这些结果不证明 NAT 穿透，也不授权真实 STUN、LAN 或公网流量。N2d 必须另行在隔离
namespace/NAT lab 中组合证明，并补足 `ss`/conntrack 等 OS 见证。
