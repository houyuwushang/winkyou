# Test-only Noise 握手核心

- 状态：**Phase 1a loopback-carrier approved 纯密码核心；仅允许被受审的精确回环 carrier 边界使用，非回环仍未授权**
- 实现：`internal/v2/noisecore`
- 固定协议：`Noise_NNpsk0_25519_ChaChaPoly_SHA256`
- ADR：[`ADR-TEST-PAIRING-CRYPTO-CANDIDATE.md`](./adr/ADR-TEST-PAIRING-CRYPTO-CANDIDATE.md)，已于 2026-08-21 Accepted（仅限仿真实现，真实网络权限另行门禁）

## 1. 边界

本包只实现 Noise rev34 中上述固定套件的内存状态机：

- `NNpsk0` 两条握手消息：`-> psk, e`、`<- e, ee`；
- X25519、ChaCha20-Poly1305、SHA-256 与 Noise HKDF；
- 握手完成后的发送、接收两个独立 `CipherState`；
- 固定递增 nonce、认证失败即终止，以及显式 `Zeroize` / `Close`。

它不拥有 socket、文件、DNS、信令或任何网络能力，也不派生、读取或持久化 PSK。调用方必须通过 `PSKSource` 注入已经得到的 32 字节一次性 pairing secret。架构门禁只允许 `punchproto`、simulation adapter 与精确的 `internal/v2/loopbackcarrier` 导入本包；CLI、Runtime 和任何其他路径均会失败。本包仍禁止导入 `net` 或仓库内其他包。

边界提升本身没有接线任何调用方，`connect_test` 仍稳定返回 `not_implemented`。本包没有授权非回环配对、身份系统、恢复控制器或生产传输。

## 2. Prologue 与 API

WinkYou 调用方必须先严格校验 `PairingContext`，再把 `testpairing.BuildNoisePrologue` 的完整输出作为 `Config.Prologue` 传入。密码核心只消费调用方给出的字节，不复制 JCS 或 pairing 规则，从而保持协议上下文与密码原语的单一职责。跨包测试会用真实 builder 输出完成自互通。

最小调用顺序是：

1. 双方分别调用 `NewInitiator` / `NewResponder`；
2. initiator `WriteMessage(nil)`，responder `ReadMessage(...)`；
3. responder `WriteMessage(nil)`，initiator `ReadMessage(...)`；
4. `Complete` 后才可调用 `Encrypt` / `Decrypt`；
5. terminal success、取消或任意错误后调用 `Close`。

核心的 `WriteMessage` 可以接收 Noise handshake payload，唯一用途是逐字节运行上游通用测试向量。WinkYou 固定 profile 的 adapter 必须传空 payload；非空 payload 的策略拒绝属于未来 carrier/adapter 审查，不是本核心的通用 Noise 规则。

没有 `SetNonce`、`Rekey`、状态导出/导入、0-RTT、resumption、静态密钥或算法协商 API。单条 Noise 消息上限为 65535 字节；WinkYou 更小的 48 字节握手和控制帧上限仍由 pairing adapter 强制。

## 3. 正确性证据

`testdata/cacophony_nnpsk0_25519_chachapoly_sha256.json` 摘录自 Haskell Cacophony 的公开向量集：

- 来源：`haskell-cryptography/cacophony` commit `8ee9d41e34a1a596cfa3ab12aa4069ff87dc1247`；
- 上游向量 blob：`b8a271ed1aba8b4a56bf429e559d7947827123b4`；
- 许可：Unlicense；
- 原始文件：`vectors/cacophony.txt`，fixture 内固定了完整 commit URL。

测试用固定 ephemeral private key 重新执行整套 `Noise_NNpsk0_25519_ChaChaPoly_SHA256` transcript，逐消息比较两条握手 ciphertext、四条 transport ciphertext 与最终 handshake hash。另有自互通、所有握手字节篡改、PSK/prologue 不一致、乱序、截断、超长、重放、低阶点、nonce 编码/溢出和 fuzz seed 测试。

Noise rev34 的 `psk0` 在第一条消息开始时执行 `MixKeyAndHash`，随后 `e` 还会进入 `MixKey`。因此即使 handshake payload 为空，第一条消息也已有 16 字节认证 tag；PSK 不一致会在 responder 读取第一条消息时失败。这比“等第二条消息才失败”更早，也是上游向量锁定的规范行为。

## 4. 已知限制

这是新写的密码学实现，尚未完成独立安全审查，不能仅凭测试向量宣称安全或翻转 ADR 状态。向量证明的是规范互操作，不证明侧信道安全、编译器行为或整个 pairing 系统正确。

实现会覆盖当前仍可到达的 Go byte slice/array，并尽早释放 key 对象引用；但 Go 的复制、逃逸分析、垃圾回收和底层密码原语内部副本意味着无法承诺所有历史内存都被物理清零。文档和 API 只作 best-effort zeroization 声明，不作不可验证的内存擦除保证。
