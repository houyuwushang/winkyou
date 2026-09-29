# C1c-3 首批实例操作规程（Stage I，Draft）

基线：`18af69d`。A1–A3 的第二人远端复核已在
[C1c ADR §7](./adr/ADR-N3C-GATE-C1C-DISPOSABLE-ROUTER.md#7-后续验收门与裁决) 关闭；
其 exact build 源码为 `57ffb5b`，**不是本规程的文档提交**。不得因为本 PR 换 SHA 而重建或
替换已复核产物。四产物完整摘要、VCS 和工具链仍以私有 A3 记录为准。

**本 PR 只提供规程与未决清单，不执行下列命令，不生成材料，不签发实例。**
Stage I 独立复审接受后仍需另发 Stage II 任务书；Stage II 只做无端点建网/拆网演练。
Stage III 才可能签发首个负面实例。§9 的相应未决项未闭合时，不把命令片段拼成运行脚本。
模板里的 `<PLACEHOLDER>` 不是已核实值；任何签字、布尔许可和测量结果都不能预填成功。

## 1. 范围、依据与命令勘误

本轮是共享 Linux 主机内的隔离 router/端点组合，不是跨设备、LAN 或公网穿透证明。
只消费 [C1c runbook](./GATE-C1C-RUNBOOK.md) 步 4–12；A1–A3 不重跑。
[Gate C1 §11](./adr/ADR-N3C-GATE-C1-SSH-PRODUCT-ASSEMBLY.md#11-现场签发纪律) 的低成本门
仍优先于 `teardown`、`predictive_apdm_pair`；后续 asymmetric、hard16、crash 另发任务。
不启动默认 `wink up`，不触碰 daemon、计划任务、宿主 sshd、默认路由或全局 sysctl。
cached self-bootstrap/autonomous recovery 的
[事故暂停与 NO-GO](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md) 不变。

| 经源码核实的入口/约束 | 依据与适用范围 |
| --- | --- |
| `wink solver pair oob --profile predictive --out-dir <NEW_PRIVATE_DIR>` | [root.go](../cmd/wink/cmd/root.go)、[solver.go](../cmd/wink/cmd/solver.go)：没有顶层 `wink pair` 别名。任务书中的短写必须补 `solver`。 |
| `wink solver direct stage --request-file <RESPONDER_REQUEST>` | [stage.go](../internal/v2/gatecstage/stage.go)：仅预置一个 responder slot；不是签发、burn 或建立连接。 |
| `wink gate-c1c run --instance <CANONICAL_INSTANCE>` | [field CLI](../cmd/wink/cmd/gate_c1c_fieldc1c.go)：仅显式 field 入口；不能附 `--config`、`--state`、`--verbose`。 |
| `c1crouter run --instance <CANONICAL_INSTANCE>` / `teardown --instance <CANONICAL_INSTANCE>` | [command_linux.go](../internal/c1crouter/command_linux.go)：参数形状精确，不能调用内部 `owned-worker`。 |
| 配置使用产品 YAML 结构，但 field 入口严格读已校验原字节 | [field_entry_linux.go](../internal/v2/gatecorchestrator/field_entry_linux.go) 的 `loadFieldConfiguration` 使用 defaults + KnownFields，不调用带环境覆盖的 `config.Load`。不以环境变量补字段。 |
| 固定 wrapper 与 wink 是同一个已审查 field binary 的独立副本 | [wrapper](../internal/v2/sshchildwrapper/wrapper.go)、[field exec](../internal/v2/sshchildwrapper/exec_fieldc1c_linux.go)：wrapper exec 固定 child，不增加 shell/child 或可选命令。 |

单个实例 = 一个场景 = 一个 credential = 一次前台 invocation。所有生成都用产品命令；
禁止 `fieldC1cFixture`、`gateC1bFixture`、合成 PSK/machine-id、测试时间窗或故障 hook 进入现场。
下面出现的固定系统路径与 UID 0 是协议要求，不是披露具体部署身份。

## 2. 目录、持久身份与复核可见性

以下是任务书要求的**逻辑布局及当前可实现性核对**，不是已经创建的目录。
所有目录由 UID 0 拥有、通常 0700；普通私有文件 0600；受审可执行副本 0700。
父链不得可被其他用户写入；拒绝 symlink、hardlink 和现有目标覆盖。

```text
/root/.winkyou-field/
  c1c/
    <ATTEMPT_ID>.json
    bin/                                      # 已复核产物，不重建
    material/<ATTEMPT_ID>/                     # PSK / SSH / WG / requests / configs
    endpoints/<ROLE>/                         # 跨实例，不按 attempt 新建身份
      machine-id
      var-lib/winkyou-safety-v2/
      home/
        .ssh/authorized_keys                  # 仅 responder，固定 key options
        .winkyou-field/c1c/<ATTEMPT_ID>.json
        .winkyou-field/c1c/evidence/<ATTEMPT_ID>/endpoint.jsonl
      run/                                    # 私有 sshd/netns runtime
      install/winkyou/{wink,gate-c-child-wrapper}
      shadow
    evidence/<ATTEMPT_ID>/
      endpoint-initiator/
      endpoint-responder/
      router/
      review/
    review/                                   # 工作稿，不在读取器白名单
  log/
```

| 路径（以上固定根的相对路径） | owner / mode | 生命周期 | 当前第二人读取器可见 | 内容敏感性 |
| --- | --- | --- | --- | --- |
| `c1c/<ATTEMPT_ID>.json` | 0 / 0600 | 永久保留签发原件 | 是 | 无 PSK，但有身份/地址/路径，仍私有 |
| `c1c/bin/` | 0 / 0700 | 固定受审产物 | 否 | 二进制；只发布摘要 |
| `c1c/material/<ATTEMPT_ID>/` | 0 / 0700，文件 0600 | 单 credential，失效也不复用 | 否，显式排除 | PSK、私钥、配置、request，绝不复制进公开或复核文本输出 |
| `c1c/endpoints/<ROLE>/machine-id` | 0 / 0600 | **角色持久**，只初始化一次 | 否 | 私有 scope 原料 |
| `c1c/endpoints/<ROLE>/var-lib/` | 外层 0 / 0700 | **角色持久**，ledger/slot/circuit 不重置 | 否 | 记账和材料引用；内部文件权限由产品 setup 管理，不递归 chmod |
| `c1c/endpoints/<ROLE>` 下的 `home` | 0 / 0700 | **角色持久** | 否 | 实例、pin/公钥及证据；不得放 PSK/私钥到将被复核读取的目录 |
| `c1c/endpoints/<ROLE>/run/` | 0 / 0700 | 角色 runtime，清理须逐项核验 | 否 | namespace/进程信息 |
| `c1c/endpoints/<ROLE>/install/` | 0 / 0700 | 固定构建独立副本 | 否 | 不接管宿主安装；两个文件 hash 相同 |
| `c1c/endpoints/<ROLE>/shadow` | 0 / 0600 | 角色私有 | 否 | 禁密码的本地 account 状态；不复制宿主 shadow |
| `c1c/evidence/<ATTEMPT_ID>/**` | 0 / 0700，文件 0600 | 永久留证 | 是 | 私有 raw witness，不能含 PSK/私钥 |
| `c1c/review/` | 0 / 0700 | 工作稿 | 否 | 最终无秘密 checklist 应位于上行 `review/` |
| `log/**` | 0 / 0700，文件 0600 | 首次失败与后续证据分存 | 是 | 输出本身不可公开 |

**U1 未决：这份逻辑布局尚不能同时满足“真实 home/ledger 位于 evidence 可读树”要求。**
[读取器](../scripts/c1c-review-evidence.sh) 只遍历 `c1c/*.json`、`c1c/evidence/**`、`log/**`，
不会进入 `c1c/endpoints`；endpoint 写入证据的物理目录又位于私有 home 内。
把汇总复制到 `evidence/` 只得到副本，不等于第二人读到了原 home/ledger。
symlink 被跳过，hardlink 被拒绝，不能拿别名绕过。把整个 home 搬入可读树也不能自动认为安全：
排除项是固定根下 `c1c/material`，**不递归排除任意嵌套的 material/私钥文件**。

后续须复审选择真实落盘布局或收窄读取器授权，并证明原件可读、秘密不可读、跨实例身份不变；
本 PR 不修改读取器，不给出伪称满足要求的挂载命令。

### 2.1 mount namespace 契约

每个 endpoint 都有自己的 mount namespace，不能只用 `ip netns exec` 冒充 machine 隔离。
[已有隔离证明](../test/natlab/gate_c1b_process_linux_test.go) 的挂载关系为：

| 私有源 | endpoint 内目标 | 必须保持的不变量 |
| --- | --- | --- |
| `<ROLE>/var-lib` | `/var/lib` | canonical ledger 仍为 `/var/lib/winkyou-safety-v2`；两角色物理源不同 |
| `<ROLE>/install` | `/usr/libexec` | 固定 wrapper/wink、同 SHA；不改宿主安装 |
| `<ROLE>/home` | `/root` | child 不依赖 HOME，按本地 passwd 的唯一 UID 0 home 定位 |
| `<ROLE>/shadow` | `/etc/shadow` | 仅私有 account view；宿主密码/账号不变 |
| `<ROLE>/run` | `/run` | 私有 sshd runtime；重新绑定外层的 `/run/netns` 注册表 |
| `<ROLE>/machine-id` | `/etc/machine-id` | 两角色独立，跨实例保留；router scope 另算，不替换宿主 machine-id |

先 `mount --make-rprivate /`。覆盖 `/run` 前必须持有注册表引用；覆盖 `/root` 后不能继续
假设原物理 `<ROLE>/...` 路径仍可见。request/config/material/三个实例副本的实际路径必须按各
mount view 分别核验。**U2 未决：现有实现只在 test helper 里组合这些挂载；尚无可直接调用的
受审现场 launcher。** 不把测试二进制的 host-process 入口用作现场 launcher。

只在首次另行批准的端点初始化中运行产品 `setup-machine-scope`（可创建 namespace/ledger），
后续每实例只用 `--check`。machine-id/var-lib/home 永不按场景删除重建；销毁前封存，不能换
scope 绕过 hard-16K 一次/24h、失败 circuit 或其他 admission 限制。

## 3. 每实例操作规程：runbook 步 4–12

下列 shell 片段是**未来执行模板**。前置条件未满足或出现 `<UNRESOLVED_...>` 就停止，不尝试
替换成猜测的命令；Stage I 不执行。执行者和独立复核者分别留私有原始输出与退出码。

### 3.1 步 4：外层隔离、anchors、SSH 配置与 before 快照

执行者先经独立管理链路只读核查：没有同批次文件、进程、注册表项或旧实例占用；已有证据不
覆盖。不在此写真实登录值。管理 SSH 的模板是：

```sh
ssh -o ConnectTimeout=75 -o ConnectionAttempts=1 -l <MANAGEMENT_USER> <MANAGEMENT_DESTINATION> <APPROVED_READONLY_COMMAND>
```

这里只增加**管理投递**的建连等待，不改变产品 SSH 的 3s、单连接、0 retry 或预算。
第一连接失败单独留存，不记作已开始/已失败的 field 实例，不自动重投同一批次。
前检的完整文件/进程清单依赖 U1/U2，未决前不能以一次 `pgrep` 的空输出代替。

第二人从固定安装的 [snapshot 脚本](../scripts/c1c-review-snapshot.sh) 取 before：

```sh
sudo -- <FIXED_SNAPSHOT_SCRIPT>
```

脚本不接受参数，输出重定向至新建 0600 私有文件；由独立第二人保存，不落 CI/终端共享日志。
确认 `ok=true`、`nonvolatile` 恰好 10 项。它主动进入 init net/mount 读取，不会误取私有 netns。

仅在后续授权的独占外层会话中：

```sh
sudo unshare --net --mount --fork /bin/bash --noprofile --norc
mount --make-rprivate /
mount --bind <NEW_PRIVATE_NETNS_REGISTRY> /var/run/netns
ip link set lo up
readlink /proc/self/ns/net
readlink /proc/1/ns/net
readlink /proc/self/ns/mnt
readlink /proc/1/ns/mnt
findmnt -n -o PROPAGATION /
findmnt --mountpoint /var/run/netns
ip netns add <INITIATOR_ANCHOR>
ip netns add <TRANSIT_ANCHOR>
ip netns add <RESPONDER_ANCHOR>
ip netns exec <INITIATOR_ANCHOR> ip link set lo up
ip netns exec <TRANSIT_ANCHOR> ip link set lo up
ip netns exec <RESPONDER_ANCHOR> ip link set lo up
stat -Lc '%i' /var/run/netns/<INITIATOR_ANCHOR>
stat -Lc '%i' /var/run/netns/<TRANSIT_ANCHOR>
stat -Lc '%i' /var/run/netns/<RESPONDER_ANCHOR>
```

执行前确认三个名称不存在。三个 anchor 记录 name/inode，唯一且不等于 init；只允许 `lo`。
不在宿主补建 `/var/run/netns`：该 mountpoint 缺失也停下。第二人核对前后 namespace inode、
private propagation、registry 挂载与三个 `ip -j link show`；地址/进程输出只留私有记录。
失败时仅按已记录 inode/PID 回收本次创建项，退出外层后重取 snapshot，不 flush 主机状态。

**U3 未决（顺序）**：anchor 名称要求来自 instance 摘要，但 instance_id 来自步 6 的产品生成，
签发 JSON 又要写入 anchor inode。因此不能在步 4 预知最终摘要。应由复审冻结分步准备顺序及
名称投影，不能拿临时 attempt 或重新生成 credential 解环。router 自己的两个 NAT 名字是
`wycr` + SHA256(`winkyou-c1c-router-owned/1\n` + instance_id) 前 6 字节的小写 hex + `a/b`，
**不是**三个 anchor 的命名算法；不能混用。

responder 私有 `sshd_config` 全文模板（来源为既有 `runGateC1bPrivateSSHD` 配置）：

```text
Port <SSH_PORT>
ListenAddress <RESPONDER_ENDPOINT_ADDRESS>
HostKey <PRIVATE_PER_INSTANCE_HOST_KEY>
AuthorizedKeysFile /root/.ssh/authorized_keys
PidFile none
PermitRootLogin forced-commands-only
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitUserEnvironment no
DisableForwarding yes
PermitTTY no
PermitUserRC no
UsePAM no
UseDNS no
PrintMotd no
PrintLastLog no
LogLevel VERBOSE
LoginGraceTime 3
MaxSessions 1
AllowUsers root
```

authorized_keys 仅一条，options 精确为：

```text
restrict,command="/usr/libexec/winkyou/gate-c-child-wrapper" <KEY_TYPE> <PUBLIC_KEY_BLOB>
```

公钥内容与 pin 不填入本文。HostKey 每实例重新生成，专用 client key 只用于 fixed command；
不用宿主个人 key/agent，known_hosts 由独立离线核验的 host public key 填写，禁止 accept-new。
后续经授权的离线 key 命令可以用 `ssh-keygen -q -t ed25519 -N '' -f <NEW_PRIVATE_KEY>`；
目录必须新建、owner-only、无链接，禁止默认交互覆盖。Stage II 的一次性 SSH key 不等于
配对材料授权，不生成 PSK、WG key 或 artifact。

配置只读解析与将来前台启动命令（必须在 **responder net + 私有 mount view** 内）：

```sh
<VERIFIED_SSHD_BINARY> -T -f <PRIVATE_SSHD_CONFIG> -C user=root,addr=<SOURCE_ADDRESS_SEEN_BY_SSHD>
<VERIFIED_SSHD_BINARY> -D -e -f <PRIVATE_SSHD_CONFIG>
ss -H -ltn 'sport = :<SSH_PORT>'
```

`-T` 的原始输出须交给
[`ValidateRootSSHDResolvedConfig`](../internal/v2/sshchildwrapper/root_profile.go)，不能仅 grep
一行就宣称 PASS。**U4 未决：该函数目前没有独立产品 CLI；不杜撰 `wink validate-sshd`，也不
为验证配置而启动 child/端点。** sshd stderr 含私有元数据，只进私有受控日志。

**U3 同时阻断 sshd 的实际启动顺序**：[router preflight](../internal/c1crouter/topology_linux.go)
要求 anchor 只有 lo，端点地址要等步 8 router 建 veth 后才存在。不得为了步 4 的排列提前手动
配置接口或打开 freebind。拟定“步 4 只解析配置；双签后 router ready → sshd ready → initiator”
须复审接受。peer-absent 场景则不启动 sshd。只停止本次私有 sshd，绝不停止管理 sshd。

### 3.2 步 5：只读安全、ledger 与冲突前检

下列命令必须在**各角色最终私有 mount/net view** 运行，不得在共享主机 scope 上代跑：

```sh
/usr/libexec/winkyou/wink setup-machine-scope --check --json
/usr/libexec/winkyou/wink safety status --json
/usr/libexec/winkyou/wink diagnose --json
test ! -e /var/lib/winkyou-safety-v2/gate-c-responder-pending-v1.json
test ! -e /var/lib/winkyou-safety-v2/gate-c-responder-claimed-v1.json
ip -j link show
ip -j address show
ip -j route show
ss -H -nup
ss -H -ntp
```

不得附 diagnose 的 active-STUN/map/allocation 参数。检查 namespace ready、trip clear、owner
无占用、无 slot/旧进程、无目标 TUN/路由冲突；读取失败为 unknown，不能因输出空就填零。
只读命令不能代替后续产品原子检查。

**U5 未决**：上述 CLI 不提供完整 pairing/campaign ledger status、admission/circuit/未完成
BURN 的只读报告。[`InspectMachinePairingLedger`](../internal/governor/pairing_ledger_format.go)
是 Go API，不是 shell 命令。`diagnose` 的 machine/safety 快照不能冒充账本报告，
`setup-machine-scope --check` 也不能证明本次 admission 被允许。需单独复审只读工具及首次
持久 scope 初始化步骤；本 PR 不新增 helper、不打开 stdio 来取得并写入 owner 状态。
任何 stale slot 先停，不能把 `solver direct cleanup` 当自动 preflight 修复。

第二人核对同一 scope 的原件/只读报告（受 U1/U5 阻断）与对象身份。失败只保留证据并终止
本实例准备，不清 trip、不删 ledger、不放宽限制、不接管已有 TUN/进程。

### 3.3 步 6：离线材料、requests、configs、实例与双签

**以下材料链仅供 Stage III 获准后使用。** 步 5 全通过且对应 §9 未决关闭后才生成一次。
首批低成本路径拟使用 predictive；不因此给尚无 scenario 编码的负面场景假签发。

```sh
<EXACT_FIELD_WINK> solver pair oob --profile predictive --out-dir <NEW_PRIVATE_PAIR_DIRECTORY>
```

准确输出为 `initiator.artifact.json`、`responder.artifact.json`、`manifest.json`。
[`GenerateOOB`](../internal/v2/pairgen/generate_oob.go) 负责随机五 ID/PSK、10 分钟原始有效期、
0700/0600、排他写与 manifest 最后提交；不会打印 secret 或自动续期。
从 manifest 私下读取 attempt_id 后，才知道 `instance_id`；不能先猜名字再要求生成器使用。
新材料目录先用本次获批的空目录名，如何归档到 `material/<ATTEMPT_ID>` 的 no-replace 步骤随
U3 冻结。目录不存在/部分写入/到期即停止，不能生成第二套补救同一实例。
asymmetric 的两个 mapping-set 命令和 hard-16k 不属于本轮执行。

两份 request 全文模板，字段严格来自
[request.go](../internal/v2/gatecrequest/request.go)，上限 16 KiB；observer 同族双地址双端口。
路径按**运行进程所见**填写，不能把宿主物理路径误当 endpoint 内路径。peer_ref 是 trusted
config 的精确本地引用，不是公网身份或远端报告。

initiator：

```json
{
  "schema": "winkyou-gate-c-local-request/1",
  "role": "initiator",
  "artifact_file": "<PRIVATE_INITIATOR_ARTIFACT_ABSOLUTE_PATH>",
  "peer_ref": "<RESPONDER_LOCAL_REFERENCE>",
  "expected_peer_public_address": "<RESPONDER_NAT_ADDRESS>",
  "observer_set": {
    "primary": "<OBSERVER_A_P1>",
    "alternate_port": "<OBSERVER_A_P2>",
    "alternate_address": "<OBSERVER_B_P1>",
    "alternate_address_port": "<OBSERVER_B_P2>"
  },
  "ssh": {
    "endpoint": "<RESPONDER_NAT_ADDRESS_PORT>",
    "user": "<DEDICATED_UID_ZERO_LOGIN>",
    "identity_file": "<PRIVATE_CLIENT_KEY_ABSOLUTE_PATH>",
    "known_hosts_file": "<PRIVATE_PIN_FILE_ABSOLUTE_PATH>"
  }
}
```

responder（**不带 ssh object**，不是复制 initiator 后只改 role）：

```json
{
  "schema": "winkyou-gate-c-local-request/1",
  "role": "responder",
  "artifact_file": "<PRIVATE_RESPONDER_ARTIFACT_ABSOLUTE_PATH>",
  "peer_ref": "<INITIATOR_LOCAL_REFERENCE>",
  "expected_peer_public_address": "<INITIATOR_NAT_ADDRESS>",
  "observer_set": {
    "primary": "<OBSERVER_A_P1>",
    "alternate_port": "<OBSERVER_A_P2>",
    "alternate_address": "<OBSERVER_B_P1>",
    "alternate_address_port": "<OBSERVER_B_P2>"
  }
}
```

两份 YAML 是产品字段的**完整最小文件模板**，未列字段保持受审构建 defaults；绝不是完整
默认配置的重新冻结。缺少具体密钥/地址/ceiling 时不能加载。`memory_*` 是现有 trusted
字段名，field 入口仍创建受控真实 TUN，不是改用 memory-TUN。

initiator config：

```yaml
node:
  name: "<INITIATOR_PRIVATE_LABEL>"
coordinator:
  url: ""
wireguard:
  private_key: "<INITIATOR_PRIVATE_WG_KEY>"
nat:
  stun_servers: []
  turn_servers: []
  auto_public_endpoint_hints: false
autonomous_mesh:
  enabled: false
gate_c:
  peers:
    - ref: "<RESPONDER_LOCAL_REFERENCE>"
      public_key: "<RESPONDER_WG_PUBLIC_KEY>"
      allowed_ips: ["<RESPONDER_VIRTUAL_IPV4>/32"]
      local_virtual_ip: "<INITIATOR_VIRTUAL_IPV4>"
      peer_virtual_ip: "<RESPONDER_VIRTUAL_IPV4>"
      memory_interface_name: "<INITIATOR_TUN_NAME>"
      memory_mtu: 1280
      session_ceiling: "<SIGNED_ABSOLUTE_CEILING>"
      session_liveness:
        mode: challenge_v1
        missed_rounds: null
```

responder config：

```yaml
node:
  name: "<RESPONDER_PRIVATE_LABEL>"
coordinator:
  url: ""
wireguard:
  private_key: "<RESPONDER_PRIVATE_WG_KEY>"
nat:
  stun_servers: []
  turn_servers: []
  auto_public_endpoint_hints: false
autonomous_mesh:
  enabled: false
gate_c:
  peers:
    - ref: "<INITIATOR_LOCAL_REFERENCE>"
      public_key: "<INITIATOR_WG_PUBLIC_KEY>"
      allowed_ips: ["<INITIATOR_VIRTUAL_IPV4>/32"]
      local_virtual_ip: "<RESPONDER_VIRTUAL_IPV4>"
      peer_virtual_ip: "<INITIATOR_VIRTUAL_IPV4>"
      memory_interface_name: "<RESPONDER_TUN_NAME>"
      memory_mtu: 1280
      session_ceiling: "<SIGNED_ABSOLUTE_CEILING>"
      session_liveness:
        mode: challenge_v1
        missed_rounds: null
```

K=20s、R=5s 为实现常量，不能在 YAML 添加 K/R 字段。M 只能是整数 2 或 3，对应 L=45/65s；
本规程要求两侧 M 与 ceiling 相同，且与实例相符。**U6 未决：本轮具体 M/ceiling 尚无签发值**。
解析器接受 ceiling 5s–24h 是校验范围，不是本轮授权；A3 fixture 的 60s 是证明配置，不自动
成为现场常量。不延长任何 candidate/active/2s drain/3 datagram/3s challenge。

WG key 是另一组材料，不是 OOB PSK。已有 `wink genkey --json` 会输出私钥，因此未来只能在
关闭 shell tracing、owner-only 新文件和不覆盖重定向下分别执行，绝不直接回显：

```sh
umask 077
set -C
<EXACT_FIELD_WINK> genkey --json > <NEW_PRIVATE_WG_KEY_FILE>
```

两角色各一次、交换公钥后人工填写 YAML；同一个 command 不循环重试。不能从测试 fixture
取 key，不能把 WG private key 写进 authorization JSON。三份实例原件不得包含 secret。

responder 在最终私有 scope 内离线预置：

```sh
/usr/libexec/winkyou/wink solver direct stage --request-file <RESPONDER_REQUEST_ABSOLUTE_PATH>
```

只能出现 `oob_stage_created`。pending 位于 canonical governor namespace，child 一次
`ClaimPending` 后留下 claimed tombstone；失败不会自动 re-arm。只在终局证据封存后，另经
复核可使用 `wink solver direct cleanup --manifest-file <MATCHED_MANIFEST>` 清除**指纹精确匹配
的 staging slot**；它不是删除 BURN/FINISH，也不是同 credential 再用许可。

实例全文与逐字段来源见 §4。签发前端点配置原字节、请求、manifest、构建和 scope 全部核对。
三角色使用同一不可变 `/2` JSON 的独立副本；endpoint 内固定路径来自 UID 0 的 home，router
原件来自外层 home。对三个**物理副本**执行：

```sh
sha256sum <ROUTER_COPY> <INITIATOR_COPY> <RESPONDER_COPY>
```

三个摘要必须一致；各 mount view 再读核对，不用软/硬链接共享实例。
正式填完后都必须 0600、无 BOM、单 UTF-8 object、无重复/未知字段、至多 65536 字节。

执行者把实例的**人工脱敏视图**私下交维护者和评审：隐藏地址/路径/machine ID/身份，保留
哈希、profile、预算、窗口及检查结论；脱敏视图不是可加载实例，不覆盖原件。维护者回复：

```text
签发 <SCENARIO> <ATTEMPT_FIRST_8>
```

原话、时间和关联原件 hash 写入私有 checklist 的维护者栏。独立评审核对原件后**自行**填
评审栏。禁止代填、从一般“授权继续”推导签发、把身份确认当复核通过。
未双签不得执行步 7 及以后；阶段失败或材料过期后停止，不在原实例自动换材料/延长窗口。

### 3.4 步 7：kill switch 与采集就绪

先验证独立管理通道还在，留本次外层 session/角色 mount namespace 的身份。
新进程的 PID 在启动前并不存在：本步只能准备采集表和核验动作，**实际 PID/starttime 必须
在步 8 每个进程启动后立即补记**，不是修改签发原件。router 的 guardian/worker 原始身份
另见 `ownership.json`。U2 关闭前不能假设 shell `$!` 一定是最终 owned controller。

只读提取 `/proc/<PID>/stat` 第 22 字段的命令（comm 可能含空格/括号，不使用简单 awk）：

```sh
python3 -I -B -c 'import pathlib,sys; s=pathlib.Path("/proc",sys.argv[1],"stat").read_text(); print(s[s.rfind(")")+2:].split()[19])' <EXACT_PID>
readlink /proc/<EXACT_PID>/ns/net
readlink /proc/<EXACT_PID>/ns/mnt
readlink /proc/<EXACT_PID>/exe
```

第二人核对 PID/starttime/executable/namespace 与已登记本次对象，不按名称杀进程。
停止动作模板 `kill -TERM -- <EXACT_OWNED_PID>` 仅在身份复核后执行；PID 复用或归属不明即
停止，不升级为 `pkill`。shell“检查后 kill”并非原子 pidfd 保证，现场 supervisor/停止工具的
精确调用随 U2 复审；不能冒充 [router 的 pidfd 身份保护](../internal/c1crouter/command_linux.go)。

验证原 **2s I/O drain**、packet 不再增长、owned socket/child/lock 排空。router 随后的 OS
cleanup 另有现存 **20s** `cleanupTimeout`；它不是把 2s 延长到 20s，也不能用 cleanup 成功
掩盖 drain 失败。任何 unknown 保持 RED，走事前签发的 containment 或停止求助。

### 3.5 步 8：唯一一次前台运行

在已登记外层非 init net/mount session 前台执行 router；不要守护化，不新增 service。

```sh
<EXACT_C1CROUTER> run --instance <ROUTER_CANONICAL_INSTANCE>
```

独立管理观察者在私有 evidence 下读取新建
`evidence/<ATTEMPT_ID>/router/ready.json`，内容须为 `{"stage":"router_ready"}`，同时核对
guardian/worker 仍是登记的启动身份、窗口未到期。不能复用旧 ready 文件，不能建立额外
TCP 连接探测就绪。router 会自行创建两 NAT netns 和四 veth；不手动重复配置。

U3 裁决后在 responder mount/net view 前台运行私有 sshd（peer-absent 除外），用 `ss` 被动
验证监听；SSH literal endpoint 是 responder NAT 地址与签发端口，非 responder 内网地址。
固定 TCP DNAT 由 router 建立，不改宿主 firewall。

initiator 的**最后一跳**命令已知；省略部分 U2 仍未决，故下面不是现在可运行的完整命令：

```text
ip netns exec <INITIATOR_ANCHOR> <UNRESOLVED_REVIEWED_PRIVATE_MOUNT_LAUNCHER> /usr/libexec/winkyou/wink gate-c1c run --instance <INITIATOR_CANONICAL_INSTANCE>
```

禁止删掉 launcher 占位符直接运行。responder 不另启一次 `run`，由唯一 SSH child 从 pending
slot 领取请求。field stdout 只有 profile/stage/class/duration_ns/counts/evidence_sha256；
progress 与详细 witness 在私有 endpoint.jsonl。对 stdout 不作“有输出即成功”的判断。
任一前置失败不允许第二 invocation、切 profile、fallback 或调整窗口。

### 3.6 步 9–10：终局、drain、teardown 与 after 快照

严格保留双端独立 terminal，顺序为：initiator 终局并核验 endpoint 排水 → 对本次 router
guardian 发 TERM → 等待并保留 guardian 原终局 → router `teardown` → 本次私有 sshd TERM →
确认无 child → 删除空 anchors → 退出各私有 mount/外层 session → after snapshot。
kill switch 故障路径也必须收集同样 witness，不提前 Fatal 掩盖残留。

```sh
<EXACT_C1CROUTER> teardown --instance <ROUTER_CANONICAL_INSTANCE>
ip netns pids <INITIATOR_ANCHOR>
ip netns pids <TRANSIT_ANCHOR>
ip netns pids <RESPONDER_ANCHOR>
ip netns del <INITIATOR_ANCHOR>
ip netns del <TRANSIT_ANCHOR>
ip netns del <RESPONDER_ANCHOR>
```

删除前由第二人核验 inode 仍相同、三次 pids 为空、原 router 残留门全过；上面不是无条件
连跑脚本。清理工具只删除 router 自己的 NAT/veth/nft/flow；外层 anchors 归操作者，不用
`ip netns del` 消失的名称冒充“没有持有 namespace fd 的进程”。
teardown 必须仍用原签发 JSON；其 cleanup-only 校验允许过窗口后清理，不延长发射 authority。

| 层 | 必需核对命令/来源 | 判定 |
| --- | --- | --- |
| packet/I/O | 原 router.jsonl/endpoint.jsonl 与已签发被动 packet witness | 2s drain 后计数稳定，无额外探测包；详细分账见 §6 |
| socket | 仍存活的 owned netns 内 `ss -H -nup` / `ss -H -ntp`；router summary | router `socket_residue=0`；endpoint 外部 witness 独立，unknown 不补 0 |
| process/child | 已登记 PID/starttime、`ip netns pids <OWNED_NS>`、parent Wait 见证 | exact child 已回收，无持有旧 mount/net namespace 的 survivor |
| conntrack | owned NAT 内 `conntrack -L -p udp`、清理报告 | 查询成功且 owned flow 为 0；不要求宿主业务连接清零，不全局 flush |
| netns/veth/nft | router `namespace_residue`/`veth_residue`/`nft_residue`，anchors 的 `ip -j link show` / `nft -j list ruleset` | router 六项 residue 全部数值 0，after anchors 只有 lo，清理外层后 registry 无本次项 |
| ledger/lease/WG/interface | 双端 FINISH/circuit、TransportLease/field WG witness、`ip -j address show` / `ip -j route show`、只读 scope 复检 | FINISH-before-release、probe/session drains 完成、owned TUN/address/route 消失；持久 BURN 不退款 |

`terminal-resolution.json` 的原 class/rule 保留；正常主动停止 router 可以是 `cancelled`，
teardown success 仅说明 cleanup，不把前一个业务失败改写成 success。
第二人再次运行固定 snapshot（无参数）。两个私有 JSON 可在复核端用如下只读比较：

```sh
python3 -I -B -c 'import json,sys; a,b=[json.load(open(p)) for p in sys.argv[1:]]; assert a["ok"] and b["ok"]; assert a["schema"]==b["schema"]=="winkyou-c1c-review-snapshot/1"; assert len(a["nonvolatile"])==len(b["nonvolatile"])==10; assert a["nonvolatile"]==b["nonvolatile"]; print("nonvolatile_equal=1 categories=10")' <BEFORE_JSON> <AFTER_JSON>
```

不额外剔除动态项，不把 compare 的异常视为相等。host nonvolatile diff 不为空就不能记
“完好退出”；现场终局失败或读数未知仍保留首次证据。

### 3.7 步 11–12：持久封存与第二人关窗

本轮不销毁共享主机/VM，不卸载管理链路，不删除端点 machine-id/ledger/home。替代验收为
**持久目录静止后封存哈希 + 宿主 10 项 nonvolatile 相同 + owned residue 全部核对**。
机器身份、journal、circuit、claims/失效实例记录跨实例保留；不能用“封存了副本”作为删账本
或创建新 scope 的理由。封存的精确原件布局仍受 U1/U2 阻断，当前不虚构归档命令。

独立第二人执行固定、无参数脚本：

```sh
sudo -- <FIXED_EVIDENCE_SCRIPT>
sudo -- <FIXED_SNAPSHOT_SCRIPT>
```

读取器仅对非移动文件给 size/mode/uid/SHA-256，指定文本后缀 ≤4 MiB 时附内容；输出也只私下
保存。真实文件不可读不是零残留。第二人逐一填 teardown/terminal/ledger/管理通道/隐私栏并
签字；实际结果另写 evidence checklist，**不补写签发原件内原来为 null 的 post-run 字段**。
公开只能发 §6 的白名单摘要。任一门未满足，本实例保持 RED/unknown，不能靠下一实例覆盖。

## 4. `/2` 全字段模板与派生值

来源为 [88 字段目录](./templates/gate-c1c-authorization.template.json) +
[router 扩展](./templates/gate-c1c-router-v2.template.json)，由两人手工填写；不直接复制
字段目录外壳的 `fields/type/value`。下方恰好 **89 个顶层字段**，仍是不可加载的占位模板。
`<D_...>` 为只读派生，`<H_...>` 为两人填写/核验；其余明确固定值。
`null` 的含义按后表分类，不能一概保留或一概替换。示例仅展示 predictive 形状，不签发场景。

```json
{
  "instance_id": "<D_ATTEMPT_ID_FROM_MANIFEST>",
  "scenario": "<H_REVIEWED_SCENARIO>",
  "operator": "<H_OPERATOR>",
  "independent_reviewer": "<H_REVIEWER>",
  "operator_signature": "<H_OPERATOR_SIGNATURE>",
  "reviewer_signature": "<H_REVIEWER_SIGNATURE>",
  "signed_at": "<H_SIGNED_AT_UTC>",
  "not_before": "<H_WINDOW_START_UTC>",
  "not_after": "<H_WINDOW_END_UTC>",
  "layout": "disposable-endpoints-and-router/1",
  "implementation_review": "<H_ACCEPTED_IMPLEMENTATION_REFERENCE>",
  "build_authorization": "<H_A3_BUILD_REFERENCE>",
  "run_authorization": "<H_THIS_INSTANCE_AUTHORIZATION>",
  "exact_sha": "<D_REVIEWED_BINARY_FULL_VCS_SHA>",
  "initiator_binary_sha256": "<D_FIELD_BINARY_SHA256>",
  "responder_binary_sha256": "<D_FIELD_BINARY_SHA256>",
  "router_binary_sha256": "<D_ROUTER_BINARY_SHA256>",
  "build_tags": ["fieldc1c"],
  "toolchain": "<D_BINARY_GO_VERSION>",
  "ordinary_build_no_field_symbols_evidence": "<H_A3_ORDINARY_NM_REFERENCE>",
  "authority_schema_revision": "winkyou-gate-c1c-authorization/2",
  "dependency_and_configuration_sha256": "<D_ENDPOINT_DEPENDENCY_CONFIG_SHA256>",
  "profile": "predictive_edm/1",
  "resource_class": "predictive_32/1",
  "initiator_role": "initiator",
  "responder_role": "responder",
  "mapping_set_role": null,
  "credential_reference": "<H_PRIVATE_MANIFEST_DIRECTORY_ABSOLUTE_PATH>",
  "manifest_sha256": "<D_MANIFEST_FILE_SHA256>",
  "credential_expires_at": "<D_MANIFEST_EXPIRES_AT_UTC>",
  "unused_credential_verified": null,
  "single_invocation_verified": null,
  "exact_cost_reference": "gate-c/predictive_32/1",
  "session_liveness_mode": "challenge_v1",
  "initiator_missed_rounds": null,
  "responder_missed_rounds": null,
  "absolute_session_ceiling": "<H_SIGNED_ABSOLUTE_CEILING>",
  "devices": [
    {"role":"initiator","os":"linux","request_reference":"<H_INITIATOR_REQUEST_ABSOLUTE_PATH>","configuration_reference":"<H_INITIATOR_CONFIG_ABSOLUTE_PATH>","configuration_sha256":"<D_INITIATOR_CONFIG_SHA256>","management_reference":"<H_INDEPENDENT_MANAGEMENT_REFERENCE>"},
    {"role":"responder","os":"linux","request_reference":"<H_RESPONDER_REQUEST_ABSOLUTE_PATH>","configuration_reference":"<H_RESPONDER_CONFIG_ABSOLUTE_PATH>","configuration_sha256":"<D_RESPONDER_CONFIG_SHA256>","management_reference":"<H_INDEPENDENT_MANAGEMENT_REFERENCE>"}
  ],
  "router_resource_inventory": [
    {"role":"router","reference":"<H_ROUTER_INVENTORY>","teardown_reference":"<H_ROUTER_TEARDOWN_PLAN>"}
  ],
  "endpoint_resource_inventory": [
    {"role":"initiator","reference":"<H_INITIATOR_INVENTORY>","teardown_reference":"<H_INITIATOR_TEARDOWN_PLAN>"},
    {"role":"responder","reference":"<H_RESPONDER_INVENTORY>","teardown_reference":"<H_RESPONDER_TEARDOWN_PLAN>"}
  ],
  "kernel_minimum_review": "<H_A1_A3_ACTUAL_KERNEL_REVIEW>",
  "tun_and_conntrack_capability_evidence": "<H_A3_CAPABILITY_REFERENCE>",
  "namespace_and_global_ceiling_authority": "<H_NON_INIT_ISOLATION_NO_HOST_CEILING_WRITES>",
  "supplier_network_permission": "<H_SHARED_HOST_ISOLATED_MODEL_PERMISSION>",
  "initiator_machine_scope_reference": "<D_INITIATOR_PERSISTENT_MACHINE_SCOPE>",
  "responder_machine_scope_reference": "<D_RESPONDER_PERSISTENT_MACHINE_SCOPE>",
  "ledger_retention_and_restore_plan": "<H_PERSISTENT_LEDGER_ARCHIVE_PLAN>",
  "ledger_determinate_evidence": "<H_BOTH_LEDGER_READONLY_EVIDENCE>",
  "admission_and_campaign_circuit_evidence": "<H_BOTH_ADMISSION_CIRCUIT_EVIDENCE>",
  "safety_trip_clear_evidence": "<H_BOTH_TRIP_CLEAR_EVIDENCE>",
  "no_stale_process_task_slot_evidence": "<H_BOTH_OWNERSHIP_PREFLIGHT_EVIDENCE>",
  "initiator_expected_peer_address": "<H_RESPONDER_NAT_ADDRESS>",
  "responder_expected_peer_address": "<H_INITIATOR_NAT_ADDRESS>",
  "observer_topology": {
    "primary":"<H_OBSERVER_A_P1>","alternate_port":"<H_OBSERVER_A_P2>",
    "alternate_address":"<H_OBSERVER_B_P1>","alternate_address_port":"<H_OBSERVER_B_P2>"
  },
  "observer_operator_permission": "<H_OWNED_OBSERVER_PERMISSION>",
  "ssh_literal_endpoint": "<H_RESPONDER_NAT_ADDRESS_PORT>",
  "ssh_authority_reference": "<H_EXACT_SSH_AUTHORITY_REFERENCE>",
  "host_key_pin_reference": "<H_PRIVATE_PIN_ABSOLUTE_PATH>",
  "ssh_identity_reference": "<H_PRIVATE_CLIENT_KEY_ABSOLUTE_PATH>",
  "forced_command_profile_evidence": "<H_VALIDATED_SSHD_AND_KEY_OPTIONS_EVIDENCE>",
  "root_risk_accepted_by_operator": null,
  "root_risk_accepted_by_reviewer": null,
  "hardening_drop_privileges": {"status":"not_implemented","reason":"<H_REASON>","risk":"<H_ACCEPTED_ROOT_RISK>","evidence_reference":"<H_RISK_REVIEW>"},
  "hardening_syscall_filesystem_isolation": {"status":"not_implemented","reason":"<H_REASON>","risk":"<H_ACCEPTED_ROOT_RISK>","evidence_reference":"<H_RISK_REVIEW>"},
  "hardening_low_privilege_parser": {"status":"not_implemented","reason":"<H_REASON>","risk":"<H_ACCEPTED_ROOT_RISK>","evidence_reference":"<H_RISK_REVIEW>"},
  "interface_route_address_authority": {
    "initiator":{"interface":"<H_INITIATOR_TUN_NAME>","local_address":"<H_INITIATOR_VIRTUAL_IPV4>","peer_address":"<H_RESPONDER_VIRTUAL_IPV4>","mtu":1280},
    "responder":{"interface":"<H_RESPONDER_TUN_NAME>","local_address":"<H_RESPONDER_VIRTUAL_IPV4>","peer_address":"<H_INITIATOR_VIRTUAL_IPV4>","mtu":1280}
  },
  "separate_host_configuration_authorization": "<H_EXACT_PRIVATE_NET_MOUNT_ACTIONS_REFERENCE>",
  "preflight_negative_matrix_evidence": "<H_ACCEPTED_PRECEDING_GATES_REFERENCE>",
  "owned_stop_target_identity": {"kind":"owned-foreground-and-child/1","verification_reference":"<H_START_IDENTITY_CHECKLIST_REFERENCE>"},
  "kill_switch_command_reference": "<H_OWNED_STOP_PROCEDURE_REFERENCE>",
  "kill_switch_readiness_evidence": "<H_PRIOR_DRILL_AND_READINESS_EVIDENCE>",
  "independent_management_channel_reference": "<H_INDEPENDENT_MANAGEMENT_REFERENCE>",
  "containment_authorization": null,
  "expected_terminal_and_fault_stage": {"terminal":"<H_REVIEWED_EXPECTED_CLASS>","stage":"<H_REVIEWED_EXPECTED_STAGE>","injection_reference":"<H_REVIEWED_INJECTION_OR_NOMINAL_REFERENCE>"},
  "witness_plan": {
    "packet":"<H_PACKET_PLAN>","socket":"<H_SOCKET_PLAN>","process":"<H_PROCESS_PLAN>",
    "conntrack":"<H_CONNTRACK_PLAN>","child":"<H_CHILD_PLAN>","ledger":"<H_LEDGER_PLAN>",
    "transport_lease":"<H_LEASE_PLAN>","wireguard":"<H_WG_PLAN>","interface_route_address":"<H_OS_OBJECT_PLAN>"
  },
  "tuple_observations": null,
  "raw_evidence_references": null,
  "evidence_sha256": null,
  "terminal_result_by_role": null,
  "durable_finish_and_circuit_evidence": null,
  "owned_residue_by_layer": null,
  "ledger_sealed_before_destruction": null,
  "cloud_teardown_evidence": null,
  "independent_management_preserved": null,
  "redacted_summary_review": null,
  "authorization_closed_at": null,
  "teardown_operator_signature": null,
  "teardown_reviewer_signature": null,
  "router": {
    "schema": "winkyou-c1c-router/1",
    "machine_scope_reference": "<D_ROUTER_MACHINE_SCOPE>",
    "dependency_and_configuration_sha256": "<D_ROUTER_DEPENDENCY_CONFIG_SHA256>",
    "anchors": [
      {"role":"initiator","name":"<D_INITIATOR_ANCHOR_NAME>","inode":null},
      {"role":"transit","name":"<D_TRANSIT_ANCHOR_NAME>","inode":null},
      {"role":"responder","name":"<D_RESPONDER_ANCHOR_NAME>","inode":null}
    ],
    "domains": [
      {"role":"initiator","mode":"apdm_sequential/1","endpoint_prefix":"<H_INITIATOR_ENDPOINT_PREFIX>","gateway_prefix":"<H_INITIATOR_GATEWAY_PREFIX>","public_prefix":"<H_INITIATOR_PUBLIC_PREFIX>","transit_prefix":"<H_TRANSIT_A_PREFIX>"},
      {"role":"responder","mode":"apdm_sequential/1","endpoint_prefix":"<H_RESPONDER_ENDPOINT_PREFIX>","gateway_prefix":"<H_RESPONDER_GATEWAY_PREFIX>","public_prefix":"<H_RESPONDER_PUBLIC_PREFIX>","transit_prefix":"<H_TRANSIT_B_PREFIX>"}
    ],
    "allow_global_conntrack_ceiling": false,
    "disposable_environment_reference": "<H_SHARED_HOST_LAYOUT_DEVIATION_AND_ISOLATION_REVIEW>"
  }
}
```

### 4.1 逐字段分类与交叉核验

上面每个字段已用固定值或 D/H 前缀给出来源；复合对象逐叶同样标注。以下是不适合只靠
字符串前缀表达的所有补充规则：

| 字段 | 类别 / 必须核验的值 |
| --- | --- |
| `instance_id`、`credential_expires_at` | D：同一 product manifest；attempt 为 16 字节 canonical base64url，不自行 UUID 替代；expires 不延长 |
| `scenario`、`preflight_negative_matrix_evidence`、`expected_terminal_and_fault_stage` | H / **U7**：前置负面场景编码、第一例尚无现场前置结果的填法及 fault 触发均待裁决；不能写“已完成”占位 |
| `operator`、`independent_reviewer`、两个 signature、`signed_at/not_before/not_after` | H：不同的人，原始签发和复核；秒精度 RFC3339 UTC，signed ≤ before ≤ now < after，材料同时未过期 |
| `layout` | F：解析器仍要求 `disposable-endpoints-and-router/1`；实际共享主机偏离写进既有 §7 引用，不发明新 layout 值 |
| `build_tags`、`authority_schema_revision`、profile/resource/cost、两 role、`session_liveness_mode` | F：逐字相等，标签恰好 fieldc1c；predictive 的 cost 必须 gate-c/predictive_32/1 |
| `exact_sha`、三个 binary digest、`toolchain`、顶层/router dependency digest、manifest/config digest | D：受审二进制/原字节；下节给公式，不能使用文档 PR 的 HEAD 或文本 pretty-print 后的 hash |
| 两个 machine scope 与 router scope | D：各自 mount view 的 machine-id/canonical namespace；两 endpoint 不能共用 host scope；hash 也是私有标识，不公开 |
| `mapping_set_role` | 本 predictive 场景 N：null；以后 asymmetric 必须为对应角色，不能缺字段 |
| `containment_authorization` | H/N：未另行授权则 null；否则是精确既有动作引用，不是任意命令执行权限 |
| `unused_credential_verified`、`single_invocation_verified`、两个 `root_risk_accepted_*` | H：模板 null，签发时核实后必须 true；false/null 都不能绕过，不能本 PR 预签 |
| 两个 `missed_rounds`、`absolute_session_ceiling` | H / U6：将 null 换成同一个合法整数，ceiling 两 config/实例相同；无数字协商 |
| `devices` | F/D/H：有序 initiator/responder、os=linux；每份 config 原字节 SHA-256；request/config 是对应 view 的绝对路径 |
| 两类 `resource_inventory` | H：router 一项、endpoint 两项，角色固定有序；共享主机填 owned 资源引用而非虚构云资源销毁 |
| `credential_reference`、`host_key_pin_reference`、`ssh_identity_reference` | H：目录/文件的 canonical absolute path；manifest 在 credential_reference/manifest.json；path 不代表读取权限已验收 |
| peer 地址、observer、SSH endpoint | H：双人明确批准 literal；initiator 指向 responder NAT，反之亦然；observer 与 request/router 逐项相等 |
| 三项 `hardening_*` | F/H：status=not_implemented，其余如实填原因/风险/接受证据，不能改 true 或声称 root sandbox |
| interface 对象 | F/H：MTU=1280；名字是合法 ≤15 字符；local/peer 对调、AllowedIPs 仅对方 /32，不任意加路由 |
| `owned_stop_target_identity` | F/H：kind 固定；引用 checklist，不嵌入尚未存在的 PID |
| `witness_plan` | H：九项完整非空、明确读取失败如何记录 unknown；具体采集待 U9 闭合，不编造“证据已齐” |
| `router.anchors` | D：有序三角色、名称 U3、inode 实际读取的正 uint64；模板 null 不是合法 inode |
| `router.domains` | F/H：predictive 两侧 apdm_sequential/1；endpoint/gateway 同 link，public/transit 同 link，不同地址；prefix 为 canonical IPv4 /24–/30，所有地址唯一 |
| `router.allow_global_conntrack_ceiling` | F：显式 false；null/遗漏都拒绝。shared-host 引用不授予全局写权限 |
| `router.disposable_environment_reference` | H：如实引用 §7 共享主机偏离及本次非 init 隔离，不能写已销毁 VM |
| 13 个 post-run 字段（下面逐项列出） | N：签发时和不可变原件中始终 null，真实结果只在另一个 evidence 文件 |
| 其余 `<H_...>` 字段 | H：逐项填对应权限/采集计划/私有证据引用；不得用一个“全部通过”字符串代替各项核查 |

13 个 post-run 字段完整集合为：`tuple_observations`、`raw_evidence_references`、
`evidence_sha256`、`terminal_result_by_role`、`durable_finish_and_circuit_evidence`、
`owned_residue_by_layer`、`ledger_sealed_before_destruction`、`cloud_teardown_evidence`、
`independent_management_preserved`、`redacted_summary_review`、`authorization_closed_at`、
`teardown_operator_signature`、`teardown_reviewer_signature`。

所有顶层字段必须出现；router 恰好 7 个字段。只把空模板 JSON 改成 89 项，并不意味着通过
[`validate.go`](../internal/v2/fieldc1c/validate.go) /
[`router_v2.go`](../internal/v2/fieldc1c/router_v2.go) 或真实签发。

### 4.2 精确派生公式（只读，不产出实例）

二进制和文件原字节：

```sh
go version -m <EXACT_FIELD_BINARY>
go version -m <EXACT_ROUTER_BINARY>
sha256sum <EXACT_FIELD_BINARY> <EXACT_ROUTER_BINARY> <INITIATOR_CONFIG> <RESPONDER_CONFIG> <MANIFEST>
```

metadata 核对 toolchain、`-tags=fieldc1c`、vcs.revision、vcs.modified=false、非 race，匹配 A3
已验证的内嵌 BuildSHA。不能用 `go version -m` 展示成功替代 A3 的 BuildSHA/nm 证明。

依赖摘要按 [instance.go](../internal/v2/fieldc1c/instance.go) 的 `dependencyDigest`：

```text
deps = sort_lexicographically(each dep.Path + NUL + dep.Version + NUL + dep.Sum)
any dep.Replace != nil => reject
payload = Go encoding/json.Marshal(struct fields in this order:
  domain        = "winkyou-c1c-dependencies-config/1"
  dependencies  = deps (array of strings, NOT array of Module objects)
  configuration = [SHA256(initiator YAML bytes), SHA256(responder YAML bytes)])
result = lowercase_hex(SHA256(payload))
```

无结尾换行，NUL 用 JSON 的 `\u0000` 转义，不按 JSON 键重新排序；保留 Go 字符串转义语义。
若空依赖表，须保持实现的 nil slice→null 行为，不擅改 `[]`。顶层用 field 依赖，router 对象
用 router binary 依赖；两份 config 顺序始终 initiator/responder。

machine scope 按 [path_linux.go](../internal/v2/fieldc1c/path_linux.go)：

```text
id = /etc/machine-id raw bytes with at most ONE final LF removed
require exactly 32 lowercase hexadecimal characters (no CR, spaces, extra LF)
namespace = "/var/lib/winkyou-safety-v2"
scope = "machine-scope-sha256/1:" + lowercase_hex(SHA256(
  UTF8("winkyou-c1c-machine-scope/1\n" + id + "\n" + namespace)))
```

**U8 未决**：没有已审查的现成派生字段 CLI；上述是精确公式，不伪造 `wink hash-instance`
或把 Go `Deps` 结构直接 JSON 化。可后续单独复审仅只读计算/打印字段的 helper，必须比较
Go 原字节 golden、拒绝 Replace、不生成可加载实例、不签字、不读取/打印 PSK。本 PR 不加脚本。

## 5. 首批场景清单与顺序

每一行独立 credential/窗口/两人签字，前一行证据复审关闭后才能进入下一行。负面场景并不
豁免完整 reservation；“低成本”指选择 predictive、在对应早期边界停止，**不是**降低账本预留。
下表的 class/stage 是候选核对目标，不把无法稳定触发的值冒充冻结的验收结果。

| 顺序 / 场景 | 计划动作与为什么低成本 | class / stage 核对与当前阻断 |
| --- | --- | --- |
| 1 peer absent | 私有 responder sshd 不启动；不建立 OOB/UDP，未 burn | SSH 失败目标为 `ssh_transport_unavailable` 或实际 child 终止归因；准确 class/stage 须先冻结，U7。不能承诺必为 presence timeout。 |
| 2 wrong PSK | 目标是在 Noise 握手终局，无候选搜索 | **U7：交叉两次 pair 输出会同时改变 attempt/credential/channel/fingerprint，不是仅 PSK 错。** 当前 `validateFieldMaterial` 会先拒绝为 `gate_c_request_invalid`/`preflight`，不能声称测到握手认证失败。待审同 context 错 PSK 注入，不手改材料。 |
| 3 post-burn OOB EOF | 已烧后断本次 child 的单一 OOB，停止候选发射 | 目标 `oob_stream_closed`，stage 取实际已完成前缀；field 无 fault CLI/同步触发点，U7。不能 kill 整个 sshd 代替精确 OOB EOF。 |
| 4 evidence unusable | 在 candidate 前取得不满足证据的结果；direct=0 | 目标 `hard_nat_evidence_insufficient` / `fresh_evidence`；模拟 router 当前没有受审现场失真/静默开关，U7。不能临时改 nft/借公网 observer。 |
| 5 lease/consumer failure | 同一 predictive attempt，lease/handoff 失败且无 session 重试 | 可能是 `transport_lease_unavailable`、`transport_handoff_failed` 或 `wireguard_binding_failed` 等，具体边界必须先定；没有现场注入命令，U7。WG 错 key 不自动等同 lease failure。 |
| 6 low-cost nominal | 提议仍为 predictive 完整成功，验证 VERIFY→handoff→WG→OOB drain；独立于正式统计样本 | success / terminal，另核对 data_plane_ready 与 FINISH。其 NAT mode 同样双 apdm_sequential/1，不能称为较容易 NAT；区别只是前置验收用途。合法 scenario 编码与前置证据填法 U7 未决。 |
| 7 teardown | 独立 predictive 实例，验证精确停止/排水/外层回收；所有前行也必须 teardown | parser 已有 `teardown`，但精确 stop stage 和 endpoint 预期 terminal 仍需实例冻结；router 主动停止 cancelled、独立 teardown success 分列 |
| 8 predictive_apdm_pair | 正式双 APDM；完整原 plan/reservation/selection、双向 VERIFY 与 WG 数据 | parser 已有该值；nominal/success + terminal，证据和前置复审齐全后才签发 |
| 后续另发任务 | asymmetric 两 orientation、hard16 near-tail/exhaustion、crash | 不从本规程继承权限。hard16 一次/24h且失败开 circuit，不因新 credential/新 netns 换 scope；near-tail 当前模型证据也不能冒充已闭合 |

**场景编码的硬阻断**：当前 `validateProfile` 只接受七行正式场景；缺席/错 PSK/EOF 等没有
独立字符串。`expected_terminal_and_fault_stage` 只是记录，不是 fault 注入控制。不得自行把
六个前置门全冒用 `teardown` 或 `crash`；需复审选择映射或新的受审实现。
`preflight_negative_matrix_evidence` 又是非空前置字段，第一例如何引用既有隔离证据并明确
“现场尚未完成”必须一起裁决，不能填未来成功或把 A3 当全部负面门的替身。

## 6. M/E 与完整见证的发布规则

router 输出位于私有 `evidence/<ATTEMPT_ID>/router/`，包括 router.jsonl、ready.json、
ownership.json、summary.json、terminal-resolution.json、teardown-checklist.json。
两 endpoint 的原始输出在各自 home 下的 endpoint.jsonl，物理路径与第二人可读性见 U1。

| C1c ADR §5 字段 | 关联方法 / 缺失规则 | 公开内容 |
| --- | --- | --- |
| tuple_ref / role / witness_clock_ref | 原始 tuple/时钟域只在私有行关联，不发布 tuple hash | role 可用于汇总；不公布关联 ID |
| mapping_age_at_hit_ns / mapping_age_at_winner_ns / mapping_idle_age_at_winner_ns | 必须把认证 hit/W 与同一 router mapping 见证关联；只有普通收包时间不能证明认证 hit | 成功关联的 duration 分布及有效/unknown 样本数 |
| hit_to_stop_ns / stop_to_winner_ns / winner_to_verify_ns / stop_to_verify_ns | 使用同一端点单调时钟，非 winner 无本地 W 则 null；不跨机/跨进程直接减墙钟 | duration、缺失数；不据此改 full schedule |
| kernel_flow_observation | present/absent/unknown 与查询是否成功分开；查询错不等于 absent | 分类计数 |
| failure_stage / terminal_class | 两端分别保留首个终局 | stable stage/class |
| missing_reason / measurement_source | 未关联、没采样、阶段未到、时钟不可比逐字段解释 | 固定 reason 类别与计数，不发原始来源路径 |

[sampler](../internal/c1crouter/sampler_linux.go) 记录 raw tuple、created/last/observed 时间和
kernel 查询；它不会认证密文，终局含 `terminal-correlation-pending`。**U9 未决**：没有可据以
声称“每个 hit 的全部 M/E 字段均已测到”的受审关联命令。endpoint 建立进度不能补出未测到
的 tuple 年龄；保留 null+reason。关联方案、完整 packet 分账与外部 lease/lock/process 收集
还需精确见证规程，不复用测试 hook，也不为取样再发包。

公开白名单仅：代码/证据 SHA-256、profile、stable stage/class、计数/ceiling、duration、
owned residue、审核结论。endpoint summary 的 external socket/conntrack/process residue
原本为 null，不能把 router 的零复制过去。原始日志、授权 JSON、metadata paths、PID、
account、网络地址、设备信息、key/pin、attempt/credential/machine 标识都不公开。
脱敏视图先人工逐字段审核；隐私测试不是任意自然语言已安全的证明。

## 7. 停止条件与失败处置

- SHA/依赖/配置/角色/哈希/权限/窗口不一致，任一 U 项未关闭，双签缺失：不启动。
- 无 witness、第二 owner/address/attempt、超 cap、异常持续发包、EOF/child death、trip/circuit
  或 ledger indeterminate：终止本次，保留首次 terminal/日志；不重试、扩窗、换种子或 fallback。
- 不重置 ledger、scope、claim 或 trip 求绿；cleanup 与下一次 admission 严格分离。
- 管理连接失败只留投递失败记录，不冒充测试 FAIL/PASS，不自动补跑。
- 主机状态变化、unknown residue 或 2s drain 失败：不关窗成功，不继续后续场景；只允许本次
  事前签发的精确 containment，不动独立管理网络或全局 firewall/sshd/sysctl。
- 不把共享主机删掉/重装，不用 broad rm/flush/kill；持久目录封存不等于删除身份。

## 8. Stage II：无端点的建网/拆网演练（未授权执行）

Stage I 接受并关闭 U1–U5 的相关项后，另发精确 Stage II 任务书。一次性 SSH host/client key
只用于 sshd 配置演练；**无 OOB credential/artifact、无 WG 配置/材料、无实例签发、无 WinkYou
端点、无 router run、无 product child 登录、无 UDP 探测**。

1. 第二人 snapshot before；私有演练目录/namespace 标识另行授权，不能伪造 attempt_id。
2. 按 §3.1 建外层 session 与三个 anchors，验证非 init、private registry、仅 lo。
3. 只在私有 responder mount/net view 准备一次性 key、fixed options 与完整 sshd_config；
   `sshd -T` 的输出必须真正通过 ValidateRootSSHDResolvedConfig。
4. **U3/U4 阻断启动**：无 instance 就不能调用 router 来提供 responder endpoint 地址，不能
   借测试 fixture 造一份。须另行裁决本演练专用绑定（如仅 loopback）或受限配置动作，并明确
   它不证明最终 NAT 地址绑定。未裁决只可设计，不执行 sshd 启动/连通测试。
5. 如后续授权了私有 sshd，只用 `ss` 被动看 listener；不 SSH 登录以触发 wrapper/ClaimPending。
6. 对确切 owned sshd TERM、验证 2s 排水；空 anchors 删除、退出所有私有 session。
7. 第二人 snapshot after，10 项 nonvolatile 相同、owned PID/socket/namespace/registry 无残留；
   私有证据 hash/签字。此次没有 BURN/FINISH，不把“不适用”填成某个 credential 成功。

Stage II 失败保留首个输出；不能用再跑一次掩盖。通过后亦须独立复核，再发 Stage III 首个
负面实例任务书；不是自动顺序执行脚本。

## 9. 未决登记与进入下一阶段的门

这些是基线源码/规程的接口缺口，不是本 PR 获得的实现权限。复审可关闭设计项，需代码/工具
支持的另开明确范围；不得由执行者临场改生产/测试 fixture。命令片段不掩盖任一项。

| 编号 | 精确缺口与最小待决内容 | 阻断 |
| --- | --- | --- |
| U1 | endpoints 物理 home/ledger 不在读取器白名单；需决定原件可读、秘密仍排除的持久目录布局或受审读取器变更，拒绝 symlink/hardlink 绕过 | Stage II 涉及布局准备及 Stage III |
| U2 | endpoint 私有 mount/注册表/路径可见性、第一次 scope 初始化、foreground PID/starttime/stop 工具尚无受审现场 launcher；不可用 natlab 入口代替 | Stage II/III |
| U3 | 步 4 名称依赖步 6 attempt，签发又依赖 anchors inode；router 后才有端点地址；需冻结分步准备/签发/启动顺序、anchor 命名及无 instance 的演练绑定 | Stage II/III |
| U4 | ValidateRootSSHDResolvedConfig 没有独立只读 CLI，`sshd -T` 不等于 Go validator PASS；需受审只读调用途径 | Stage II/III |
| U5 | CLI 缺完整 ledger/admission/circuit 原件只读状态；需独立工具和两人检查的精确方法，不新建 owner 或修复账本来“检查” | Stage III（Stage II 不打开 governor） |
| U6 | 首批 M/absolute ceiling 具体取值未签发；只能选原合法范围、两端相同，不能把 fixture 60s 当正式裁决 | Stage III |
| U7 | 六个前置门的合法 scenario、第一例 preflight 引用、精确 class/stage 与现场 fault 触发；混 pair 不是仅错 PSK，无 CLI 注入不能冒用测试 hook | Stage III 首例及各负面门 |
| U8 | binary deps/config、scope 精确公式已给，未有受审只读派生 CLI；需可重算的逐字节证据，不生成实例/签字 | Stage III |
| U9 | M/E 认证事件关联、packet 分账、endpoint 外部 process/socket/lock/lease 采集的完整现场命令未冻结；未测只能 unknown，不能宣称满足全部见证 | Stage III 相应验收 |

本规程提交不关闭上述项，不重开 A1–A3，不改变此前三个 namespace/共享主机裁决。
独立复审给出哪些项可先关闭、哪些需工具 PR 后，再分发 Stage II；Stage III 每个实例仍独立签发。

### 9.1 独立复审裁决（2026-09-29）

复审接受本规程为 Stage I 基线。U1–U9 逐项裁决如下；"设计关闭"指本表文字即为裁决，
"工具 PR"指需另开范围明确的 PR 并独立复审后才算关闭。任何工具 PR 都不得改端点/router 协议
数字、`/1`/`/2` 契约或 workflow。

| 编号 | 裁决 | 关闭方式 | 解锁阶段 |
| --- | --- | --- | --- |
| U1 | 端点 home/ledger 保持在 `c1c/endpoints/<ROLE>/`（读取器不可见）。**原件可读**通过 bind mount 达成而不是复制：启动前在角色 mount view 内把读取器可见的 `c1c/evidence/<ATTEMPT_ID>/endpoint-<role>/` 绑定到 `<ROLE>/home` 内的 `.winkyou-field/c1c/evidence/<ATTEMPT_ID>/`，endpoint 直接写入原件；每角色材料以 `c1c/material/<ATTEMPT_ID>/<role>/` 绑定到 home 内固定路径 `/root/.winkyou-field/c1c/material/<ATTEMPT_ID>/`（读取器白名单先于排除，home 不在白名单内，故不可读）。ledger 与实例副本的第二人可读性由读取器**白名单扩展**解决：新增 `c1c/endpoints/<role>/var-lib/**` 与 `c1c/endpoints/<role>` 下 home 内的 `.winkyou-field/c1c/*.json`，其余 endpoints 子树（`shadow`、`install`、`run`、home 内的 `.ssh` 与 `.winkyou-field/c1c/material`）仍不可读；契约与变异测试同步更新。 | 工具 PR（scripts + architecture 契约） | Stage II（布局）/ Stage III（ledger 读取） |
| U2 | 新增三个受审脚本，均无自由参数（仅 `<role>` 与 `<attempt_id>` 经正则校验）、固定布局、契约测试锁定：`scripts/c1c-endpoint-init.sh`（**每角色仅一次**：生成 32 hex machine-id 到独占新文件、创建 var-lib/home/run/install/shadow、复制受审 field 二进制两份并核对哈希、在角色 view 内运行 `wink setup-machine-scope`；再次运行即拒绝）；`scripts/c1c-endpoint-launch.sh`（`unshare -m` + 2.1 表全部 bind + `/run/netns` 重绑 + U1 的 evidence/material bind + `ip netns exec <anchor>` + `exec` 固定 `/usr/libexec/winkyou/wink gate-c1c run --instance <固定路径>`；启动后由父进程立即打印 PID/starttime/ns inode 见证行）；`scripts/c1c-owned-stop.sh`（读 `/proc/<pid>/stat` starttime 与 exe，与登记值全等才 `kill -TERM`，随后 2 s 内轮询退出并打印见证；不匹配即拒绝）。Stage II 用 launcher 以 `wink version` 为 payload 演练挂载与停止，不开 governor。 | 工具 PR（scripts + architecture 契约） | Stage II |
| U3 | 冻结顺序：① `solver pair oob` → 读 manifest 得 `attempt_id`；② anchors 命名 `c1c` + SHA256(`winkyou-c1c-anchor/1\n` + attempt_id) 前 4 字节小写 hex + `-i`/`-t`/`-r`，`ip netns add` 三个并记 inode；③ 填实例（含 inode）；④ 第二段签字（见 U6 行下方"双段签字"）；⑤ router run → `ready.json`；⑥ 在 responder anchor + 私有 mount view 启动 sshd（peer-absent 实例除外）；⑦ initiator。因 artifact 有效期为 `MaxPairingLifetime`=10 分钟且实例 `credential_expires_at` 必须等于它，①–⑦ 必须在 10 分钟内完成；超时则本套材料作废、不复用、不延长，重新走①并重新签字。Stage II 无 instance：sshd 绑定 responder anchor 内 `lo` 上的 `127.0.0.1:<port>`，明确不证明 NAT 地址绑定。 | 设计关闭 | Stage II/III |
| U4 | 新增 field-only 只读子命令 `wink gate-c1c verify-sshd`：从 stdin 读取 `sshd -T` 原始输出，调用 `ValidateRootSSHDResolvedConfig`，stdout 仅 `ok` 或固定 class；无 exec、无网络、无文件写入；nm 门登记。 | 工具 PR（fieldc1c 生产，RED→GREEN+变异） | Stage II |
| U5 | 新增 field-only 只读子命令 `wink gate-c1c ledger --json`：在当前 mount view 内以 `InspectMachinePairingLedger` 等只读 API 输出 pairing/campaign ledger、pending/claimed slot、trip、circuit、admission 状态的固定字段 JSON；不创建 namespace/owner，不修复，不打开 stdio。 | 工具 PR（同上一 PR） | Stage III |
| U6 | 首批全部实例：`session_liveness.mode=challenge_v1`，两侧 `missed_rounds=3`（L=65 s），`absolute_session_ceiling=2m0s`，两侧相同并写入实例；这是本批签发值，不是产品默认。**双段签字**：第一段——执行者提交除 attempt 派生字段（`instance_id`、anchors、`manifest_sha256`、`credential_reference`、`credential_expires_at`、`signed_at/not_before/not_after`、三副本哈希）外已填满的脱敏实例，维护者回复 `预批 <SCENARIO>`，评审核对；第二段——① 完成后执行者只填派生字段并提交与预批稿的逐字段 diff，维护者回复 `签发 <SCENARIO> <ATTEMPT_FIRST_8>`，评审核对 diff 仅含派生字段后填评审栏。两段原话与时间均入私有 checklist。 | 设计关闭 | Stage III |
| U7 | 六个前置门按可诱发性分三类。**现场可诱发（保留）**：peer absent（不启动私有 sshd）；材料不匹配（两套 `pair oob` 交叉）——如实命名为"材料不匹配零 I/O 拒绝"，预期 `gate_c_request_invalid`/preflight，不称"握手错 PSK"。**现场不可诱发（以隔离 CI 证据代替）**：post-burn OOB EOF、evidence unusable、lease/consumer failure——field build 与 router 按设计无故障注入面，三项由 C1b/C1c 隔离 CI 的 RED→GREEN 证据闭合；ADR §7 记录为对 Gate C1 §11 的显式偏离，`crash` 是首轮唯一现场注入场景。**合并**：表中第 6 行"低成本 nominal"与第 8 行 `predictive_apdm_pair` 同一形态，删去第 6 行。**编码**：两个现场负面门以 `scenario=predictive_apdm_pair` 签发，`expected_terminal_and_fault_stage` 填签发的非 success 预期，`preflight_negative_matrix_evidence` 引用隔离 CI 证据文档的 SHA-256 与本裁决；不改 `validateProfile`。 | 设计关闭 + ADR 记录 | Stage III |
| U8 | 新增 field-only 只读子命令 `wink gate-c1c derive --field <bin> --router <bin> --initiator-config <f> --responder-config <f>`：输出 `dependency_and_configuration_sha256`（端点与 router 两值）、三个二进制 sha256、`exact_sha`/`toolchain`、本 mount view 的 machine scope reference；不写文件、不产出实例。第二人用同一命令在只读视图独立重算。 | 工具 PR（同 U4/U5 PR） | Stage III |
| U9 | 关联在**事后离线**完成：`scripts/c1c-me-correlate.sh`（只读，输入私有 endpoint.jsonl×2 + router.jsonl，输出 §5 各字段的值或 null+reason，不发包、不改文件）；未能关联的字段保持 null。它阻断的是 M/E 公开摘要，不阻断实例执行。 | 工具 PR（scripts，可与 U1/U2 同 PR） | M/E 发布 |

**Stage II 前置**：U1、U2、U4 的工具 PR 合入。**Stage III 前置**：U5、U8 合入；每实例仍单独两段签字。
U9 在首个 `predictive_apdm_pair` 发布摘要前合入即可。

## 10. 本 PR 的验收口径

只改本文和 C1c ADR §7 一行。验证命令为 `go test ./internal/architecture -run 'Privacy'`、
`go vet ./...`、相对链接检查、模板顶层 89 字段与原目录逐项比对、`git diff --check`。
docs 隐私门自动遍历 docs 下全部文件，不加豁免；不跑现场命令/生成器/host helper。
CI 首跑另列，首次 RED 保留，不 rerun 求绿。Draft PR 未合并，等待独立复审。
