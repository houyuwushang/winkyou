# TURN 回退验证（本地 / 云主机）

## 目的
验证客户端可消费 `nat.turn_servers` 静态凭证，并在穿透失败后使用 relay 路径。

## 步骤

1. 启动 coturn（可本地，也可云主机）
   - 参考 `deploy/relay/README.md`。
2. 在两个客户端节点配置同一组 `nat.turn_servers`。
3. 启动两端：`wink up --config <node>.yaml`。
4. 观察：
   - `wink peers` 的 `Conn Type` 字段。
   - `wink ping <peer>` 输出中的 `context=direct|relay`。
   - runtime state 文件中 peer 的 `connection_type`。

## 判定
- **direct 成功**：`connection_type=direct`。
- **TURN 回退**：`connection_type=relay`。

## 注意
- MVP 阶段不新增 coordinator TURN 凭证 RPC，仍使用静态 `nat.turn_servers`。
- 本文档不涉及仓库内 `pkg/relay` 或 `cmd/wink-relay`。
