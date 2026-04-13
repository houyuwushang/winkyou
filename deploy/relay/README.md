# TURN relay 最小部署示例（MVP）

> 目标：给 WinkYou 客户端提供 `nat.turn_servers` 静态长期凭证的 TURN 回退。

## 1) 方案 A：使用外部 coturn（兼容）

```bash
cd deploy/relay
docker compose up -d
```

默认示例配置：
- TURN 地址：`turn:127.0.0.1:3478`
- 用户名：`wink`
- 密码：`secret`

## 2) 方案 B：使用仓库内 `wink-relay`（UDP TURN + 长期凭证）

本仓库新增了最小可用 TURN server：

```bash
go run ./cmd/wink-relay --listen :3478 --realm winkyou --users wink:secret
```

也可用 Dockerfile 构建镜像：

```bash
docker build -f deploy/relay/Dockerfile -t wink-relay:dev .
docker run --rm -p 3478:3478/udp wink-relay:dev --listen :3478 --realm winkyou --users wink:secret
```

## 3) 客户端配置

在客户端配置中添加：

```yaml
nat:
  stun_servers: []
  turn_servers:
    - url: "turn:127.0.0.1:3478"
      username: "wink"
      password: "secret"
```

## 4) 观察 TURN 回退是否生效

- 启动两个节点后查看：
  - `wink peers` 中 `Conn Type` 是否为 `relay`。
  - `wink ping <peer>` 输出的 `context=relay`。
- 运行状态文件中也会记录 `connection_type=relay`。

> 当前 MVP 实现优先直连；直连候选失败后，会尝试 relay candidate 回退。
