# WinkYou 文档索引

当前仓库首页的 [`README.md`](../README.md) 已经改为真实可部署入口，优先阅读那里提供的 quickstart。  
本目录只保留文档索引和执行基线引用。

## 优先级顺序

1. [`EXECUTION-BASELINE.md`](./EXECUTION-BASELINE.md)
2. [`../README.md`](../README.md)
3. 其他设计和任务文档

## 推荐阅读

- [`EXECUTION-BASELINE.md`](./EXECUTION-BASELINE.md)
- [`ARCHITECTURE.md`](./ARCHITECTURE.md)
- [`PEER-RELAY-DESIGN.md`](./PEER-RELAY-DESIGN.md)
- [`tasks/`](./tasks)

## 当前事实

- 已支持的快速部署路径：Windows client（Wintun/TUN） + Linux coordinator + Linux relay + Linux peer。
- 当前数据面已经使用进程内 `wireguard-go`，不再依赖系统 `wg`。
- `userspace` / `proxy` / no-admin 模式未完成，当前文档不再声称这条路径可用。
- `memory backend` 保留给测试，不作为部署路径。
