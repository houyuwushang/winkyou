# 历史 Windows 部署紧急停机 Runbook

> **状态说明（2026-08-13）：** 历史部署的计划任务已经保持 `Disabled`；当前二进制也已通过 fail-closed 门禁拒绝相关的 autonomous birthday recovery 配置。本手册只描述同类历史部署残留的处置原则，不记录个人机器路径、现场 IP、具体构建或可识别拓扑，也不是当前部署或重新启用指南。下述 NO-GO 与暂停决定继续有效。

## 适用情形

2026-07-22 的历史部署同时包含计划任务、supervisor 与 client 子进程。失联 peer 触发 cached self-bootstrap 后，多个有界窗口叠加，短时间内创建大量 UDP socket、目标五元组和出口 conntrack/session 状态，最终影响了共享网络。

该事件对应的 cached self-bootstrap / autonomous birthday recovery 在完成独立立项、资源硬上限、退避、熔断、kill switch 与隔离验收前均为 **NO-GO**。项目决定仍是：**短期暂停，不安排修复、现场测试或重新部署。** 根因、影响模型和恢复门禁见 [`INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md`](./INCIDENT-2026-07-22-SELF-BOOTSTRAP-UDP-STORM.md)。

本 runbook 只适用于仍残留“计划任务 -> supervisor -> 历史 client”自动拉起链路的机器。当前正常构建不会授权恢复这条链路。

## 紧急停止顺序

1. 在计划任务管理器中先**禁用**对应任务，再结束任务实例。只结束 client 子进程不够，supervisor 可能再次拉起它。
2. 按该机器的受控部署记录创建 stop marker；不要从公开文档复制个人路径，也不要猜测现场目录。
3. 只停止可同时由已核验安装路径和命令行参数证明属于该部署的 supervisor/client，避免按进程名批量终止无关程序。
4. 等待进程退出后，核对任务状态、stop marker、部署进程与该部署声明的监听端口；四项必须分别得到确定结果。
5. 任一项无法确认时，视为停机未完成并升级给现场管理员；不得通过删除 marker、重启任务或单独启动 child 试错。

验收结果至少应满足：

```text
scheduled task: Disabled
stop marker: present
owned supervisor/client processes: 0
deployment listeners: 0
```

## 出口设备处置

源进程停止后，NAT/防火墙上已经建立的 UDP conntrack/session 可能按设备的 idle timeout 逐步老化，而不是立即消失。

如果共享网络仍未恢复，应由网管根据当时的 DHCP、ARP、终端资产和出口日志重新核实源主机，再只处理被证明属于该源的 UDP 会话。不要在公开 runbook 中固化历史 IP，也不要为单一事件重启整台防火墙、清空全局会话表或扩大到无关终端。

## 重新启用门禁

当前结论不是“按下面步骤即可恢复”，而是保持禁用。未来只有重新立项后，至少完成以下门禁，才可以另行评审是否允许隔离验证：

1. 节点级 single-flight/semaphore，禁止多个 peer 同时启动 heavyweight punch。
2. socket、目标、五元组、窗口、周期与总包数均有不可由配置突破的保守硬上限。
3. 节点级 packets-per-second 限制；临时错误、资源耗尽或连续写失败会停止本轮并进入退避。
4. 取消会关闭 socket、等待全部 sender/reader 退出，并有持久 kill switch 与资源指标。
5. 单 peer、多 peer、长时间失联和故障注入只在隔离网络验收，同时核对主机资源与出口 conntrack/session。
6. 冻结候选二进制摘要、配置上限和回滚责任，并由独立评审确认；办公网或公网 canary 仍需要单独授权。

即使未来完成上述工作，也不得直接删除 stop marker 或恢复历史任务。恢复动作必须在新的、经过审查的部署记录中定义，不能依赖本历史 runbook。
