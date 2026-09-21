# 容器来源关联

`Resolver` 面向 **64 位 Linux、cgroup v2、在宿主机直接运行的 TraceGuard**。Ubuntu 虚拟机是这里的“宿主机”；不要把本版采集器放入另一个容器运行。

## 关联过程

1. `Refresh` 通过本地 Unix socket 读取 Docker 容器列表并 inspect 正在运行的容器。
2. 读取容器 init 进程的 `/proc/<PID>/cgroup`，要求路径包含 Docker 返回的完整容器 ID，避免 inspect 与读取 proc 之间发生 PID 重用而误关联。
3. 找到该容器的 cgroup 根目录，扫描其子 cgroup，并将目录 inode 映射为容器来源。
4. `Resolve` 优先查询内存快照；缓存未命中时只读取本地 proc/cgroup，**不调用 Docker API**。

Linux 6.8 的 [`cgroup_id()`](https://github.com/torvalds/linux/blob/v6.8/include/linux/cgroup.h) 返回 kernfs ID，[`kernfs_id_ino()`](https://github.com/torvalds/linux/blob/v6.8/include/linux/kernfs.h) 在 64 位内核上将此 ID 用作 inode。统一 cgroup 路径取自[内核文档规定的 `0::/path` 条目](https://docs.kernel.org/admin-guide/cgroup-v2.html)。Docker 元数据字段以 [Docker Engine API](https://docs.docker.com/reference/api/engine/version/v1.45/) 为依据。

## 使用约定

调用 `New(socketPath, cgroupRoot, procRoot)` 后，先同步执行一次 `Refresh(ctx)`，随后由调用方定期刷新并记录错误；默认配置每 5 秒一次。`Close()` 关闭闲置 HTTP 连接；本包不自行启动后台任务。

所有 Docker 请求均为 GET；每次请求限时 5 秒、本包每次刷新限时 30 秒（主程序另设 15 秒的整体上限）、响应体上限 8 MiB、单个容器子树最多 4096 个目录。快照在锁外构建，再短暂加锁替换，Docker 等待不会持有查询所需的锁。

## 边界与降级

- 最后一次成功观察到的映射保留最多 5 分钟，超过期限后即使 Docker 一直故障也不再使用。容器退出或下一次扫描未找到的旧映射通过 `source.reason` 标注；这不是容器当前仍在运行的证明。
- 新容器和新建子 cgroup 在下一次刷新前可能得到 `unknown`。极短寿命、从未进入快照的容器无法仅凭已退出的 PID 恢复名称和镜像。
- 未命中的进程必须通过目录 inode 与事件 cgroup ID 一致性校验，才进一步判断来源。Docker 路径但无元数据、其他容器运行时的路径线索、进程已退出或迁移、无法识别的布局，都返回 `unknown`。
- Docker 完整快照超过 30 秒未更新时，未命中的事件也返回 `unknown`。正常快照下的 `host` 表示 inode 匹配、路径符合 Ubuntu 常见宿主布局且没有已知容器线索，不能用作隔离或安全授权依据。
- 支持标准 systemd `docker-<ID>.scope` 和包含完整 ID 组件的 cgroupfs 布局；隐藏完整 ID 的定制布局明确报错并降级，不猜测归属。
- 嵌套的 cgroup 能关联到所属容器；其他 Docker daemon 管理的嵌套容器、Kubernetes、Podman、LXC 等不在本版元数据支持范围内。

2026-09-21 已在 Ubuntu 24.04.3 x86_64、内核 7.0.0-31-generic、
Docker 29.1.3、cgroup v2 / systemd 环境完成真实运行验证。
完整集成验证的 16 项检查全部通过，其中包括两个已有容器的精确 ID / 名称关联、
运行中新容器发现，以及已观察到的宿主进程不被错误归为 Docker 来源。
具体结果见 [Ubuntu 验证报告](../../docs/validation/2026-09-21/REPORT.md)。

这次验证不代表其他运行时、arm64、定制 cgroup 布局或全部缓存竞态已经实测，
也未进行性能或压力测试；上述支持与降级边界继续适用。
