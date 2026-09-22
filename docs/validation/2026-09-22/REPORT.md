# Ubuntu v0.4.0 验证报告 · 2026-09-22

**最终结果：完整验收与 root 包管理器专项场景全部通过，退出码 0。** 本报告对应当前 v0.4.0 源码；v0.1.0 的历史报告继续独立保留。

项目位于虚拟机 `/home/urgot/TraceGuard`。完整验收目录为 `build/validation/20260922T072702Z-5941/`，结束于北京时间 2026-09-22 15:27:16；专项场景结束于 15:30:18。同步前的远端源码备份为 `/home/urgot/TraceGuard-backup-before-v0.4-20260922.tgz`。

## 环境

| 项目 | 实际值 |
| --- | --- |
| 系统与内核 | Ubuntu 24.04.3 LTS；Linux 7.0.0-31-generic；x86_64 |
| Go / Clang | Go 1.22.2；Clang 18.1.3 |
| Docker / cgroup | Docker 29.1.3；cgroup v2；systemd 驱动 |
| 镜像 | `ubuntu:24.04`，ID `sha256:6232b387...e0f2ef` |

## 完整验收

| 阶段 | 实际结果 |
| --- | --- |
| C/eBPF 与 Go 构建 | 成功；二进制 SHA-256 为 `04009b493ab95451c3567651d8cee12ab815240e21687ccf0dba879bb5bde16b` |
| `go test -race -count=1 -v ./...` | 22 个顶层测试函数及子场景通过，6 个包有测试 |
| `go vet ./...` | 退出 0，无诊断 |
| 配置校验、doctor | 通过；真实 eBPF 加载另由集成阶段确认 |
| 原三行合成回放 | 3 个事件、1 条 `docker-shell` 告警，回放标记正确 |
| 真实集成 | 16 项全部通过；主采集 45 个事件、4 条告警 |

真实集成覆盖探针加载、ready、shell/discovery 正例、sleep 负例、双容器精确归属、宿主机作用域、失败 exec、新容器刷新、输出目录锁、正常退出、重启和清理。完整结构化结果及日志位于证据包。

## v0.4.0 专项场景

专项场景使用独立无网络容器 `traceguard-v04-pkg-7509`，验证结果如下：

| 检查 | 实际结果 |
| --- | --- |
| 版本、配置与规则列表 | 显示 v0.4.0；三条默认规则可读取；新规则包含 Docker、UID 0 和 `apt-get` 条件 |
| 不落盘预览 | 4 个合成事件中仅 root 容器 `apt-get` 命中；`preview_alerts=1`、`host_filtered=1` |
| 逐规则例外 | 排除 `traceguard-app` 后无终端告警，`excluded_alerts=1` 且规则 ID 正确 |
| 真实 root 正例 | 容器内 UID 0 执行 `apt-get --version`，保存事件并产生 1 条 `docker-root-package-manager` 告警 |
| 非 root 对照 | 同容器 UID 1000 执行 `apt-get --version`，保存事件但不产生该规则告警 |
| 正常程序对照 | 同容器 UID 0 执行 `sleep 1`，保存事件但不产生该规则告警 |
| 停止与清理 | 采集器正常退出；测试容器和 TraceGuard 进程残留均为 0 |

专项实时采集共收到 17 个事件，保存 9 个、过滤 8 个宿主机事件，6 个来源为 `unknown`；目标容器的三条对照事件均按容器名、文件名和 UID 精确核对。产生 1 条新规则告警，`kernel_dropped=0`。这些计数只描述本次短时场景，不能推导全局零漏报。

专项测试同时实际覆盖了 v0.2.0 的文本告警与容器名例外、v0.3.0 的 `list-rules` 和 `replay --dry-run`。v0.3.0 的 verifier 详细失败诊断没有通过故意篡改 BPF 对象触发；本轮只确认正常对象能够真实加载。

## 证据与边界

- [status.json](status.json)：本轮总状态。
- [scenario-summary.json](scenario-summary.json)：专项场景结构化摘要。
- [raw-evidence.tar.gz](raw-evidence.tar.gz)：完整验收与专项场景的环境、配置、命令结果、事件、告警及统计；SHA-256 为 `17190d9a013a3a1cf5dd08330c80bfde4ffb99c49997d758fbad0db5a92f38f2`。

本轮证明该环境和这些用例下的实际行为，不代表其他内核、arm64、rootless Docker、其他运行时或长期压力场景。包管理器规则仍只能证明程序成功启动，不能区分版本查询和安装，也不能确认安装结果或攻击成立。
