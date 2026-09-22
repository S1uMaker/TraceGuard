# 检测场景：运行时容器由 root 启动包管理器

当前聚焦场景是：**已经运行的 Docker 容器中，UID 0 启动操作系统包管理器**。这可能表示有人进入容器临时安装工具，使运行实例偏离原镜像；也可能是获准排障、镜像构建或只查看版本。TraceGuard 将它作为需要核查的行为，不将一次命中直接判定为攻击。

本场景随 v0.4.0 加入，并于 2026-09-22 在 Ubuntu 24.04.3 虚拟机完成构建、不落盘回放和真实容器验证，结果见 [v0.4.0 验证报告](validation/2026-09-22/REPORT.md)。

## 检测依据

默认规则 ID 为 `docker-root-package-manager`，四个条件必须同时满足：

| 条件 | 数据来源 | 用途 |
| --- | --- | --- |
| `type=process_exec` | eBPF `sched_process_exec` | 只处理已经成功执行的新程序 |
| `source.kind=docker` | cgroup v2 与 Docker 元数据关联 | 排除已确认的宿主机事件；unknown 不冒充容器 |
| 文件名为操作系统包管理器 | 内核事件中的 `filename` | 匹配 `apt`、`apt-get`、`dpkg`、`apk`、`dnf`、`yum`、`rpm`、`microdnf`、`zypper` 或 `pacman` |
| `uid=0` | 内核记录的主机侧 UID | 将默认范围收窄到高权限执行 |

告警证据会保留实际来源、文件名、匹配项和 UID。规则没有采集命令参数、父进程或文件写入，因此准确含义是“root 在 Docker 容器内成功启动了包管理器”，不能证明软件包已经安装，也不能证明容器已经被入侵。

## 正常行为对照

本轮在 TraceGuard 显示 `ready` 且容器归属缓存已经刷新后实际执行了以下三类操作；命令中的固定演示容器名便于以后复现：

```bash
# 场景信号：只查看版本，不修改软件包，但仍应触发规则
sudo docker exec traceguard-demo /usr/bin/apt-get --version

# 同容器、同为 root 的正常进程对照：应记录事件，不命中本规则
sudo docker exec traceguard-demo /usr/bin/sleep 1

# 宿主机对照：即使由 root 启动 apt-get，也不命中 scope=docker
sudo /usr/bin/apt-get --version
```

第一条故意使用只读的 `--version`，用来展示本规则的判断边界：TraceGuard 当前能确认包管理器被启动，不能根据参数区分查询与安装。第三条只有在 `include_host=true` 时会保存为事件；默认配置会先过滤明确的宿主机来源。

也可用独立的合成输入预览规则，不创建输出目录：

```bash
./build/traceguard replay --input examples/package-manager-events.jsonl --dry-run --alert-format text
```

这四条合成事件依次表示 root 容器包管理器、非 root 容器包管理器、root 容器普通程序和 root 宿主机包管理器。实际结果仅第一条产生 `docker-root-package-manager` 预览告警；统计为 `received=4`、`host_filtered=1`、`saved=0`、`alerts=0`、`preview_alerts=1`。加入容器名例外后，告警被排除并计入 `excluded_alerts=1`。

## 如何判断与处置

出现告警后，先用 `event_id` 在 `events.jsonl` 和 `alerts.jsonl` 之间关联记录，再核对：

1. 容器名称、镜像和 UID 是否与预期工作负载一致。
2. 当时是否有镜像构建、故障排查、应急维护或发布变更。
3. 同一容器附近是否还出现 shell、身份查询或其他不符合用途的执行事件。
4. 若行为获准且反复出现，优先修正部署流程；确有必要时，在该规则的 `exclude_container_names` 中精确列出维护容器并保留当时配置。

TraceGuard 当前不自动阻断或删除容器，也不根据单条告警给出“已入侵”结论。

## 误报与漏报边界

容易产生告警但可能正常的情况：

- `apt-get --version`、`dpkg --version` 等只读查询；程序名命中即可告警。
- 直接在运行容器中进行获准排障或临时安装。
- Docker 镜像构建过程在同一 daemon 上运行，且构建容器被来源缓存识别。
- 入口脚本在容器启动时安装依赖；这通常是可改进的部署方式，但不等于攻击。

可能漏掉的情况：

- 非 root 用户启动包管理器，因为默认规则限定 `uid=0`。
- 启用用户命名空间时，容器内 root 可能映射为主机侧非零 UID，因此不会满足本规则。
- 包管理器被改名、由自定义安装器替代，或只使用 shell 内建／语言代码修改文件。
- 容器太短命、Docker 快照过期或 cgroup 布局无法识别，事件来源成为 `unknown`。
- 程序成功启动后安装失败；本项目没有包管理结果、网络请求和文件修改证据。

容器名例外是精确匹配，容器改名会改变结果；它适合已知维护容器，不是强安全边界。若未来要区分“查询版本”和“真正安装”，需要新增 argv、父进程或文件行为采集，这会扩大 eBPF ABI 和验证范围，本轮不引入。

## 开源参考与本项目取舍

Falco 的 [Launch Package Management Process in Container](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml) 将包管理器执行用于观察容器漂移，并预留已知正常活动的调优条件。TraceGuard 只采用场景思想，以现有 `process_exec + docker + executable + uid` 字段表达，不复制 Falco 规则，也不声称具备其命令行、父进程、用户名或镜像级例外能力。
