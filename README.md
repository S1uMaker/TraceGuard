# TraceGuard

基于 **C/eBPF + Go** 的单机 Docker 容器运行时行为监控项目。第一版监控成功的进程执行，关联容器，按配置检测并保留原始事件与告警，面向 Ubuntu 24.04 虚拟机中的学习、演示和简历项目积累。

**当前源码：0.4.0，已于 2026-09-22 在 Ubuntu 24.04.3、Linux 7.0.0-31-generic、amd64、Docker 29.1.3 环境完成重新构建、race 单测、静态检查、回放、16 项真实集成检查和 root 包管理器专项场景，全部通过。** 专项场景实际覆盖规则列表、不落盘预览、文本告警、容器例外，以及 root 正例、非 root 和普通程序对照；测试容器和进程已清理。详见 [v0.4.0 验证报告与原始证据](docs/validation/2026-09-22/REPORT.md)。verifier 的详细失败诊断未通过篡改 BPF 对象强制触发；正常对象已真实加载。v0.1.0 的历史记录继续保留在 [首轮报告](docs/validation/2026-09-21/REPORT.md)。

## 当前功能

- eBPF 挂载 `sched/sched_process_exec`，采集成功 exec 的文件名、主机 PID/TID、UID/GID、任务名、cgroup ID 和单调时间。
- Go 通过 ring buffer 读取事件，用 Docker 元数据与 cgroup v2 inode 关联来源；不能确认的来源保留为 `unknown`。
- 默认检测容器内启动 shell、执行 `id/whoami/uname`，以及 UID 0 启动操作系统包管理器；规则可限定容器名、UID 和精确可执行文件名，并可按规则排除指定容器的告警，原始事件仍保留。
- 追加保存 `events.jsonl` 与 `alerts.jsonl`；告警包含事件快照、规则 ID 和命中依据。终端默认输出 JSON，可选简洁文本；标准错误输出状态、内核丢失计数、unknown 原因和各规则告警／例外次数。
- 提供配置校验、规则列表、运行前环境检查、退出清理和离线 JSONL 回放；回放可预览规则结果而不创建输出文件。

告警只表示满足规则条件。正常维护也可能触发默认规则，不能直接当作确认攻击。首版不包含文件/网络探针、Web 页面、Kubernetes、机器学习或自动阻断。

## 在 Ubuntu 24.04 中开始

以下命令都在 **Ubuntu 虚拟机终端**执行。把项目复制到虚拟机本地目录，例如 `~/TraceGuard`，从该目录运行。Windows 共享目录可能不支持输出文件所需的 Unix 权限。

要求：64 位 amd64 或 arm64、cgroup v2、可用的 tracefs、本机 rootful Docker。采集器直接运行在虚拟机中，保留主机 PID/mount/cgroup 命名空间。首版不以 rootless Docker、WSL 或容器内运行采集器为验收环境。

### 1. 安装构建依赖

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev linux-libc-dev golang-go jq
go version
```

Go 要求 **1.22 或更高**。如果已经有 Docker，保留现有安装；没有时可使用 Ubuntu 软件包：

```bash
sudo apt install -y docker.io
sudo systemctl enable --now docker
sudo docker info --format 'Cgroup={{.CgroupVersion}} Driver={{.CgroupDriver}}'
```

上面应显示 cgroup 版本 `2`，实际显示值请自行记录。eBPF 功能最终仍以该虚拟机内核加载结果为准。

### 2. 构建并检查配置

```bash
cd ~/TraceGuard
make build
./build/traceguard check-config
sudo ./build/traceguard doctor
```

`make build` 根据 `go.mod` 和已保留的真实 `go.sum` 下载并校验固定版本依赖，编译 `build/exec.bpf.o` 和 `build/traceguard`。首次需要访问 Go 模块服务。运行不依赖 Clang，也不需要 Go 工具链，但二进制和 eBPF 对象两个文件都需要保留。

`doctor` 检查权限、cgroup 文件系统、tracepoint 字段布局、对象文件存在性以及 Docker 元数据访问。它**不会加载 eBPF，也不验证真实采集与日志写入**。若提示 tracefs 不可用，先检查，再仅在尚未挂载时挂载：

```bash
mountpoint /sys/kernel/tracing
# 仅在上一条提示不是挂载点时执行：
sudo mount -t tracefs tracefs /sys/kernel/tracing
sudo ./build/traceguard doctor
```

### 3. 准备容器，再启动采集

先创建持久运行的演示容器，避免新容器在第一次缓存刷新前就退出。容器不开放端口，也不需要联网执行演示命令：

```bash
sudo docker run -d --name traceguard-demo --network none ubuntu:24.04 sleep infinity
sudo ./build/traceguard run
```

容器名如已存在，先用 `sudo docker ps -a --filter name=traceguard-demo` 查看并复用，勿覆盖已有工作。等待采集终端出现 `ready`，再在另一个 Ubuntu 终端触发：

```bash
sudo docker exec traceguard-demo /bin/sh -c 'echo traceguard-demo'
sudo docker exec traceguard-demo /usr/bin/id
sudo docker exec traceguard-demo /usr/bin/sleep 1
```

预期前两条分别命中 `docker-shell`、`docker-discovery`；第三条应有事件、不触发默认规则。`echo` 是 shell 内建命令，这里采集到的是新启动的 `/bin/sh`。完整的对照场景和证据保存操作见 [演示说明](docs/DEMO.md)。

按 `Ctrl+C` 停止采集。查看已保存结果：

```bash
sudo jq -c 'select(.source.container_name == "traceguard-demo")' data/events.jsonl
sudo jq -c '{rule_id, severity, evidence, source: .event.source}' data/alerts.jsonl
```

## 配置与命令

配置入口为 [configs/traceguard.json](configs/traceguard.json)，字段语义和匹配边界见 [配置说明](configs/README.md)。相对路径均相对于启动时的工作目录。修改配置后重启进程生效。

```bash
./build/traceguard help
./build/traceguard version
./build/traceguard check-config --config configs/traceguard.json
./build/traceguard list-rules
./build/traceguard list-rules --format json
sudo ./build/traceguard run --config configs/traceguard.json --output data-session-01
./build/traceguard replay --input examples/events.jsonl --output data-replay-01
```

v0.2.0 的可选文本展示适合手工演示；当前版本已经重新构建，文本输出也在 v0.4.0 专项场景中通过：

```bash
sudo ./build/traceguard run --output data-session-02 --alert-format text
./build/traceguard replay --input examples/events.jsonl --output data-replay-02 --alert-format text
```

`--alert-format json|text` 覆盖配置的 `alert_format`；省略配置字段时仍为 JSON。文本仅改变终端告警，磁盘中的两份 JSONL 保留完整结构。正常维护可通过规则的 `exclude_container_names` 设置例外，具体例子和新增统计字段见 [配置说明](configs/README.md)。默认配置未启用任何例外。

回放不需要 root、Docker 或 eBPF 权限，但需要先构建 Go 程序。示例是三条**合成数据**，正常回放预期保存三个事件、一条 shell 告警。它们不能证明真实内核采集可用。正常回放要求单独的输出目录，拒绝与配置中实时目录相同，也拒绝向输入文件本身追加；输出事件会带 `replay: true`。回放保留原事件 ID，因此重复回放到同一目录会有重复记录。

v0.3.0 可用同一份事件反复预览规则结果；该入口已在 v0.4.0 专项场景中实际验证：

```bash
./build/traceguard replay --input examples/events.jsonl --dry-run --alert-format text
```

`--dry-run` 与 `--output` 不能同用。预览仅向终端输出告警及统计，不创建／追加日志或获取输出目录锁，也不访问配置中的输出路径。统计 `mode=replay-dry-run`，`saved` 与 `alerts` 均为 0，预览告警另计入 `preview_alerts` 和 `preview_alerts_by_rule`。仍按配置过滤 host、执行规则例外，输出中的事件带 `replay: true`。输入应选用已经停止追加的普通文件；shell 重定向输出由使用者自行负责，勿指向输入文件。

`list-rules` 默认以文本列出全部规则（含停用规则）的条件与例外；`--format json` 输出规则数组。它会校验配置，但不访问 Docker、加载 eBPF 或创建日志。规则列表与预览的详细语义见 [配置说明](configs/README.md)。

v0.4.0 的重点场景是 `docker-root-package-manager`：仅当已确认 Docker 来源、UID 为 0，且成功执行 `apt/apt-get/dpkg/apk/dnf/yum/rpm/microdnf/zypper/pacman` 之一时告警。它用于提示可能的运行时容器漂移，不证明已经安装软件或发生攻击。检测依据、正常行为对照、误报／漏报边界和独立合成输入见 [场景说明](docs/SCENARIOS.md)。

默认 `include_host=false`：过滤明确判断为主机来源的事件，保留 Docker 和 unknown 事件。`unknown` 不匹配 `scope=docker/host`，但可匹配显式的 `scope=any`。如要演示 host 规则，需要同时将 `include_host` 改为 `true`。

输出目录由程序新建，Linux 权限为 `0700`，日志为 `0600`；已有路径不合要求时会报错，不会替你修改权限。每个输出目录仅允许一个写入进程。正常退出同步文件；记录采用追加方式，重新运行不会清空旧日志。

## 代码导航

| 位置 | 职责 |
| --- | --- |
| `bpf/exec.bpf.c` | tracepoint 采集、304 字节事件、ring buffer 与丢失计数 |
| `internal/collector/` | 加载 ELF、附加探针、解码与释放资源 |
| `internal/container/` | Docker 只读 API、cgroup 缓存和 unknown 降级 |
| `internal/model/` | C 到 Go 解码后的事件与告警结构 |
| `internal/config/`、`internal/rules/` | 严格 JSON 校验、条件匹配与解释依据 |
| `internal/output/` | 私有权限、单实例锁、JSONL 追加保存 |
| `cmd/traceguard/` | 命令入口、实时处理、统计、信号退出和回放 |
| `docs/DESIGN.md` | 数据流、选择理由、讲解线索和边界 |
| `docs/OPEN_SOURCE.md` | 开源依赖、借鉴来源、本轮取舍及实现对应关系 |
| `docs/SCENARIOS.md` | 具体检测场景、对照行为、分析步骤与误报／漏报边界 |
| `scripts/`、各包 `*_test.go` | Ubuntu 自动验收、单元测试与真实集成检查 |
| `docs/DEMO.md`、`docs/validation/` | 演示步骤、验证报告和真实证据 |

环境准备好且本地已有 `ubuntu:24.04` 镜像后，可在 Ubuntu 项目目录执行 `sudo bash scripts/validate_vm.sh`，重复完整验收。脚本会检查并安装缺少的构建依赖，每次独立保存结果；详见 [验证脚本说明](scripts/README.md)。

## 已知边界与常见问题

| 现象／限制 | 解释与处理 |
| --- | --- |
| `make` 报 `asm/types.h` 或 BPF target 错误 | 检查 `linux-libc-dev`、`build-essential`、Ubuntu 的 Clang 安装；Makefile 通过 GCC multiarch 路径找头文件 |
| Docker 连接失败 | 检查本机 daemon 和配置 socket；首次快照失败时停止启动，运行中刷新失败则报告并继续采集 |
| 加载 eBPF 报权限／verifier 错误 | v0.3.0 对 verifier 拒绝会附带依赖库提供的详细日志；其他加载错误保留原提示。保存错误、`uname -r` 和 tracepoint format，不要把 doctor 成功当作加载成功 |
| 容器为 `unknown` | 查看 `source.reason`；默认每 5 秒发起刷新，Docker 请求和扫描耗时另计，刷新失败时可能持续 unknown；极短寿命容器可能无法识别 |
| 没有告警 | 先查 events，再核对来源和规则；检查 `excluded_by_rule` 是否命中例外。未知来源、未命中名称、shell 内建命令或失败 exec 均有不同含义 |
| 文件名未匹配 | filename 最多 255 字节，可能相对路径、截断或为空；不解析软链接、脚本解释器或 BusyBox applet |
| `kernel_dropped` 增大 | ring buffer 已满；慢磁盘／慢标准输出会产生背压。不能据此计算所有类型的事件丢失 |
| 停止时有积压 | 首版退出不排空 ring buffer 和用户态队列，最后的积压可能丢失；触发完成后等待日志出现再停止 |
| 程序写输出阻塞 | 第二次 `Ctrl+C` 可强制退出，可能留下未同步记录；避免接入不消费的输出管道 |
| 日志增长 | 暂无自动轮转、跨文件事务和每条记录 fsync；以短时演示为主，保留磁盘空间 |

首版已取得上述环境的真实运行证据，尚未测量吞吐量、准确率或长期稳定性，不承诺零漏报或生产可用。

## 参考

实现时核对了 [cilium/ebpf 对象加载文档](https://ebpf-go.dev/concepts/loader/)、[Linux v6.8 exec tracepoint 定义](https://github.com/torvalds/linux/blob/v6.8/include/trace/events/sched.h)、[内核 cgroup v2 文档](https://docs.kernel.org/admin-guide/cgroup-v2.html) 和 [Docker Engine API](https://docs.docker.com/reference/api/engine/version/v1.45/)。具体 ABI 与关联说明分别在 `bpf/README.md` 和 `internal/container/README.md`。

v0.2.0 参考 Falco 的逐规则例外设计和 libbpf-bootstrap 的简洁终端展示，保留现有 cilium/ebpf 依赖及采集架构；实际采用范围见 [开源参考说明](docs/OPEN_SOURCE.md)。

v0.3.0 再次核对 Falco 的规则列举与回放／输出分离设计，以及 cilium/ebpf 的 verifier 错误示例，补齐规则查看、离线预览和加载排错；未引入新依赖或增加探针。

v0.4.0 参考 Falco 的容器包管理器场景，以现有字段实现范围更窄的 root 操作系统包管理器规则，并明确记录无法判断命令参数、父进程和实际文件变更的边界。
