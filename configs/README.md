# 配置说明

以 `traceguard.json` 为起点修改。第一版使用 JSON，无注释、无正则表达式、无 shell 表达式。未知字段、重复键、额外 JSON 内容及无效字段会在启动时报告。相对的 `bpf_object`、`output_dir` 路径相对于**启动命令的当前目录**，不是配置文件所在目录。

| 字段 | 含义 |
| --- | --- |
| `bpf_object` | 编译好的 eBPF 对象文件；示例使用 `build/exec.bpf.o` |
| `docker_socket` | Docker Unix socket 的绝对路径 |
| `cgroup_root` | cgroup v2 文件系统的绝对路径 |
| `proc_root` | 主机 proc 文件系统的绝对路径 |
| `output_dir` | JSONL 输出目录；示例为 `data` |
| `alert_format` | 可选，终端告警格式：`json` 或 `text`；省略、`null` 或空字符串默认 JSON。run/replay 的 `--alert-format` 可覆盖此值 |
| `refresh_seconds` | 容器和 cgroup 缓存刷新间隔，1–3600 秒；示例为 5 秒 |
| `include_host` | 是否保留已明确识别为主机来源的事件；未知来源仍保留 |
| `rules` | 规则数组；可为空，此时只记录事件 |

规则字段之间是 AND；同一名单内多个候选是 OR。引擎仅处理 `type=process_exec` 的事件，每个事件可命中多条规则。

| 规则字段 | 含义 |
| --- | --- |
| `id` | 唯一规则 ID，1–64 个 ASCII 字母、数字、`.`、`_` 或 `-` |
| `name` / `description` | 规则名称及含义；告警会保留这些内容 |
| `severity` | `info`、`warning` 或 `critical` |
| `scope` | `docker`、`host` 或 `any`；`unknown` 只可能匹配 `any` |
| `executables` | 至少一个候选；例如 `sh` 匹配路径的最后一段，`/usr/bin/sh` 只匹配完整路径 |
| `container_names` | 可选，精确匹配来源中的容器名；非空时只可能匹配 Docker 来源。使用不带前导 `/` 的容器名 |
| `exclude_container_names` | 可选，精确匹配 Docker 容器名的规则例外；仅跳过本条规则告警，原始事件保留。非空时不可搭配 `scope=host` |
| `uid` | 可选，精确匹配事件中内核记录的 UID；`0` 是有效条件，省略或 `null` 表示不限制 |
| `enabled` | `true` 才启用；省略时为 `false`。停用规则也会检查配置有效性 |

`executables` 不匹配命令参数、shell 内建命令或 `comm`。字符串 `*` 没有通配符含义。这里的 UID 由主机侧内核事件提供，不能直接假定为启用用户命名空间时容器内部看到的 UID。

## v0.2.0：逐规则例外

下面是可放入 `rules` 数组的一条完整规则示例，不是完整配置文件。本轮未执行该示例。

```json
{
  "id": "docker-shell",
  "name": "Docker 容器中启动 shell",
  "description": "记录 shell 告警，已知维护容器按本规则例外处理。",
  "severity": "warning",
  "scope": "docker",
  "executables": ["bash", "sh", "dash", "ash", "zsh"],
  "exclude_container_names": ["traceguard-maintenance"],
  "enabled": true
}
```

先检查来源、可执行文件、容器名及 UID 的全部正向条件，再检查例外。`traceguard-maintenance` 中命中的 shell 执行仍进入 `events.jsonl`，但本条规则不写入 `alerts.jsonl`，也不显示终端告警；其他规则照常判断。名单省略、`null` 或为空数组时没有例外。只比较 Docker 来源的容器名，不将 unknown 的名称提示当作已确认容器；不修剪名称、不去掉前导 `/`，也不支持通配符。

同一名称同时出现在 `container_names` 和 `exclude_container_names` 时，在满足正向条件后由例外排除。例外会覆盖该容器中本规则匹配的所有执行，请只填确实需要排除的容器；默认 `traceguard.json` 没有启用例外。配置修改后重启生效，回放使用当次配置和原事件的来源快照。

## v0.2.0：终端显示与统计

`alert_format=text` 输出单行摘要：UTC 观察时间、级别、规则 ID、来源、容器名、主机 PID/UID、可执行文件、事件 ID 与 replay 标记。时间沿用事件的 `observed_at`，不是精确内核执行时刻；回放沿用输入事件时间。字符串使用带引号的转义形式，避免文件名或容器名中的换行、控制字符破坏终端显示。完整告警依据仍从 `alerts.jsonl` 按 `event_id` 查阅。

省略格式字段时沿用 JSON，原有脚本可继续读取默认 stdout。文本模式下 stdout 不再适合直接传给 `jq`，应查询保存的 JSONL 或显式使用 `--alert-format json`。标准错误依旧包含诊断日志与 JSON 统计，不能把整个 stderr 当作纯 JSONL。

| 统计字段 | 含义 |
| --- | --- |
| `unknown_reasons` | unknown 事件按 `source.reason` 分类的次数；包括收到但后来写入失败的事件，与 `unknown` 的计数阶段一致 |
| `alerts_by_rule` | 已成功追加到告警文件的各规则条数；总和等于 `alerts`，不代表已逐条同步磁盘 |
| `excluded_alerts` | 事件满足正向条件但命中例外的“事件－规则”次数；一个事件被两条规则排除计 2 次 |
| `excluded_by_rule` | 上述例外次数按规则 ID 分类；总和等于 `excluded_alerts` |

所有统计均为**本次进程运行累计**，实时每 10 秒及停止时输出，回放在结束时输出；不扫描旧日志、不在进程重启后恢复。实时／正常回放中，例外次数仅在原事件成功追加后增加；v0.3.0 预览模式的差异见下一节。三个分类对象没有记录时省略，`excluded_alerts` 为 0 时仍输出。告警成功落盘后若终端写入失败，已写入告警仍计数并报告错误。

unknown 分类只允许代码中固定的原因：`missing_cgroup_id_or_pid`、`process_cgroup_unavailable`、`cgroup_path_unavailable`、`event_cgroup_no_longer_matches_process`、`docker_metadata_not_cached`、`unresolved_container_cgroup`、`docker_snapshot_unavailable_or_stale`、`unrecognized_cgroup_layout`、`conflicting_container_cgroup_mapping`、`cached_container_not_in_latest_snapshot`。缺少原因归入 `unspecified`，其他文字（包括合成样例的解释文字）归入 `other`，避免回放无限产生分类键。原事件的详细 `source.reason` 不变；Docker 来源附带的缓存提示不会计入 unknown。

本节新增行为属于 v0.2.0 源码实现，初次交付时按要求未编译或测试。文本告警和规则例外后来在 2026-09-22 的 v0.4.0 专项场景中通过；v0.1.0 的历史验收仍不覆盖这些新增字段。

## v0.3.0：查看规则与不落盘预览

这两个入口使用同一份现有配置，没有新增 JSON 配置字段。以下命令已在 2026-09-22 的当前源码验证中覆盖。

```bash
./build/traceguard list-rules --config configs/traceguard.json
./build/traceguard list-rules --config configs/traceguard.json --format json
./build/traceguard replay --config configs/traceguard.json --input examples/events.jsonl --dry-run --alert-format text
```

`list-rules` 默认 `--format text`，按配置顺序显示全部规则的 ID、启用状态、名称、级别、scope、文件名条件、容器条件、例外、UID 与说明。停用规则仍列出，不表示它们会参与检测；UID 为 0 时显示 0，未限制时显示 `any`。JSON 模式输出完整规则数组，空规则输出 `[]`。它加载并严格校验配置（包括停用规则），但不会启动采集器、查询 Docker 或打开日志。列表的 `--format` 独立于告警的 `alert_format`。

`replay --dry-run` 读取普通输入文件并运行相同的解析、过滤与规则逻辑。省略 `--output`，显式提供该参数（即使空字符串）会报错。程序不会创建／追加输出文件或目录，不获取输出锁，不检查配置输出路径的权限或存在性；配置本身仍接受完整字段校验。标准输出是 JSON/text 告警，标准错误是结束统计及错误信息。告警结构沿用回放格式、事件保留 `replay: true`，是否落盘由命令及统计 `mode` 区分，不能只凭 stdout 告警推断已写文件。

| 预览统计 | 含义 |
| --- | --- |
| `mode` | 固定 `replay-dry-run` |
| `received`、`host_filtered`、`unknown`、`unknown_reasons` | 沿用普通回放的读取、过滤及原因统计 |
| `saved`、`alerts` | 始终为 0，表示没有写入事件／告警文件；`alerts_by_rule` 不出现 |
| `preview_alerts`、`preview_alerts_by_rule` | 预览匹配的告警数与规则分布，每条在尝试输出终端前增加；没有预览告警时省略这两个字段 |
| `excluded_alerts`、`excluded_by_rule` | 预览中满足正向条件但命中例外的事件－规则次数；不会以原事件落盘作为前提 |

预览保持每行最多 1 MiB、非法内容报出行号、缺失 ID／时间补全及 host 过滤规则。遇到后续坏行或终端输出错误时停止并返回错误；此前可能已经输出部分告警和统计，不能把它们当作完整成功结果。输入文件应已经停止追加，程序不锁定输入文件，也不提供实时跟随。输入权限仍由操作系统控制；如果自行使用 shell 重定向，不要把 stdout/stderr 指向输入文件。

该预览命令用于调整规则。2026-09-22 已使用 v0.4.0 专项夹具验证预览统计、文本告警和容器名例外；结果见 [最新验证报告](../docs/validation/2026-09-22/REPORT.md)。原 v0.1.0 报告保持原样。

## v0.4.0：root 包管理器场景

默认配置新增 `docker-root-package-manager`，匹配已经确认属于 Docker、主机侧 UID 为 0，且文件名最后一段为以下操作系统包管理器之一的成功 exec：

```text
apt apt-get dpkg apk dnf yum rpm microdnf zypper pacman
```

这条规则使用现有字段组合，没有特殊代码分支。它的告警准确含义是“root 在容器中启动了包管理器”，并不证明参数是安装命令、安装成功或行为恶意。`apt-get --version` 也会命中；非 root、host、unknown 和未列出的程序不会命中。完整的正反对照、分析步骤与误报／漏报边界见 [场景说明](../docs/SCENARIOS.md)。

若某个固定维护容器确实需要反复执行包管理器，可在该规则添加 `exclude_container_names`。例外只按已确认的精确容器名匹配，原始事件仍保留；不要把动态生产容器普遍加入例外，也不要把容器名当作不可绕过的安全身份。

本规则和配套合成输入已于 2026-09-22 完成配置校验、规则列表、不落盘回放、容器名例外和真实容器采集。root 正例产生一条新规则告警，非 root 和普通进程对照均未产生该规则告警；证据见 [v0.4.0 验证报告](../docs/validation/2026-09-22/REPORT.md)。v0.1.0 验证报告中的默认配置仍只有当时的两条规则。

## 输出权限与恢复边界

在 Linux 上，新建最终输出目录请求权限 `0700`，新建 `events.jsonl`、`alerts.jsonl` 及 `.traceguard.lock` 请求 `0600`。已有目录和文件必须已分别为 `0700` 和 `0600`，程序不会改变它们的权限；不符合条件会报错。建议使用新的专用输出目录，不要把仓库根目录配置为 `output_dir`。拒绝最终输出目录和日志文件为符号链接，拒绝设备、FIFO 等非普通日志文件。父级目录应由可信用户管理；程序不防御有权改写父级目录的用户。

Linux 上使用 `.traceguard.lock` 的非阻塞独占锁，拒绝两个 TraceGuard 实时监控或回放进程同时写入相同目录。退出时先同步、关闭日志，再关闭锁文件释放锁；初始化失败也释放已经获取的锁。锁文件会保留在目录中，不删除它，残留文件本身不表示仍有进程占用。进程被终止时内核会释放其文件锁。锁属于协作式锁，不能阻止其他不遵守锁约定的程序直接改写日志。

Ubuntu 虚拟机共享文件夹可能不支持所需的 Unix 权限和锁，建议将项目复制到 Ubuntu 本地文件系统再构建运行。非 Linux 平台的文件输出仅供离线回放，不提供 Linux 的权限检查、`O_NOFOLLOW` 和目录独占锁保证，每个进程必须使用不同输出目录。

日志以追加模式保存，一行一个 JSON 对象。程序退出时同步并关闭两个文件，写入、同步及关闭错误均向调用方返回。没有按条同步磁盘、日志轮转或两份文件之间的事务保证；突然断电可能丢失最近记录，中途写入失败可能留下最后一条不完整记录。排错时先备份原日志并换一个新输出目录，勿把残缺尾行当成完整事件。长期运行需自行管理磁盘空间。
