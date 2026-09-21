# 开源参考与采用范围

记录日期：2026-09-21。当前源码版本：v0.3.0；本文分别保留两轮优化的来源和采用范围。目标是完善单机 Docker 个人项目，继续使用 C/eBPF + Go、简单 JSON 规则、CLI 和本地 JSONL。

## 第一轮（v0.2.0）：与三个开源项目的关系

| 项目与官方来源 | 与 TraceGuard 的关系 | 本轮采用范围 |
| --- | --- | --- |
| [cilium/ebpf](https://github.com/cilium/ebpf)、[对象加载文档](https://ebpf-go.dev/concepts/loader/) | 已有底层依赖，提供 Go 侧对象加载、挂载和 ring buffer 读取 | 保留现有 `v0.17.3` 和对象加载流程；没有引入整个 Cilium 平台，也没有迁移到 bpf2go |
| [Falco](https://github.com/falcosecurity/falco)、[Rule Exceptions](https://falco.org/docs/concepts/rules/exceptions/) | 规则设计参考，不是运行依赖 | 借鉴“例外属于单条规则”的思想；只增加 `exclude_container_names` 精确容器名名单，沿用本项目 JSON 配置 |
| [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap#bootstrap) | 小型 eBPF 应用和终端展示参考，不是新增依赖 | 借鉴其紧凑事件行的展示方式，增加可选文本告警；未移植 C 用户态加载器、CO-RE、父进程或退出事件采集 |

上表区分项目现有能力与本项目实际采用的部分。本轮按本项目已有接口自行实现，没有复制上述项目的源文件，也未新增 Go 模块依赖。现有 cilium/ebpf 仍承担通用基础能力，TraceGuard 自己负责事件定义、Docker 来源关联、规则、统计、记录和回放的组合。

## 第一轮（v0.2.0）：从参考到实现

### 1. 规则例外与可解释的排除计数

Falco 的例外设计允许对每条检测规则表达已知正常行为。TraceGuard 仅保留一个简单用法：在满足原有来源、文件名、容器及 UID 条件后，按已确认的 Docker 容器名跳过本条规则告警。事件仍保存，其他规则照常评估。

实现位置：`internal/config/config.go`、`internal/rules/engine.go`。新增 `Evaluate` 返回实际告警和被排除规则 ID，原 `Match` 接口继续可用。`cmd/traceguard/pipeline.go` 统计 `excluded_alerts` 与 `excluded_by_rule`，让用户知道例外是否生效。默认配置没有例外。

### 2. 观测结果的分类统计

这是在 TraceGuard 已有 `source.reason` 和状态计数上的增量，不将它归为从某个开源项目移植的功能。首轮真实记录有 86 条事件、26 条 unknown；这个现象提示需要更方便地区分原因，但不能据此断言这些事件都来自同一种故障。

实现位置：`cmd/traceguard/pipeline.go`。新增 `unknown_reasons` 和 `alerts_by_rule`，沿用 stderr 的 JSON 统计。原因使用固定分类，避免任意回放输入使统计键无限增长；不更改原事件或来源识别策略。

### 3. 适合演示的终端输出

libbpf-bootstrap 的示例以紧凑的终端行展示进程事件。TraceGuard 借鉴这种展示取舍，提供 `--alert-format text`，一行显示时间、规则、容器、PID/UID、文件名、事件 ID 和回放标记；详细证据继续保存在 JSONL。

实现位置：`cmd/traceguard/console.go`、`main.go`、`run.go`、`replay.go`。只使用 Go 标准库，默认 JSON 输出保持兼容；事件与配置中的字符串统一转义，文本不解释为终端控制序列。

## 第二轮（v0.3.0）：规则查看、回放预览与加载诊断

2026-09-21 再次检索了 Falco、cilium/ebpf 与 Tracee 的官方资料，采用与现有代码直接相关的三个做法。Tracee 的策略／输出说明用于对照，本轮没有移植其代码或新增相应依赖。

| 核实的官方能力 | TraceGuard 的小范围实现 | 代码位置 |
| --- | --- | --- |
| [Falco CLI](https://falco.org/docs/reference/daemon/cli-arguments/) 支持 `-L` 列出规则、`-l` 查看单条规则 | `list-rules` 显示当前配置的全部规则（含停用状态、条件及例外），默认文本，可用 `--format json` 导出数组；不启动采集 | `cmd/traceguard/list_rules.go`、`main.go` |
| [Falco 配置源码](https://github.com/falcosecurity/falco/blob/master/falco.yaml) 将 replay 输入及 stdout/file 输出分别配置 | 在已有 JSONL 回放上增加 `--dry-run`，复用规则判断，只向 stdout/stderr 输出，不打开日志或输出目录 | `cmd/traceguard/replay.go`、`pipeline.go` |
| [cilium/ebpf v0.17.3 的 VerifierError 示例](https://pkg.go.dev/github.com/cilium/ebpf@v0.17.3#example-VerifierError-RetrieveFullLog) 使用 `errors.As` 和 `%+v` 读取详细 verifier 错误 | 仅在内核加载失败且错误为 `VerifierError` 时附带库返回的详细日志，保留原错误链，便于定位拒绝原因 | `internal/collector/collector_linux.go` |

**这里的 `replay --dry-run` 是本项目的命令设计。** Falco 自身的 `--dry-run` 不处理事件，用于检查配置；本项目借鉴的是其离线输入与输出通道分离的思路，不能将两者描述为同一功能。

TraceGuard 的预览会处理输入事件，保留 `replay: true`，沿用来源快照、host 过滤和逐规则例外；显式 `--output` 与预览互斥。终端告警格式与普通回放一致，结束统计以 `mode=replay-dry-run` 区分。`saved` 和 `alerts` 仍表示写文件的数量，所以预览中为 0；`preview_alerts`、`preview_alerts_by_rule` 单独记录预览告警，例外计数照常保留。预览不检查输出路径、不创建目录或锁，输入则必须是可读取的普通文件。

这轮仍使用 cilium/ebpf `v0.17.3`，没有升级依赖、改变探针或引入外部分析服务。详细 verifier 日志来自失败时的错误对象，不额外开启成功加载的调试输出；权限、对象路径等其他错误继续保留原诊断。具体日志内容和完整程度取决于内核与依赖库提供的数据。

本轮按用户要求未编译、未运行测试或上述新命令，只进行了源码静态阅读、格式化与文档核对。v0.2.0 和 v0.3.0 都属于待验证增量；v0.1.0 的历史报告与原始证据没有更新。

## 复杂度与验证边界

- 不新增 Web、数据库、消息队列、规则表达式语言、Kubernetes 或自动阻断。
- 暂不迁移 bpf2go/CO-RE，不增加 argv、父子进程链或 exit 探针；这些会扩大构建或内核验证范围。
- 分类统计是本次进程累计，日志追加、缓存刷新窗口、退出不排空和无轮转等既有边界仍保留。
- v0.1.0 的 [Ubuntu 验证报告](validation/2026-09-21/REPORT.md) 及证据保持原样。本轮仅作源码阅读、格式化和文档一致性核对，按用户要求未编译、未测试、未运行程序、未连接虚拟机。
- 新功能的示例属于使用说明，不能当作已经执行的结果。后续验证应单独记录，不覆盖历史报告。
