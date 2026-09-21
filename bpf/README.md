# exec 采集程序

`exec.bpf.c` 挂载 `sched/sched_process_exec`，记录成功的可执行映像替换。
它覆盖成功的 `execve` / `execveat`，不记录执行失败或 shell 内建命令。
运行目标为 Ubuntu 24.04 的小端 amd64 / arm64；编译目标使用 `bpfel`。

## 数据约定

每条 ring buffer 记录固定 304 字节，按下面顺序排列，数值为小端。
Go 解码实现在 `internal/collector/decode.go`。

| 字段 | 偏移 | 长度 | 含义 |
| --- | ---: | ---: | --- |
| timestamp_ns | 0 | 8 | `bpf_ktime_get_ns()` 单调时钟纳秒，不是 Unix 时间 |
| cgroup_id | 8 | 8 | 内核 cgroup ID，不等同于容器 ID |
| pid | 16 | 4 | 宿主 PID 命名空间中的 TGID |
| tid | 20 | 4 | 宿主 PID 命名空间中的线程 ID |
| uid | 24 | 4 | 真实 UID，不是有效 UID |
| gid | 28 | 4 | 真实 GID，不是有效 GID |
| comm | 32 | 16 | 任务名称，最多 15 字节加终止符 |
| filename | 48 | 256 | exec 请求文件名，最多 255 字节加终止符 |

文件名来自 tracepoint 的动态字符串，不保证是绝对路径，也不解析软链接。
读取失败时文件名为空，其他元数据仍然保留；当前 ABI 不单独标记文件名截断。
程序不采集 argv、环境变量、父进程 PID、文件内容或网络数据。

`events` 是 4 MiB ring buffer。`stats` 是单元素 per-CPU array，键 `0` 保存
ring buffer 预留失败次数。用户态按 CPU 求和；该计数不包含后续过滤、
输出错误或程序退出时未消费的缓冲记录。采集程序退出后不会 pin 任何 map。

## Tracepoint 布局来源

本版使用固定 tracepoint 布局，没有依赖 `task_struct`、`vmlinux.h` 或 CO-RE
重定位。内核字段为 8 字节公共头、4 字节 `__data_loc_filename`、4 字节
`pid`、4 字节 `old_pid`；动态字符串位置取 `__data_loc` 的低 16 位。
若目标内核修改了该 tracepoint 布局，需要同步调整采集程序。

参考内核原始定义：

- [Linux v6.8 sched_process_exec 定义](https://github.com/torvalds/linux/blob/v6.8/include/trace/events/sched.h#L375-L395)
- [Linux v6.8 trace_entry 公共头](https://github.com/torvalds/linux/blob/v6.8/include/linux/trace_events.h#L72-L77)
- [成功 exec 后触发 tracepoint](https://github.com/torvalds/linux/blob/v6.8/fs/exec.c#L1701-L1741)

2026-09-21 已在 Ubuntu 24.04.3 x86_64 虚拟机完成真实编译、探针加载和事件采集验证；
实际内核为 7.0.0-31-generic，使用 Go 1.22.2、Clang 18.1.3。
加载前的 tracepoint 布局检查通过，完整集成验证的 16 项检查全部通过。
具体环境、检查结果和证据见 [Ubuntu 验证报告](../docs/validation/2026-09-21/REPORT.md)。

以上结果仅对应报告中的环境与用例。arm64 路径尚未实测，未做吞吐量、延迟或压力测试；
不据此宣称无丢失或兼容所有内核版本。

## v0.3.0 加载失败诊断（未重新测试）

Go 加载器遇到 `*ebpf.VerifierError` 时，会在 `verifier details:` 后展示 cilium/ebpf 提供的详细校验日志，同时保留原始错误。实现遵循 [v0.17.3 官方示例](https://pkg.go.dev/github.com/cilium/ebpf@v0.17.3#example-VerifierError-RetrieveFullLog)，直接格式化内部错误，避免外层包装只显示摘要。它不改变 C 程序、探针或成功加载路径，也不会把其他加载错误一律归因为 verifier。日志能提供多少细节仍取决于内核与库。

本轮未加载 eBPF 或制造失败场景；排错时仍需保留实际内核版本、tracepoint format 和完整错误，不能用此前加载成功的报告证明新增错误路径已经验证。
