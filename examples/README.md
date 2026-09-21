# 合成回放样例

`events.jsonl` 的三行都是手工构造的数据，不是真实运行证据；时间、PID、cgroup ID 和容器 ID 均为示例。它们用于离线解释 JSON 结构及规则边界，不能证明 eBPF 采集、Docker 关联或性能已经验证。

使用默认配置回放至全新的输出目录，预期保留 3 个事件并产生 1 条 `docker-shell` 告警：

| 样例 | 预期 |
| --- | --- |
| Docker 来源执行 `/bin/sh` | 命中 `docker-shell`，`warning` |
| Docker 来源执行 `/usr/bin/sleep` | 保留事件，不告警 |
| 未知来源执行 `/bin/sh` | 保留事件，不匹配 `scope=docker` 的规则 |

2026-09-21 已使用 v0.1.0 在 Ubuntu 24.04.3 虚拟机实际执行该回放：保留 3 个事件、产生 1 条
`docker-shell` 告警，事件及告警内嵌事件的 `replay: true` 标记检查通过。
结果及独立的真实采集验证见 [Ubuntu 验证报告](../docs/validation/2026-09-21/REPORT.md)；
本文件中的样例仍是合成数据。

具体回放命令见仓库根目录 README。输出使用追加模式，重复运行到同一目录会累积记录；
比较条数时每次使用新的目录。回放事件中的 `replay: true` 标记应保留，
告警内嵌的事件也带有该标记。

v0.2.0 可选 `--alert-format text` 只改变终端显示，不改样例或保存的 JSONL。样例中的 unknown 原因是解释性文字，新增统计会归入 `unknown_reasons.other`；若在配置副本的 shell 规则中用 `exclude_container_names` 排除 `traceguard-demo`，预期仍保存三个事件，但 shell 告警改为一次例外计数。以上为新增功能预期，本轮按要求未回放或测试，不属于前述历史验证结果。
