# Ubuntu 真实验证报告 · 2026-09-21

**最终结果：全部已配置验证阶段通过，退出码 0。** 首次失败记录也原样保留，没有用重跑结果覆盖。

项目目录：`/home/urgot/TraceGuard`。最终完整验收目录：`build/validation/20260921T062733Z-16549/`；结束于北京时间 2026-09-21 14:27:42（UTC 06:27:42）。用户在已登录的终端执行 sudo 入口，日志通过临时 SSH 授权读取。

## 环境与版本

| 项目 | 实际值 |
| --- | --- |
| 系统与内核 | Ubuntu 24.04.3 LTS；7.0.0-31-generic；x86_64 |
| Go / Clang | Go 1.22.2；Clang 18.1.3 |
| Docker / cgroup | Docker 29.1.3；cgroup v2；systemd 驱动 |
| 镜像 | ubuntu:24.04；按本地不可变镜像 ID 创建容器 |
| 镜像 ID | `sha256:6232b38791000e3818b58d8847b5a8f5612d606929e01156dd8febc423e0f2ef` |
| 镜像仓库摘要 | `sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3` |

完整版本输出见 [environment.txt](environment.txt)。仅安装缺少的构建依赖，未升级系统或替换 Docker。测试容器使用 `--network none`，以随机名称和本次专用标签标识。

## 结果

| 阶段 | 实际结果 |
| --- | --- |
| C/eBPF 和 Go 构建 | 成功；保留真实生成的 `go.sum` |
| `go test -race -count=1 -v ./...` | 22 个顶层测试函数及其子场景通过，6 个包有测试；model 包无测试文件 |
| `go vet ./...` | 退出 0，无诊断 |
| 配置校验 / doctor | 通过；真实 eBPF 加载另由集成检查确认 |
| 合成回放 | 3 条事件、1 条 docker-shell 告警，replay 标记正确 |
| 真实集成 | 下列 16 项全部通过 |

| 检查 | 核验依据 |
| --- | --- |
| prerequisites | 对象、程序、镜像、配置和 doctor |
| initial_ready | 真实加载并附加探针后就绪 |
| initial_evidence_deadline | 限时内观察到正例事件、告警和精确宿主 PID |
| shell_alert | 第一容器 sh 命中 docker-shell |
| discovery_alert | 第一容器 id 命中 docker-discovery |
| sleep_event_no_alert | sleep 有事件、无告警 |
| second_container_attribution | 第二容器 id 归属自身完整 ID 和名称 |
| host_no_docker_alert | 精确宿主 PID 的 id 被观察为 host，未归为 Docker、未触发 Docker 规则 |
| failed_exec_no_event | 不存在的文件返回 127、对应成功事件数为 0，并观察到之后的成功命令 |
| late_container_attribution | 采集启动后新建的容器在刷新后正确归属并告警 |
| directory_lock | 同目录第二实例以锁错误退出 |
| graceful_stop | SIGINT 后 10 秒内退出 0，无强制信号 |
| restart_ready | 再次启动并就绪 |
| restart_event | 重启后真实 id 事件与告警保存成功 |
| restart_graceful_stop | 重启实例正常退出，无强制信号 |
| cleanup | 仅删除标签核验属于本次运行的三个容器 |

集成测试使用配置副本将 `include_host` 设为 true，以实际观测到的宿主 PID 验证负例。生产配置和默认规则未改动。事件 ID、进程退出码、容器 ID 和断言细节见 [integration-summary.json](integration-summary.json)。

主采集保存 86 条事件、4 条告警，其中 26 条事件来源 unknown；重启采集保存 4 条事件、1 条告警，其中 2 条 unknown。两次均 `kernel_dropped=0`，原始退出统计见 [主采集](live-statistics.txt) 和 [重启采集](restart-statistics.txt)。这些计数包括运行时和后台行为，不等于测试命令数量；目标事件逐条核验，unknown 不冒充已确认归属。

## 失败与修正经过

首次完整运行 `20260921T061521Z-6104` 有 15 项集成检查通过，只有 `failed_exec_no_event` 失败。原始命令确实返回 127，对应成功事件为零，后续正常命令也被采集到；原因是 Docker 将错误文本输出到 stdout，测试脚本误以为它只能出现在 stderr。

脚本改为同时检查两个输出流，并记录实际诊断流；失败状态、零事件及后续成功事件的要求均保留。最终日志中的 `diagnostic_streams` 为 `["stdout"]`。这次没有修改监控核心来规避失败。

补充输出权限单测时，测试临时目录权限使程序提前拒绝目录，未到达待验证的文件权限分支。夹具显式设为 0700 后，目标断言通过；原始失败日志保存在 `userspace-final/unit-tests-before-fixture-fix.log`。最终完整流程重新执行全部测试与真实集成，见 [status.json](status.json) 和 [unit-tests.txt](unit-tests.txt)。

## 证据文件

- [raw-evidence.tar.gz](raw-evidence.tar.gz)：首次失败、最终通过和补充用户态检查的完整原始日志，包括实际配置、镜像/容器元数据、操作输出、events/alerts JSONL 与摘要。
- [integration-summary.json](integration-summary.json)：最终 16 项检查的结构化结果。
- [status.json](status.json)、[environment.txt](environment.txt)、[unit-tests.txt](unit-tests.txt)、[replay-check.json](replay-check.json)：从最终运行原样复制，日志仅改变扩展名以便随项目保存。
- `raw-evidence.tar.gz` SHA-256：`770ce0a9334ce2bd860462b16d2f306eba2766e92e331d9a8ba79fafa1756d4c`。

产物 SHA-256：Go 程序 `dceebf4dd7f5e264af39c488ae4e028c1ec1ff723383eefd066fd9d35fecde25`；BPF 对象 `d26e95fab5131774604b164cf92e8a8c240231c5f42c5350ea77e67cbe143786`。本次原始证据不含 SSH 私钥或密码；包含本机环境及进程信息，按需要选择用于演示的记录。

## 复现与边界

在 Ubuntu 项目目录、Docker 已运行且本地已有 `ubuntu:24.04` 镜像时，执行：

```bash
sudo bash scripts/validate_vm.sh
```

每次创建新证据目录，不覆盖先前结果，完整说明见 [验证脚本说明](../../../scripts/README.md)。测试容器与采集器已经清理，构建产物、依赖和镜像保留供演示使用。临时 SSH 公钥已撤销，并确认同一密钥的新连接被拒绝；宿主机四个临时密钥文件已删除。远程授权和临时文件清理记录见 [ssh-cleanup.json](ssh-cleanup.json)。

结论限于上述实际环境和记录区间，不涵盖 arm64、其他内核、rootless Docker 或 Kubernetes。未做性能压测、长时间运行及故障注入；负例和零内核预留失败不代表全局零漏报。短寿命容器可能错过刷新，停止时不排空缓冲，文件名规则与 JSONL 持久化的限制仍保留。
