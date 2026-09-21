# Ubuntu 首次运行与演示记录

本文件用于手工演示与再次复现。2026-09-21 已通过对应的自动化场景，详见 [实际验证报告](validation/2026-09-21/REPORT.md)；自动化采用独立随机容器名，不是下文固定演示名称。先完成 [README](../README.md) 的依赖安装和构建，命令从 Ubuntu 本地 `~/TraceGuard` 目录执行。下表“未填写”供你下次亲自演示时记录。

上述历史结果对应 v0.1.0。v0.2.0 新增文本输出、规则例外和分类统计；v0.3.0 新增规则列表、回放预览和内核加载诊断。两轮增量均未重新编译、演示或测试；使用新选项前需同步并重新构建源码。

## 固定终端分工

| 终端 | 用途 |
| --- | --- |
| A：采集端 | 运行 TraceGuard，观察告警，最后 Ctrl+C |
| B：行为端 | 创建测试容器并执行触发命令 |
| C：查看端 | 查询 JSONL，记录环境、实际结果和问题 |

## 1. B 终端先准备两个来源

```bash
sudo docker run -d --name traceguard-demo --network none ubuntu:24.04 sleep infinity
sudo docker run -d --name traceguard-control --network none ubuntu:24.04 sleep infinity
```

同名容器已存在时先查看状态；容器适用于本项目时可 `sudo docker start traceguard-demo traceguard-control` 复用。首次镜像下载需要网络；演示中的容器运行时使用 `--network none`。

## 2. A 终端启动

每次演示换一个不存在的新目录，防止把本次计数与旧数据混在一起：

```bash
sudo ./build/traceguard doctor
sudo ./build/traceguard run --output data-demo-01
```

等待 `ready`。它表示本轮初始化和附加已完成，仍需下一步用真实事件验证链路。

v0.2.0 手工展示时可在这条 `run` 命令后添加 `--alert-format text`，在同一次采集中使用简洁文本告警；保留默认 JSON 也可以。两种方式都保存完整 JSONL，无需为切换显示而同时启动两个采集器。

## 3. B 终端依次执行

```bash
# 应触发 shell 规则
sudo docker exec traceguard-demo /bin/sh -c 'echo demo-shell'

# 应触发 discovery 规则
sudo docker exec traceguard-demo /usr/bin/id

# 对照：应有事件，没有默认规则告警
sudo docker exec traceguard-demo /usr/bin/sleep 1

# 第二个容器：应触发同一规则，但来源必须是 traceguard-control
sudo docker exec traceguard-control /usr/bin/id

# 宿主机对照：不应触发 docker 范围的规则
/usr/bin/id

# 执行失败：预期 Docker 报错，不产生该文件名的成功 exec 事件
sudo docker exec traceguard-demo /traceguard-does-not-exist
```

`docker exec` 及运行时自身也可能在宿主机执行新进程；不要把总事件数简单当作测试命令数。以容器名、filename 和 rule_id 核对。最后一条命令预期返回非零状态，不应因此重装环境。

## 4. C 终端查看记录

```bash
sudo jq -c 'select(.source.container_name == "traceguard-demo") | {id, filename, source}' data-demo-01/events.jsonl
sudo jq -c '{rule_id, event_id, filename: .event.filename, container: .event.source.container_name, evidence}' data-demo-01/alerts.jsonl
sudo jq -c 'select(.source.kind == "unknown") | {filename, source}' data-demo-01/events.jsonl
```

核对完成后暂时保持 A 终端继续采集，下面还要演示新容器。没有观察到事件时先定位原因，不能直接写“行为没有发生”。

| 待核对项目 | 预期 | 下次手工演示记录 |
| --- | --- | --- |
| demo `/bin/sh` | source=docker，容器正确，docker-shell 告警 | 未填写 |
| demo `/usr/bin/id` | docker-discovery 告警 | 未填写 |
| demo `/usr/bin/sleep` | 有事件，无默认规则告警 | 未填写 |
| control `/usr/bin/id` | 归属 control，不能串到 demo | 未填写 |
| host `/usr/bin/id` | 不产生 docker 范围告警 | 未填写 |
| 不存在的文件 | 无该文件名的成功 exec 事件 | 未填写 |
| Ctrl+C 后再次启动 | 正常释放资源，可再次运行 | 未填写 |

## 5. 新容器与配置异常

保持 A 采集时，在 B 中创建另一个长期运行容器，等待缓存刷新后再执行行为。下面的 6 秒是演示等待值，默认每 5 秒发起刷新，Docker 请求与扫描本身还需要时间；若来源仍为 unknown，应检查刷新错误并等待后再次执行：

```bash
sudo docker run -d --name traceguard-late --network none ubuntu:24.04 sleep infinity
sleep 6
sudo docker exec traceguard-late /usr/bin/id
```

容器刚启动的 `sleep` 事件可能为 unknown；刷新后的 `id` 应关联到新容器。若不能关联，保留对应 `source.reason` 和刷新错误。首版不保证识别在两次刷新间创建并退出的极短容器。

核对完成后在 A 终端按 `Ctrl+C`。保存退出统计，尤其是 `received`、`saved`、`host_filtered`、`unknown`、`alerts` 和 `kernel_dropped`。它们是本次进程的计数，不是输出目录历史总数。后续检查重复启动时使用另一个新输出目录。

v0.2.0 还可读取 `unknown_reasons` 定位来源未知的原因，`alerts_by_rule` 查看各规则告警，`excluded_alerts` / `excluded_by_rule` 查看例外次数。这些是新增源码能力，本轮尚未验证。标准错误还包含诊断文字，不要将整个输出流当作纯 JSON。

配置错误场景：复制配置到新文件，故意将某条规则 `scope` 改为 `dockre`，执行 `check-config --config 新文件路径`，应明确报错且不加载采集器。不要修改或删除已有采集证据。

## 6. 离线回放（不作为真实采集证据）

```bash
./build/traceguard replay --input examples/events.jsonl --output data-replay-01
jq -c '{id, replay, filename, source}' data-replay-01/events.jsonl
jq -c '{rule_id, event_id, replay: .event.replay}' data-replay-01/alerts.jsonl
```

在新的空输出目录里，三个合成样例预期输出三个事件、一条 `docker-shell` 告警。Docker sleep 和 unknown shell 不命中默认规则。若回放真实 root 所有的日志，可用 sudo，并使用另一个新目录；回放保留来源快照，不重新查询 Docker。

## 7. 保留证据与收尾

```bash
uname -a
go version
clang --version
sudo docker version
sudo docker info --format 'Cgroup={{.CgroupVersion}} Driver={{.CgroupDriver}}'
sudo docker image inspect ubuntu:24.04 --format '{{json .RepoDigests}}'
```

把上述实际输出、操作时间、使用的配置、日志目录和遇到的问题保存到本地验收记录，可参考 [已有验证报告](validation/2026-09-21/REPORT.md) 的记录方式。镜像标签会更新，记录实际镜像摘要便于复现。

全部完成后，仅对这次专门创建且不再需要的演示容器执行：

```bash
sudo docker stop traceguard-demo traceguard-control
sudo docker rm traceguard-demo traceguard-control
# 若执行了 late 场景，再清理它：
sudo docker stop traceguard-late
sudo docker rm traceguard-late
```

保留 JSONL，不在清理演示容器时删除证据目录。

## 8. 可选：解释规则例外（v0.2.0，尚未执行）

修改配置副本中的一条规则，为其添加 `exclude_container_names`，例如 shell 规则排除 `traceguard-control`；完整字段说明见 [配置文档](../configs/README.md)。使用该副本重新启动后，匹配的 control shell 事件仍应保存，本条 shell 告警应被排除并计入 `excluded_by_rule`；demo 容器和其他规则仍按各自条件判断。保留配置副本才能解释当时的例外决定。

这里只记录新功能的使用方法，没有运行这些操作，也没有将预期写入历史通过记录。回放同样支持例外和 `--alert-format text`，使用输入中的来源快照，不重新识别容器。

## 9. 查看规则与预览告警（v0.3.0，尚未执行）

下面的命令只读取配置和已有样例，不需要启动采集器：

```bash
./build/traceguard list-rules
./build/traceguard list-rules --format json
./build/traceguard replay --input examples/events.jsonl --dry-run --alert-format text
```

`list-rules` 包含启用及禁用规则，展示条件、容器例外和描述。需要查看配置副本时添加 `--config 新文件路径`；默认文本便于阅读，JSON 格式输出完整规则数组。

`replay --dry-run` 使用当前规则评估输入并显示告警，不创建输出目录、日志或锁文件，也不能同时指定 `--output`。默认样例预期产生一条预览告警；退出统计的 `mode` 为 `replay-dry-run`，`saved` 和 `alerts` 都为 0，`preview_alerts` 为 1，`preview_alerts_by_rule.docker-shell` 为 1。预览仍应用宿主机过滤及规则例外，更多字段说明见 [配置文档](../configs/README.md)。

预览使用已有事件的来源快照，不能验证采集或容器归属是否正确。输入应为已停止写入的普通文件；不要把标准输出或标准错误重定向到输入文件。以上是使用说明及预期，本轮没有执行这些命令。
