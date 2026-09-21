# Ubuntu 验证脚本

这两个脚本用于真实验证首版实现。Windows 宿主机不执行 eBPF 测试；测试结果以 Ubuntu 中实际生成的日志为准。

## 完整流程

先将项目放到 Ubuntu 本地文件系统，确保 Docker 已运行，且 `ubuntu:24.04` 镜像已在本机。然后从普通用户终端执行：

```bash
sudo bash scripts/validate_vm.sh
```

脚本需要 sudo，因为安装开发依赖和加载 eBPF 需要 root。它会：

1. 记录系统、内核、Docker、cgroup 和构建工具版本。
2. 只安装缺少的 `build-essential`、`clang`、`llvm`、`libbpf-dev`、`linux-libc-dev`、`golang-go`，不执行系统升级或替换 Docker。
3. 以调用 sudo 的普通用户身份构建，执行 `go test -race -count=1 -v ./...` 和 `go vet ./...`。
4. 校验配置、回放三个合成样例，断言事件数、告警数与回放标记。
5. 检查环境并执行真实 eBPF/Docker 集成测试。

每次使用独立的 `build/validation/<UTC时间>-<PID>/` 证据目录；`build/validation/latest.txt` 指向最近一次目录。`bootstrap.log` 保存过程，`status.json` 保存退出状态，某一阶段失败后不会伪称后续阶段通过。脚本结束时将本次证据归还普通用户所有，便于读取。

## 单独执行真实集成测试

环境和构建产物已准备好时，可只执行：

```bash
sudo python3 scripts/verify_vm.py --image ubuntu:24.04 --output build/manual-verification-01
```

输出目录必须不存在。脚本不拉取镜像，按本地镜像 ID 创建本次独有的三个容器，不开放端口。检查包含成功执行的事件、两条默认规则、sleep 对照、第二容器来源、宿主行为、新容器刷新、失败 exec、目录锁、SIGINT 退出及重新启动。

为避免“宿主事件根本没有保存，所以没有告警”的空验证，脚本使用配置副本设置 `include_host=true`，按实际宿主进程 PID 核对负例；原配置和默认规则不改变。测试完成或异常时，都会尝试停止本次采集器，并且只删除通过本次随机标签验证的测试容器。

`summary.json` 提供每项检查及证据关联；原配置、实际配置、程序与对象文件摘要、镜像和容器元数据、事件和告警文件一起保留。这些场景通过也不代表零漏报、生产可用或已经完成性能评测。
