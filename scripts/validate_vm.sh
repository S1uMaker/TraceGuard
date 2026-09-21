#!/usr/bin/env bash
# One explicit sudo invocation prepares Ubuntu and runs the bounded test suite.
set -Eeuo pipefail

if [[ ${EUID} -ne 0 || -z ${SUDO_USER:-} || ${SUDO_USER} == root ]]; then
    echo 'Run this script with sudo from your normal Ubuntu user account.' >&2
    exit 1
fi

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$project_dir"
operator=${SUDO_USER}
run_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
results="$project_dir/build/validation/$run_id"
if [[ ! -e "$project_dir/build" ]]; then
    install -d -m 755 -o "$SUDO_UID" -g "$SUDO_GID" "$project_dir/build"
fi
mkdir -p -- "$project_dir/build/validation"
mkdir -m 700 -- "$results"
chown "$SUDO_UID:$SUDO_GID" "$results"
touch "$results/bootstrap.log"
chmod 600 "$results/bootstrap.log"
chown "$SUDO_UID:$SUDO_GID" "$results/bootstrap.log"
printf '%s\n' "$results" > "$project_dir/build/validation/latest.txt"
chmod 644 "$project_dir/build/validation/latest.txt"
exec > >(tee -a "$results/bootstrap.log") 2>&1

phase=starting
finish() {
    result=$?
    trap - EXIT
    python3 - "$results/status.json" "$phase" "$result" <<'PY'
import datetime, json, os, pathlib, sys
target, phase, code = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
target.write_text(json.dumps({"finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "phase": phase, "exit_code": code, "passed": code == 0}, indent=2) + "\n")
os.chmod(target, 0o600)
PY
    # This directory was created exclusively for this invocation above.
    chown -R "$SUDO_UID:$SUDO_GID" "$results"
    echo "Validation finished: exit=$result phase=$phase results=$results"
    exit "$result"
}
trap finish EXIT

echo "TraceGuard validation: $run_id"
echo "Project: $project_dir"
phase=environment
{
    date -u --iso-8601=seconds
    cat /etc/os-release
    uname -a
    stat -fc %T /sys/fs/cgroup
    docker version
    docker info --format 'Cgroup={{.CgroupVersion}} Driver={{.CgroupDriver}}'
} > "$results/environment.txt"

phase=dependencies
packages=(build-essential clang llvm libbpf-dev linux-libc-dev golang-go)
missing=()
for package in "${packages[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed'; then
        missing+=("$package")
    fi
done
if ((${#missing[@]})); then
    echo "Installing missing build packages: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
fi
{
    go version
    clang --version
    gcc --version
    dpkg-query -W "${packages[@]}"
} >> "$results/environment.txt"

phase=build
echo 'Building C/eBPF and Go as the ordinary user.'
runuser -u "$operator" -- make build 2>&1 | tee "$results/build.log"

phase=unit-tests
echo 'Running unit tests, including the Go race detector.'
runuser -u "$operator" -- go test -race -count=1 -v ./... 2>&1 | tee "$results/unit-tests.log"
phase=vet
runuser -u "$operator" -- go vet ./... 2>&1 | tee "$results/vet.log"

phase=configuration
runuser -u "$operator" -- ./build/traceguard check-config 2>&1 | tee "$results/config-check.log"

phase=replay
runuser -u "$operator" -- ./build/traceguard replay --input examples/events.jsonl --output "$results/replay" > "$results/replay.stdout.jsonl" 2> "$results/replay.stderr.log"
python3 - "$results" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
events = [json.loads(line) for line in (root / 'replay/events.jsonl').read_text().splitlines()]
alerts = [json.loads(line) for line in (root / 'replay/alerts.jsonl').read_text().splitlines()]
assert len(events) == 3, f'Expected three replay events, got {len(events)}'
assert len(alerts) == 1, f'Expected one replay alert, got {len(alerts)}'
assert all(event.get('replay') is True for event in events)
assert alerts[0]['rule_id'] == 'docker-shell'
assert alerts[0]['event']['replay'] is True
assert alerts[0]['event']['source']['kind'] == 'docker'
(root / 'replay-check.json').write_text(json.dumps({'passed': True, 'events': 3, 'alerts': 1, 'rule_id': 'docker-shell'}, indent=2) + '\n')
print('Replay assertions passed: 3 events, 1 docker-shell alert, replay markers present.')
PY

phase=doctor
if ! mountpoint -q /sys/kernel/tracing && ! mountpoint -q /sys/kernel/debug/tracing; then
    mount -t tracefs tracefs /sys/kernel/tracing
fi
./build/traceguard doctor 2>&1 | tee "$results/doctor.log"
if [[ -r /sys/kernel/tracing/events/sched/sched_process_exec/format ]]; then
    cat /sys/kernel/tracing/events/sched/sched_process_exec/format > "$results/tracepoint-format.txt"
else
    cat /sys/kernel/debug/tracing/events/sched/sched_process_exec/format > "$results/tracepoint-format.txt"
fi

phase=integration
docker image inspect ubuntu:24.04 > "$results/image-inspect.json"
python3 scripts/verify_vm.py --image ubuntu:24.04 --output "$results/integration"

phase=completed
echo 'All configured validation stages completed successfully.'
