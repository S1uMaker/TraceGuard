#!/usr/bin/env python3
"""Run real TraceGuard integration checks in its prepared Ubuntu VM.

Run as root from the project directory after `make build`:
    python3 scripts/verify_vm.py --output evidence/run-001

Uses Python's standard library and an already available Docker image. It never
pulls images, edits the production configuration, or removes existing evidence.
Only containers bearing this invocation's random ownership labels are removed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import time
import traceback
import uuid


LABEL_RUN = "io.traceguard.verify.run"
LABEL_OWNER = "io.traceguard.verify.owner"
OWNER = "scripts/verify_vm.py"
CHECK_NAMES = (
    "prerequisites", "initial_ready", "initial_evidence_deadline", "shell_alert", "discovery_alert",
    "sleep_event_no_alert", "second_container_attribution",
    "host_no_docker_alert", "failed_exec_no_event",
    "late_container_attribution", "directory_lock", "graceful_stop",
    "restart_ready", "restart_event", "restart_graceful_stop", "cleanup",
)


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class VerificationError(RuntimeError):
    pass


class Verification:
    def __init__(self, project, output, image):
        self.project = project
        self.output = output
        self.image = image
        self.run_id = uuid.uuid4().hex
        self.binary = project / "build" / "traceguard"
        self.config = output / "config.used.json"
        self.containers = []
        self.processes = []
        self.summary = {
            "run_id": self.run_id,
            "started_at": now(),
            "project": str(project),
            "evidence_dir": str(output),
            "image_requested": image,
            "checks": {
                name: {"status": "FAIL", "detail": "not reached"}
                for name in CHECK_NAMES
            },
            "errors": [],
            "notes": [
                "These checks use real kernel events, not synthetic replay.",
                "The copied test configuration sets include_host=true so the "
                "host negative assertion requires an observed host PID. "
                "Default rules and the production configuration are unchanged.",
                "Negative assertions cover the recorded verification interval, "
                "not all possible executions or a claim of zero event loss.",
            ],
        }

    def save_json(self, name, value):
        (self.output / name).write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    def check(self, name, passed, detail, **evidence):
        self.summary["checks"][name] = {
            "status": "PASS" if passed else "FAIL",
            "detail": detail,
            **evidence,
        }
        print("{} {}: {}".format("PASS" if passed else "FAIL", name, detail), flush=True)
        self.save_json("summary.json", self.summary)

    def error(self, where, exc):
        self.summary["errors"].append({"where": where, "error": str(exc)})

    def command(self, args, timeout=15, required=True):
        """Record each command and its actual result; never invoke a shell."""
        started = time.monotonic()
        proc = subprocess.Popen(
            [str(arg) for arg in args], cwd=self.project,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
        )
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
        except BaseException:
            proc.kill()
            proc.communicate()
            raise
        record = {
            "at": now(), "argv": [str(arg) for arg in args], "pid": proc.pid,
            "returncode": proc.returncode, "timed_out": timed_out,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "stdout": stdout, "stderr": stderr,
        }
        with (self.output / "commands.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        if timed_out or (required and proc.returncode != 0):
            raise VerificationError(
                "command {} {}: {}".format(
                    args, "timed out" if timed_out else "failed", stderr.strip()
                )
            )
        return record

    def prerequisites(self):
        for filename in (self.binary, self.project / "build" / "exec.bpf.o"):
            if not filename.is_file():
                raise VerificationError("missing {}; run make build first".format(filename))
        original = self.project / "configs" / "traceguard.json"
        original_bytes = original.read_bytes()
        (self.output / "config.original.json").write_bytes(original_bytes)
        config = json.loads(original_bytes)
        config["include_host"] = True
        self.save_json("config.used.json", config)
        self.summary["artifacts_sha256"] = {
            str(filename.relative_to(self.project)): hashlib.sha256(filename.read_bytes()).hexdigest()
            for filename in (original, self.binary, self.project / "build" / "exec.bpf.o")
        }
        self.save_json("environment.json", {
            "uname": list(platform.uname()), "euid": os.geteuid(),
            "python": sys.version, "os_release": Path("/etc/os-release").read_text(),
        })
        version = self.command(["docker", "version", "--format", "{{json .}}"])
        self.save_json("docker-version.json", json.loads(version["stdout"]))
        info_format = (
            '{"CgroupVersion":{{json .CgroupVersion}},'
            '"CgroupDriver":{{json .CgroupDriver}},'
            '"ServerVersion":{{json .ServerVersion}},'
            '"KernelVersion":{{json .KernelVersion}},'
            '"Architecture":{{json .Architecture}},'
            '"OperatingSystem":{{json .OperatingSystem}}}'
        )
        info = self.command(["docker", "info", "--format", info_format])
        self.save_json("docker-info.json", json.loads(info["stdout"]))
        image = self.command(["docker", "image", "inspect", self.image])
        metadata = json.loads(image["stdout"])
        self.save_json("image.json", metadata)
        self.summary["image_id"] = metadata[0]["Id"]
        self.command([self.binary, "check-config", "--config", self.config])
        self.command([self.binary, "doctor", "--config", self.config], timeout=20)
        self.check("prerequisites", True, "Built artifacts, local image, configuration and doctor checked")

    def create_container(self, suffix):
        name = "traceguard-verify-{}-{}".format(self.run_id[:12], suffix)
        # Register before creation: a CLI timeout may still leave the container.
        owned = {"name": name, "suffix": suffix, "id": None}
        self.containers.append(owned)
        result = self.command([
            "docker", "run", "--pull=never", "-d", "--name", name,
            "--label", LABEL_RUN + "=" + self.run_id,
            "--label", LABEL_OWNER + "=" + OWNER,
            "--network", "none", self.summary["image_id"], "sleep", "infinity",
        ], timeout=20)
        owned["id"] = result["stdout"].strip()
        if not re.fullmatch(r"[a-f0-9]{64}", owned["id"]):
            raise VerificationError("Docker did not return a full container ID for " + name)
        detail = json.loads(self.command(["docker", "inspect", owned["id"]])["stdout"])
        self.save_json("container-{}-created.json".format(suffix), detail)
        if not detail[0].get("State", {}).get("Running"):
            raise VerificationError("test container is not running: " + name)
        return owned

    def start_collector(self, name, output_name):
        stdout = (self.output / (name + ".stdout.log")).open("wb")
        stderr = (self.output / (name + ".stderr.log")).open("wb")
        try:
            proc = subprocess.Popen(
                [str(self.binary), "run", "--config", str(self.config),
                 "--output", str(self.output / output_name)],
                cwd=self.project, stdin=subprocess.DEVNULL, stdout=stdout,
                stderr=stderr, start_new_session=True,
            )
        except BaseException:
            stdout.close()
            stderr.close()
            raise
        managed = {
            "name": name, "process": proc, "stdout": stdout, "stderr": stderr,
            "directory": self.output / output_name, "stopped": False,
        }
        self.processes.append(managed)
        return managed

    def wait_ready(self, managed, check_name):
        deadline = time.monotonic() + 20
        filename = self.output / (managed["name"] + ".stderr.log")
        while time.monotonic() < deadline:
            if managed["process"].poll() is not None:
                raise VerificationError("{} exited before ready; inspect {}".format(managed["name"], filename))
            if "ready: session=" in filename.read_text(encoding="utf-8", errors="replace"):
                self.check(check_name, True, "Collector reached ready", pid=managed["process"].pid)
                return
            time.sleep(0.1)
        self.check(check_name, False, "Collector did not reach ready within 20 seconds")
        raise VerificationError("collector startup timed out")

    def stop_collector(self, managed, check_name=None):
        if managed["stopped"]:
            return
        proc = managed["process"]
        forced = []
        already_exited = proc.poll() is not None
        if not already_exited:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                forced.append("SIGTERM")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    forced.append("SIGKILL")
                    proc.kill()
                    proc.wait(timeout=3)
        managed["stdout"].close()
        managed["stderr"].close()
        managed["stopped"] = True
        result = {
            "returncode": proc.returncode, "forced_signals": forced,
            "already_exited": already_exited,
        }
        self.summary.setdefault("collector_exits", {})[managed["name"]] = result
        passed = proc.returncode == 0 and not forced and not already_exited
        if check_name:
            self.check(check_name, passed, "Expected clean exit after SIGINT within 10 seconds", **result)
        elif forced or proc.returncode != 0:
            self.error("stop " + managed["name"], result)

    @staticmethod
    def records(directory, name, complete=False):
        path = directory / name
        if not path.exists():
            return []
        # Refuse unexpected volume instead of consuming unbounded verifier RAM.
        if path.stat().st_size > 32 * 1024 * 1024:
            raise VerificationError("verification log exceeds 32 MiB: " + str(path))
        data = path.read_bytes()
        if complete and data and not data.endswith(b"\n"):
            raise VerificationError("closed JSONL log has an incomplete final record: " + str(path))
        lines = data.split(b"\n")[:-1]  # An in-flight final partial line is retried.
        return [json.loads(line) for line in lines if line.strip()]

    def snapshot(self, managed):
        complete = managed["process"].poll() is not None
        return (self.records(managed["directory"], "events.jsonl", complete),
                self.records(managed["directory"], "alerts.jsonl", complete))

    @staticmethod
    def matches(events, container, basename):
        return [event for event in events
                if event.get("source", {}).get("kind") == "docker"
                and event["source"].get("container_id") == container["id"]
                and event["source"].get("container_name") == container["name"]
                and Path(event.get("filename", "")).name == basename]

    @staticmethod
    def matching_alerts(alerts, events, rule_id):
        ids = {event.get("id") for event in events}
        return [alert for alert in alerts if alert.get("event_id") in ids
                and alert.get("rule_id") == rule_id]

    def wait_evidence(self, managed, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while True:
            if managed["process"].poll() is not None:
                raise VerificationError("collector exited while waiting for evidence")
            events, alerts = self.snapshot(managed)
            if predicate(events, alerts):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def execute_checks(self):
        self.prerequisites()
        first = self.create_container("first")
        second = self.create_container("second")
        live = self.start_collector("live", "live-data")
        self.wait_ready(live, "initial_ready")

        self.command(["docker", "exec", first["id"], "/bin/sh", "-c", "echo traceguard-test"])
        self.command(["docker", "exec", first["id"], "/usr/bin/id"])
        self.command(["docker", "exec", first["id"], "/usr/bin/sleep", "1"])
        self.command(["docker", "exec", second["id"], "/usr/bin/id"])
        host = self.command(["/usr/bin/id"])
        missing_name = "/traceguard-verify-missing-" + self.run_id
        failed = self.command(["docker", "exec", first["id"], missing_name], required=False)
        # A subsequent successful exec is a processing barrier for negative cases.
        self.command(["docker", "exec", second["id"], "/usr/bin/sleep", "1"])

        def initial_evidence(events, alerts):
            return (
                self.matching_alerts(alerts, self.matches(events, first, "sh"), "docker-shell")
                and self.matching_alerts(alerts, self.matches(events, first, "id"), "docker-discovery")
                and self.matches(events, first, "sleep")
                and self.matching_alerts(alerts, self.matches(events, second, "id"), "docker-discovery")
                and self.matches(events, second, "sleep")
                and any(event.get("pid") == host["pid"] and Path(event.get("filename", "")).name == "id"
                        for event in events)
            )

        timely_evidence = self.wait_evidence(live, initial_evidence)
        self.check("initial_evidence_deadline", timely_evidence,
                   "Initial positive events, expected alerts and exact host PID must appear within 15 seconds")

        late = self.create_container("late")
        deadline = time.monotonic() + 20
        associated = False
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            self.command(["docker", "exec", late["id"], "/usr/bin/id"], timeout=max(0.1, min(5, remaining)))
            associated = self.wait_evidence(
                live,
                lambda events, alerts: bool(self.matching_alerts(
                    alerts, self.matches(events, late, "id"), "docker-discovery")),
                timeout=max(0, min(1, deadline - time.monotonic())),
            )
            if associated:
                break
        self.check("late_container_attribution", associated,
                   "New container must become attributable and alert within 20 seconds",
                   container_id=late["id"], container_name=late["name"])

        contender = self.command([
            self.binary, "run", "--config", self.config, "--output", live["directory"],
        ], timeout=20, required=False)
        lock_error = contender["returncode"] != 0 and "already in use by another TraceGuard instance" in contender["stderr"]
        self.check("directory_lock", lock_error,
                   "Second instance must fail with the output-directory lock error",
                   returncode=contender["returncode"])
        self.stop_collector(live, "graceful_stop")
        events, alerts = self.snapshot(live)
        self.evaluate_initial(events, alerts, first, second, host, failed, missing_name)
        self.save_json("live-counts.json", {"events": len(events), "alerts": len(alerts)})

        restarted = self.start_collector("restart", "restart-data")
        self.wait_ready(restarted, "restart_ready")
        self.command(["docker", "exec", first["id"], "/usr/bin/id"])
        restart_ok = self.wait_evidence(
            restarted,
            lambda events, alerts: bool(self.matching_alerts(
                alerts, self.matches(events, first, "id"), "docker-discovery")),
        )
        self.check("restart_event", restart_ok, "Restarted collector must save and alert on a real container id exec")
        self.stop_collector(restarted, "restart_graceful_stop")

    def evaluate_initial(self, events, alerts, first, second, host, failed, missing_name):
        shell = self.matches(events, first, "sh")
        discovery = self.matches(events, first, "id")
        sleeps = self.matches(events, first, "sleep")
        second_id = self.matches(events, second, "id")
        self.check("shell_alert", bool(self.matching_alerts(alerts, shell, "docker-shell")),
                   "First container sh must match docker-shell", event_ids=[e["id"] for e in shell])
        self.check("discovery_alert", bool(self.matching_alerts(alerts, discovery, "docker-discovery")),
                   "First container id must match docker-discovery", event_ids=[e["id"] for e in discovery])
        sleep_ids = {event["id"] for event in sleeps}
        self.check("sleep_event_no_alert", bool(sleeps) and not any(a.get("event_id") in sleep_ids for a in alerts),
                   "First container sleep must have an event and no alert", event_ids=sorted(sleep_ids))
        self.check("second_container_attribution", bool(self.matching_alerts(alerts, second_id, "docker-discovery")),
                   "Second container id must carry its own exact container ID and name",
                   event_ids=[e["id"] for e in second_id], expected_container_id=second["id"])
        host_events = [e for e in events if e.get("pid") == host["pid"] and Path(e.get("filename", "")).name == "id"]
        host_ids = {e["id"] for e in host_events}
        wrong_host_alerts = [a for a in alerts if a.get("event_id") in host_ids
                             and a.get("rule_id") in ("docker-shell", "docker-discovery")]
        self.check("host_no_docker_alert", bool(host_events) and not wrong_host_alerts
                   and all(e.get("source", {}).get("kind") != "docker" for e in host_events),
                   "Observed exact host id PID must never receive Docker attribution or a Docker rule alert",
                   host_pid=host["pid"], event_ids=sorted(host_ids),
                   source_kinds=[e.get("source", {}).get("kind") for e in host_events])
        missing_events = [e for e in events if Path(e.get("filename", "")).name == Path(missing_name).name]
        barrier = bool(self.matches(events, second, "sleep"))
        # Docker/runc can print startup diagnostics on stdout (observed with
        # Docker 29.1.3) or stderr. Require the expected failure and target name,
        # but do not mistake a stream-selection difference for a sensor failure.
        failure_output = failed["stdout"] + failed["stderr"]
        self.check("failed_exec_no_event", failed["returncode"] != 0
                   and missing_name in failure_output and not missing_events and barrier,
                   "Nonexistent executable must fail with no successful exec record; later success must be observed",
                   returncode=failed["returncode"], filename=missing_name, later_barrier_observed=barrier,
                   successful_exec_records=len(missing_events),
                   diagnostic_streams=[name for name in ("stdout", "stderr") if missing_name in failed[name]])

    def cleanup(self):
        problems = []
        for managed in reversed(self.processes):
            try:
                self.stop_collector(managed)
            except Exception as exc:
                problems.append("collector {}: {}".format(managed["name"], exc))
        removed = []
        for owned in reversed(self.containers):
            try:
                result = self.command(["docker", "inspect", owned["id"] or owned["name"]], required=False)
                if result["returncode"] != 0:
                    if "No such object" in result["stderr"] or "No such container" in result["stderr"]:
                        continue
                    raise VerificationError(result["stderr"])
                detail = json.loads(result["stdout"])
                self.save_json("container-{}-before-cleanup.json".format(owned["suffix"]), detail)
                actual = detail[0]
                labels = actual.get("Config", {}).get("Labels") or {}
                if labels.get(LABEL_RUN) != self.run_id or labels.get(LABEL_OWNER) != OWNER:
                    raise VerificationError("ownership labels differ; refusing to remove " + owned["name"])
                container_id = actual.get("Id", "")
                if not re.fullmatch(r"[a-f0-9]{64}", container_id):
                    raise VerificationError("invalid inspected container ID; refusing removal")
                # Remove the verified immutable ID, never a name that can be reused.
                self.command(["docker", "rm", "-f", container_id], timeout=20)
                removed.append(container_id)
            except Exception as exc:
                problems.append("container {}: {}".format(owned["name"], exc))
        for problem in problems:
            self.error("cleanup", problem)
        self.check("cleanup", not problems, "Only label-verified containers created by this run were removed",
                   removed_container_ids=removed, problems=problems)

    def run(self):
        try:
            self.execute_checks()
        except BaseException as exc:
            self.error("verification", exc)
            (self.output / "failure-traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
            print("FAIL verification: {}".format(exc), file=sys.stderr, flush=True)
        finally:
            try:
                self.cleanup()
            except BaseException as exc:
                self.error("cleanup interrupted", exc)
            self.summary["finished_at"] = now()
            passed = (not self.summary["errors"] and all(
                check["status"] == "PASS" for check in self.summary["checks"].values()
            ))
            self.summary["status"] = "PASS" if passed else "FAIL"
            self.save_json("summary.json", self.summary)
        print("{}: evidence retained in {}".format(self.summary["status"], self.output), flush=True)
        return 0 if self.summary["status"] == "PASS" else 1


def interrupted(signum, _frame):
    raise KeyboardInterrupt("received signal {}".format(signum))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default="ubuntu:24.04", help="already present Docker image; never pulled")
    parser.add_argument("--output", required=True, type=Path, help="new, independent evidence directory (must not exist)")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run as root in the prepared Ubuntu VM")
    project = Path.cwd().resolve()
    if not (project / "configs" / "traceguard.json").is_file():
        parser.error("run from the TraceGuard project directory")
    output = args.output.expanduser().absolute()
    if output.exists() or output.is_symlink():
        parser.error("--output must be a new directory; existing evidence is never overwritten")
    os.umask(0o077)
    try:
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
    except OSError as exc:
        parser.error("cannot create evidence directory: {}".format(exc))
    signal.signal(signal.SIGTERM, interrupted)
    return Verification(project, output.resolve(), args.image).run()


if __name__ == "__main__":
    sys.exit(main())
