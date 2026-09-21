//go:build linux && (amd64 || arm64)

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"syscall"

	"github.com/zjc20/traceguard/internal/config"
)

func checkRuntime(cfg config.Config) error {
	if os.Geteuid() != 0 {
		return errors.New("live collection requires root; run sudo ./build/traceguard run (replay does not require root)")
	}
	var fs syscall.Statfs_t
	if err := syscall.Statfs(cfg.CgroupRoot, &fs); err != nil {
		return fmt.Errorf("read cgroup filesystem: %w", err)
	}
	if fs.Type != 0x63677270 {
		return errors.New("cgroup_root must be a cgroup v2 filesystem; cgroup v1 is unsupported")
	}
	if _, err := os.Stat(filepath.Join(cfg.CgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("cgroup v2 controllers are unavailable: %w", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.ProcRoot, "1", "cgroup")); err != nil {
		return fmt.Errorf("host proc filesystem is unavailable: %w", err)
	}
	info, err := os.Stat(cfg.ObjectPath)
	if err != nil {
		return fmt.Errorf("eBPF object unavailable; run make build first: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("bpf_object must be a regular ELF object file")
	}
	return checkTracepointFormat()
}

func checkTracepointFormat() error {
	var data []byte
	var err error
	for _, base := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		data, err = os.ReadFile(filepath.Join(base, "events/sched/sched_process_exec/format"))
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("sched_process_exec tracepoint format is unavailable; check tracefs mount and permissions: %w", err)
	}
	// The fixed tracepoint ABI is deliberately checked before loading the C
	// program. Refuse unexpected layouts instead of decoding wrong fields.
	patterns := []string{
		`field:__data_loc\s+char\[\]\s+filename;\s*offset:8;\s*size:4;`,
		`field:(?:pid_t|int)\s+pid;\s*offset:12;\s*size:4;`,
		`field:(?:pid_t|int)\s+old_pid;\s*offset:16;\s*size:4;`,
	}
	for _, pattern := range patterns {
		if !regexp.MustCompile(pattern).Match(data) {
			return errors.New("unsupported sched_process_exec tracepoint layout; compare its format with bpf/exec.bpf.c")
		}
	}
	return nil
}
