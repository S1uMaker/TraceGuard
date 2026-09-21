// SPDX-License-Identifier: GPL-2.0-only
// Trace successful execve/execveat image replacements using a stable tracepoint.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Linux trace_entry is 8 bytes; sched_process_exec appends a data_loc string,
// pid, and old_pid. No task_struct offsets or vmlinux.h are required.
// Reference: Linux v6.8 include/trace/events/sched.h, sched_process_exec.
struct sched_process_exec_ctx {
    __u8 common[8];
    __u32 filename_loc;
    __s32 pid;
    __s32 old_pid;
};

// Keep this wire format in sync with internal/collector/decode.go.
struct exec_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 gid;
    char comm[16];
    char filename[256];
};

_Static_assert(sizeof(struct exec_event) == 304, "exec_event ABI changed");
_Static_assert(__builtin_offsetof(struct sched_process_exec_ctx, filename_loc) == 8,
               "unexpected tracepoint filename offset");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

// Key 0 counts records that could not be reserved in the ring buffer.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct sched_process_exec_ctx *ctx)
{
    struct exec_event *event;
    __u64 pid_tgid;
    __u64 uid_gid;
    __u32 filename_offset;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        __u32 key = 0;
        __u64 *dropped = bpf_map_lookup_elem(&stats, &key);

        if (dropped)
            __sync_fetch_and_add(dropped, 1);
        return 0;
    }

    // Initialize the full record, including string tails, before publishing it.
    __builtin_memset(event, 0, sizeof(*event));
    pid_tgid = bpf_get_current_pid_tgid();
    uid_gid = bpf_get_current_uid_gid();
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->pid = pid_tgid >> 32;
    event->tid = (__u32)pid_tgid;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // __data_loc uses its low 16 bits as an offset from the tracepoint record.
    filename_offset = ctx->filename_loc & 0xffff;
    if (bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                                  (const char *)ctx + filename_offset) < 0)
        event->filename[0] = '\0';

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
