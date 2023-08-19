//go:build ignore

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event  {
    u32 pid;
    u8 command[64];
    u8 path[64];
};

struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ring_buffer SEC(".maps");

// Written after /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct openat_ctx {
	unsigned short common_type;
	unsigned char common_flags;
	unsigned char common_preempt_count;
	int common_pid;

	int __syscall_nr;
	int dfd;
	const char * filename;
	int flags;
	umode_t mode;
};

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(const struct openat_ctx *ctx) {
	struct event *event = 0;
	event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
	if (!event) {
		return 0;
	}
	bpf_probe_read_str(&event->path, sizeof(event->path), (void *) ctx->filename);

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->command, sizeof(event->command));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
