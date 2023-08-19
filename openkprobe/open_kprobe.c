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

SEC("kprobe/sys_openat")
int BPF_KPROBE(kprobe_openat, struct pt_regs *regs) {
	struct event *event = 0;
	event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct event), 0);
	if (!event) {
		return 0;
	}
	char *pathname;
	pathname = (char*) PT_REGS_PARM2_CORE(regs);
	bpf_probe_read_str(&event->path, sizeof(event->path), (void *) pathname);

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->command, sizeof(event->command));
	bpf_ringbuf_submit(event, 0);
	return 0;
}
