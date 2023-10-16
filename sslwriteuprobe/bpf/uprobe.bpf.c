// go:build ignore

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct arguments
{
    __u32 pid;
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct arguments);
} params_array SEC(".maps");

struct active_ssl_buf
{
    uintptr_t buf;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, struct active_ssl_buf);
    __uint(max_entries, 1024);
} active_ssl_write_args_map SEC(".maps");

#define MAX_DATA_SIZE_OPENSSL 1024 * 4

struct ssl_data_event_t
{
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u8 data[MAX_DATA_SIZE_OPENSSL];
    s32 data_len;
    u8 comm[TASK_COMM_LEN];
};

struct ssl_data_event_t *unused __attribute__((unused));

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ring_buffer SEC(".maps");

static int process_SSL_data(struct pt_regs *ctx, u64 id,
                            const char *buf)
{
    int len = (int)PT_REGS_RC(ctx);
    if (len < 0)
    {
        return 0;
    }

    bpf_printk("openssl process_SSL_data len :%d buf %s\n", len, buf);

    struct ssl_data_event_t *event = 0;
    event = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct ssl_data_event_t), 0);
    if (!event)
    {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;

    event->data_len =
        (len < MAX_DATA_SIZE_OPENSSL ? (len & (MAX_DATA_SIZE_OPENSSL - 1))
                                     : MAX_DATA_SIZE_OPENSSL);
    bpf_probe_read_user(event->data, event->data_len, buf);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/SSL_write")
int probe_entry_SSL_write(struct pt_regs *ctx)
{
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;

    struct arguments *args = 0;
    __u32 argsKey = 0;
    args = (struct arguments *)bpf_map_lookup_elem(&params_array, &argsKey);
    if (!args)
    {
        bpf_printk("no args");
        return -1;
    }
    if (args->pid != 0 && args->pid != pid)
    {
        return 0;
    }

    bpf_printk("openssl uprobe/SSL_write pid :%d\n", pid);

    const char *buf = (const char *)PT_REGS_PARM2(ctx);
    struct active_ssl_buf active_ssl_buf_t;
    active_ssl_buf_t.buf = (uintptr_t)buf;
    bpf_map_update_elem(&active_ssl_write_args_map, &current_pid_tgid,
                        &active_ssl_buf_t, BPF_ANY);

    return 0;
}

SEC("uretprobe/SSL_write")
int probe_ret_SSL_write(struct pt_regs *ctx)
{
    u64 current_pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = current_pid_tgid >> 32;
    u64 current_uid_gid = bpf_get_current_uid_gid();

    struct arguments *args = 0;
    __u32 argsKey = 0;
    args = (struct arguments *)bpf_map_lookup_elem(&params_array, &argsKey);
    if (!args)
    {
        bpf_printk("no args");
        return -1;
    }
    if (args->pid != 0 && args->pid != pid)
    {
        return 0;
    }
    bpf_printk("openssl uretprobe/SSL_write pid :%d\n", pid);
    struct active_ssl_buf *active_ssl_buf_t =
        bpf_map_lookup_elem(&active_ssl_write_args_map, &current_pid_tgid);
    if (active_ssl_buf_t != NULL)
    {
        const char *buf;
        bpf_probe_read(&buf, sizeof(const char *), &active_ssl_buf_t->buf);
        process_SSL_data(ctx, current_pid_tgid, buf);
    }
    bpf_map_delete_elem(&active_ssl_write_args_map, &current_pid_tgid);
    return 0;
}