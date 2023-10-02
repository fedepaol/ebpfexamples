//go:build ignore

#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

#define PERF_MAX_STACK_DEPTH      127
#define PROFILE_MAPS_SIZE         16384

struct stack_key {
	__u32 pid;
	__s64 stack_id;
	char  comm[16];
};

struct arguments
{
  __u32 pid;
};

struct arguments *unused __attribute__((unused));
struct stack_key *unused1 __attribute__((unused));


struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct arguments);
} params_array SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
  __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
  __uint(max_entries, PROFILE_MAPS_SIZE);
} stacks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct stack_key);
	__type(value, u32);
	__uint(max_entries, PROFILE_MAPS_SIZE);
} counts SEC(".maps");


SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
  u64 id = bpf_get_current_pid_tgid();
  u32 tgid = id >> 32;
  u32 pid = id;
  
  bpf_printk("got event for pid %d", pid);

  struct arguments *args = 0;
  __u32 argsKey = 0;
  args = (struct arguments *)bpf_map_lookup_elem(&params_array, &argsKey);
  if (!args)
  {
    bpf_printk("no args");
    return -1;
  }

  if (pid != args->pid) {
    return 0;
  }

  struct stack_key key;
  key.pid = pid;
  bpf_get_current_comm(&key.comm, sizeof(key.comm));
  key.stack_id = bpf_get_stackid(ctx, &stacks, USER_STACKID_FLAGS);
  
  
  u32* val = bpf_map_lookup_elem(&counts, &key);
  if (val)
    (*val)++;
  else {
    u32 one = 1;
    bpf_map_update_elem(&counts, &key, &one, BPF_NOEXIST);
  }

  return 0;
}
