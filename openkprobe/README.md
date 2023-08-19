# Monitoring openat events using kprobes

This simple examples uses a kprobe handler to monitor `openat` events and send them to user space using a ringbuf ebpf map.
