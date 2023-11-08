#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf__custom_printk(fmt, ...)                            \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})


SEC("tracepoint/syscalls/sys_exit_open")
int tracepoint__syscalls__sys_exit_open(struct trace_event_raw_sys_exit* ctx)
{
	bpf__custom_printk("Hello world1");
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int tracepoint__syscalls__sys_exit_openat(struct trace_event_raw_sys_exit* ctx)
{
	bpf__custom_printk("Hello world2");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";