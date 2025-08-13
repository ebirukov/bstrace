#include "vmlinux.h"
#include "common.h"
#include "testing.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

const int SC_NR = 0;

SEC("raw_tracepoint/sys_enter")
 int BPF_PROG(read_syscall, struct pt_regs *pt_regs, __s64 syscall_nr)
 {
    return 0;
 }

char LICENSE[] SEC("license") = "GPL";