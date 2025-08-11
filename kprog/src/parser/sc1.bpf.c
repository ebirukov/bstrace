#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

const int SC_NR = 1;

SEC("raw_tracepoint/sys_enter")
 int read_syscall(struct bpf_raw_tracepoint_args *ctx)
 {
    // args[0] — указатель на pt_regs
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    // Чтение регистров
    int fd = PT_REGS_PARM1_CORE_SYSCALL(regs); // RDI
    unsigned long buf = PT_REGS_PARM2_CORE_SYSCALL(regs); // RSI
    unsigned long size = PT_REGS_PARM3_CORE_SYSCALL(regs); // RDX

    return 0;
 }

char LICENSE[] SEC("license") = "GPL";