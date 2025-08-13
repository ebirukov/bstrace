#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


static __always_inline void fill_syscall_args(struct pt_regs *pt_regs, struct syscall_args *args) {
#ifdef __TEST_RUN
    struct pt_regs tmp = {};
    if (bpf_probe_read_user(&tmp, sizeof(tmp), pt_regs) < 0) {
        bpf_probe_read_kernel(&tmp, sizeof(tmp), pt_regs);
    }
    pt_regs = &tmp;
#endif

    args->arg1 = PT_REGS_PARM1_CORE_SYSCALL(pt_regs);
    args->arg2 = PT_REGS_PARM2_CORE_SYSCALL(pt_regs);
    args->arg3 = PT_REGS_PARM3_CORE_SYSCALL(pt_regs);
    args->arg4 = PT_REGS_PARM4_CORE_SYSCALL(pt_regs);
    args->arg5 = PT_REGS_PARM5_CORE_SYSCALL(pt_regs);
    args->arg6 = PT_REGS_PARM6_CORE_SYSCALL(pt_regs);
}