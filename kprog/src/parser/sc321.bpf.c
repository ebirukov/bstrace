#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

const int SC_NR = 321;

SEC("raw_tracepoint/sys_enter")
 int bpf_syscall(struct bpf_raw_tracepoint_args *ctx)
 {
    union bpf_attr bpf_attr = {};
    // args[0] — указатель на pt_regs
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    // Чтение регистров
    u64 cmd = PT_REGS_PARM1_CORE_SYSCALL(regs); // RDI
    u64 attr = PT_REGS_PARM2_CORE_SYSCALL(regs); // RSI
    u64 size = PT_REGS_PARM3_CORE_SYSCALL(regs); // RDX
    bpf_probe_read_user(&bpf_attr, sizeof(bpf_attr), (void *)attr);
    if (cmd == 6) {
        bpf_printk("pathname_ptr=0x%llx bpf_fd=%u flags=%u path_fd=%u\n",
                   bpf_attr.pathname, bpf_attr.bpf_fd, bpf_attr.file_flags, bpf_attr.path_fd);
    }
    if (cmd == 0) {
        bpf_printk("map_type=%u key_size=%u value_size=%u max_entries=%u btf_fd=%u\n",
                   bpf_attr.map_type, bpf_attr.key_size, bpf_attr.value_size, bpf_attr.max_entries, bpf_attr.btf_fd);
    }

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid; // младшие 32 бита - tid

    struct cdata info = {};
    info.syscall_nr=321;
    info.attr=bpf_attr;
    info.sc_arg1=cmd;

    bpf_map_update_elem(&sc_data, &tid, &info, BPF_ANY);

    bpf_printk("bpf_syscall: cmd=%lu, attr=0x%lx, size=%lu\n", cmd, attr, size);
    return 0;
 }

char LICENSE[] SEC("license") = "GPL";