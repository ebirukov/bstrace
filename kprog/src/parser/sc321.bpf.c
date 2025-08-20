#include "vmlinux.h"
#include "common.h"
#include "testing.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

const int SC_NR = 321;

// Инициализируем память под большую структуру в read-only map
const struct cdata zero_cdata = {};

SEC("raw_tracepoint/sys_enter")
int BPF_PROG(bpf_syscall, struct pt_regs *pt_regs, __s64 syscall_nr) {
    struct syscall_args sc_args = {};
    fill_syscall_args(pt_regs, &sc_args);

    u64 cmd  = sc_args.arg1; // RDI / x0
    u64 attr = sc_args.arg2; // RSI / x1
    u64 size = sc_args.arg3; // RDX / x2

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;

    struct cdata *info = bpf_map_lookup_elem(&sc_data, &tid);
    if (!info) {
        // копируем zero_cdata из read-only map в map sc_data
        bpf_map_update_elem(&sc_data, &tid, &zero_cdata, BPF_ANY);
        info = bpf_map_lookup_elem(&sc_data, &tid);
        if (!info)
            return 0;
    } else {
         // очищаем существующую структуру копированием zero_cdata
         *info = zero_cdata;
     }

    // Заполняем структуру прямо в карте
    info->syscall_nr = syscall_nr;
    info->sc_arg1    = cmd;
    info->sc_arg2    = sc_args.arg2;
    info->sc_arg3    = sc_args.arg3;

    // читаем user-space union bpf_attr
    bpf_probe_read_user(&info->attr, sizeof(info->attr), (void *)attr);

    if (cmd == 6) {
        bpf_printk("pathname_ptr=0x%llx bpf_fd=%u flags=%u\n",
                   info->attr.pathname,
                   info->attr.bpf_fd,
                   info->attr.file_flags);
    }
    if (cmd == 0) {
        bpf_printk("map_type=%u key_size=%u value_size=%u max_entries=%u btf_fd=%u\n",
                   info->attr.map_type,
                   info->attr.key_size,
                   info->attr.value_size,
                   info->attr.max_entries,
                   info->attr.btf_fd);
    }

    bpf_printk("bpf_syscall: cmd=%lu, attr=0x%lx, size=%lu\n", cmd, attr, size);
    return 0;
 }

char LICENSE[] SEC("license") = "GPL";