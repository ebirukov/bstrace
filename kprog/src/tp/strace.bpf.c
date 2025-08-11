#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct {
     __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
     __uint(key_size, sizeof(u32));
     __uint(max_entries, 400);
     __array(values, u32 (void *));
} sc_parsers SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} evt_buf SEC(".maps");

SEC("raw_tp/sys_enter")
int BPF_PROG(sc_enter, struct pt_regs *regs, __s64 syscall_nr)
{
    bpf_tail_call(ctx, &sc_parsers, syscall_nr);

    return 0;
}

SEC("raw_tp/sys_exit")
int BPF_PROG(sc_exit, struct pt_regs *regs, __s64 ret)
{
    unsigned long syscall_nr = BPF_CORE_READ(regs, orig_ax);
    if (syscall_nr != 321 /*&& syscall_nr != 1*/)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;

    struct cdata *info = bpf_map_lookup_elem(&sc_data, &tid);
    if (!info) {
        bpf_printk("syscall no info\n");

        return 0;
    }

    info->syscall_ret = ret;

    bpf_printk("syscall %lu returned %ld cmd %lu", info->syscall_nr, info->syscall_ret, info->sc_arg1);

    struct cdata *event = bpf_ringbuf_reserve(&evt_buf, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&sc_data, &tid);

        return 0;
    }

    *event = *info;  // копируем данные о системном вызове в кольцевой буфер

    bpf_map_delete_elem(&sc_data, &tid);

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";