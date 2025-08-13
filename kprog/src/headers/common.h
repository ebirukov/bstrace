#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#pragma once

struct cdata {
    u32 syscall_nr;
    u64 sc_arg1;
    u64 sc_arg2;
    u64 sc_arg3;
    union bpf_attr attr;
    s32 syscall_ret;
};

struct syscall_args {
    __u64 arg1;
    __u64 arg2;
    __u64 arg3;
    __u64 arg4;
    __u64 arg5;
    __u64 arg6;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);      // tid
    __type(value, struct cdata);    // информация о syscall
} sc_data SEC(".maps");