/*
 * Этот файл содержит вспомогательные функции и макросы для
 * поддержки прозрачного тестирования eBPF-программ,
 * работающих с системными вызовами и регистрами pt_regs.
 *
 * В режиме тестирования (__TEST_RUN) чтение полей структуры pt_regs
 * производится через bpf_probe_read_user(), т.к. регистры копируются из
 * userspace, а не из ядра.
 * В обычном режиме используется BPF_CORE_READ() для прямого доступа.
 *
 * Это обеспечивает единую точку доступа к данным регистров для
 * различных архитектур и режимов запуска, упрощая код eBPF-программ.
 *
 * Примеры:
 *  - bpf_get_syscall_nr(): возвращает номер системного вызова,
 *    учитывая архитектуру и режим запуска.
 *  - fill_syscall_args(): заполняет структуру аргументов системного
 *    вызова безопасно копируя данные при необходимости.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifdef __TEST_RUN
#define BPF_CORE_READ_AUTO(ptr, field) BPF_CORE_READ_USER(ptr, field)
#else
#define BPF_CORE_READ_AUTO(ptr, field) BPF_CORE_READ(ptr, field)
#endif

/**
 * bpf_get_syscall_nr - получить номер системного вызова из pt_regs
 * @regs: указатель на структуру pt_regs
 *
 * Возвращает номер системного вызова с учётом архитектуры CPU и режима запуска.
 * В режиме тестирования данные читаются из userspace.
 */
static __always_inline u32 bpf_get_syscall_nr(struct pt_regs *regs) {
#if defined(__TARGET_ARCH_x86)
    return BPF_CORE_READ_AUTO(regs, orig_ax);
#elif defined(__TARGET_ARCH_arm64)
    return BPF_CORE_READ_AUTO(regs, syscallno);
#elif defined(__TARGET_ARCH_s390)
    return BPF_CORE_READ_AUTO(regs, int_code) >> 16;
#elif defined(__TARGET_ARCH_riscv)
    return BPF_CORE_READ_AUTO(regs, a7);
#else
    #error "Unsupported target architecture for syscall number extraction"
#endif
};

/**
 * fill_syscall_args - безопасно заполнить структуру аргументов системного вызова
 * @pt_regs: указатель на структуру pt_regs
 * @args: указатель на структуру syscall_args для заполнения
 *
 * В режиме тестирования копирует данные из userspace, иначе использует данные напрямую.
 */
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