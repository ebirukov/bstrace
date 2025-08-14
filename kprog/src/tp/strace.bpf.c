/*
 * Этот файл реализует eBPF-программу для трассировки системных вызовов.
 *
 * Основные компоненты:
 *
 * 1. Карта sc_parsers:
 *    Тип: BPF_MAP_TYPE_PROG_ARRAY
 *    Содержит eBPF-программы, вызываемые через bpf_tail_call() в зависимости
 *    от номера системного вызова (syscall_nr).
 *    Эти программы реализуют парсинг данных, специфичных для конкретных
 *    системных вызовов, что позволяет:
 *      - уменьшить сложность кода основной точки входа,
 *      - повысить читаемость,
 *      - легко управлять набором обрабатываемых вызовов: чтобы исключить
 *        ненужный системный вызов — достаточно не добавлять его в карту.
 *
 * 2. Карта evt_buf:
 *    Тип: BPF_MAP_TYPE_RINGBUF
 *    Используется для передачи данных из eBPF в пользовательское пространство
 *    через кольцевой буфер.
 *
 * 3. Точка входа sc_enter:
 *    Подписана на raw tracepoint `sys_enter`.
 *    Получает регистры (pt_regs) и номер системного вызова (syscall_nr),
 *    после чего делегирует выполнение соответствующей eBPF-программе из карты
 *    `sc_parsers` с помощью bpf_tail_call().
 *
 * Этот файл работает совместно с поддержкой тестирования, реализованной
 * в `testing.h`, которая позволяет использовать eBPF-программы в
 * пользовательских тестах с корректной интерпретацией регистров.
 */

#include "vmlinux.h"
#include "common.h"
#include "testing.h"
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

/**
 * sc_enter - обработчик события входа в системный вызов
 * @pt_regs: указатель на структуру pt_regs, содержащую аргументы syscall
 * @syscall_nr: номер системного вызова
 *
 * Используется как точка входа на tracepoint `raw_tp/sys_enter`.
 * Выполняет хвостовой вызов в карту `sc_parsers` в зависимости от номера системного вызова.
 * Это позволяет перенаправить выполнение на eBPF-программу, отвечающую за обработку
 * конкретного системного вызова. Если программа не добавлена в `sc_parsers`,
 * функция завершает выполнение без дальнейшей обработки.
 */
SEC("raw_tp/sys_enter")
int BPF_PROG(sc_enter, struct pt_regs *pt_regs, __s64 syscall_nr)
{
    bpf_tail_call(ctx, &sc_parsers, syscall_nr);

    return 0;
}

/**
 * sc_exit - обработчик события выхода из системного вызова
 * @regs: указатель на структуру pt_regs
 * @ret: возвращаемое значение системного вызова
 *
 * Используется как точка входа на tracepoint `raw_tp/sys_exit`.
 * Для вызывающего идентификатор потока (TID),
 * находит связанные с ним сохранённые входные данные (`sc_data`),
 * копирует все данные в кольцевой буфер (`evt_buf`) для дальнейшего их чтения в user-space.
 * Если данные в карте не найдены или не соответствуют ожидаемому syscall —
 * функция завершает выполнение без дальнейшей обработки.
 */
SEC("raw_tp/sys_exit")
int BPF_PROG(sc_exit, struct pt_regs *regs, __s64 ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;

    struct cdata *info = bpf_map_lookup_elem(&sc_data, &tid);
    if (!info) {
        return 0;
    }

    u32 syscall_nr = bpf_get_syscall_nr(regs);
    if (syscall_nr != info->syscall_nr) {
        bpf_printk("skip syscall %lu", syscall_nr);
        return 0;
    }

    info->syscall_ret = ret;

    bpf_printk("syscall %lu returned %ld cmd %lu", info->syscall_nr, info->syscall_ret, info->sc_arg1);

    struct cdata *event = bpf_ringbuf_reserve(&evt_buf, sizeof(*event), 0);
    if (!event) {
        bpf_map_delete_elem(&sc_data, &tid);//удаляем временные данные из карты
        return 0;
    }

    *event = *info;  // копируем данные о системном вызове в кольцевой буфер
    bpf_map_delete_elem(&sc_data, &tid); //удаляем временные данные из карты

    bpf_ringbuf_submit(event, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";