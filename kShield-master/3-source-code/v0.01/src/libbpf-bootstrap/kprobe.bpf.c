// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura
 *
 * non-CO-RE rewrite for Linux 5.13.x without BTF (no /sys/kernel/btf/vmlinux).
 * Replaces vmlinux.h with kernel_defs.h.
 * All BPF_CORE_READ → bpf_probe_read_kernel.
 * All bpf_core_field_exists → removed (hardcoded for 5.13 behaviour).
 * CFI hook removed (requires deep task_struct access, not needed for DirtyCred PoC).
 */
#include "kernel_defs.h"          /* replaces vmlinux.h */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "context.h"
#include "filesystem.h"
#include "args.h"
#include "my_string.h"
#include "maps.h"
#include "types.h"

/* ── compat patches ── */
#ifndef typeof
#define typeof __typeof__
#endif
#ifndef EPERM
#define EPERM 1
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EVIL_OPEN_CNT      100
#define MODPROBE_PATH_MAXLEN 64
#define MAY_WRITE   0x00000002
#define MAY_APPEND  0x00000008

const volatile char security_files[MAX_SECURITY_FILE_ID][MAX_CACHED_PATH_SIZE] = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers"
};

const volatile char right_modprobe[15] = {"/sbin/modprobe"};
volatile char previous_modprobe[15]    = {"/sbin/modprobe"};

volatile int should_trace_hooks[MAX_HOOKS_NUM] = {0};
volatile int open_cnt = 0;

/* ── [P5] modprobe_state_map helpers ── */
#define MODPROBE_STATE_KEY 0

static __always_inline u32 get_modprobe_state(void)
{
    u32 key = MODPROBE_STATE_KEY;
    u32 *val = bpf_map_lookup_elem(&modprobe_state_map, &key);
    return val ? *val : 0;
}

static __always_inline void set_modprobe_state(u32 state)
{
    u32 key = MODPROBE_STATE_KEY;
    bpf_map_update_elem(&modprobe_state_map, &key, &state, BPF_ANY);
}

/* PROTOTYPES */
static __always_inline int common_file_modification_ent(struct pt_regs *ctx);
static __always_inline int common_file_modification_ret(struct pt_regs *ctx);

/* ════════════════════════════════════════════════════════
 * TASK_CRED_OVERWRITTEN
 * Hooks: kprobe/commit_creds, kretprobe/commit_creds,
 *        raw_tracepoint/sys_enter, raw_tracepoint/sys_exit
 * ════════════════════════════════════════════════════════ */

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new)
{
    if (!should_trace_hooks[TRACE_COMMIT_CREDS])
        return 0;

    /*
     * [non-CO-RE] Read old uid via BPF helper.
     * At kprobe entry the cred change has NOT happened yet,
     * so bpf_get_current_uid_gid() returns the OLD uid.
     */
    args_t args = {};
    args.args[0] = bpf_get_current_uid_gid() & 0xffffffff;
    save_args(&args, TASK_CRED_OVERWRITTEN);
    return 0;
}

SEC("kretprobe/commit_creds")
int BPF_KPROBE(trace_ret_commit_creds, struct cred *new)
{
    if (!should_trace_hooks[TRACE_RET_COMMIT_CREDS])
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, TASK_CRED_OVERWRITTEN) != 0)
        return 0;
    del_args(TASK_CRED_OVERWRITTEN);

    u32 old_uid = (u32)saved_args.args[0];
    u32 new_uid = bpf_get_current_uid_gid() & 0xffffffff;

    /* [P4] use TGID as map key */
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
    cred_info_t cred_info = {old_uid, new_uid};
    bpf_map_update_elem(&cred_modification_map, &tgid, &cred_info, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    if (!should_trace_hooks[RP_SYS_ENTER])
        return 0;

    u32 pid       = (u32)bpf_get_current_pid_tgid(); /* TID */
    u32 syscall_id = (u32)ctx->args[1];
    u32 uid       = bpf_get_current_uid_gid() & 0xffffffff;

    syscall_mod_key_t key = {syscall_id, pid};
    bpf_map_update_elem(&syscall_trace_map, &key, &uid, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint__sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    if (!should_trace_hooks[RP_SYS_EXIT])
        return 0;

    int ret = 0;
    program_info_t info = {};
    if (init_context(&info.context))
        return 0;

    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];
    u32 syscall_id = 0;
    bpf_probe_read_kernel(&syscall_id, sizeof(syscall_id),
                          &regs->orig_ax);       /* x86_64 orig_ax */

    /* [P4] TID for syscall_trace_map, TGID for cred_modification_map */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid  = (u32)pid_tgid;
    u32 tgid = (u32)(pid_tgid >> 32);
    u32 uid  = bpf_get_current_uid_gid() & 0xffffffff;

    syscall_mod_key_t skey = {syscall_id, tid};
    u32 *old_uid = bpf_map_lookup_elem(&syscall_trace_map, &skey);
    if (!old_uid)
        return 0;

    cred_info_t *changed = bpf_map_lookup_elem(&cred_modification_map, &tgid);
    if (!changed && *old_uid != uid) {
        bpf_printk("illegal cred overwrite! old=%d new=%d", *old_uid, uid);
        bpf_send_signal_thread(9);
        info.context.eventid = TASK_CRED_OVERWRITTEN;
        info.old_uid = *old_uid;
        info.new_uid = uid;
        goto submit;
    } else if (!changed) {
        return 0;
    } else {
        bpf_map_delete_elem(&cred_modification_map, &tgid);
    }
    return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map,
                                BPF_F_CURRENT_CPU, &info, sizeof(info));
    if (ret < 0)
        bpf_printk("perf_event_output error %d", ret);
    return 0;
}

/* ════════════════════════════════════════════════════════
 * EVIL_OPEN  (DirtyCred detection — high-freq security file open)
 * Hooks: kprobe/fd_install, kprobe/do_linkat
 * ════════════════════════════════════════════════════════ */

SEC("kprobe/fd_install")
int BPF_KPROBE(trace_evil_open, unsigned int fd, struct file *file)
{
    if (!should_trace_hooks[TRACE_EVIL_OPEN])
        return 0;

    unsigned short mode = get_inode_mode_from_file(file);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    int ret = 0;
    program_info_t info = {};
    if (init_context(&info.context))
        return 0;

    file_info_t finfo = get_file_info(file);
    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0], sizeof(path.name),
                              finfo.pathname_p);

    for (int i = 0; i < MAX_SECURITY_FILE_ID; i++) {
        if (!my_bpf_strncmp(&path.name[0], sizeof(path.name),
                            (const char *)security_files[i])) {
            /* [P3] atomic increment */
            __sync_fetch_and_add(&open_cnt, 1);
            bpf_printk("evil_open cnt=%d", open_cnt);
            break;
        }
    }

    if (open_cnt > EVIL_OPEN_CNT) {
        open_cnt = 0;
        bpf_send_signal_thread(9);
        info.context.eventid = EVIL_OPEN;
        bpf_printk("EVIL_OPEN KILLED pid=%d", info.context.pid);
        goto submit;
    }
    return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map,
                                BPF_F_CURRENT_CPU, &info, sizeof(info));
    if (ret < 0)
        bpf_printk("perf_event_output error");
    return 0;
}

SEC("kprobe/do_linkat")
int BPF_KPROBE(trace_do_linkat, int olddfd, struct filename *old,
               int newdfd, struct filename *new, int flags)
{
    if (!should_trace_hooks[TRACE_DO_LINKAT])
        return 0;

    /* Read filename->name (offset 0) */
    const char *name_p = NULL;
    bpf_probe_read_kernel(&name_p, sizeof(name_p), &old->name);

    char fname[MAX_CACHED_PATH_SIZE];
    bpf_probe_read_kernel_str(&fname[0], sizeof(fname), name_p);

    for (int i = 0; i < MAX_SECURITY_FILE_ID; i++) {
        if (my_bpf_strncmp(&fname[0], sizeof(fname), (const char *)security_files[i])) {
            bpf_printk("hard link on security file blocked");
            bpf_send_signal_thread(9);
            break;
        }
    }
    return 0;
}

/* ════════════════════════════════════════════════════════
 * MODPROBE_PATH_OVERWRITTEN
 * Hooks: tp/sched/sched_process_exec,
 *        kprobe/proc_dostring (LAYER 1),
 *        kprobe/call_usermodehelper_setup (LAYER 2)
 * ════════════════════════════════════════════════════════ */

SEC("tp/sched/sched_process_exec")
int tp_trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    if (!should_trace_hooks[TP_TRACE_EXEC])
        return 0;

    if (get_modprobe_state())
        bpf_send_signal_thread(20);
    return 0;
}

/* LAYER 1 — sysctl write-time block */
SEC("kprobe/proc_dostring")
int BPF_KPROBE(trace_proc_dostring, struct ctl_table *table, int write)
{
    if (!should_trace_hooks[TRACE_PROC_DOSTRING])
        return 0;
    if (!write)
        return 0;

    unsigned int key = 0;
    unsigned long *modprobe_addr = bpf_map_lookup_elem(&modprobe_path, &key);
    if (!modprobe_addr)
        return 0;

    /* Read ctl_table->data (offset 8) */
    void *table_data = NULL;
    bpf_probe_read_kernel(&table_data, sizeof(table_data), &table->data);

    if ((unsigned long)table_data != *modprobe_addr)
        return 0;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid != 0) {
        bpf_send_signal_thread(9);
        bpf_printk("proc_dostring: non-root modprobe_path write blocked uid=%d", uid);

        int ret = 0;
        program_info_t info = {};
        if (init_context(&info.context))
            return 0;
        info.context.eventid = MODPROBE_PATH_OVERWRITTEN;
        set_modprobe_state(1);

        ret = bpf_perf_event_output(ctx, &program_submit_map,
                                    BPF_F_CURRENT_CPU, &info, sizeof(info));
        if (ret < 0)
            bpf_printk("perf_event_output error %d", ret);
    } else {
        bpf_printk("proc_dostring: root modprobe_path write — logged");
    }
    return 0;
}

/* LAYER 2 — use-time block (closes TOCTOU gap) */
SEC("kprobe/call_usermodehelper_setup")
int BPF_KPROBE(trace_call_usermodehelper_setup, const char *path)
{
    if (!should_trace_hooks[TRACE_CALL_UMH_SETUP])
        return 0;

    if (!get_modprobe_state())
        return 0;

    char exec_path[MODPROBE_PATH_MAXLEN];
    bpf_probe_read_kernel_str(exec_path, sizeof(exec_path), path);

    unsigned int key = 0;
    unsigned long *modprobe_addr = bpf_map_lookup_elem(&modprobe_path, &key);
    if (!modprobe_addr)
        return 0;

    char current_modprobe[MODPROBE_PATH_MAXLEN];
    bpf_probe_read_kernel_str(current_modprobe, sizeof(current_modprobe),
                              (const void *)(*modprobe_addr));

    if (my_bpf_strncmp(&current_modprobe[0], sizeof(current_modprobe),
                       &right_modprobe[0]) != 0 &&
        my_bpf_strncmp(&exec_path[0], sizeof(exec_path),
                       &current_modprobe[0]) == 0) {
        bpf_send_signal_thread(9);
        bpf_printk("call_usermodehelper_setup: evil modprobe blocked: %s",
                   exec_path);

        int ret = 0;
        program_info_t info = {};
        if (init_context(&info.context))
            return 0;
        info.context.eventid = MODPROBE_PATH_OVERWRITTEN;

        ret = bpf_perf_event_output(ctx, &program_submit_map,
                                    BPF_F_CURRENT_CPU, &info, sizeof(info));
        if (ret < 0)
            bpf_printk("perf_event_output error %d", ret);
    }
    return 0;
}

/* ════════════════════════════════════════════════════════
 * FILE_MODIFICATION
 * Hooks: kprobe/fd_install, kprobe/filp_close,
 *        kprobe/file_update_time, kretprobe/file_update_time,
 *        kprobe/file_modified,    kretprobe/file_modified,
 *        lsm/file_permission  (P2 — proactive block)
 * ════════════════════════════════════════════════════════ */

SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install, unsigned int fd, struct file *file)
{
    if (!should_trace_hooks[TRACE_FD_INSTALL])
        return 0;

    unsigned short mode = get_inode_mode_from_file(file);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    file_info_t finfo = get_file_info(file);
    file_mod_key_t fkey = {};
    fkey.inode  = finfo.id.inode;
    fkey.device = finfo.id.device;
    int op = FILE_MODIFICATION_SUBMIT;
    bpf_map_update_elem(&file_modification_map, &fkey, &op, BPF_ANY);
    return 0;
}

SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close, struct file *filp, void *id)
{
    if (!should_trace_hooks[TRACE_FLIP_CLOSE])
        return 0;

    file_info_t finfo = get_file_info(filp);
    file_mod_key_t fkey = {};
    fkey.inode  = finfo.id.inode;
    fkey.device = finfo.id.device;
    bpf_map_delete_elem(&file_modification_map, &fkey);
    return 0;
}

SEC("kprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time)
{
    if (!should_trace_hooks[TRACE_FILE_UPDATE_TIME])
        return 0;
    return common_file_modification_ent(ctx);
}

SEC("kretprobe/file_update_time")
int BPF_KPROBE(trace_ret_file_update_time)
{
    if (!should_trace_hooks[TRACE_RET_FILE_UPDATE_TIME])
        return 0;
    return common_file_modification_ret(ctx);
}

/*
 * file_modified() calls file_update_time() on kernels < 6.
 * On kernel 5.13 f_iocb_flags does NOT exist (added in 6.x),
 * so we always skip this hook to avoid double-counting.
 */
SEC("kprobe/file_modified")
int BPF_KPROBE(trace_file_modified)
{
    if (!should_trace_hooks[TRACE_FILE_MODIFIED])
        return 0;
    /* kernel 5.13 < 6: file_modified() calls file_update_time() internally,
     * so skip to avoid double-submit. */
    return 0;
}

SEC("kretprobe/file_modified")
int BPF_KPROBE(trace_ret_file_modified)
{
    if (!should_trace_hooks[TRACE_RET_FILE_MODIFIED])
        return 0;
    return 0; /* same reason as above */
}

static __always_inline int common_file_modification_ent(struct pt_regs *ctx)
{
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);

    unsigned short mode = get_inode_mode_from_file(file);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    u64 ctime = get_ctime_nanosec_from_file(file);
    args_t args = {};
    args.args[0] = (unsigned long)file;
    args.args[1] = ctime;
    save_args(&args, FILE_MODIFICATION);
    return 0;
}

static __always_inline int common_file_modification_ret(struct pt_regs *ctx)
{
    int ret = 0;
    program_info_t info = {};
    if (init_context(&info.context))
        return 0;

    info.context.eventid = FILE_MODIFICATION;
    info.context.retval  = PT_REGS_RC(ctx);

    args_t saved_args = {};
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;
    del_args(FILE_MODIFICATION);

    struct file *file    = (struct file *)saved_args.args[0];
    u64          old_ctime = saved_args.args[1];

    file_info_t finfo = get_file_info(file);
    file_mod_key_t fkey = {};
    fkey.inode  = finfo.id.inode;
    fkey.device = finfo.id.device;

    int *op = bpf_map_lookup_elem(&file_modification_map, &fkey);
    if (!op || *op == FILE_MODIFICATION_SUBMIT) {
        int done = FILE_MODIFICATION_DONE;
        bpf_map_update_elem(&file_modification_map, &fkey, &done, BPF_ANY);
    } else {
        return 0;
    }

    info.device    = finfo.id.device;
    info.inode     = finfo.id.inode;
    info.old_ctime = old_ctime;
    info.new_ctime = finfo.id.ctime;

    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0], sizeof(path.name),
                              finfo.pathname_p);
    int i;
    for (i = 0; i < MAX_SECURITY_FILE_ID; i++) {
        if (!my_bpf_strncmp(&path.name[0], sizeof(path.name),
                            (const char *)security_files[i])) {
            info.security_file = i;
            break;
        }
    }

    if (i < MAX_SECURITY_FILE_ID) {
        ret = bpf_perf_event_output(ctx, &program_submit_map,
                                    BPF_F_CURRENT_CPU, &info, sizeof(info));
        if (ret < 0)
            bpf_printk("perf_event_output error");
    }
    return 0;
}

/*
 * [P2] LSM proactive block — non-root writes to security files
 * Returns -EPERM before any data is written.
 * Requires CONFIG_BPF_LSM=y in the target kernel.
 */
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission_check, struct file *file, int mask)
{
    if (!should_trace_hooks[LSM_FILE_PERMISSION])
        return 0;
    if (!(mask & MAY_WRITE) && !(mask & MAY_APPEND))
        return 0;

    unsigned short mode = get_inode_mode_from_file(file);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid == 0)
        return 0;

    file_info_t finfo = get_file_info(file);
    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0], sizeof(path.name),
                              finfo.pathname_p);

    for (int i = 0; i < MAX_SECURITY_FILE_ID; i++) {
        if (!my_bpf_strncmp(&path.name[0], sizeof(path.name),
                            (const char *)security_files[i])) {
            bpf_printk("lsm_file_permission: blocked non-root write to %s uid=%d",
                       (const char *)security_files[i], uid);
            return -EPERM;
        }
    }
    return 0;
}
