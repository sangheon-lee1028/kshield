#ifndef TASK_H
#define TASK_H

#define statfunc static __always_inline

/*
 * non-CO-RE version: task namespace PID/TGID/PPID via BPF helpers only.
 * bpf_get_current_pid_tgid() → upper32=TGID(pid), lower32=TID
 * PPID is set to 0 (display only, not used in security logic).
 */

statfunc u32 get_task_ns_pid(struct task_struct *task)
{
    /* TID — lower 32 bits */
    return (u32)bpf_get_current_pid_tgid();
}

statfunc u32 get_task_ns_tgid(struct task_struct *task)
{
    /* TGID — upper 32 bits */
    return (u32)(bpf_get_current_pid_tgid() >> 32);
}

statfunc u32 get_task_ns_ppid(struct task_struct *task)
{
    /* Simplified: reading real_parent requires deep task_struct access.
     * Not used in security logic, only for display. */
    return 0;
}

#endif
