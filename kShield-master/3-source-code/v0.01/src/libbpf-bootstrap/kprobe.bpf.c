// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "context.h"
#include "filesystem.h"
#include "args.h"
#include "my_string.h"

/* BPF_PROG/BPF_KPROBE 매크로가 내부적으로 typeof를 사용하는데,
 * 일부 컴파일러 환경에서 typeof를 키워드로 인식하지 못하는 경우를 대비한 패치 */
#ifndef typeof
#define typeof __typeof__
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define EVIL_OPEN_CNT 100
#define ADDRS_BYTE_LEN 8
#define WCFI_CALLSITE_FLAG 0

/* linux/fs.h의 퍼미션 비트 — BPF 환경에서 직접 include 불가하므로 명시 정의 */
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
volatile char previous_modprobe[15] = {"/sbin/modprobe"}; //记录上一次modprobe_path的值（这是为了防止重复提交）
/* [P5] modprobe_overwritten 전역 플래그 제거 → modprobe_state_map 으로 교체 */

volatile int should_trace_hooks[MAX_HOOKS_NUM] = {0}; //0表示不需要启用该hook
volatile int open_cnt = 0; //记录各安全敏感文件被打开的次数

/* [P5] modprobe_path 변조 상태 맵 헬퍼 — CPU 간 즉시 동기화 보장 */
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

//PROTOTYPE
statfunc int common_file_modification_ent(struct pt_regs *ctx);
statfunc int common_file_modification_ret(struct pt_regs *ctx);

/*
* 名称: CFI_VIOLATION
* 功能: 基于eBPF的控制流完整性保证
* 类型: kprobe
* Hooks: commit_creds
*/
SEC("kprobe/commit_creds")
int BPF_KPROBE(cfi_trace)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[CFI_TRACE])
        return 0;

	int ret = 0;
    program_info_t info = {};
    
    if(init_context(&info.context))
        return 0;
    info.context.eventid = CFI_VIOLATION;

    struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
    unsigned long addrs[MAX_STACK_DEPTH];
    unsigned long stack_mask = ~((unsigned long)(1 << 16) - 1);

    void* curr_stack = BPF_CORE_READ(cu, stack);

    pid_t curr_pid = BPF_CORE_READ(cu, pid);

    bpf_get_stack(ctx, addrs, MAX_STACK_DEPTH * ADDRS_BYTE_LEN, 0);
	
    //检查当前函数调用栈是否位于预期的栈中，并在不符合预期的情况下，提交一个事件到用户态
     if (((unsigned long)ctx->sp & stack_mask) != ((unsigned long)curr_stack & stack_mask)) 
     {
        int init_stack_idx = 0;
        unsigned long *init_stack_ptr = bpf_map_lookup_elem(&init_stack, &init_stack_idx);
        if(!init_stack_ptr)
        {
            bpf_printk("init_stack failed bpf_map_lookup_elem");
            return 0;
        }
        
        if (init_stack_ptr && ((unsigned long)curr_stack != *init_stack_ptr) && curr_pid != 0)
        {
            // PID:0 (swapper/0)
            struct task_struct *cu = (struct task_struct *)bpf_get_current_task();
            info.reg_sp = ctx->sp;
            void* curr_sp = BPF_CORE_READ(cu, stack);
            info.current_sp = (unsigned long)curr_sp;
            unsigned long curr_ip = BPF_CORE_READ(cu, thread.sp);
            info.ip = curr_ip;
            
            bpf_printk("not in proper stack\n");
            bpf_send_signal_thread(9);

            goto submit;
            
         } // failed 
     }
    
    //该循环用于遍历函数调用栈，并检查每个地址是否匹配预定义的条件
    for(int i = 1; i < MAX_STACK_DEPTH; i++) 
    {
        unsigned idx = addrs[i] & 0xffffffff; // 取低32位（高位全是f）
        if (idx == 0)
            break;

        uint8_t *val;
        val = bpf_map_lookup_elem(&callsite_bitmap, &idx);
        
        // right callsite
        if (val) 
        {
            if (*val == WCFI_CALLSITE_FLAG)
                continue;
        }
        if(!val) 
        {
            unsigned max_idx = 0xffff, min_idx = 0x0;
            unsigned *max = bpf_map_lookup_elem(&callsite_bitmap_maxmin, &max_idx);
            unsigned *min = bpf_map_lookup_elem(&callsite_bitmap_maxmin, &min_idx);
            //地址不合法(不在内核地址空间内)
            if (min && max && (idx > *max || idx < *min))
                continue;
        }
        if (idx != 0 && !val) 
        {
            //地址合法且找不到（val=NULL）说明这是一个不合法的调用地址。将事件记录下来并提交到用户态。
            info.reg_sp = ctx->sp;
            void* stack = BPF_CORE_READ(cu, stack);
            info.current_sp = (unsigned long)stack;
            info.ip = addrs[i];
            
            bpf_printk("cfi violated!\n");
            bpf_send_signal_thread(9);
            
            goto submit;
            break;
        }
    }

     return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error\n");
        return 0;
    } 

    return 0;
}

/*
* 名称: TASK_CRED_OVERWRITTEN
* 功能: 检测进程cred是否被恶意覆写，若是，杀死恶意进程。
* Hooks: 
*    commit_creds(kprobe & kretprobe)
*    sys_enter(raw_tracepoint)
*    sys_exit(raw_tracepoint)
*/

SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_COMMIT_CREDS])
        return 0;

    struct task_struct* task;
    kuid_t uid;
    task = (struct task_struct *)bpf_get_current_task();
    uid = BPF_CORE_READ(task, cred, uid);

    //记录执行commit_creds之前的uid
    args_t args = {};
    args.args[0] = uid.val; 
    save_args(&args, TASK_CRED_OVERWRITTEN);

    return 0;
}

SEC("kretprobe/commit_creds")
int BPF_KPROBE(trace_ret_commit_creds, struct cred *new)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_RET_COMMIT_CREDS])
        return 0;

    args_t saved_args;
    if (load_args(&saved_args, TASK_CRED_OVERWRITTEN) != 0)
        return 0;
    del_args(TASK_CRED_OVERWRITTEN);

    u32 old_uid = saved_args.args[0];
    u32 new_uid = bpf_get_current_uid_gid();
    /*
     * [P4 수정] TGID(상위 32비트)를 키로 사용.
     * commit_creds는 프로세스 전체 자격증명을 바꾸므로, 같은 TGID를 가진
     * 어느 스레드의 sys_exit에서 조회해도 변경 사실을 정확히 확인할 수 있다.
     * 기존 TID 키 사용 시: 스레드 A의 commit_creds → cred_modification_map[TID_A].
     * 스레드 B의 sys_exit → cred_modification_map[TID_B] 조회 → 없음 → 오탐/우회.
     */
    u32 tgid = (u32)(bpf_get_current_pid_tgid() >> 32);

    cred_info_t cred_info = {old_uid, new_uid};
    bpf_map_update_elem(&cred_modification_map, &tgid, &cred_info, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_tracepoint__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{   
    //检查这个hook是否启用
    if(!should_trace_hooks[RP_SYS_ENTER])
        return 0;

    u32 pid = bpf_get_current_pid_tgid();
    u32 syscall_id = ctx->args[1];
    u32 uid = bpf_get_current_uid_gid();

    syscall_mod_key_t syscall_mod_key = {syscall_id, pid};
    bpf_map_update_elem(&syscall_trace_map, &syscall_mod_key, &uid, BPF_ANY);

    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tracepoint__sys_exit(struct bpf_raw_tracepoint_args *ctx) 
{
    //检查这个hook是否启用
    if(!should_trace_hooks[RP_SYS_EXIT])
        return 0;

    int ret = 0;
    program_info_t info = {};

    if (init_context(&info.context))
        return 0;

    struct pt_regs *regs = (struct pt_regs*)ctx->args[0];
    
    u32 syscall_id = BPF_CORE_READ(regs, orig_ax);

    /*
     * [P4 수정] TID / TGID 분리.
     *   tid  (하위 32비트) → syscall_trace_map 키: 스레드별 syscall enter/exit 쌍 추적
     *   tgid (상위 32비트) → cred_modification_map 키: 프로세스 단위 cred 변경 추적
     *
     * 기존 코드는 두 맵 모두 TID를 사용해 스레드 A가 commit_creds를 호출한 뒤
     * 스레드 B의 sys_exit에서 cred_modification_map[TID_B]를 조회하면 항목을 찾지 못해
     * "uid 변화 + commit_creds 없음" 오탐이 발생했다.
     */
    u64 pid_tgid  = bpf_get_current_pid_tgid();
    u32 tid       = (u32)pid_tgid;         /* 스레드 ID  — syscall_trace_map 키 */
    u32 tgid      = (u32)(pid_tgid >> 32); /* 프로세스 ID — cred_modification_map 키 */

    syscall_mod_key_t syscall_mod_key = {syscall_id, tid};

    u32 uid = bpf_get_current_uid_gid();
    u32 *old_uid = bpf_map_lookup_elem(&syscall_trace_map, &syscall_mod_key);
    if(old_uid == NULL)
    {
        return 0;
    }

    cred_info_t* changed = bpf_map_lookup_elem(&cred_modification_map, &tgid);
    if(changed == NULL && *old_uid != uid)
    {
        bpf_printk("no commit_creds: %d %d",*old_uid,uid);
        bpf_printk("illegal cred overwrite found!!!");
        bpf_send_signal_thread(9);

        info.context.eventid = TASK_CRED_OVERWRITTEN;
        info.old_uid = *old_uid;
        info.new_uid = uid;

        goto submit;
    }
    else if(changed == NULL && *old_uid == uid)
    {
        return 0;
    }
    else
    {
        if(*old_uid != uid)
        {
            bpf_printk("TASK_CRED_MODIFICATION: %d %d",*old_uid, uid);
        }
        bpf_map_delete_elem(&cred_modification_map, &tgid);
    }

    return 0;

// 提交事件到用户态    
submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error %d\n",ret);
        return 0;
    }

    return 0;
}


/*
* 名称: EVIL_OPEN
* 功能: 通过检查安全敏感文件被打开的频率，检测是否发生DirtyCred攻击，若是，杀死恶意进程。do_linkat阻止在安全敏感文件上建立硬链接
* Hooks: 
*    fd_install(kprobe)
*    do_linkat(kprobe)
*/
SEC("kprobe/fd_install")
int BPF_KPROBE(trace_evil_open,unsigned int fd, struct file *file)
{
    if(!should_trace_hooks[TRACE_EVIL_OPEN])
        return 0;

	// 检测打开文件的类型是否是普通文件，若不是，不提交该事件
	unsigned short file_mode = get_inode_mode_from_file(file);
	if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    int ret = 0;
    program_info_t info = {};

    if (init_context(&info.context))
        return 0;

	// 获取文件基本信息
	file_info_t file_info = get_file_info(file);

    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0],sizeof(path.name),file_info.pathname_p);
    
    int i;
    for(i = 0; i < MAX_SECURITY_FILE_ID; i++)
    {
        if(!my_bpf_strncmp(&path.name[0], sizeof(path.name), &security_files[i]))
        {
            /*
             * 멀티코어 원자 증가: BPF_STX_XADD 명령으로 컴파일됨.
             * 기존 open_cnt++는 비원자적이어서 여러 CPU가 동시에 증가할 때
             * 카운트가 유실될 수 있었다.
             */
            __sync_fetch_and_add(&open_cnt, 1);
            bpf_printk("open_cnt=%d", open_cnt);
            break;
        }
    }

    if(open_cnt > EVIL_OPEN_CNT)
    {
        open_cnt = 0; /* 임계값 초과 후 리셋 (4바이트 정렬 volatile 쓰기 = x86_64 원자적) */

        bpf_send_signal_thread(9);
        info.context.eventid = EVIL_OPEN;
        bpf_printk("pid = %d comm = %s EVIL OPEN KILLED!!!",info.context.pid, &info.context.comm[0]);

        goto submit;
    } 
	
	return 0;

submit:
    ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
    if(ret < 0)
    {
        bpf_printk("bpf_perf_event_output error\n");
        return 0;
    } 
    return 0; 
}



SEC("kprobe/do_linkat")
int BPF_KPROBE(trace_do_linkat, int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_DO_LINKAT])
        return 0;

    const char* old_name_p = NULL;
    char filename[MAX_CACHED_PATH_SIZE];

    old_name_p = BPF_CORE_READ(old, name);
    bpf_probe_read_kernel_str(&filename[0],sizeof(filename),old_name_p);
    
    //检查这个硬链接是不是与安全敏感文件相关
    for(int i = 0; i < MAX_SECURITY_FILE_ID; i++)
    {
        if(my_bpf_strncmp(&filename[0], sizeof(&filename), &security_files[i]))
        {
            bpf_printk("build hard link on security file %s: not allowd", &security_files[i]); //不允许的操作
            bpf_send_signal_thread(9);
            break;
        }
    }

    return 0;
}


/*
* 名称: MODPROBE_PATH_OVERWRITTEN
* 功能: 监测modprobe_path是否被恶意覆写，如果是，杀死恶意进程
* Hooks: 
*    sched_process_exec(tracepoint)
*    sys_exit(raw_tracepoint)
*/
SEC("tp/sched/sched_process_exec")
int tp_trace_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TP_TRACE_EXEC])
        return 0;

    //如果检测到modprobe_path已经被覆写，禁止新的进程开始执行
    //因为该利用方式提权的方式是：覆写modprobe_path后，以suid权限执行恶意脚本，这种方式需要创建新进程。
    /* [P5] 맵에서 상태 조회 — volatile 플래그 대비 CPU 간 즉시 가시성 보장 */
    if(get_modprobe_state())
    {
        bpf_send_signal_thread(20);
    }

    return 0;
}

/*
 * 名称: MODPROBE_PATH_OVERWRITTEN - LAYER 1 (쓰기 시점 차단)
 * 기능: proc_dostring kprobe로 sysctl 경로(/proc/sys/kernel/modprobe)를 통한
 *       modprobe_path 쓰기를 가로채 비root 프로세스의 변경을 즉시 차단한다.
 *
 * 한계: 익스플로잇에 의한 직접 메모리 덮어쓰기는 이 훅을 우회한다.
 *       그 경우는 LAYER 2(call_usermodehelper_setup)에서 최종 차단한다.
 *
 * Hook: kprobe/proc_dostring
 * Signature: int proc_dostring(struct ctl_table *table, int write,
 *                              void *buffer, size_t *lenp, loff_t *ppos)
 */
#define MODPROBE_PATH_MAXLEN 64

SEC("kprobe/proc_dostring")
int BPF_KPROBE(trace_proc_dostring,
               struct ctl_table *table, int write)
{
    if (!should_trace_hooks[TRACE_PROC_DOSTRING])
        return 0;

    /* 쓰기 요청이 아닌 경우 무시 */
    if (!write)
        return 0;

    /*
     * table->data 주소와 우리가 맵에 저장해 둔 modprobe_path 커널 주소를 비교해
     * 이 proc_dostring 호출이 실제로 modprobe_path sysctl 항목을 대상으로 하는지 확인한다.
     */
    unsigned key = 0;
    unsigned long *modprobe_addr = bpf_map_lookup_elem(&modprobe_path, &key);
    if (!modprobe_addr)
        return 0;

    void *table_data = NULL;
    bpf_probe_read_kernel(&table_data, sizeof(table_data),
                          __builtin_preserve_access_index(&table->data));

    if ((unsigned long)table_data != *modprobe_addr)
        return 0; /* 다른 sysctl 항목 — 무시 */

    /* --- 이 시점부터는 modprobe_path를 쓰려는 요청임 --- */

    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;

    if (uid != 0) {
        /*
         * 비root가 modprobe_path를 바꾸려 함 → 즉시 차단.
         * 이 단계에서 실제 쓰기는 아직 일어나지 않았으므로
         * 데이터 변조 없이 프로세스를 종료할 수 있다.
         */
        bpf_send_signal_thread(9);
        bpf_printk("proc_dostring: non-root modprobe_path write blocked (uid=%d)", uid);

        int ret = 0;
        program_info_t info = {};
        if (init_context(&info.context))
            return 0;
        info.context.eventid = MODPROBE_PATH_OVERWRITTEN;
        set_modprobe_state(1); /* [P5] 맵 업데이트 — 모든 CPU에 즉시 반영 */

        ret = bpf_perf_event_output(ctx, &program_submit_map,
                                    BPF_F_CURRENT_CPU, &info, sizeof(info));
        if (ret < 0)
            bpf_printk("bpf_perf_event_output error %d\n", ret);
        return 0;
    }

    /* root 쓰기는 허용하되 기록만 남긴다 (정상 관리 작업) */
    bpf_printk("proc_dostring: root is writing modprobe_path — logged only");
    return 0;
}

/*
 * 名称: MODPROBE_PATH_OVERWRITTEN - LAYER 2 (사용 시점 차단 — TOCTOU 완전 봉쇄)
 * 기능: call_usermodehelper_setup kprobe로 커널이 usermodehelper를 실행하려는
 *       바로 그 순간을 가로채, modprobe_path가 변조된 상태에서의 악성 실행을 차단한다.
 *
 * 이 훅이 TOCTOU를 막는 이유:
 *   기존 sys_exit 검사 = 시스템 콜이 끝난 뒤 감지 (이미 늦음)
 *   이 훅          = 실행이 시작되기 직전에 검사 (아직 이르지 않음)
 *   따라서 검사 시점(check)과 사용 시점(use)이 동일한 함수 내에서 이루어져
 *   공격자가 두 시점 사이에 끼어들 수 없다.
 *
 * Hook: kprobe/call_usermodehelper_setup
 * Signature: struct subprocess_info *call_usermodehelper_setup(
 *     const char *path, char **argv, char **envp, gfp_t gfp_mask, ...)
 */
SEC("kprobe/call_usermodehelper_setup")
int BPF_KPROBE(trace_call_usermodehelper_setup, const char *path)
{
    if (!should_trace_hooks[TRACE_CALL_UMH_SETUP])
        return 0;

    /*
     * 빠른 경로: modprobe_path가 변조된 적이 없으면 즉시 리턴.
     * call_usermodehelper_setup은 firmware, hotplug 등에서도 호출되므로
     * 이 검사로 무관한 호출에 대한 오버헤드를 최소화한다.
     */
    /* [P5] 맵 기반 상태 조회 — volatile 플래그 대비 CPU 간 가시성 보장 */
    if (!get_modprobe_state())
        return 0;

    /* 실행하려는 경로를 커널 공간에서 읽는다 */
    char exec_path[MODPROBE_PATH_MAXLEN];
    bpf_probe_read_kernel_str(exec_path, sizeof(exec_path), path);

    /* BPF 맵에 저장된 modprobe_path 커널 변수 주소로 현재 값을 읽는다 */
    unsigned key = 0;
    unsigned long *modprobe_addr = bpf_map_lookup_elem(&modprobe_path, &key);
    if (!modprobe_addr)
        return 0;

    char current_modprobe[MODPROBE_PATH_MAXLEN];
    bpf_probe_read_kernel_str(current_modprobe, sizeof(current_modprobe),
                              (const void *)(*modprobe_addr));

    /*
     * 차단 조건:
     *   1) 실행하려는 경로 == 현재 modprobe_path (call_modprobe가 트리거한 호출)
     *   2) 현재 modprobe_path != /sbin/modprobe (변조된 상태)
     *
     * 두 조건이 모두 충족되면 악성 usermodehelper 실행을 시도하는 것이므로
     * 실행 직전에 프로세스를 종료한다.
     */
    if (my_bpf_strncmp(&current_modprobe[0], sizeof(current_modprobe),
                        &right_modprobe[0]) != 0 &&
        my_bpf_strncmp(&exec_path[0], sizeof(exec_path),
                        &current_modprobe[0]) == 0)
    {
        bpf_send_signal_thread(9);
        bpf_printk("call_usermodehelper_setup: evil modprobe execution blocked: %s",
                   exec_path);

        int ret = 0;
        program_info_t info = {};
        if (init_context(&info.context))
            return 0;
        info.context.eventid = MODPROBE_PATH_OVERWRITTEN;

        ret = bpf_perf_event_output(ctx, &program_submit_map,
                                    BPF_F_CURRENT_CPU, &info, sizeof(info));
        if (ret < 0)
            bpf_printk("bpf_perf_event_output error %d\n", ret);
        return 0;
    }

    return 0;
}

/*
* 名称: FILE_MODIFICATION
* 功能: 记录对安全敏感文件的修改,如果修改是非法的，回滚（TODO）
* Hooks: 
*    fd_install(kprobe)
*    filp_close(kprobe)
*    file_update_time(kprobe & kretprobe)
*    file_modified(kprobe & kretprobe)
*/
// Catch the open of a file and set the event of file_modification to be submitted for it
SEC("kprobe/fd_install")
int BPF_KPROBE(trace_fd_install,unsigned int fd, struct file *file)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FD_INSTALL])
        return 0;

	// 检测打开文件的类型是否是普通文件，若不是，不提交该事件
	unsigned short file_mode = get_inode_mode_from_file(file);
	if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

	// 获取文件基本信息
	file_info_t file_info = get_file_info(file);

	// 将获取到的文件信息存储到file_modification_map中
    file_mod_key_t file_mod_key = {};
    file_mod_key.inode = file_info.id.inode;
    file_mod_key.device = file_info.id.device;
	int op = FILE_MODIFICATION_SUBMIT;
	bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);

    return 0;
}

// Catch the close of a file and remove it from cache of files t submit the event for
SEC("kprobe/filp_close")
int BPF_KPROBE(trace_filp_close,struct file *filp, fl_owner_t id)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FLIP_CLOSE])
        return 0;

    file_info_t file_info = get_file_info(filp);

    file_mod_key_t file_mod_key = {};
    file_mod_key.inode = file_info.id.inode;
    file_mod_key.device = file_info.id.device;

    bpf_map_delete_elem(&file_modification_map, &file_mod_key);

    return 0;
}

//Catch the file ctime change and submit the event if marked to be submitted
SEC("kprobe/file_update_time")
int BPF_KPROBE(trace_file_update_time)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FILE_UPDATE_TIME])
        return 0;

    return common_file_modification_ent(ctx);
}

SEC("kretprobe/file_update_time")
int BPF_KPROBE(trace_ret_file_update_time)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_RET_FILE_UPDATE_TIME])
        return 0;

    return common_file_modification_ret(ctx);
}

//与file_update_time处的hook功能相同，有它是为了同时支持新旧内核版本。
//Catch the file ctime change and submit the event if marked to be submitted
SEC("kprobe/file_modified")
int BPF_KPROBE(trace_file_modified)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_FILE_MODIFIED])
        return 0;
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ent(ctx);
    }

    return 0;
}

SEC("kretprobe/file_modified")
int BPF_KPROBE(trace_ret_file_modified)
{
    //检查这个hook是否启用
    if(!should_trace_hooks[TRACE_RET_FILE_MODIFIED])
        return 0;
    /*
     * we want this probe to run only on kernel versions >= 6.
     * this is because on older kernels the file_modified() function calls the file_update_time()
     * function. in those cases, we don't need this probe active.
     */
    if (bpf_core_field_exists(((struct file *) 0)->f_iocb_flags)) {
        /* kernel version >= 6 */
        return common_file_modification_ret(ctx);
    }

    return 0;
}

statfunc int common_file_modification_ent(struct pt_regs *ctx)
{
    struct file *file = (struct file *) PT_REGS_PARM1(ctx);

    // check if regular file. otherwise don't output the event.
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG) {
        return 0;
    }

    u64 ctime = get_ctime_nanosec_from_file(file);

    args_t args = {};
    args.args[0] = (unsigned long) file;
    args.args[1] = ctime;
    save_args(&args, FILE_MODIFICATION);

    return 0;
}

statfunc int common_file_modification_ret(struct pt_regs *ctx)
{
    int ret = 0;
    program_info_t info = {};

    if (init_context(&info.context))
        return 0;

    info.context.eventid = FILE_MODIFICATION;
    info.context.retval = PT_REGS_RC(ctx);

    args_t saved_args = {};
    if (load_args(&saved_args, FILE_MODIFICATION) != 0)
        return 0;
    del_args(FILE_MODIFICATION);

    struct file *file = (struct file *) saved_args.args[0];
    u64 old_ctime = saved_args.args[1];

    file_info_t file_info = get_file_info(file);

    file_mod_key_t file_mod_key = {};
    file_mod_key.inode = file_info.id.inode;
    file_mod_key.device = file_info.id.device;

    int *op = bpf_map_lookup_elem(&file_modification_map, &file_mod_key);
    if (op == NULL || *op == FILE_MODIFICATION_SUBMIT) {
        // we should submit the event once and mark as done.
        int op = FILE_MODIFICATION_DONE;
        bpf_map_update_elem(&file_modification_map, &file_mod_key, &op, BPF_ANY);
    } else {
        // no need to submit. return.
        return 0;
    }
   
    //feed info
    info.device = file_info.id.device;
    info.inode = file_info.id.inode;
    info.old_ctime = old_ctime;
    info.new_ctime = file_info.id.ctime;
    //filename
    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0],sizeof(path.name),file_info.pathname_p);
    //bpf_printk("in common_file_modification_ret: %s inode=%d",file_info.pathname_p,file_info.id.inode);
    int i;
    for(i = 0; i < MAX_SECURITY_FILE_ID; i++)
    {
        if(!my_bpf_strncmp(&path.name[0], sizeof(path.name), &security_files[i]))
        {
            info.security_file = i; 
            break;
        }
    }

    //提交
    if(i < MAX_SECURITY_FILE_ID)
    {
        ret = bpf_perf_event_output(ctx, &program_submit_map, BPF_F_CURRENT_CPU, &info, sizeof(info));
        if(ret < 0)
        {
            bpf_printk("bpf_perf_event_output error\n");
            return 0;
        }
        return 0;
    }

    return 0;
}


/*
 * 名称: FILE_MODIFICATION - LSM 사전 차단 (우선순위 2 수정)
 * 기능: 보안 민감 파일(/etc/passwd 등)에 대한 비root 쓰기를
 *       LSM 계층에서 데이터가 디스크에 기록되기 전에 즉시 거부(-EPERM)한다.
 *
 * [기존 방식의 문제]
 *   kprobe(file_update_time) 감지 → perf buffer → 유저스페이스 → restore_backup()
 *   이 구조는 파일이 이미 변조된 뒤에 복구하므로 TOCTOU 창이 존재한다.
 *
 * [이 훅이 TOCTOU를 막는 방식]
 *   vfs_write() → security_file_permission() → [이 훅] → -EPERM 반환
 *   쓰기 자체가 VFS 계층에서 차단되므로 파일 데이터·ctime 어느 것도 변경되지 않는다.
 *
 * [요구 사항]
 *   커널 빌드: CONFIG_BPF_LSM=y
 *   부트 파라미터 또는 /sys/kernel/security/lsm 에 "bpf" 포함
 *
 * Hook: lsm/file_permission
 * 반환: 0 = 허용,  -EPERM = 거부
 */
SEC("lsm/file_permission")
int BPF_PROG(lsm_file_permission_check, struct file *file, int mask)
{
    if (!should_trace_hooks[LSM_FILE_PERMISSION])
        return 0;

    /* 쓰기·추가 작업이 아니면 즉시 통과 */
    if (!(mask & MAY_WRITE) && !(mask & MAY_APPEND))
        return 0;

    /* 일반 파일(regular file)이 아니면 통과 (소켓·파이프·디렉토리 제외) */
    unsigned short file_mode = get_inode_mode_from_file(file);
    if ((file_mode & S_IFMT) != S_IFREG)
        return 0;

    /* root(uid=0)는 허용 — 관리 목적의 수정은 kprobe 체인이 별도 감시 */
    u32 uid = bpf_get_current_uid_gid() & 0xffffffff;
    if (uid == 0)
        return 0;

    /* 보안 민감 파일 목록과 경로 비교 */
    file_info_t file_info = get_file_info(file);
    file_pathname_t path = {};
    bpf_probe_read_kernel_str(&path.name[0], sizeof(path.name), file_info.pathname_p);

    for (int i = 0; i < MAX_SECURITY_FILE_ID; i++) {
        if (!my_bpf_strncmp(&path.name[0], sizeof(path.name), &security_files[i])) {
            bpf_printk("lsm_file_permission: blocked non-root write to %s (uid=%d)",
                       &security_files[i], uid);
            /*
             * -EPERM 반환 → security_file_permission() 이 즉시 에러 전파
             * → vfs_write()가 EACCES를 syscall에 반환 → 파일 내용 불변
             */
            return -EPERM;
        }
    }

    return 0;
}
