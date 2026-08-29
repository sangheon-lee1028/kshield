#ifndef FILTERING_H
#define FILTERING_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "types.h"
#include "kprobe.skel.h"

//PROTOTYPE
void set_hooks_by_event_num(int num, struct kprobe_bpf *skel);
void bpf_hooks_init(struct env* env, struct kprobe_bpf *skel);


//FUCNS
void set_hooks_by_event_num(int num, struct kprobe_bpf *skel)
{
	switch (num)
	{
	case CFI_VIOLATION:
		skel->bss->should_trace_hooks[CFI_TRACE] = 1;
		break;
	case TASK_CRED_OVERWRITTEN:
		skel->bss->should_trace_hooks[TRACE_COMMIT_CREDS] = 1;
		skel->bss->should_trace_hooks[TRACE_RET_COMMIT_CREDS] = 1;
		skel->bss->should_trace_hooks[RP_SYS_ENTER] = 1;
		skel->bss->should_trace_hooks[RP_SYS_EXIT] = 1;
		break;
	case EVIL_OPEN:
		skel->bss->should_trace_hooks[TRACE_EVIL_OPEN] = 1;
		skel->bss->should_trace_hooks[TRACE_DO_LINKAT] = 1;
		break;
	case MODPROBE_PATH_OVERWRITTEN:
		skel->bss->should_trace_hooks[TP_TRACE_EXEC] = 1;
		skel->bss->should_trace_hooks[TRACE_PROC_DOSTRING] = 1;   /* LAYER 1: sysctl 쓰기 시점 차단 */
		skel->bss->should_trace_hooks[TRACE_CALL_UMH_SETUP] = 1;  /* LAYER 2: 실행 시점 차단 (TOCTOU 봉쇄) */
	case FILE_MODIFICATION:
		skel->bss->should_trace_hooks[LSM_FILE_PERMISSION] = 1;        /* 사전 차단: 비root 쓰기 거부 */
		skel->bss->should_trace_hooks[TRACE_FD_INSTALL] = 1;           /* 이하: root 쓰기 감시용 유지 */
		skel->bss->should_trace_hooks[TRACE_FLIP_CLOSE] = 1;
		skel->bss->should_trace_hooks[TRACE_FILE_UPDATE_TIME] = 1;
		skel->bss->should_trace_hooks[TRACE_RET_FILE_UPDATE_TIME] = 1;
		skel->bss->should_trace_hooks[TRACE_FILE_MODIFIED] = 1;
		skel->bss->should_trace_hooks[TRACE_RET_FILE_MODIFIED] = 1;
		break;
	default:
		break;
	}
	printf("init hooks for event %d\n",num);
}

void bpf_hooks_init(struct env* env, struct kprobe_bpf *skel)
{
	if(env->trace_all == 1)
	{
		for(int i = 0; i < MAX_EVENT_NUM; i++)
		{
			set_hooks_by_event_num(i, skel);
		}
	}
	else
	{
		for(int i = 0; i < MAX_EVENT_NUM; i++)
		{
			if(env->event[i] == 1)
			{
				set_hooks_by_event_num(i, skel);
			}
		}
	}
}

#endif