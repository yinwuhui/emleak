#ifndef __MEM_LEAK_SHARE_H__
#define __MEM_LEAK_SHARE_H__

#include "common.h"

#define TASK_COMM_LEN 16

#define MAX_CALL_STACKS 65536

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100

#define SHOULD_PRINT 1
#define SAMPLE_EVERY_N 5
#define USER_STACK_FLAGS (0 | BPF_F_USER_STACK)
#define KERNEL_STACK_FLAGS 0
#define PAGE_SIZE_BYTES 4096

typedef __s8  s8;
typedef __u8  u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;

enum progstate_e{
       PROG_IDEL_STATE = 0,
       PROG_START_STATE = 1,
       PROG_END_STATE = 2,

       PROG_MAX_STATE
};

struct alloc_info_t {
        __be64 size;
        __be64 timestamp_ns;
        int stack_id;
};

struct combined_alloc_info_t {
        __be64 total_size;
        __be64 number_of_allocs;
};

struct prog_infor_t {
        u64 prog_pid;                          /**< 进程pid*/
        volatile enum progstate_e prog_state;  /**< 进程状态*/
        u64 trace_kernel;                      /**< 是否跟踪内核内存*/
        char prog_comm[TASK_COMM_LEN];         /**< 进程名字*/
        u64 start_time;                        /**< 开始时间*/      
        u64 end_time;                          /**< 结束时间*/
};

struct msg_event_t{
        u64 pid;
        u64 msg_type;
        enum progstate_e old_state;
        enum progstate_e new_state;
};

struct event_t{
        u64 pid;
        u64 msg_type;
        enum progstate_e old_state;
        enum progstate_e new_state;
};

#endif
