#ifndef __MEM_LEAK_H__
#define __MEM_LEAK_H__

#include "uthash.h"
#include "emleak.share.h"

#define PRINT_RAW_ADDR 1
#define MAXFILELEN 512

#define STACK_OUTFILE_NAME "mleakstacks.txt"
#define SUMMARY_OUTFILE_NAME "mleaksummary.csv"
#define STATICS_OUTFILE_NAME "mleakstatics.csv"

struct emleakpara{
    unsigned long pid;                     /**< 进程 pid*/
    char prog_comm[TASK_COMM_LEN];         /**< 进程名字*/
    int interval;                          /**< 统计周期/单位s*/
    char stackfile[MAXFILELEN];            /**< 调动栈文件*/     
    char summaryfile[MAXFILELEN];          /**< 摘要信息文件*/   
    char statisticalfile[MAXFILELEN];      /**< 详细统计文件*/
    char elffile[MAXFILELEN];              /**< 可执行文件的路径或者库的路径*/
    char mfuncname[MAXFILELEN];            /**< 申请内存的API的名字*/
    char ffuncname[MAXFILELEN];            /**< 释放内存的API名字*/
};

struct stack_node {
    int stack_id;                    /* key */
    int memtimes;                    /*申请的总次数*/
    int memsum;                      /*call stak memleak的总大小*/
    UT_hash_handle hh;               /* makes this structure hashable */
};

struct ksym {
	long addr;
	char *name;
};

struct statistical{
	int stack_hash[MAX_CALL_STACKS];
	int stack_num;
	int stack_id[MAX_CALL_STACKS];
	int stack_summry[MAX_CALL_STACKS];
};

#endif