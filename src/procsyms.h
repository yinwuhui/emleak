#ifndef __PROC_SYMS_H__
#define __PROC_SYMS_H__

#ifdef __cplusplus       
extern "C"
{
#endif

#include "common.h"
#include "bcc_syms.h"

#define SYMBOL_NAME_LEN 128

typedef struct pro_resolver{
    int state;
    void *resolver;
    int pid;
}pro_resolver_t;

struct proc_symbol {
    char *name;
    char *demangle_name;
    char *module;
    uint64_t offset;
};

extern int proc_syms_load(int pid);
extern int get_stack_symbol(stack_trace_t stack, char *symname[]);
extern int proc_symbol_resolve(uint64_t stack, struct proc_symbol *symbol);

#ifdef __cplusplus
}
#endif

#endif