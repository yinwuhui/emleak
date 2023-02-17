#include <iostream>
#include <cstring>
#include <gelf.h>
#include "bcc_proc.h"
#include "bcc_syms.h"
#include "procsyms.h"
#include "common.h"

using namespace std;

#ifdef __cplusplus       
extern "C"
{
#endif

pro_resolver_t g_proc_syms;

int proc_syms_load(int pid)
{
    int ret = 0;
    void *resolver = NULL;


    if(pid <= 0){
        return -1;
    }

    resolver = bcc_symcache_new(pid, NULL);
    if(!resolver){
        return -1;
    }

    /*If a symbol table already exists, release it*/
    if(g_proc_syms.state){
        bcc_free_symcache(g_proc_syms.resolver, g_proc_syms.pid);
        memset(&g_proc_syms, 0x00, sizeof(g_proc_syms));
    }

    g_proc_syms.resolver = resolver;
    g_proc_syms.pid = pid;
    g_proc_syms.state = 1;

    return ret;
}

int get_stack_symbol(stack_trace_t stack, char *symname[]){
    int ret_num = 0;
    struct bcc_symbol symbol;

    for(int i = 0; i < PERF_MAX_STACK_DEPTH; i++){
        if(!stack[i]){
            break;
        }

        ret_num ++;
        if(!g_proc_syms.resolver){
            strcpy(symname[i], "[UNKNOWN]");
            continue;
        }

        if (bcc_symcache_resolve(g_proc_syms.resolver, stack[i], &symbol) != 0){
            strcpy(symname[i], "[UNKNOWN]");
        }else {
            strcpy(symname[i], symbol.demangle_name);
            bcc_symbol_free_demangle_name(&symbol);
        }
    }

    return ret_num;
}

static void symbol_clone(struct bcc_symbol *src, struct proc_symbol *dst)
{
    strcpy(dst->name, src->name);
    strcpy(dst->demangle_name, src->demangle_name);
    strcpy(dst->module, src->module);
    dst->offset = src->offset;
    return ;
}

static void symbol_unknown(struct proc_symbol *dst)
{
    dst->offset = 0;
    strcpy(dst->name, "[UNKNOWN]");
    strcpy(dst->demangle_name, "[UNKNOWN]");
    strcpy(dst->module, "[UNKNOWN]");
    return ;
}

int proc_symbol_resolve(uint64_t stack, struct proc_symbol *symbol)
{
    int ret = 0;
    struct bcc_symbol bccsymbol;

    if(!g_proc_syms.resolver){
        symbol_unknown(symbol);
        return 0;
    }

    ret = bcc_symcache_resolve(g_proc_syms.resolver, stack, &bccsymbol);
    if(ret != 0){
        symbol_unknown(symbol);
        return 0;
    }else {
        symbol_clone(&bccsymbol, symbol);
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

