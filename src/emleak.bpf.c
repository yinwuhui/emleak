#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "emleak.share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct prog_infor_t g_emleak_prog;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be64);
	__type(value, __be64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be64);
	__type(value, struct alloc_info_t);
	__uint(max_entries, 1000000);
} allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be64);
	__type(value, __be64);
	__uint(max_entries, 10240);
} memptrs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, stack_trace_t);
} stack_traces SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be64);
	__type(value, struct combined_alloc_info_t);
	__uint(max_entries, 10240);
} combined_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static inline int prog_is_enable()
{
    __be64 group_pid = bpf_get_current_pid_tgid() >> 32;

    if(g_emleak_prog.prog_state != PROG_START_STATE 
            || group_pid != g_emleak_prog.prog_pid){
        return 0;
    }

    return 1;
}

static inline void update_statistics_add(u64 stack_id, u64 sz) {
    struct combined_alloc_info_t *existing_cinfo;
    struct combined_alloc_info_t cinfo = {0};

    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if (existing_cinfo != 0){
        cinfo = *existing_cinfo;
    }

    cinfo.total_size += sz;
    cinfo.number_of_allocs += 1;

    bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static inline void update_statistics_del(u64 stack_id, u64 sz) {
    struct combined_alloc_info_t *existing_cinfo;
    struct combined_alloc_info_t cinfo = {0};

    existing_cinfo = bpf_map_lookup_elem(&combined_allocs, &stack_id);
    if (existing_cinfo != 0){
        cinfo = *existing_cinfo;
    }   

    if (sz >= cinfo.total_size){
        cinfo.total_size = 0;
    }else{
        cinfo.total_size -= sz;
    }

    if (cinfo.number_of_allocs > 0){
        cinfo.number_of_allocs -= 1;
    }

    bpf_map_update_elem(&combined_allocs, &stack_id, &cinfo, BPF_ANY);
}

static inline int gen_alloc_enter(size_t size) {
    if(!prog_is_enable()){
        return 0;
    }

    if (SAMPLE_EVERY_N > 1) 
    {
        u64 ts = bpf_ktime_get_ns();
        if (ts % SAMPLE_EVERY_N != 0){
            return 0;
        } 
    }

    __be64 pid = bpf_get_current_pid_tgid();
    __be64 size64 = size;
    bpf_map_update_elem(&sizes, &pid, &size64, BPF_ANY);

    if (SHOULD_PRINT)
    {
        char alloc_fmt[] = "alloc entered, size = %u\\n";
        bpf_trace_printk(alloc_fmt, sizeof(alloc_fmt), size);  
    }

    return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address) {
    u64 pid = bpf_get_current_pid_tgid();
    u64* size64 = bpf_map_lookup_elem(&sizes, &pid);
    struct alloc_info_t info = {0};

    if (size64 == 0){
        return 0; // missed alloc entry
    }

    info.size = *size64;
    bpf_map_delete_elem(&sizes, &pid);

    if (address != 0) {
        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = bpf_get_stackid(ctx, &stack_traces, STACK_FLAGS);
        bpf_map_update_elem(&allocs, &address, &info, BPF_ANY);
        update_statistics_add(info.stack_id, info.size);
    }

    if (SHOULD_PRINT) {
        char alloc_fmt[] = "alloc exited, size = %lu, result = %lx\\n";
        bpf_trace_printk(alloc_fmt, sizeof(alloc_fmt), info.size, address);
    }

    return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx) {
    if(!prog_is_enable()){
        return 0;
    }

    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx));
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address) {
    if(!prog_is_enable()){
        return 0;
    }

    u64 addr = (u64)address;
    struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &addr);
    if (info == 0){
        return 0;
    }

    bpf_map_delete_elem(&allocs, &addr);

    update_statistics_del(info->stack_id, info->size);

    if (SHOULD_PRINT) {
        char free_fmt[] = "free entered, address = %lx, size = %lu\\n";
        bpf_trace_printk(free_fmt, sizeof(free_fmt), addr, info->size);
    }
    
    return 0;
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int malloc_enter(struct pt_regs *ctx)
{
    int ret = 0;
    size_t size = PT_REGS_PARM1(ctx);

    ret = gen_alloc_enter(size);
    return ret;
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int malloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit(ctx);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:free")
int free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_RET(ctx);
    return gen_free_enter(ctx, address);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:calloc")
int calloc_enter(struct pt_regs *ctx) {
    size_t nmemb = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    return gen_alloc_enter(nmemb * size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:calloc")
int calloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:realloc")
int realloc_enter(struct pt_regs *ctx) {
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    gen_free_enter(ctx, ptr);
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:realloc")
int realloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:mmap")
int mmap_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:mmap")
int mmap_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:munmap")
int munmap_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_RET(ctx);

    return gen_free_enter(ctx, address);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:posix_memalign")
int posix_memalign_enter(struct pt_regs *ctx) {
    void **memptr = (void **)PT_REGS_PARM1(ctx);
    size_t alignment = (size_t)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    u64 memptr64 = (u64)(size_t)memptr;
    u64 pid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:posix_memalign")
int posix_memalign_exit(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *memptr64 = bpf_map_lookup_elem(&memptrs, &pid);
    void *addr;

    if (memptr64 == 0)
        return 0;

    bpf_map_delete_elem(&memptrs, &pid);

    if (bpf_probe_read_user(&addr, sizeof(void*), (void*)(size_t)*memptr64))
        return 0;

    u64 addr64 = (u64)(size_t)addr;
    return gen_alloc_exit2(ctx, addr64);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:aligned_alloc")
int aligned_alloc_enter(struct pt_regs *ctx) {
    size_t alignment = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:aligned_alloc")
int aligned_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:valloc")
int valloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:valloc")
int valloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:memalign")
int memalign_enter(struct pt_regs *ctx) {
    size_t alignment = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:memalign")
int memalign_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:pvalloc")
int pvalloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);

    return gen_alloc_enter(size);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:pvalloc")
int pvalloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx);
}

static inline int commcmp(char *cmp1, char *cmp2){
    int i = 0;
    for(i = 0; i < TASK_COMM_LEN; i++){
        if(cmp1[i] != cmp2[i]){
            return 1;
        }

        if(cmp1[i] == '\0'){
            return 0;
        }
    }

    return 1;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
     char progcomm[TASK_COMM_LEN] = {0};

     if(g_emleak_prog.prog_state != PROG_IDEL_STATE){
        return 0;
     }

     bpf_get_current_comm(progcomm, sizeof(progcomm));
     if(commcmp(progcomm, g_emleak_prog.prog_comm) != 0){
        return 0;
     }

     g_emleak_prog.prog_pid = bpf_get_current_pid_tgid() >> 32;
     g_emleak_prog.prog_state = PROG_START_STATE;
     g_emleak_prog.start_time = bpf_ktime_get_ns();
     g_emleak_prog.end_time = 0;

     struct event_t new_msg;
     new_msg.pid = g_emleak_prog.prog_pid;
     new_msg.msg_type = 0;
     new_msg.old_state = PROG_IDEL_STATE;
     new_msg.new_state = PROG_START_STATE;

     bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &new_msg, sizeof(new_msg));

     return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
    if(!prog_is_enable()){
        return 0;
    }

    u32 old_state = g_emleak_prog.prog_state;

    g_emleak_prog.prog_state = PROG_END_STATE;
    g_emleak_prog.end_time = bpf_ktime_get_ns();


    struct event_t new_msg;
    new_msg.pid = g_emleak_prog.prog_pid;
    new_msg.msg_type = 0;
    new_msg.old_state = old_state;
    new_msg.new_state = PROG_END_STATE;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &new_msg, sizeof(new_msg));

    return 0;
}

SEC("uprobe")
int BPF_KPROBE(malloc_add)
{
	int ret = 0;
    size_t size = PT_REGS_PARM1(ctx);

    ret = gen_alloc_enter(size);
    return ret;
}

SEC("uretprobe")
int BPF_KRETPROBE(retmalloc_add)
{
	return gen_alloc_exit(ctx);
}

SEC("uprobe")
int BPF_KRETPROBE(free_add)
{
	void *address = (void *)PT_REGS_RET(ctx);
    return gen_free_enter(ctx, address);
}