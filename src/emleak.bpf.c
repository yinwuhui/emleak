#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "emleak.share.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct prog_infor_t g_emleak_prog;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct alloc_ctx_key_t);
	__type(value, __be64);
	__uint(max_entries, 10240);
} sizes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct alloc_key_t);
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

static inline int user_prog_is_enable()
{
    __be64 group_pid = bpf_get_current_pid_tgid() >> 32;

    if(g_emleak_prog.trace_kernel
            || g_emleak_prog.prog_state != PROG_START_STATE
            || group_pid != g_emleak_prog.prog_pid){
        return 0;
    }

    return 1;
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

static inline int allocation_filter_matches(size_t size)
{
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 cgroup_id;
    char comm[TASK_COMM_LEN] = {};

    if (g_emleak_prog.filter_pid && tgid != g_emleak_prog.filter_pid)
        return 0;
    if (g_emleak_prog.filter_cgroup_id) {
        cgroup_id = bpf_get_current_cgroup_id();
        if (cgroup_id != g_emleak_prog.filter_cgroup_id)
            return 0;
    }
    if (g_emleak_prog.filter_comm_enabled) {
        bpf_get_current_comm(comm, sizeof(comm));
        if (commcmp(comm, g_emleak_prog.prog_comm) != 0)
            return 0;
    }
    if (g_emleak_prog.min_size && size < g_emleak_prog.min_size)
        return 0;
    if (g_emleak_prog.max_size && size > g_emleak_prog.max_size)
        return 0;
    if (g_emleak_prog.sample_rate > 1
            && bpf_get_prandom_u32() % g_emleak_prog.sample_rate != 0)
        return 0;

    return 1;
}

static inline int kernel_prog_is_enable()
{
    return g_emleak_prog.trace_kernel
            && g_emleak_prog.prog_state == PROG_START_STATE;
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

static inline int gen_alloc_enter(size_t size, u64 family) {
    if(!user_prog_is_enable()){
        return 0;
    }

    if (!allocation_filter_matches(size))
        return 0;

    struct alloc_ctx_key_t key = {
        .family = family,
        .pid = bpf_get_current_pid_tgid(),
    };
    __be64 size64 = size;
    bpf_map_update_elem(&sizes, &key, &size64, BPF_ANY);

    if (SHOULD_PRINT)
    {
        char alloc_fmt[] = "alloc entered, size = %u\\n";
        bpf_trace_printk(alloc_fmt, sizeof(alloc_fmt), size);  
    }

    return 0;
}

static inline int gen_alloc_exit2(struct pt_regs *ctx, u64 address, u64 family) {
    struct alloc_ctx_key_t size_key = {
        .family = family,
        .pid = bpf_get_current_pid_tgid(),
    };
    struct alloc_key_t alloc_key = {
        .family = family,
        .address = address,
    };
    u64* size64 = bpf_map_lookup_elem(&sizes, &size_key);
    struct alloc_info_t info = {0};

    if (size64 == 0){
        return 0; // missed alloc entry
    }

    info.size = *size64;
    bpf_map_delete_elem(&sizes, &size_key);

    if (address != 0) {
        info.timestamp_ns = bpf_ktime_get_ns();
        info.stack_id = bpf_get_stackid(ctx, &stack_traces,
                    g_emleak_prog.trace_kernel ? KERNEL_STACK_FLAGS : USER_STACK_FLAGS);
        struct alloc_info_t *old_info = bpf_map_lookup_elem(&allocs, &alloc_key);
        if (old_info != 0)
            update_statistics_del(old_info->stack_id, old_info->size);
        bpf_map_update_elem(&allocs, &alloc_key, &info, BPF_ANY);
        update_statistics_add(info.stack_id, info.size);
    }

    if (SHOULD_PRINT) {
        char alloc_fmt[] = "alloc exited, size = %lu, result = %lx\\n";
        bpf_trace_printk(alloc_fmt, sizeof(alloc_fmt), info.size, address);
    }

    return 0;
}

static inline int gen_alloc_exit(struct pt_regs *ctx, u64 family) {
    if(!user_prog_is_enable()){
        return 0;
    }

    return gen_alloc_exit2(ctx, PT_REGS_RC(ctx), family);
}

static inline int gen_free_enter(struct pt_regs *ctx, void *address, u64 family) {
    if(!user_prog_is_enable()){
        return 0;
    }

    struct alloc_key_t key = {
        .family = family,
        .address = (u64)address,
    };
    struct alloc_info_t *info = bpf_map_lookup_elem(&allocs, &key);
    if (info == 0){
        return 0;
    }

    bpf_map_delete_elem(&allocs, &key);

    update_statistics_del(info->stack_id, info->size);

    if (SHOULD_PRINT) {
        char free_fmt[] = "free entered, address = %lx, size = %lu\\n";
        bpf_trace_printk(free_fmt, sizeof(free_fmt), key.address, info->size);
    }
    
    return 0;
}

static inline int gen_kernel_alloc_enter(size_t size, u64 family)
{
    if (!kernel_prog_is_enable()) {
        return 0;
    }

    if (!allocation_filter_matches(size))
        return 0;

    struct alloc_ctx_key_t key = {
        .family = family,
        .pid = bpf_get_current_pid_tgid(),
    };
    __be64 size64 = size;

    bpf_map_update_elem(&sizes, &key, &size64, BPF_ANY);
    return 0;
}

static inline int gen_kernel_alloc_exit2(void *ctx, u64 address, u64 family)
{
    if (!kernel_prog_is_enable()) {
        return 0;
    }

    return gen_alloc_exit2((struct pt_regs *)ctx, address, family);
}

static inline int gen_kernel_free_enter(void *ctx, void *address, u64 family)
{
    struct alloc_key_t key = {
        .family = family,
        .address = (u64)address,
    };
    struct alloc_info_t *info;

    if (!kernel_prog_is_enable()) {
        return 0;
    }

    info = bpf_map_lookup_elem(&allocs, &key);
    if (info == 0){
        return 0;
    }

    bpf_map_delete_elem(&allocs, &key);
    update_statistics_del(info->stack_id, info->size);
    return 0;
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int malloc_enter(struct pt_regs *ctx)
{
    int ret = 0;
    size_t size = PT_REGS_PARM1(ctx);

    ret = gen_alloc_enter(size, ALLOC_FAMILY_USER);
    return ret;
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:malloc")
int malloc_exit(struct pt_regs *ctx)
{
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:free")
int free_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);
    return gen_free_enter(ctx, address, ALLOC_FAMILY_USER);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:calloc")
int calloc_enter(struct pt_regs *ctx) {
    size_t nmemb = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    return gen_alloc_enter(nmemb * size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:calloc")
int calloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:realloc")
int realloc_enter(struct pt_regs *ctx) {
    void *ptr = (void *)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    gen_free_enter(ctx, ptr, ALLOC_FAMILY_USER);
    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:realloc")
int realloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:mmap")
int mmap_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM2(ctx);
    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:mmap")
int mmap_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:munmap")
int munmap_enter(struct pt_regs *ctx) {
    void *address = (void *)PT_REGS_PARM1(ctx);

    return gen_free_enter(ctx, address, ALLOC_FAMILY_USER);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:posix_memalign")
int posix_memalign_enter(struct pt_regs *ctx) {
    void **memptr = (void **)PT_REGS_PARM1(ctx);
    size_t alignment = (size_t)PT_REGS_PARM2(ctx);
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    u64 memptr64 = (u64)(size_t)memptr;
    u64 pid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&memptrs, &pid, &memptr64, BPF_ANY);
    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
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
    return gen_alloc_exit2(ctx, addr64, ALLOC_FAMILY_USER);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:aligned_alloc")
int aligned_alloc_enter(struct pt_regs *ctx) {
    size_t alignment = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:aligned_alloc")
int aligned_alloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:valloc")
int valloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:valloc")
int valloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}


SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:memalign")
int memalign_enter(struct pt_regs *ctx) {
    size_t alignment = (size_t)PT_REGS_PARM1(ctx);
    size_t size = (size_t)PT_REGS_PARM2(ctx);

    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:memalign")
int memalign_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}

SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:pvalloc")
int pvalloc_enter(struct pt_regs *ctx) {
    size_t size = (size_t)PT_REGS_PARM1(ctx);

    return gen_alloc_enter(size, ALLOC_FAMILY_USER);
}

SEC("uretprobe//lib/x86_64-linux-gnu/libc.so.6:pvalloc")
int pvalloc_exit(struct pt_regs *ctx) {
    return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
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
    if(!user_prog_is_enable()){
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

    ret = gen_alloc_enter(size, ALLOC_FAMILY_USER);
    return ret;
}

SEC("uretprobe")
int BPF_KRETPROBE(retmalloc_add)
{
	return gen_alloc_exit(ctx, ALLOC_FAMILY_USER);
}

SEC("uprobe")
int BPF_KRETPROBE(free_add)
{
	void *address = (void *)PT_REGS_PARM1(ctx);
    return gen_free_enter(ctx, address, ALLOC_FAMILY_USER);
}

SEC("tp/kmem/kmalloc")
int handle_kmalloc(struct trace_event_raw_kmalloc *ctx)
{
    size_t size = ctx->bytes_alloc;
    u64 ptr = (u64)ctx->ptr;

    gen_kernel_alloc_enter(size, ALLOC_FAMILY_KERNEL_SLAB);
    return gen_kernel_alloc_exit2(ctx, ptr, ALLOC_FAMILY_KERNEL_SLAB);
}

SEC("tp/kmem/kmalloc_node")
int handle_kmalloc_node(struct trace_event_raw_kmalloc *ctx)
{
    size_t size = ctx->bytes_alloc;
    u64 ptr = (u64)ctx->ptr;

    gen_kernel_alloc_enter(size, ALLOC_FAMILY_KERNEL_SLAB);
    return gen_kernel_alloc_exit2(ctx, ptr, ALLOC_FAMILY_KERNEL_SLAB);
}

SEC("tp/kmem/kmem_cache_alloc")
int handle_kmem_cache_alloc(struct trace_event_raw_kmem_cache_alloc *ctx)
{
    size_t size = ctx->bytes_alloc;
    u64 ptr = (u64)ctx->ptr;

    gen_kernel_alloc_enter(size, ALLOC_FAMILY_KERNEL_SLAB);
    return gen_kernel_alloc_exit2(ctx, ptr, ALLOC_FAMILY_KERNEL_SLAB);
}

SEC("tp/kmem/kmem_cache_alloc_node")
int handle_kmem_cache_alloc_node(struct trace_event_raw_kmem_cache_alloc *ctx)
{
    size_t size = ctx->bytes_alloc;
    u64 ptr = (u64)ctx->ptr;

    gen_kernel_alloc_enter(size, ALLOC_FAMILY_KERNEL_SLAB);
    return gen_kernel_alloc_exit2(ctx, ptr, ALLOC_FAMILY_KERNEL_SLAB);
}

SEC("tp/kmem/kfree")
int handle_kfree(struct trace_event_raw_kfree *ctx)
{
    return gen_kernel_free_enter(ctx, (void *)ctx->ptr, ALLOC_FAMILY_KERNEL_SLAB);
}

SEC("tp/kmem/kmem_cache_free")
int handle_kmem_cache_free(struct trace_event_raw_kmem_cache_free *ctx)
{
    return gen_kernel_free_enter(ctx, (void *)ctx->ptr, ALLOC_FAMILY_KERNEL_SLAB);
}

SEC("tp/kmem/mm_page_alloc")
int handle_mm_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
    u64 addr = ctx->pfn;
    u64 size = g_emleak_prog.page_size << ctx->order;

    gen_kernel_alloc_enter(size, ALLOC_FAMILY_KERNEL_PAGE);
    return gen_kernel_alloc_exit2(ctx, addr, ALLOC_FAMILY_KERNEL_PAGE);
}

SEC("tp/kmem/mm_page_free")
int handle_mm_page_free(struct trace_event_raw_mm_page_free *ctx)
{
    u64 addr = ctx->pfn;

    return gen_kernel_free_enter(ctx, (void *)addr, ALLOC_FAMILY_KERNEL_PAGE);
}
