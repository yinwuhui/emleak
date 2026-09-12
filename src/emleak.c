#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <getopt.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>

#define __USE_GNU
#include <dlfcn.h>

#include "uthash.h"
#include "common.h"
#include "emleak.share.h"
#include "procsyms.h"
#include "emleak.h"
#include "emleak.skel.h"
#include "bcc_syms.h"

#define MAXBUFFLEN 1024
#define PRINT_STACK(fp, fmt, ...) \
do{	\
	char buffer[MAXBUFFLEN] = {0};\
	snprintf(buffer, MAXBUFFLEN, fmt, __VA_ARGS__);\
	if(fp){	\
		fwrite(buffer, 1, strlen(buffer), fp);\
	}else{\
		printf("%s", buffer);\
	}\
}while(0)\

struct emleak_bpf *skel;
struct emleakpara cmdparas = 
		{ 0, "a.out", 10, STACK_OUTFILE_NAME, SUMMARY_OUTFILE_NAME, STATICS_OUTFILE_NAME};

int g_exiting = 0;
volatile int g_signal = 0;

static int g_sizes_fd;
static int g_allocs_fd;
static int g_memptrs_fd;
static int g_stack_traces_fd;
static int g_combined_allocs_fd;

pthread_mutex_t g_perf_event_mutex;  /*Avoid  kernel event and user sigfun printing at the same time*/

static const char *__doc__ = 
"usage: %s [OPTS] \n"
"   Trace outstanding memory allocations that weren't freed.\n"
"Supports allocations made with libc functions\n"
"Supports allocations made with you customization functions\n"
"\nOPTS:\n"
"    -p    the PID to trace \n"
"    -c    the program name to trace, must start emleak before program \n"
"    -i    interval in seconds to print outstanding allocations \n"
"    -k    trace kernel allocations \n"
"    --kernel-pages trace kernel page allocator too \n"
"    --cgroup PATH    filter allocations by cgroup path \n"
"    --sample-rate N  sample roughly one allocation in N \n"
"    --min-size BYTES only trace allocations at least this size \n"
"    --max-size BYTES only trace allocations at most this size \n"
"    --older MS       report only allocations older than MS milliseconds \n"
"    -m    set you customized malloc function. ex(-m my_malloc) \n"
"    -f    set you customized free function. ex(-m my_free) \n";

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "pid", required_argument, NULL, 'p' },
	{ "comm", required_argument, NULL, 'c' },
	{ "interval", required_argument, NULL, 'i' },
	{ "kernel", no_argument, NULL, 'k' },
	{ "kernel-pages", no_argument, NULL, 1000 },
	{ "cgroup", required_argument, NULL, 1001 },
	{ "sample-rate", required_argument, NULL, 1002 },
	{ "min-size", required_argument, NULL, 1003 },
	{ "max-size", required_argument, NULL, 1004 },
	{ "older", required_argument, NULL, 1005 },
	{ "malloc", required_argument, NULL, 'm' },
	{ "free", required_argument, NULL, 'f' },
	{}
};

static void *g_kernel_syms;

static int parse_u64_option(const char *arg, uint64_t *value)
{
	char *end = NULL;
	unsigned long long parsed;

	errno = 0;
	parsed = strtoull(arg, &end, 0);
	if (errno || end == arg || *end != '\0')
		return -1;
	*value = parsed;
	return 0;
}

static int load_cgroup_id(struct emleakpara *paras)
{
	struct stat cgroup_stat;

	if (!paras->cgroup_path[0])
		return 0;
	if (stat(paras->cgroup_path, &cgroup_stat) != 0) {
		fprintf(stderr, "Failed to stat cgroup path %s: %s\n",
				paras->cgroup_path, strerror(errno));
		return -1;
	}
	if (!S_ISDIR(cgroup_stat.st_mode) || cgroup_stat.st_ino == 0) {
		fprintf(stderr, "Cgroup path is not a valid cgroup directory: %s\n",
				paras->cgroup_path);
		return -1;
	}

	paras->cgroup_id = cgroup_stat.st_ino;
	return 0;
}

static int kernel_syms_load(void)
{
	g_kernel_syms = bcc_symcache_new(-1, NULL);
	if (!g_kernel_syms) {
		fprintf(stderr, "Failed to load kernel symbols through libbcc.\n");
		return -1;
	}

	printf("Loaded kernel symbols through libbcc.\n");
	return 0;
}

static int kernel_symbol_resolve(uint64_t addr, struct proc_symbol *symbol)
{
	struct bcc_symbol bccsymbol = {};

	if (!symbol || !symbol->name || !g_kernel_syms)
		return -1;

	if (bcc_symcache_resolve_no_demangle(g_kernel_syms, addr, &bccsymbol) != 0
			|| !bccsymbol.name) {
		strcpy(symbol->name, "[UNKNOWN]");
		strcpy(symbol->module, "[UNKNOWN]");
		symbol->offset = 0;
		return -1;
	}

	snprintf(symbol->name, SYMBOL_NAME_LEN, "%s", bccsymbol.name);
	if (bccsymbol.module) {
		snprintf(symbol->module, SYMBOL_NAME_LEN, "%s", bccsymbol.module);
	} else {
		symbol->module[0] = '\0';
	}
	symbol->offset = bccsymbol.offset;
	return 0;
}

static int tracepoint_exists(const char *category, const char *name)
{
	char path[MAXFILELEN];

	snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s/id",
		 category, name);
	return access(path, R_OK) == 0;
}

static void set_user_programs_autoload(struct emleak_bpf *skel, bool autoload)
{
	bpf_program__set_autoload(skel->progs.malloc_enter, autoload);
	bpf_program__set_autoload(skel->progs.malloc_exit, autoload);
	bpf_program__set_autoload(skel->progs.free_enter, autoload);
	bpf_program__set_autoload(skel->progs.calloc_enter, autoload);
	bpf_program__set_autoload(skel->progs.calloc_exit, autoload);
	bpf_program__set_autoload(skel->progs.realloc_enter, autoload);
	bpf_program__set_autoload(skel->progs.realloc_exit, autoload);
	bpf_program__set_autoload(skel->progs.mmap_enter, autoload);
	bpf_program__set_autoload(skel->progs.mmap_exit, autoload);
	bpf_program__set_autoload(skel->progs.munmap_enter, autoload);
	bpf_program__set_autoload(skel->progs.posix_memalign_enter, autoload);
	bpf_program__set_autoload(skel->progs.posix_memalign_exit, autoload);
	bpf_program__set_autoload(skel->progs.aligned_alloc_enter, autoload);
	bpf_program__set_autoload(skel->progs.aligned_alloc_exit, autoload);
	bpf_program__set_autoload(skel->progs.valloc_enter, autoload);
	bpf_program__set_autoload(skel->progs.valloc_exit, autoload);
	bpf_program__set_autoload(skel->progs.memalign_enter, autoload);
	bpf_program__set_autoload(skel->progs.memalign_exit, autoload);
	bpf_program__set_autoload(skel->progs.pvalloc_enter, autoload);
	bpf_program__set_autoload(skel->progs.pvalloc_exit, autoload);
	bpf_program__set_autoload(skel->progs.malloc_add, autoload);
	bpf_program__set_autoload(skel->progs.retmalloc_add, autoload);
	bpf_program__set_autoload(skel->progs.free_add, autoload);
}

static void set_kernel_programs_autoload(struct emleak_bpf *skel, bool autoload, bool trace_pages)
{
	bpf_program__set_autoload(skel->progs.handle_kmalloc,
				  autoload && tracepoint_exists("kmem", "kmalloc"));
	bpf_program__set_autoload(skel->progs.handle_kmalloc_node,
				  autoload && tracepoint_exists("kmem", "kmalloc_node"));
	bpf_program__set_autoload(skel->progs.handle_kmem_cache_alloc,
				  autoload && tracepoint_exists("kmem", "kmem_cache_alloc"));
	bpf_program__set_autoload(skel->progs.handle_kmem_cache_alloc_node,
				  autoload && tracepoint_exists("kmem", "kmem_cache_alloc_node"));
	bpf_program__set_autoload(skel->progs.handle_kfree,
				  autoload && tracepoint_exists("kmem", "kfree"));
	bpf_program__set_autoload(skel->progs.handle_kmem_cache_free,
				  autoload && tracepoint_exists("kmem", "kmem_cache_free"));
	bpf_program__set_autoload(skel->progs.handle_mm_page_alloc,
				  autoload && trace_pages && tracepoint_exists("kmem", "mm_page_alloc"));
	bpf_program__set_autoload(skel->progs.handle_mm_page_free,
				  autoload && trace_pages && tracepoint_exists("kmem", "mm_page_free"));
}

static void configure_bpf_programs(struct emleak_bpf *skel, struct emleakpara *paras)
{
	if (paras->trace_kernel) {
		set_user_programs_autoload(skel, false);
		bpf_program__set_autoload(skel->progs.handle_exec, false);
		bpf_program__set_autoload(skel->progs.handle_exit, false);
		set_kernel_programs_autoload(skel, true, paras->trace_kernel_pages);
	} else {
		set_user_programs_autoload(skel, true);
		bpf_program__set_autoload(skel->progs.handle_exec, true);
		bpf_program__set_autoload(skel->progs.handle_exit, true);
		set_kernel_programs_autoload(skel, false, false);
	}
}

void emleak_usage(char *argv[], const struct option *long_options,
		  		const char *doc, bool error)
{
	int i;

	printf("\n%s\nOption for %s:\n", doc, argv[0]);
	for (i = 0; long_options[i].name != 0; i++) {
		printf(" --%-15s", long_options[i].name);
		if (long_options[i].flag != NULL)
			printf(" flag (internal value: %d)",
			       *long_options[i].flag);
		else if (long_options[i].val >= 32 && long_options[i].val <= 126)
			printf("\t short-option: -%c", long_options[i].val);
		else
			printf("\t long-only option");
		printf("\n");
	}
	printf("\n");
}

int cmd_opts_analytic(int argc, char **argv, struct emleakpara* paras)
{
	int ret = 0;
	bool error = true;
	int opt;
	int longindex = 0;
	
	/* Parse commands line args */
	while ((opt = getopt_long(argc, argv, "p:c:i:m:f:kh",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'p':
			paras->pid = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			if(strlen(optarg) >= TASK_COMM_LEN){
				error = true;
				goto err_out;
			}
			strcpy(paras->prog_comm, optarg);
			paras->comm_filter = 1;
			break;
		case 'i':
			paras->interval = strtoul(optarg, NULL, 0);
			break;
		case 'k':
			paras->trace_kernel = 1;
			break;
		case 1000:
			paras->trace_kernel = 1;
			paras->trace_kernel_pages = 1;
			break;
		case 1001:
			if (strlen(optarg) >= MAXFILELEN) {
				error = true;
				goto err_out;
			}
			strcpy(paras->cgroup_path, optarg);
			break;
		case 1002:
			if (parse_u64_option(optarg, &paras->sample_rate) != 0
					|| paras->sample_rate == 0) {
				error = true;
				goto err_out;
			}
			break;
		case 1003:
			if (parse_u64_option(optarg, &paras->min_size) != 0) {
				error = true;
				goto err_out;
			}
			break;
		case 1004:
			if (parse_u64_option(optarg, &paras->max_size) != 0) {
				error = true;
				goto err_out;
			}
			break;
		case 1005: {
			uint64_t older_ms;

			if (parse_u64_option(optarg, &older_ms) != 0
					|| older_ms > UINT64_MAX / 1000000ULL) {
				error = true;
				goto err_out;
			}
			paras->older_ns = older_ms * 1000000ULL;
			break;
		}
		case 'm':
			if(strlen(optarg) > MAXFILELEN){
				error = true;
				goto err_out;
			}
			strcpy(paras->mfuncname, optarg);
			break;
		case 'f':
			if(strlen(optarg) > MAXFILELEN){
				error = true;
				goto err_out;
			}
			strcpy(paras->ffuncname, optarg);
			break;
		case 'h':
			error = false;
			goto err_out;
		default:
			error = true;
			goto err_out;
		}
	}

	if (paras->sample_rate == 0)
		paras->sample_rate = 1;
	if (paras->max_size && paras->min_size > paras->max_size) {
		error = true;
		goto err_out;
	}

	return ret;

err_out:
	emleak_usage(argv, long_options, __doc__, error);
	return -1;
}

int cmp_by_memsum(const struct stack_node *a, const struct stack_node *b) {
    if(a->memsum < b->memsum){
		return -1;
	}else if(a->memsum == b->memsum){
		return 0;
	}else{
		return 1;
	}
}

void p_symbol_init(struct proc_symbol *symbol)
{
	memset(symbol, 0x00, sizeof(*symbol));
	symbol->name = malloc(SYMBOL_NAME_LEN);
	symbol->module = malloc(SYMBOL_NAME_LEN);
	symbol->demangle_name = malloc(SYMBOL_NAME_LEN);
}

void p_symbol_uninit(struct proc_symbol *symbol)
{
	free(symbol->name);
	free(symbol->module);
	free(symbol->demangle_name);
}

static void print_stacks(struct stack_node **stackmaps, char *outfilename)
{
	int ret = 0;
	stack_trace_t progstack = {};
	struct stack_node *tmpnode = NULL;
	struct proc_symbol symbol;
	FILE *fp = NULL;

	p_symbol_init(&symbol);

	if(outfilename && strlen(outfilename)){
		fp = fopen(outfilename,"a+");
		if(!fp){
			printf("Failed to open stacks outfile. filename = %s.", outfilename);
			return ;
		}
	}

	for (tmpnode = *stackmaps; tmpnode != NULL; tmpnode = tmpnode->hh.next) 
	{
        if (bpf_map_lookup_elem(g_stack_traces_fd, &tmpnode->stack_id, progstack) != 0) {
			printf("---;");
			continue;
		} 
		
		PRINT_STACK(fp, "%d bytes allocated at callstack id %d: \n", tmpnode->memsum, tmpnode->stack_id);

		for (int i = 0; i < PERF_MAX_STACK_DEPTH ; i++)
		{
			if(!progstack[i]){
				continue;
			}

			if (cmdparas.trace_kernel) {
				ret = kernel_symbol_resolve(progstack[i], &symbol);
			} else {
				ret = proc_symbol_resolve(progstack[i], &symbol);
			}
			if(ret != 0){
				break;
			}

			if (cmdparas.trace_kernel && symbol.module[0]) {
				PRINT_STACK(fp, "\t%s+0x%lx [%s];\n",
						symbol.name, symbol.offset, symbol.module);
			} else {
				PRINT_STACK(fp, "\t%s+0x%lx;\n", symbol.name, symbol.offset);
			}
		}
    }

	if(fp){
		fclose(fp);
	}
	p_symbol_uninit(&symbol);
	return ;
}

static void print_summary(struct stack_node **stackmaps, char *outfilename)
{
#define MAX_BUFF_LEN 256
	FILE *fp = NULL;
	struct stack_node *tmpnode = NULL;
	char buffer[MAX_BUFF_LEN] = {0};

	if(outfilename == NULL || strlen(outfilename) == 0){
		return ;
	}

	fp = fopen(outfilename,"a+");
	if(!fp){
		printf("Failed to open summary outfile. filename = %s.", outfilename);
		return ;
	}

	for (tmpnode = *stackmaps; tmpnode != NULL; tmpnode = tmpnode->hh.next){
		snprintf(buffer, MAX_BUFF_LEN, "%d, %d, %d \n", 
					tmpnode->stack_id, tmpnode->memsum, tmpnode->memtimes);
		fwrite(buffer, 1, strlen(buffer), fp);
	}

	if(fp){
		fclose(fp);
	}

	return;
}

int outfiles_init(int pid, struct emleakpara *para)
{
	char path[MAXFILELEN/2] = {0}; 
    struct stat sb;
	FILE* fp = NULL;
	memset(&sb, 0x00, sizeof(sb));

	if(para == NULL)
	{
		printf("Failed to init outfiles, nvalid parameter.");
		return -1;
	}
	
	/* Use the process pid and current time as the 
	 * name of the output directory*/
	sprintf(path, "mleak_pid%d_time%ld", pid, time(NULL));

    if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
        printf("Folder already exists.\n");

    } else {
        if (mkdir(path, 0777) == 0) {
            printf("Folder created.\n");
        } else {
            printf("Failed to create folder.\n");
        }
    }

	snprintf(para->stackfile, MAXFILELEN, "%s/%s", path, STACK_OUTFILE_NAME);
	snprintf(para->summaryfile, MAXFILELEN, "%s/%s", path, SUMMARY_OUTFILE_NAME);
	snprintf(para->statisticalfile, MAXFILELEN, "%s/%s", path, STATICS_OUTFILE_NAME);

	fp = fopen(para->stackfile, "w");
    if (fp == NULL) {
        printf("Failed to create stackfile file.\n");
		return -1;
    } else {
        fclose(fp); 
    }

	fp = fopen(para->summaryfile, "w");
    if (fp == NULL) {
        printf("Failed to create summaryfile file.\n");
		return -1;
    } else {
        fclose(fp); 
    }

	fp = fopen(para->statisticalfile, "w");
    if (fp == NULL) {
        printf("Failed to create statisticalfile file.\n");
		return -1;
    } else {
        fclose(fp); 
    }

	printf("outfiles in dir: %s.\n", path);

	return 0;
}

struct statistical g_statistical = {.stack_num = 1};
static void print_statistical_head(char *outfilename)
{
	FILE *fp = NULL;
	char buffer[1024]  = {0};
	memset(buffer, 0x0, sizeof(buffer));

	fp = fopen(outfilename,"a+");
	if(!fp){
		printf("Failed to open statistical outfile. filename = %s.\n", outfilename);
		return ;
	}
	
	for(int i = 0; i < g_statistical.stack_num; i++)
	{
		sprintf(buffer + strlen(buffer), "%d,", g_statistical.stack_id[i]);
		if(i > 50){
			fwrite(buffer, 1, strlen(buffer), fp);
			memset(buffer, 0x0, sizeof(buffer));
		}
	}
	sprintf(buffer + strlen(buffer), "\n");
	fwrite(buffer, 1, strlen(buffer), fp);

	fclose(fp);

	return ;
}

static void print_statistical(struct stack_node **stackmaps, char *outfilename)
{
	FILE *fp = NULL;
	char buffer[1024]  = {0};
	int index_summry = 0;
	struct stack_node *tmpnode = NULL;

	if(outfilename == NULL || strlen(outfilename) == 0){
		return ;
	}

	g_statistical.stack_summry[0] = time(NULL);
	for (tmpnode = *stackmaps; tmpnode != NULL; tmpnode = tmpnode->hh.next)
	{
		if(tmpnode->stack_id < 0 || tmpnode->stack_id >= MAX_CALL_STACKS
				|| g_statistical.stack_num >= MAX_CALL_STACKS){
			continue;
		}

		if(g_statistical.stack_hash[tmpnode->stack_id] == 0){
			g_statistical.stack_hash[tmpnode->stack_id] = g_statistical.stack_num;
			index_summry = g_statistical.stack_num;
			g_statistical.stack_num++;
		}else{
			index_summry = g_statistical.stack_hash[tmpnode->stack_id];
		}

		g_statistical.stack_id[index_summry] = tmpnode->stack_id;
		g_statistical.stack_summry[index_summry] = tmpnode->memsum;
	}

	if(g_statistical.stack_num <= 1){
		return ;
	}

	memset(buffer, 0x0, sizeof(buffer));
	fp = fopen(outfilename,"a+");
	if(!fp){
		printf("Failed to open statistical outfile. filename = %s.\n", outfilename);
		return ;
	}

	for(int i = 0; i < g_statistical.stack_num; i++)
	{
		sprintf(buffer + strlen(buffer), "%d,", g_statistical.stack_summry[i]);
		if(i > 50){
			fwrite(buffer, 1, strlen(buffer), fp);
			memset(buffer, 0x0, sizeof(buffer));
		}
	}
	sprintf(buffer + strlen(buffer), "\n");

	fwrite(buffer, 1, strlen(buffer), fp);
	fclose(fp);

	return;
}

void add_stack_node(struct stack_node **stackmaps, int stack_id, int memsize) {
    struct stack_node *s;

    HASH_FIND_INT(*stackmaps, &stack_id, s);  /* id already in the hash? */
    if (s == NULL) {
      s = (struct stack_node *)malloc(sizeof *s);
      s->stack_id = stack_id;
	  s->memtimes = 1; 
	  s->memsum = memsize;
      HASH_ADD_INT(*stackmaps, stack_id, s);  /* id: name of key field */
    }

	/*update node*/
    s->memtimes ++;
	s->memsum += memsize;
}

void print_outstanding(char *stacksfile, char *summaryfile, char *statisticalfile, int islastprint)
{
	struct alloc_key_t prev_key = {}, key = {};
	__u64 now_ns = 0;
	struct alloc_info_t alloc_info;
	struct stack_node *stackmaps = NULL;
	struct timespec now;

	if (cmdparas.older_ns) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		now_ns = (__u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
	}

	while (bpf_map_get_next_key(g_allocs_fd, &prev_key, &key) == 0) 
	{
		if (bpf_map_lookup_elem(g_allocs_fd, &key, &alloc_info) != 0) {
			prev_key = key;
			continue;
		}

		if (cmdparas.older_ns && now_ns > alloc_info.timestamp_ns
				&& now_ns - alloc_info.timestamp_ns < cmdparas.older_ns) {
			prev_key = key;
			continue;
		}

		if(alloc_info.stack_id < 0){
			prev_key = key;
			continue;
		}

		add_stack_node(&stackmaps, alloc_info.stack_id, alloc_info.size);
		prev_key = key;
	}
	
	/*Sort by memory size*/
	HASH_SORT(stackmaps, cmp_by_memsum);

	if (stacksfile && strlen(stacksfile)) {
		print_stacks(&stackmaps, stacksfile);
	}
	if (summaryfile && strlen(summaryfile)) {
		print_summary(&stackmaps, summaryfile);
	}
	print_statistical(&stackmaps, statisticalfile);
	if(islastprint)
	{
		print_statistical_head(statisticalfile);
	}

	HASH_CLEAR(hh, stackmaps);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

int get_executable_path_by_pid(int pid, char *path_buf, size_t buf_size)
{
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);

    char exe_link[MAXFILELEN];
    memset(exe_link, 0, sizeof(exe_link));
    snprintf(exe_link, sizeof(exe_link), "/proc/%s/exe", pid_str);

    ssize_t len = readlink(exe_link, path_buf, buf_size);
    if (len == -1) {
        perror("readlink");
        return -1;
    }

    path_buf[len] = '\0';
    return 0;
}

static void bpf_para_load(struct emleak_bpf *skel, struct emleakpara *paras)
{
	long page_size = sysconf(_SC_PAGESIZE);

	if (page_size <= 0)
		page_size = 4096;
	skel->bss->g_emleak_prog.page_size = page_size;
	skel->bss->g_emleak_prog.filter_pid = paras->trace_kernel ? paras->pid : 0;
	skel->bss->g_emleak_prog.filter_cgroup_id = paras->cgroup_id;
	skel->bss->g_emleak_prog.filter_comm_enabled = paras->comm_filter;
	skel->bss->g_emleak_prog.sample_rate = paras->sample_rate;
	skel->bss->g_emleak_prog.min_size = paras->min_size;
	skel->bss->g_emleak_prog.max_size = paras->max_size;

	if (paras->trace_kernel) {
		skel->bss->g_emleak_prog.trace_kernel = 1;
		skel->bss->g_emleak_prog.prog_pid = 0;
		skel->bss->g_emleak_prog.prog_state = PROG_START_STATE;
		kernel_syms_load();
		outfiles_init(0, paras);
		goto set_start_time;
	}

	/*load program pwd*/
	if(paras->pid != 0){
		get_executable_path_by_pid(paras->pid, paras->elffile, MAXFILELEN);
	}

	/*If is not pid, wait until the process is checked before initializing*/
	if(paras->pid != 0){
		int ret = proc_syms_load(paras->pid);
		if(ret == 0){
			printf("Loaded successfully, pid = %ld...\n", paras->pid);
		}else{
			printf("Loaded failed, pid = %ld!\n", paras->pid);
		}

		outfiles_init(paras->pid, paras);
	}

	if(paras->pid != 0){
		skel->bss->g_emleak_prog.prog_pid = paras->pid;
		skel->bss->g_emleak_prog.prog_state = PROG_START_STATE;
	}else{
		strcpy(skel->bss->g_emleak_prog.prog_comm, paras->prog_comm);
		skel->bss->g_emleak_prog.prog_state = PROG_IDEL_STATE;
	}

set_start_time:
	struct timespec stime;
	clock_gettime(CLOCK_MONOTONIC, &stime);
	skel->bss->g_emleak_prog.start_time = stime.tv_sec;
	skel->bss->g_emleak_prog.end_time = 0;
	
	return ;
}

static void old_environment_clean(void)
{
	struct alloc_ctx_key_t size_prev_key = {}, size_key = {};
	struct alloc_key_t alloc_prev_key = {}, alloc_key = {};
	__u64 prev_key = 0, key = 0;
	__u32 prev_key1 = 0, key1 = 0;

	while (bpf_map_get_next_key(g_sizes_fd, &size_prev_key, &size_key) == 0){
		bpf_map_delete_elem(g_sizes_fd, &size_key);
		size_prev_key = size_key;
	}

	while (bpf_map_get_next_key(g_allocs_fd, &alloc_prev_key, &alloc_key) == 0){
		bpf_map_delete_elem(g_allocs_fd, &alloc_key);
		alloc_prev_key = alloc_key;
	}

	prev_key = 0;
	while (bpf_map_get_next_key(g_memptrs_fd, &prev_key, &key) == 0){
		bpf_map_delete_elem(g_memptrs_fd, &key);
	}

	prev_key = 0;
	while (bpf_map_get_next_key(g_stack_traces_fd, &prev_key1, &key1) == 0){
		bpf_map_delete_elem(g_stack_traces_fd, &key1);
	}

	prev_key = 0;
	while (bpf_map_get_next_key(g_combined_allocs_fd, &prev_key, &key) == 0){
		bpf_map_delete_elem(g_combined_allocs_fd, &key);
	}

	return ;
}

static void handle_perf_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event_t *msg = data;

	pthread_mutex_lock(&g_perf_event_mutex);
	if(skel->bss->g_emleak_prog.prog_state == PROG_IDEL_STATE){
		pthread_mutex_unlock(&g_perf_event_mutex);
		return ;
	}
	
	if(msg->old_state == PROG_START_STATE 
	   	&& msg->new_state == PROG_END_STATE)
	{
		print_outstanding(cmdparas.stackfile, cmdparas.summaryfile, cmdparas.statisticalfile, 1);

		old_environment_clean();
		skel->bss->g_emleak_prog.prog_state = PROG_IDEL_STATE;

		printf("untouch ok pid = %lld.\n", skel->bss->g_emleak_prog.prog_pid);
	}else if(msg->old_state == PROG_IDEL_STATE 
	   			&& msg->new_state == PROG_START_STATE){
		skel->bss->g_emleak_prog.prog_state = PROG_START_STATE;
		int pid = skel->bss->g_emleak_prog.prog_pid;
		printf("touch ok pid = %d.\n", pid);

		int ret = proc_syms_load(pid);
		if(ret == 0){
			printf("Loaded successfully, pid = %d...\n", pid);
		}else{
			printf("Loaded failed, pid = %d!\n", pid);
		}
		outfiles_init(pid, &cmdparas);
	}

	pthread_mutex_unlock(&g_perf_event_mutex);

	return ;
}

static void handle_lost_perf_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void* print_thread(void* arg)
{
	int ret = 0;
	int interval = *(int*)arg;
	int epoll_fd = 0;
	struct epoll_event events[1];

	epoll_fd = epoll_create(1); 
    if (epoll_fd < 0) {
        printf("epoll_create error, Error:[%d:%s]", errno, strerror(errno));
        return NULL;
    }

	struct epoll_event event;
	memset(&event, 0, sizeof(event));
    event.data.fd = socket(AF_INET, SOCK_STREAM, 0);
	if(event.data.fd <= 0){
		printf("inviled socket = %d\n", event.data.fd);
		return NULL;
	}
    event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event.data.fd, &event);
    if(ret < 0) {
        printf("epoll_ctl Add fd:%d error, Error:[%d:%s]", event.data.fd, errno, strerror(errno));
        return NULL;
    }

	int times_index = 0;
	while(1){
		ret = epoll_wait(epoll_fd, events, sizeof(events)/sizeof(struct epoll_event), 1000);
		times_index++;

		if(g_signal){
			close(event.data.fd);
			return NULL;
		}

		if(times_index < interval){
			continue;
		}

		if(skel->bss->g_emleak_prog.prog_state == PROG_START_STATE)
		{
			print_outstanding(NULL, NULL, cmdparas.statisticalfile, 0);
		}
		times_index = 0;
	}
}

void emleak_signal(int sig)
{
	printf("start process emleak_signal. sig = %d.\n", sig);

	/*Notification print thread*/
	g_signal = sig;

	return ;
}

ssize_t get_symbol_uprobe_offset(char *elf_pwd, char *symbol_name)
{
	void *handle = NULL;
    void *func_ptr = NULL;
	Dl_info info;

	memset(&info, 0x00, sizeof(info));

	if(elf_pwd == NULL || symbol_name == NULL){
		return 0;
	}
	if(strlen(elf_pwd) == 0 || strlen(symbol_name) == 0){
		return 0;
	}

	/*open the elf file.*/
	handle = dlopen(elf_pwd, RTLD_NOW); 
    if (!handle) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 0;
    }

	func_ptr = dlsym(handle, symbol_name);
    if (!func_ptr) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 0;
    }

	if (!dladdr(func_ptr, &info)) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 0;
    }

	dlclose(handle);

    return func_ptr - info.dli_fbase;
}

int user_defined_func_attach(struct emleak_bpf *skel,
				char *elf_pwd, char *malloc_func, char *free_func)
{
	long m_offset, f_offset;

	if(!skel){
		return -1;
	}

	m_offset = get_symbol_uprobe_offset(elf_pwd, malloc_func);
	f_offset = get_symbol_uprobe_offset(elf_pwd, free_func);

	/*touch malloc*/
	if(m_offset != 0){
		skel->links.malloc_add = bpf_program__attach_uprobe(skel->progs.malloc_add,
							    		false, 0, elf_pwd, m_offset);
		if (!skel->links.malloc_add) {
			//fprintf(stderr, "Failed to attach uprobe malloc: %d\n", err);
			return -1;
		}

		skel->links.retmalloc_add = bpf_program__attach_uprobe(skel->progs.retmalloc_add,
									true, 0, elf_pwd, m_offset);
		if (!skel->links.retmalloc_add) {
			//fprintf(stderr, "Failed to attach upretrobe malloc: %d\n", err);
			return -1;
		}
	}

	/*touch free*/
	if(f_offset != 0){
		skel->links.free_add = bpf_program__attach_uprobe(skel->progs.free_add,
							    		false, 0, elf_pwd, f_offset);
		if (!skel->links.free_add) {
			//fprintf(stderr, "Failed to attach uprobe free: %d\n", err);
			return -1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int err;
	int ret = 0;
	struct perf_buffer *pb = NULL;

	pthread_mutex_init(&g_perf_event_mutex, NULL);

	ret = cmd_opts_analytic(argc, argv, &cmdparas);
	if(ret < 0){

		return -1;
	}
	if (load_cgroup_id(&cmdparas) != 0)
		return -1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = emleak_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	bpf_para_load(skel, &cmdparas);
	configure_bpf_programs(skel, &cmdparas);

	/* Load & verify BPF programs */
	err = emleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	if (!cmdparas.trace_kernel) {
		err = user_defined_func_attach(skel,
							cmdparas.elffile, cmdparas.mfuncname, cmdparas.ffuncname);
		if (err) {
			fprintf(stderr, "Failed to attach customized allocation functions\n");
			goto cleanup;
		}
	}

	g_sizes_fd = bpf_map__fd(skel->maps.sizes); 
	g_allocs_fd = bpf_map__fd(skel->maps.allocs);
	g_memptrs_fd = bpf_map__fd(skel->maps.memptrs);
	g_stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
	g_combined_allocs_fd = bpf_map__fd(skel->maps.combined_allocs);

	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
			      handle_perf_event, handle_lost_perf_events, NULL, NULL);
	if (!pb) {
		err = -errno;
		printf("failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
	 * NOTICE: we provide path and symbol info in SEC for BPF programs
	 */
	err = emleak_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	pthread_t print_tid;
	if(cmdparas.interval){
		if (pthread_create(&print_tid, NULL, (void*)print_thread, (void*)&cmdparas.interval) != 0) {
			printf("print pthread create error.");
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGINT, emleak_signal);

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	while(!g_exiting) {
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			printf("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		if (g_signal) {
			struct event_t new_msg;

			new_msg.pid = skel->bss->g_emleak_prog.prog_pid;
			new_msg.msg_type = 0;
			new_msg.old_state = skel->bss->g_emleak_prog.prog_state;
			new_msg.new_state = PROG_END_STATE;

			handle_perf_event(NULL, 0 , &new_msg, sizeof(new_msg));
			printf("Exporting call stack data successfully. outfile[%s,%s,%s]\n",
			            cmdparas.stackfile, cmdparas.summaryfile, cmdparas.statisticalfile);
			g_exiting = 1;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	if (g_kernel_syms)
		bcc_free_symcache(g_kernel_syms, -1);
	emleak_bpf__destroy(skel);
	return -err;
}
