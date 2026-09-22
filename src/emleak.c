#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <termios.h>
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
#include <sys/ioctl.h>
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
#include "tui.h"
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
struct emleakpara cmdparas = {
	.pid = 0,
	.prog_comm = "a.out",
	.interval = 10,
	.sample_rate = 1,
	.top_n = 0,
	.mode = EMLEAK_MODE_RECORD,
};

static volatile sig_atomic_t g_exiting;
static volatile sig_atomic_t g_signal;

static int g_sizes_fd;
static int g_realloc_ptrs_fd;
static int g_allocs_fd;
static int g_memptrs_fd;
static int g_stack_traces_fd;
static int g_combined_allocs_fd;
static uint64_t g_last_alloc_events;
static uint64_t g_last_free_events;
static uint64_t g_last_total_bytes;
static uint64_t g_last_snapshot_ns;

static int attach_user_allocator(struct emleak_bpf *skeleton, pid_t pid);
int user_defined_func_attach(struct emleak_bpf *skel, char *elf_pwd,
		char *malloc_func, char *free_func, pid_t pid);

static uint64_t read_meminfo_kb(const char *name)
{
	FILE *fp;
	char line[256];
	unsigned long long parsed;
	char key[64];

	fp = fopen("/proc/meminfo", "r");
	if (!fp)
		return 0;
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%63s %llu", key, &parsed) == 2
				&& strcmp(key, name) == 0) {
			fclose(fp);
			return (uint64_t)parsed;
		}
	}
	fclose(fp);
	return 0;
}

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
	"    --top N          limit top mode to N rows (default fills terminal) \n"
	"    --show-stacks    show resolved stack details in top mode \n"
	"    --by-stack       show one row per stack in top mode (default folds by process) \n"
"    --duration SEC   stop record mode after SEC seconds \n"
"    -m    set you customized malloc function. ex(-m my_malloc) \n"
	"    -f    set you customized free function. ex(-m my_free) \n";

static uid_t output_owner_uid(void)
{
	const char *sudo_uid = getenv("SUDO_UID");
	char *end;
	unsigned long uid;

	if (!sudo_uid)
		return getuid();
	uid = strtoul(sudo_uid, &end, 10);
	return *end == '\0' ? (uid_t)uid : getuid();
}

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
	{ "top", required_argument, NULL, 1006 },
	{ "duration", required_argument, NULL, 1007 },
	{ "show-stacks", no_argument, NULL, 1008 },
	{ "by-stack", no_argument, NULL, 1010 },
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

static void set_user_programs_autoattach(struct emleak_bpf *skel, bool autoattach)
{
	#define SET_AUTOATTACH(name) bpf_program__set_autoattach(skel->progs.name, autoattach)
	SET_AUTOATTACH(malloc_enter); SET_AUTOATTACH(malloc_exit); SET_AUTOATTACH(free_enter);
	SET_AUTOATTACH(calloc_enter); SET_AUTOATTACH(calloc_exit); SET_AUTOATTACH(realloc_enter);
	SET_AUTOATTACH(realloc_exit); SET_AUTOATTACH(mmap_enter); SET_AUTOATTACH(mmap_exit);
	SET_AUTOATTACH(munmap_enter); SET_AUTOATTACH(posix_memalign_enter);
	SET_AUTOATTACH(posix_memalign_exit); SET_AUTOATTACH(aligned_alloc_enter);
	SET_AUTOATTACH(aligned_alloc_exit); SET_AUTOATTACH(valloc_enter); SET_AUTOATTACH(valloc_exit);
	SET_AUTOATTACH(memalign_enter); SET_AUTOATTACH(memalign_exit); SET_AUTOATTACH(pvalloc_enter);
	SET_AUTOATTACH(pvalloc_exit); SET_AUTOATTACH(malloc_add); SET_AUTOATTACH(retmalloc_add);
	SET_AUTOATTACH(free_add);
	#undef SET_AUTOATTACH
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
		/* Standard libc probes are attached explicitly to the selected PID. */
		set_user_programs_autoload(skel, true);
		set_user_programs_autoattach(skel, false);
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
		case 1006: {
			uint64_t top_n;

			if (parse_u64_option(optarg, &top_n) != 0 || top_n == 0 || top_n > 1000) {
				error = true;
				goto err_out;
			}
			paras->top_n = top_n;
			break;
		}
	case 1007:
			if (parse_u64_option(optarg, &paras->duration) != 0) {
				error = true;
				goto err_out;
			}
		break;
	case 1008:
		paras->show_stacks = 1;
		break;
	case 1010:
		paras->by_stack = 1;
		break;
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
	    if(a->memsum > b->memsum){
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
	        if (tmpnode->key.stack_id < 0
				|| bpf_map_lookup_elem(g_stack_traces_fd, &tmpnode->key.stack_id, progstack) != 0) {
			printf("---;");
			continue;
		} 
		
		PRINT_STACK(fp, "%llu bytes allocated by pid %llu (%s), stack id %d: \n",
				(unsigned long long)tmpnode->memsum,
				(unsigned long long)tmpnode->key.tgid, tmpnode->key.comm,
				tmpnode->key.stack_id);

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
			snprintf(buffer, MAX_BUFF_LEN, "%llu,%s,%llu,%d,%llu,%llu,%llu,%llu\n",
						(unsigned long long)tmpnode->key.tgid,
						tmpnode->key.comm,
						(unsigned long long)tmpnode->key.family,
						tmpnode->key.stack_id,
						(unsigned long long)tmpnode->memsum,
						(unsigned long long)tmpnode->memtimes,
						(unsigned long long)tmpnode->allocated_bytes,
						(unsigned long long)tmpnode->freed_bytes);
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
	uid_t owner = output_owner_uid();
	memset(&sb, 0x00, sizeof(sb));

	if(para == NULL)
	{
		printf("Failed to init outfiles, nvalid parameter.");
		return -1;
	}
	
	/* Use the process pid and current time as the 
	 * name of the output directory*/
	if (snprintf(path, sizeof(path), "mleak_pid%d_time%ld", pid, time(NULL))
			>= (int)sizeof(path))
		return -1;

	if (stat(path, &sb) == 0 && S_ISDIR(sb.st_mode)) {
	        printf("Folder already exists.\n");

	} else {
		if (mkdir(path, 0750) == 0) {
	            printf("Folder created.\n");
	        } else {
	            printf("Failed to create folder.\n");
	        }
	}
	if (chown(path, owner, (gid_t)-1) != 0 && errno != EPERM)
		fprintf(stderr, "Failed to set output owner for %s: %s\n", path, strerror(errno));

	snprintf(para->stackfile, MAXFILELEN, "%s/%s", path, STACK_OUTFILE_NAME);
	snprintf(para->summaryfile, MAXFILELEN, "%s/%s", path, SUMMARY_OUTFILE_NAME);
	snprintf(para->statisticalfile, MAXFILELEN, "%s/%s", path, STATICS_OUTFILE_NAME);
	snprintf(para->foldedfile, MAXFILELEN, "%s/%s", path, FOLDED_OUTFILE_NAME);
	snprintf(para->healthfile, MAXFILELEN, "%s/%s", path, HEALTH_OUTFILE_NAME);

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
		fputs("tgid,comm,family,stack_id,bytes,objects,allocated_bytes,freed_bytes\n", fp);
		fclose(fp);
    }

	fp = fopen(para->statisticalfile, "w");
    if (fp == NULL) {
        printf("Failed to create statisticalfile file.\n");
		return -1;
    } else {
		fputs("timestamp_ns,tgid,comm,family,stack_id,bytes,objects,allocated_bytes,freed_bytes\n", fp);
		fclose(fp);
	}
	fp = fopen(para->foldedfile, "w");
	if (fp == NULL) {
		printf("Failed to create folded stack file.\n");
		return -1;
	}
	fclose(fp);
	fp = fopen(para->healthfile, "w");
	if (fp == NULL) {
		printf("Failed to create capture health file.\n");
		return -1;
	}
	fputs("timestamp_ns,alloc_events,free_events,alloc_map_failures,context_map_failures,aggregate_map_failures,stack_trace_failures\n", fp);
	fclose(fp);

	printf("outfiles in dir: %s.\n", path);

	return 0;
}

static void write_snapshot(struct stack_node **stackmaps, char *outfilename)
{
	struct stack_node *node;
	struct timespec now;
	FILE *fp;

	if (!outfilename || !outfilename[0])
		return;
	clock_gettime(CLOCK_REALTIME, &now);
	fp = fopen(outfilename, "a");
	if (!fp)
		return;
	for (node = *stackmaps; node; node = node->hh.next) {
		fprintf(fp, "%llu,%llu,%s,%llu,%d,%llu,%llu,%llu,%llu\n",
				(unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec,
				(unsigned long long)node->key.tgid, node->key.comm,
				(unsigned long long)node->key.family, node->key.stack_id,
				(unsigned long long)node->memsum,
				(unsigned long long)node->memtimes,
				(unsigned long long)node->allocated_bytes,
				(unsigned long long)node->freed_bytes);
	}
	fclose(fp);
}

static void write_folded_stacks(struct stack_node **stackmaps, const char *outfilename)
{
	struct stack_node *node;
	FILE *fp;

	if (!outfilename || !outfilename[0])
		return;
	fp = fopen(outfilename, "w");
	if (!fp)
		return;
	for (node = *stackmaps; node; node = node->hh.next) {
		stack_trace_t stack = {};
		struct proc_symbol symbol;
		char folded[8192] = {};
		size_t used = 0;
		int i;

		if (node->key.stack_id < 0
				|| bpf_map_lookup_elem(g_stack_traces_fd, &node->key.stack_id, stack) != 0)
			continue;
		p_symbol_init(&symbol);
		for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
			int ret;
			int written;

			if (!stack[i])
				continue;
			ret = cmdparas.trace_kernel ? kernel_symbol_resolve(stack[i], &symbol)
					: proc_symbol_resolve(stack[i], &symbol);
			if (ret != 0)
				continue;
			written = snprintf(folded + used, sizeof(folded) - used, "%s%s",
					used ? ";" : "", symbol.name);
			if (written < 0 || (size_t)written >= sizeof(folded) - used)
				break;
			used += written;
		}
		if (used)
			fprintf(fp, "%s %llu\n", folded, (unsigned long long)node->memsum);
		p_symbol_uninit(&symbol);
	}
	fclose(fp);
}

static void write_capture_health(const char *outfilename)
{
	struct timespec now;
	FILE *fp;

	if (!outfilename || !outfilename[0])
		return;
	clock_gettime(CLOCK_REALTIME, &now);
	fp = fopen(outfilename, "a");
	if (!fp)
		return;
	fprintf(fp, "%llu,%llu,%llu,%llu,%llu,%llu,%llu\n",
			(unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec,
			(unsigned long long)skel->bss->g_emleak_prog.alloc_events,
			(unsigned long long)skel->bss->g_emleak_prog.free_events,
			(unsigned long long)skel->bss->g_emleak_prog.alloc_map_failures,
			(unsigned long long)skel->bss->g_emleak_prog.context_map_failures,
			(unsigned long long)skel->bss->g_emleak_prog.aggregate_map_failures,
			(unsigned long long)skel->bss->g_emleak_prog.stack_trace_failures);
	fclose(fp);
}

static void free_stack_nodes(struct stack_node **stackmaps)
{
	struct stack_node *node;
	struct stack_node *tmp;

	HASH_ITER(hh, *stackmaps, node, tmp) {
		HASH_DEL(*stackmaps, node);
		free(node);
	}
}

static void add_stack_node(struct stack_node **stackmaps,
		const struct combined_alloc_key_t *key, uint64_t memsize, uint64_t memtimes,
		uint64_t allocated_bytes, uint64_t freed_bytes,
		uint64_t alloc_count, uint64_t free_count) {
    struct stack_node *s;

	HASH_FIND(hh, *stackmaps, key, sizeof(*key), s);
	if (s == NULL) {
		s = calloc(1, sizeof(*s));
		if (!s)
			return;
		s->key = *key;
		s->memtimes = memtimes;
		s->memsum = memsize;
		s->allocated_bytes = allocated_bytes;
		s->freed_bytes = freed_bytes;
		s->alloc_count = alloc_count;
		s->free_count = free_count;
		HASH_ADD(hh, *stackmaps, key, sizeof(s->key), s);
		return;
	}

	s->memtimes += memtimes;
	s->memsum += memsize;
	s->allocated_bytes += allocated_bytes;
	s->freed_bytes += freed_bytes;
	s->alloc_count += alloc_count;
	s->free_count += free_count;
}

#define TOP_MAX_PROC 1024

struct top_proc {
	uint64_t tgid;
	char comm[TASK_COMM_LEN];
	uint64_t memsum;
	uint64_t memtimes;
	uint64_t allocated_bytes;
	uint64_t freed_bytes;
	uint64_t alloc_count;
	uint64_t free_count;
	int nstacks;
};

static uint64_t g_sel_tgid;		/* selected process */
static bool g_sel_valid;		/* g_sel_tgid is meaningful (0 is a
					   real tgid: kernel self allocs) */
static uint64_t g_expanded_tgid;	/* expanded process */
static bool g_exp_valid;		/* g_expanded_tgid is meaningful */
static uint64_t g_proc_tgids[TOP_MAX_PROC]; /* processes as last rendered */
static int g_proc_count;
static bool g_top_skip_accounting;	/* key-triggered re-render leaves the
					   period accounting untouched */

static int cmp_top_proc_by_memsum(const void *a, const void *b)
{
	const struct top_proc *pa = a, *pb = b;

	if (pa->memsum > pb->memsum)
		return -1;
	if (pa->memsum == pb->memsum)
		return 0;
	return 1;
}

/* fold the per-stack rows into one summary row per process */
static int top_fold_procs(const struct stack_node *stackmaps,
		struct top_proc *procs, int max_procs)
{
	const struct stack_node *node;
	int n = 0;

	for (node = stackmaps; node; node = node->hh.next) {
		int i;

		for (i = 0; i < n; i++) {
			if (procs[i].tgid == node->key.tgid) {
				procs[i].memsum += node->memsum;
				procs[i].memtimes += node->memtimes;
				procs[i].allocated_bytes += node->allocated_bytes;
				procs[i].freed_bytes += node->freed_bytes;
				procs[i].alloc_count += node->alloc_count;
				procs[i].free_count += node->free_count;
				procs[i].nstacks++;
				break;
			}
		}
		if (i < n || n >= max_procs)
			continue;
		procs[n].tgid = node->key.tgid;
		snprintf(procs[n].comm, sizeof(procs[n].comm), "%s", node->key.comm);
		procs[n].memsum = node->memsum;
		procs[n].memtimes = node->memtimes;
		procs[n].allocated_bytes = node->allocated_bytes;
		procs[n].freed_bytes = node->freed_bytes;
		procs[n].alloc_count = node->alloc_count;
		procs[n].free_count = node->free_count;
		procs[n].nstacks = 1;
		n++;
	}
	qsort(procs, n, sizeof(*procs), cmp_top_proc_by_memsum);
	return n;
}

static void print_top_snapshot(struct stack_node **stackmaps,
		uint64_t total_bytes, uint64_t object_count)
{
	struct stack_node *node;
	struct timespec ts_now;
	struct tm tm_wall;
	time_t wall_now;
	FILE *fp;
	double uptime = 0, load1 = 0, load5 = 0, load15 = 0;
	uint64_t now_ns;
	uint64_t alloc_delta = 0;
	uint64_t free_delta = 0;
	uint64_t mem_total = read_meminfo_kb("MemTotal:");
	uint64_t mem_free = read_meminfo_kb("MemFree:");
	uint64_t mem_available = read_meminfo_kb("MemAvailable:");
	uint64_t buffers = read_meminfo_kb("Buffers:");
	uint64_t cached = read_meminfo_kb("Cached:");
	uint64_t swap_total = read_meminfo_kb("SwapTotal:");
	uint64_t swap_free = read_meminfo_kb("SwapFree:");
	const char *target;
	int days, up_hours, up_mins;
	int budget, overhead, table_area, stack_rows = 0, limit, shown;

	clock_gettime(CLOCK_MONOTONIC, &ts_now);
	now_ns = (__u64)ts_now.tv_sec * 1000000000ULL + ts_now.tv_nsec;
	if (g_last_snapshot_ns) {
		alloc_delta = skel->bss->g_emleak_prog.alloc_events - g_last_alloc_events;
		free_delta = skel->bss->g_emleak_prog.free_events - g_last_free_events;
	}

	fp = fopen("/proc/uptime", "r");
	if (fp) {
		fscanf(fp, "%lf", &uptime);
		fclose(fp);
	}
	fp = fopen("/proc/loadavg", "r");
	if (fp) {
		fscanf(fp, "%lf %lf %lf", &load1, &load5, &load15);
		fclose(fp);
	}
	wall_now = time(NULL);
	localtime_r(&wall_now, &tm_wall);
	days = (int)(uptime / 86400);
	up_hours = (int)(uptime / 3600) % 24;
	up_mins = (int)(uptime / 60) % 60;

	target = cmdparas.trace_kernel
			? (cmdparas.comm_filter ? cmdparas.prog_comm : "ALL")
			: (cmdparas.comm_filter ? cmdparas.prog_comm : cmdparas.elffile);

	/* reset frame */
	tui_begin_frame();

	/* header block, top(1) style */
	if (days > 0)
		tui_rowf(TUI_STYLE_NORMAL, "top - %02d:%02d:%02d up %d day%s, %02d:%02d, load average: %.2f, %.2f, %.2f",
				tm_wall.tm_hour, tm_wall.tm_min, tm_wall.tm_sec,
				days, days > 1 ? "s" : "", up_hours, up_mins,
				load1, load5, load15);
	else
		tui_rowf(TUI_STYLE_NORMAL, "top - %02d:%02d:%02d up %02d:%02d, load average: %.2f, %.2f, %.2f",
				tm_wall.tm_hour, tm_wall.tm_min, tm_wall.tm_sec,
				up_hours, up_mins, load1, load5, load15);
	tui_rowf(TUI_STYLE_NORMAL, "MiB Mem : %8.1f total, %8.1f free, %8.1f avail, %8.1f buff/cache",
			mem_total / 1024.0, mem_free / 1024.0, mem_available / 1024.0,
			(buffers + cached) / 1024.0);
	tui_rowf(TUI_STYLE_NORMAL, "MiB Swap: %8.1f total, %8.1f free, %8.1f used",
			swap_total / 1024.0, swap_free / 1024.0,
			(swap_total - swap_free) / 1024.0);
	tui_rowf(TUI_STYLE_NORMAL, "emleak: mode=%s, interval=%ds, target=%s",
			cmdparas.trace_kernel ? "kernel" : "user", cmdparas.interval,
			target);
	tui_rowf(TUI_STYLE_NORMAL, "captured outstanding: %llu bytes, %llu objects, period growth: %+lld bytes",
			(unsigned long long)total_bytes, (unsigned long long)object_count,
			g_last_snapshot_ns ? (long long)((int64_t)total_bytes - (int64_t)g_last_total_bytes) : 0LL);
	tui_rowf(TUI_STYLE_NORMAL, "");

	/* reserve fixed line counts so every region stays at the same row */
	budget = tui_height();
	overhead = 11; /* header(6) + table header + events + health + blank + hint */
	if (cmdparas.show_stacks) {
		int want = cmdparas.top_n ? cmdparas.top_n : budget;
		int max_stack = (budget - overhead) / 2;

		if (max_stack < 1)
			max_stack = 1;
		stack_rows = want > max_stack ? max_stack : want;
		overhead += 1 + stack_rows; /* stacks title + stack lines */
	}
	table_area = budget - overhead;
	if (table_area < 1)
		table_area = 1;
	limit = cmdparas.top_n ? cmdparas.top_n : table_area;
	if (limit > table_area)
		limit = table_area;

	/* table */
	tui_rowf(TUI_STYLE_HEADER, "%8s  %-16s  %-6s  %13s  %17s  %17s  %9s  %5s  %5s",
			"TGID", "COMMAND", "KIND", "OUTSTANDING", "ALLOC_TOTAL",
			"FREE_TOTAL", "OBJECTS", "%MEM", "STACK");
	shown = 0;
	if (cmdparas.by_stack || !tui_is_active()) {
		for (node = *stackmaps; node && shown < limit; node = node->hh.next) {
			const char *kind = node->key.family == ALLOC_FAMILY_KERNEL_PAGE ? "page" :
				node->key.family == ALLOC_FAMILY_KERNEL_SLAB ? "slab" : "user";
			char alloc_buf[32], free_buf[32];

			snprintf(alloc_buf, sizeof(alloc_buf), "%llu/%llu",
					(unsigned long long)node->allocated_bytes,
					(unsigned long long)node->alloc_count);
			snprintf(free_buf, sizeof(free_buf), "%llu/%llu",
					(unsigned long long)node->freed_bytes,
					(unsigned long long)node->free_count);
			tui_rowf(TUI_STYLE_NORMAL, "%8llu  %-16.16s  %-6.6s  %13llu  %17s  %17s  %9llu  %5.1f  %d",
					(unsigned long long)node->key.tgid, node->key.comm, kind,
					(unsigned long long)node->memsum,
					alloc_buf, free_buf,
					(unsigned long long)node->memtimes,
					mem_total ? node->memsum / 1024.0 / mem_total * 100.0 : 0.0,
					node->key.stack_id);
			shown++;
		}
	} else {
		static struct top_proc procs[TOP_MAX_PROC];
		int nprocs = top_fold_procs(*stackmaps, procs, TOP_MAX_PROC);
		int p;

		g_proc_count = nprocs;
		for (p = 0; p < g_proc_count; p++)
			g_proc_tgids[p] = procs[p].tgid;
		for (p = 0; p < nprocs && shown < limit; p++) {
			const struct top_proc *proc = &procs[p];
			char alloc_buf[32], free_buf[32], nstack_buf[16];
			enum tui_row_style style = g_sel_valid
					&& proc->tgid == g_sel_tgid ?
				TUI_STYLE_SELECTED : TUI_STYLE_NORMAL;

			snprintf(alloc_buf, sizeof(alloc_buf), "%llu/%llu",
					(unsigned long long)proc->allocated_bytes,
					(unsigned long long)proc->alloc_count);
			snprintf(free_buf, sizeof(free_buf), "%llu/%llu",
					(unsigned long long)proc->freed_bytes,
					(unsigned long long)proc->free_count);
			snprintf(nstack_buf, sizeof(nstack_buf), "[%d]", proc->nstacks);
			tui_rowf(style, "%8llu  %-16.16s  %-6s  %13llu  %17s  %17s  %9llu  %5.1f  %5s",
					(unsigned long long)proc->tgid, proc->comm, "-",
					(unsigned long long)proc->memsum,
					alloc_buf, free_buf,
					(unsigned long long)proc->memtimes,
					mem_total ? proc->memsum / 1024.0 / mem_total * 100.0 : 0.0,
					nstack_buf);
			shown++;
			if (!g_exp_valid || g_expanded_tgid != proc->tgid)
				continue;
			for (node = *stackmaps; node && shown < limit;
					node = node->hh.next) {
				const char *kind;

				if (node->key.tgid != proc->tgid)
					continue;
				kind = node->key.family == ALLOC_FAMILY_KERNEL_PAGE ? "page" :
					node->key.family == ALLOC_FAMILY_KERNEL_SLAB ? "slab" : "user";
				snprintf(alloc_buf, sizeof(alloc_buf), "%llu/%llu",
						(unsigned long long)node->allocated_bytes,
						(unsigned long long)node->alloc_count);
				snprintf(free_buf, sizeof(free_buf), "%llu/%llu",
						(unsigned long long)node->freed_bytes,
						(unsigned long long)node->free_count);
				tui_rowf(TUI_STYLE_NORMAL,
						"%8s  %-16s  %-6.6s  %13llu  %17s  %17s  %9llu  %5.1f  %d",
						"", "", kind,
						(unsigned long long)node->memsum,
						alloc_buf, free_buf,
						(unsigned long long)node->memtimes,
						mem_total ? node->memsum / 1024.0 / mem_total * 100.0 : 0.0,
						node->key.stack_id);
				shown++;
			}
		}
	}
	while (tui_is_active() && shown++ < table_area)
		tui_rowf(TUI_STYLE_NORMAL, "");

	/* footer */
	tui_rowf(TUI_STYLE_NORMAL, "Captured events: alloc=%llu/s, free=%llu/s, outstanding=%llu bytes",
			(unsigned long long)alloc_delta,
			(unsigned long long)free_delta,
			(unsigned long long)total_bytes);
	tui_rowf(TUI_STYLE_NORMAL, "Capture health: alloc-map=%llu context=%llu aggregate=%llu stack=%llu",
			(unsigned long long)skel->bss->g_emleak_prog.alloc_map_failures,
			(unsigned long long)skel->bss->g_emleak_prog.context_map_failures,
			(unsigned long long)skel->bss->g_emleak_prog.aggregate_map_failures,
			(unsigned long long)skel->bss->g_emleak_prog.stack_trace_failures);
	tui_rowf(TUI_STYLE_NORMAL, "");

	if (cmdparas.show_stacks) {
		tui_rowf(TUI_STYLE_NORMAL, "Top %d outstanding allocation stacks:", stack_rows);
		shown = 0;
		for (node = *stackmaps; node && shown < stack_rows; node = node->hh.next) {
			stack_trace_t stack = {};
			struct proc_symbol symbol;

			p_symbol_init(&symbol);
			if (node->key.stack_id >= 0
					&& bpf_map_lookup_elem(g_stack_traces_fd, &node->key.stack_id, stack) == 0
					&& stack[0]
					&& (cmdparas.trace_kernel
							? kernel_symbol_resolve(stack[0], &symbol) == 0
							: proc_symbol_resolve(stack[0], &symbol) == 0)) {
				char detail[1024];

				snprintf(detail, sizeof(detail), "%s+0x%lx",
						symbol.name, symbol.offset);
				if (cmdparas.trace_kernel && symbol.module[0]) {
					strncat(detail, " [", sizeof(detail) - strlen(detail) - 1);
					strncat(detail, symbol.module,
							sizeof(detail) - strlen(detail) - 1);
					strncat(detail, "]", sizeof(detail) - strlen(detail) - 1);
				}
				tui_rowf(TUI_STYLE_NORMAL, "%2d. %llu bytes, %llu objects, stack=%d, %s",
						shown + 1, (unsigned long long)node->memsum,
						(unsigned long long)node->memtimes, node->key.stack_id,
						detail);
			} else {
				tui_rowf(TUI_STYLE_NORMAL, "%2d. %llu bytes, %llu objects, stack=%d",
						shown + 1, (unsigned long long)node->memsum,
						(unsigned long long)node->memtimes, node->key.stack_id);
			}
			p_symbol_uninit(&symbol);
			shown++;
		}
		while (tui_is_active() && shown++ < stack_rows)
			tui_rowf(TUI_STYLE_NORMAL, "");
	}

	if (tui_status_text()[0])
		tui_rowf(TUI_STYLE_NORMAL, "%s", tui_status_text());
	else if (!cmdparas.by_stack && tui_is_active())
		tui_rowf(TUI_STYLE_NORMAL, "up/down: select  Enter: expand/collapse  Esc: collapse  q: quit");
	else
		tui_rowf(TUI_STYLE_NORMAL, "q: quit   Ctrl-C: export and quit");

	/* flush the frame */
	tui_flush();

	if (!g_top_skip_accounting) {
		g_last_alloc_events = skel->bss->g_emleak_prog.alloc_events;
		g_last_free_events = skel->bss->g_emleak_prog.free_events;
		g_last_total_bytes = total_bytes;
		g_last_snapshot_ns = now_ns;
	}
}

static void collect_old_allocations(struct stack_node **stackmaps,
		uint64_t *total_bytes, uint64_t *object_count)
{
	struct alloc_key_t prev_key = {}, key = {};
	struct alloc_info_t info;
	struct timespec now;
	uint64_t now_ns;

	clock_gettime(CLOCK_MONOTONIC, &now);
	now_ns = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
	while (bpf_map_get_next_key(g_allocs_fd, &prev_key, &key) == 0) {
		struct combined_alloc_key_t aggregate_key = {};

		if (bpf_map_lookup_elem(g_allocs_fd, &key, &info) == 0
				&& now_ns >= info.timestamp_ns
				&& now_ns - info.timestamp_ns >= cmdparas.older_ns) {
			aggregate_key.tgid = info.tgid;
			aggregate_key.family = info.family;
			aggregate_key.stack_id = info.stack_id;
			memcpy(aggregate_key.comm, info.comm, sizeof(aggregate_key.comm));
			add_stack_node(stackmaps, &aggregate_key, info.size, 1, info.size, 0, 1, 0);
			*total_bytes += info.size;
			(*object_count)++;
		}
		prev_key = key;
	}
}

void print_outstanding(char *stacksfile, char *summaryfile, char *statisticalfile, int islastprint)
{
	struct combined_alloc_key_t prev_key = {}, key = {};
	struct combined_alloc_info_t *values;
	struct stack_node *stackmaps = NULL;
	uint64_t total_bytes = 0;
	uint64_t object_count = 0;
	int ncpus;

	if (cmdparas.older_ns) {
		collect_old_allocations(&stackmaps, &total_bytes, &object_count);
	} else {
		ncpus = libbpf_num_possible_cpus();
		if (ncpus <= 0)
			return;
		values = calloc(ncpus, sizeof(*values));
		if (!values)
			return;
		while (bpf_map_get_next_key(g_combined_allocs_fd, &prev_key, &key) == 0) {
		int cpu;
		int64_t bytes = 0;
		int64_t objects = 0;
		uint64_t allocated_bytes = 0;
		uint64_t freed_bytes = 0;
		uint64_t alloc_count = 0;
		uint64_t free_count = 0;

		if (bpf_map_lookup_elem(g_combined_allocs_fd, &key, values) != 0) {
			prev_key = key;
			continue;
		}
		for (cpu = 0; cpu < ncpus; cpu++) {
			bytes += values[cpu].total_size;
			objects += values[cpu].number_of_allocs;
			allocated_bytes += values[cpu].allocated_bytes;
			freed_bytes += values[cpu].freed_bytes;
			alloc_count += values[cpu].alloc_count;
			free_count += values[cpu].free_count;
		}
		if (bytes > 0 && objects > 0) {
			add_stack_node(&stackmaps, &key, bytes, objects,
					allocated_bytes, freed_bytes, alloc_count, free_count);
			total_bytes += bytes;
			object_count += objects;
		}
			prev_key = key;
		}
		free(values);
	}

	/*Sort by memory size*/
	HASH_SORT(stackmaps, cmp_by_memsum);
	if (cmdparas.mode == EMLEAK_MODE_TOP) {
		print_top_snapshot(&stackmaps, total_bytes, object_count);
		free_stack_nodes(&stackmaps);
		return;
	}

	if (stacksfile && strlen(stacksfile)) {
		print_stacks(&stackmaps, stacksfile);
	}
	if (summaryfile && strlen(summaryfile)) {
		print_summary(&stackmaps, summaryfile);
	}
	write_snapshot(&stackmaps, statisticalfile);
	write_capture_health(cmdparas.healthfile);
	if (islastprint)
		write_folded_stacks(&stackmaps, cmdparas.foldedfile);
	free_stack_nodes(&stackmaps);
}

/* move the process selection by dir (+1/-1), wrapping around the list of
 * processes as last rendered; dir>0 picks the first process when nothing
 * is selected yet, dir<0 the last
 */
static void top_selection_move(int dir)
{
	int i, idx = -1;

	if (g_proc_count <= 0) {
		g_sel_valid = false;
		return;
	}
	if (g_sel_valid) {
		for (i = 0; i < g_proc_count; i++) {
			if (g_proc_tgids[i] == g_sel_tgid) {
				idx = i;
				break;
			}
		}
	}
	if (idx < 0) {
		idx = dir > 0 ? 0 : g_proc_count - 1;
	} else {
		idx = (idx + dir + g_proc_count) % g_proc_count;
	}
	g_sel_tgid = g_proc_tgids[idx];
	g_sel_valid = true;
}

/* Enter: nothing selected -> select first process; the selected process is
 * expanded -> collapse it, otherwise expand it
 */
static void top_selection_toggle(void)
{
	if (g_proc_count <= 0)
		return;
	if (!g_sel_valid) {
		g_sel_tgid = g_proc_tgids[0];
		g_sel_valid = true;
		return;
	}
	if (g_exp_valid && g_expanded_tgid == g_sel_tgid) {
		g_exp_valid = false;
	} else {
		g_expanded_tgid = g_sel_tgid;
		g_exp_valid = true;
	}
}

static void top_selection_collapse(void)
{
	g_exp_valid = false;
}

/* re-render the current snapshot immediately after a key press, without
 * waiting for the next interval and without touching period accounting
 */
static void top_render_request(void)
{
	g_top_skip_accounting = true;
	print_outstanding(NULL, NULL, NULL, 0);
	g_top_skip_accounting = false;
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
		if (paras->mode == EMLEAK_MODE_RECORD)
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

		if (paras->mode == EMLEAK_MODE_RECORD)
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
	struct alloc_ctx_key_t realloc_prev_key = {}, realloc_key = {};
	struct alloc_key_t alloc_prev_key = {}, alloc_key = {};
	__u64 prev_key = 0, key = 0;
	struct combined_alloc_key_t combined_prev_key = {}, combined_key = {};
	__u32 prev_key1 = 0, key1 = 0;

	while (bpf_map_get_next_key(g_sizes_fd, &size_prev_key, &size_key) == 0){
		bpf_map_delete_elem(g_sizes_fd, &size_key);
		size_prev_key = size_key;
	}
	while (bpf_map_get_next_key(g_realloc_ptrs_fd, &realloc_prev_key, &realloc_key) == 0){
		bpf_map_delete_elem(g_realloc_ptrs_fd, &realloc_key);
		realloc_prev_key = realloc_key;
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

	while (bpf_map_get_next_key(g_combined_allocs_fd, &combined_prev_key,
						&combined_key) == 0){
		bpf_map_delete_elem(g_combined_allocs_fd, &combined_key);
		combined_prev_key = combined_key;
	}

	return ;
}

static void handle_perf_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event_t *msg = data;

	if(skel->bss->g_emleak_prog.prog_state == PROG_IDEL_STATE){
		return ;
	}
	
	if(msg->old_state == PROG_START_STATE 
	   	&& msg->new_state == PROG_END_STATE)
	{
		if (cmdparas.mode == EMLEAK_MODE_RECORD) {
			print_outstanding(cmdparas.stackfile, cmdparas.summaryfile,
					cmdparas.statisticalfile, 1);
		} else {
			print_outstanding(NULL, NULL, NULL, 0);
		}

		old_environment_clean();
		skel->bss->g_emleak_prog.prog_state = PROG_IDEL_STATE;

		if (cmdparas.mode == EMLEAK_MODE_TOP)
			tui_statusf("untouch ok pid = %lld.", skel->bss->g_emleak_prog.prog_pid);
		else
			printf("untouch ok pid = %lld.\n", skel->bss->g_emleak_prog.prog_pid);
	}else if(msg->old_state == PROG_IDEL_STATE
	   			&& msg->new_state == PROG_START_STATE){
		skel->bss->g_emleak_prog.prog_state = PROG_START_STATE;
		int pid = skel->bss->g_emleak_prog.prog_pid;

		if (cmdparas.mode == EMLEAK_MODE_TOP)
			tui_statusf("touch ok pid = %d.", pid);
		else
			printf("touch ok pid = %d.\n", pid);

		int ret = proc_syms_load(pid);
		if(ret == 0){
			if (cmdparas.mode == EMLEAK_MODE_TOP)
				tui_statusf("Loaded successfully, pid = %d...", pid);
			else
				printf("Loaded successfully, pid = %d...\n", pid);
		}else{
			if (cmdparas.mode == EMLEAK_MODE_TOP)
				tui_statusf("Loaded failed, pid = %d!", pid);
			else
				printf("Loaded failed, pid = %d!\n", pid);
		}
		if (attach_user_allocator(skel, pid) != 0)
			fprintf(stderr, "Failed to attach libc allocation probes for pid %d\n", pid);
		if (cmdparas.mfuncname[0] || cmdparas.ffuncname[0]) {
			char executable[MAXFILELEN] = {};

			if (get_executable_path_by_pid(pid, executable, sizeof(executable)) == 0)
				user_defined_func_attach(skel, executable, cmdparas.mfuncname,
						cmdparas.ffuncname, pid);
		}
		if (cmdparas.mode == EMLEAK_MODE_RECORD)
			outfiles_init(pid, &cmdparas);
	}

	return ;
}

static void handle_lost_perf_events(void *ctx, int cpu, __u64 lost_cnt)
{
	if (cmdparas.mode == EMLEAK_MODE_TOP)
		tui_statusf("lost %llu events on CPU #%d", lost_cnt, cpu);
	else
		printf("lost %llu events on CPU #%d\n", lost_cnt, cpu);
}

void emleak_signal(int sig)
{
	g_signal = sig;
}

ssize_t get_symbol_uprobe_offset(char *elf_pwd, char *symbol_name)
{
	void *handle = NULL;
    void *func_ptr = NULL;
	Dl_info info;

	memset(&info, 0x00, sizeof(info));

	if(elf_pwd == NULL || symbol_name == NULL){
		return -1;
	}
	if(strlen(elf_pwd) == 0 || strlen(symbol_name) == 0){
		return -1;
	}

	/*open the elf file.*/
	handle = dlopen(elf_pwd, RTLD_NOW); 
    if (!handle) {
        fprintf(stderr, "Error: %s\n", dlerror());
		return -1;
    }

	func_ptr = dlsym(handle, symbol_name);
    if (!func_ptr) {
        fprintf(stderr, "Error: %s\n", dlerror());
		dlclose(handle);
		return -1;
    }

    if (!dladdr(func_ptr, &info)) {
        fprintf(stderr, "Error: %s\n", dlerror());
		dlclose(handle);
		return -1;
    }

	dlclose(handle);

	return (char *)func_ptr - (char *)info.dli_fbase;
}

static int get_libc_path_by_pid(pid_t pid, char *path, size_t path_size)
{
	char maps_path[64];
	char line[2048];
	FILE *maps;

	if (snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid)
			>= (int)sizeof(maps_path))
		return -1;
	maps = fopen(maps_path, "r");
	if (!maps)
		return -1;
	while (fgets(line, sizeof(line), maps)) {
		char *file = strchr(line, '/');
		char *deleted;

		if (!file || (!strstr(file, "/libc.so") && !strstr(file, "/libc-")))
			continue;
		file[strcspn(file, "\n")] = '\0';
		deleted = strstr(file, " (deleted)");
		if (deleted)
			*deleted = '\0';
		if (snprintf(path, path_size, "/proc/%d/root%s", pid, file)
				>= (int)path_size) {
			fclose(maps);
			return -1;
		}
		fclose(maps);
		return 0;
	}
	fclose(maps);
	return -1;
}

static int attach_libc_probe(struct bpf_program *prog, struct bpf_link **link,
		const char *libc_path, pid_t pid, const char *symbol, bool retprobe,
		bool required)
{
	ssize_t offset = get_symbol_uprobe_offset((char *)libc_path, (char *)symbol);

	if (offset < 0)
		return required ? -1 : 0;
	*link = bpf_program__attach_uprobe(prog, retprobe, pid, libc_path, offset);
	return *link ? 0 : (required ? -1 : 0);
}

static void detach_user_allocator(struct emleak_bpf *skeleton)
{
	#define DETACH_LIBC(member) do { \
		if (skeleton->links.member) { \
			bpf_link__destroy(skeleton->links.member); \
			skeleton->links.member = NULL; \
		} \
	} while (0)
	DETACH_LIBC(malloc_enter); DETACH_LIBC(malloc_exit); DETACH_LIBC(free_enter);
	DETACH_LIBC(calloc_enter); DETACH_LIBC(calloc_exit); DETACH_LIBC(realloc_enter);
	DETACH_LIBC(realloc_exit); DETACH_LIBC(mmap_enter); DETACH_LIBC(mmap_exit);
	DETACH_LIBC(munmap_enter); DETACH_LIBC(posix_memalign_enter);
	DETACH_LIBC(posix_memalign_exit); DETACH_LIBC(aligned_alloc_enter);
	DETACH_LIBC(aligned_alloc_exit); DETACH_LIBC(valloc_enter); DETACH_LIBC(valloc_exit);
	DETACH_LIBC(memalign_enter); DETACH_LIBC(memalign_exit); DETACH_LIBC(pvalloc_enter);
	DETACH_LIBC(pvalloc_exit);
	#undef DETACH_LIBC
}

static int attach_user_allocator(struct emleak_bpf *skeleton, pid_t pid)
{
	char libc_path[MAXFILELEN];
	int err = 0;

	if (get_libc_path_by_pid(pid, libc_path, sizeof(libc_path)) != 0) {
		fprintf(stderr, "Failed to find libc for pid %d\n", pid);
		return -1;
	}
	detach_user_allocator(skeleton);
	#define ATTACH_LIBC(member, symbol, ret, required) \
		do { err = attach_libc_probe(skeleton->progs.member, &skeleton->links.member, \
				libc_path, pid, symbol, ret, required); if (err) return err; } while (0)
	ATTACH_LIBC(malloc_enter, "malloc", false, true);
	ATTACH_LIBC(malloc_exit, "malloc", true, true);
	ATTACH_LIBC(free_enter, "free", false, true);
	ATTACH_LIBC(calloc_enter, "calloc", false, true);
	ATTACH_LIBC(calloc_exit, "calloc", true, true);
	ATTACH_LIBC(realloc_enter, "realloc", false, true);
	ATTACH_LIBC(realloc_exit, "realloc", true, true);
	ATTACH_LIBC(mmap_enter, "mmap", false, true);
	ATTACH_LIBC(mmap_exit, "mmap", true, true);
	ATTACH_LIBC(munmap_enter, "munmap", false, true);
	ATTACH_LIBC(posix_memalign_enter, "posix_memalign", false, false);
	ATTACH_LIBC(posix_memalign_exit, "posix_memalign", true, false);
	ATTACH_LIBC(aligned_alloc_enter, "aligned_alloc", false, false);
	ATTACH_LIBC(aligned_alloc_exit, "aligned_alloc", true, false);
	ATTACH_LIBC(valloc_enter, "valloc", false, false);
	ATTACH_LIBC(valloc_exit, "valloc", true, false);
	ATTACH_LIBC(memalign_enter, "memalign", false, false);
	ATTACH_LIBC(memalign_exit, "memalign", true, false);
	ATTACH_LIBC(pvalloc_enter, "pvalloc", false, false);
	ATTACH_LIBC(pvalloc_exit, "pvalloc", true, false);
	#undef ATTACH_LIBC
	return 0;
}

int user_defined_func_attach(struct emleak_bpf *skel,
				char *elf_pwd, char *malloc_func, char *free_func, pid_t pid)
{
	long m_offset, f_offset;

	if(!skel){
		return -1;
	}

	m_offset = get_symbol_uprobe_offset(elf_pwd, malloc_func);
	f_offset = get_symbol_uprobe_offset(elf_pwd, free_func);

	/*touch malloc*/
	if(m_offset > 0){
		skel->links.malloc_add = bpf_program__attach_uprobe(skel->progs.malloc_add,
										false, pid, elf_pwd, m_offset);
		if (!skel->links.malloc_add) {
			//fprintf(stderr, "Failed to attach uprobe malloc: %d\n", err);
			return -1;
		}

		skel->links.retmalloc_add = bpf_program__attach_uprobe(skel->progs.retmalloc_add,
										true, pid, elf_pwd, m_offset);
		if (!skel->links.retmalloc_add) {
			//fprintf(stderr, "Failed to attach upretrobe malloc: %d\n", err);
			return -1;
		}
	}

	/*touch free*/
	if(f_offset > 0){
		skel->links.free_add = bpf_program__attach_uprobe(skel->progs.free_add,
										false, pid, elf_pwd, f_offset);
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
	time_t deadline = 0;
	uint64_t next_snapshot_ns = 0;

	if (argc > 1 && strcmp(argv[1], "top") == 0) {
		cmdparas.mode = EMLEAK_MODE_TOP;
		argv++;
		argc--;
	} else if (argc > 1 && strcmp(argv[1], "record") == 0) {
		cmdparas.mode = EMLEAK_MODE_RECORD;
		argv++;
		argc--;
	}

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
		if (cmdparas.pid && attach_user_allocator(skel, cmdparas.pid) != 0) {
			fprintf(stderr, "Failed to attach libc allocation probes for pid %lu\n",
					cmdparas.pid);
			goto cleanup;
		}
		err = user_defined_func_attach(skel,
							cmdparas.elffile, cmdparas.mfuncname, cmdparas.ffuncname,
							(pid_t)cmdparas.pid);
		if (err) {
			fprintf(stderr, "Failed to attach customized allocation functions\n");
			goto cleanup;
		}
	}

	g_sizes_fd = bpf_map__fd(skel->maps.sizes); 
	g_realloc_ptrs_fd = bpf_map__fd(skel->maps.realloc_ptrs);
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

	signal(SIGINT, emleak_signal);
	signal(SIGTERM, emleak_signal);
	if (cmdparas.mode == EMLEAK_MODE_TOP)
		tui_enter();
	if (cmdparas.duration)
		deadline = time(NULL) + cmdparas.duration;
	if (cmdparas.interval) {
		struct timespec now;

		clock_gettime(CLOCK_MONOTONIC, &now);
		next_snapshot_ns = ((uint64_t)now.tv_sec + cmdparas.interval) * 1000000000ULL;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");

	/* paint the initial frame right away instead of waiting one interval */
	if (cmdparas.mode == EMLEAK_MODE_TOP)
		print_outstanding(NULL, NULL, NULL, 0);

	while(!g_exiting) {
		if (deadline && time(NULL) >= deadline) {
			struct event_t new_msg;

			g_signal = SIGTERM;
			new_msg.pid = skel->bss->g_emleak_prog.prog_pid;
			new_msg.msg_type = 0;
			new_msg.old_state = skel->bss->g_emleak_prog.prog_state;
			new_msg.new_state = PROG_END_STATE;
			handle_perf_event(NULL, 0, &new_msg, sizeof(new_msg));
			g_exiting = 1;
			continue;
		}
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR) {
			printf("error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		{
			enum tui_key key = tui_poll_key();
			bool rerender = false;

			switch (key) {
			case TUI_KEY_QUIT:
				g_signal = SIGTERM;
				break;
			case TUI_KEY_UP:
				top_selection_move(-1);
				rerender = true;
				break;
			case TUI_KEY_DOWN:
				top_selection_move(1);
				rerender = true;
				break;
			case TUI_KEY_ENTER:
				top_selection_toggle();
				rerender = true;
				break;
			case TUI_KEY_ESC:
				top_selection_collapse();
				rerender = true;
				break;
			default:
				break;
			}
			if (rerender && cmdparas.mode == EMLEAK_MODE_TOP
					&& !cmdparas.by_stack && tui_is_active())
				top_render_request();
		}
		if (next_snapshot_ns) {
			struct timespec now;
			uint64_t now_ns;

			clock_gettime(CLOCK_MONOTONIC, &now);
			now_ns = (uint64_t)now.tv_sec * 1000000000ULL + now.tv_nsec;
			if (now_ns >= next_snapshot_ns) {
				if (skel->bss->g_emleak_prog.prog_state == PROG_START_STATE) {
					if (cmdparas.mode == EMLEAK_MODE_RECORD)
						print_outstanding(NULL, NULL, cmdparas.statisticalfile, 0);
					else
						print_outstanding(NULL, NULL, NULL, 0);
				}
				next_snapshot_ns = now_ns + (uint64_t)cmdparas.interval * 1000000000ULL;
			}
		}
		if (g_signal) {
			struct event_t new_msg;

			new_msg.pid = skel->bss->g_emleak_prog.prog_pid;
			new_msg.msg_type = 0;
			new_msg.old_state = skel->bss->g_emleak_prog.prog_state;
			new_msg.new_state = PROG_END_STATE;

			handle_perf_event(NULL, 0 , &new_msg, sizeof(new_msg));
			tui_leave();
			printf("Exporting call stack data successfully. outfile[%s,%s,%s]\n",
			            cmdparas.stackfile, cmdparas.summaryfile, cmdparas.statisticalfile);
			g_exiting = 1;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	tui_leave();
	if (g_kernel_syms)
		bcc_free_symcache(g_kernel_syms, -1);
	emleak_bpf__destroy(skel);
	return -err;
}
