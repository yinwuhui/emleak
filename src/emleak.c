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

static int g_sizes_fd;
static int g_allocs_fd;
static int g_memptrs_fd;
static int g_stack_traces_fd;
static int g_combined_allocs_fd;

static const char *__doc__ = 
"usage: %s [OPTS] \n"
"   Trace outstanding memory allocations that weren't freed.\n"
"Supports allocations made with libc functions\n"
"Supports allocations made with you customization functions\n"
"\nOPTS:\n"
"    -p    the PID to trace \n"
"    -c    the program name to trace, must start emleak before program \n"
"    -i    interval in seconds to print outstanding allocations \n";

static const struct option long_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "pid", required_argument, NULL, 'p' },
	{ "comm", required_argument, NULL, 'c' },
	{ "interval", required_argument, NULL, 'i' },
	{}
};

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
		else
			printf("\t short-option: -%c", long_options[i].val);
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
	while ((opt = getopt_long(argc, argv, "p:c:i:h",
				  long_options, &longindex)) != -1) {
		switch (opt) {
		case 'p':
			paras->pid = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			if(strlen(optarg) > TASK_COMM_LEN){
				error = true;
				goto err_out;
			}
			strcpy(paras->prog_comm, optarg);
			break;
		case 'i':
			paras->interval = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			error = false;
			goto err_out;
		default:
			error = true;
			goto err_out;
		}
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

			ret = proc_symbol_resolve(progstack[i], &symbol);	
			if(ret != 0){
				break;
			}

			PRINT_STACK(fp, "\t%s+0x%lx;\n", symbol.name, symbol.offset);
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
	FILE* fp;

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
static void print_statistical(struct stack_node **stackmaps, char *outfilename)
{
	FILE *fp = NULL;
	char buffer[1024]  = {0};
	int isnewstack = 0;
	int index_summry = 0;
	struct stack_node *tmpnode = NULL;

	if(outfilename == NULL || strlen(outfilename) == 0){
		return ;
	}

	g_statistical.stack_summry[0] = time(NULL);
	for (tmpnode = *stackmaps; tmpnode != NULL; tmpnode = tmpnode->hh.next)
	{
		if(g_statistical.stack_hash[tmpnode->stack_id] == 0){
			isnewstack  = 1;
			g_statistical.stack_hash[tmpnode->stack_id] = g_statistical.stack_num;
			index_summry = g_statistical.stack_num;
			g_statistical.stack_num++;
		}else{
			index_summry = g_statistical.stack_hash[tmpnode->stack_id];
		}

		g_statistical.stack_id[index_summry] = tmpnode->stack_id;
		g_statistical.stack_summry[index_summry] = tmpnode->memsum;
	}

	/*update stack id*/
	if(isnewstack){
		memset(buffer, 0x0, sizeof(buffer));
		fp = fopen(outfilename,"r+");
		if(!fp){
			printf("Failed to open statistical outfile. filename = %s.\n", outfilename);
			return ;
		}
		
		for(int i = 0; i < g_statistical.stack_num; i++)
		{
			sprintf(buffer + strlen(buffer), "%d ", g_statistical.stack_id[i]);
			if(i > 50){
				fwrite(buffer, 1, strlen(buffer), fp);
				memset(buffer, 0x0, sizeof(buffer));
			}
		}
		sprintf(buffer + strlen(buffer), "\n");

		fseek(fp, 0, SEEK_SET);
		fwrite(buffer, 1, strlen(buffer), fp);
		fseek(fp, 0, SEEK_END);

		fclose(fp);
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
		sprintf(buffer + strlen(buffer), "%d ", g_statistical.stack_summry[i]);
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

void print_outstanding(char *stacksfile, char *summaryfile, char *statisticalfile)
{
	__u64 prev_key, key;
	struct alloc_info_t alloc_info;
	struct stack_node *stackmaps = NULL;

	prev_key = 0;
	while (bpf_map_get_next_key(g_allocs_fd, &prev_key, &key) == 0) 
	{
		bpf_map_lookup_elem(g_allocs_fd, &key, &alloc_info);

		if(alloc_info.stack_id < 0){
			continue;
		}

		add_stack_node(&stackmaps, alloc_info.stack_id, alloc_info.size);
		prev_key = key;
	}
	
	/*Sort by memory size*/
	HASH_SORT(stackmaps, cmp_by_memsum);

	print_stacks(&stackmaps, stacksfile);
	print_summary(&stackmaps, summaryfile);
	print_statistical(&stackmaps, statisticalfile);

	HASH_CLEAR(hh, stackmaps);
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bpf_para_load(struct emleak_bpf *skel, struct emleakpara *paras)
{
	/*If it is a name, wait until the process is checked before initializing*/
	if(paras->pid != 0){
		outfiles_init(paras->pid, paras);
	}

	if(paras->pid != 0){
		skel->bss->g_emleak_prog.prog_pid = paras->pid;
		skel->bss->g_emleak_prog.prog_state = PROG_START_STATE;
	}else{
		strcpy(skel->bss->g_emleak_prog.prog_comm, paras->prog_comm);
		skel->bss->g_emleak_prog.prog_state = PROG_IDEL_STATE;
	}

	struct timespec stime;
	clock_gettime(CLOCK_MONOTONIC, &stime);
	skel->bss->g_emleak_prog.start_time = stime.tv_sec;
	skel->bss->g_emleak_prog.end_time = 0;
	
	return ;
}

static void all_mem_statistics_output(void)
{
	print_outstanding(cmdparas.stackfile, cmdparas.summaryfile, cmdparas.statisticalfile);
}

static void old_environment_clean(void)
{
	__u64 prev_key = 0, key = 0;
	__u32 prev_key1 = 0, key1 = 0;

	while (bpf_map_get_next_key(g_sizes_fd, &prev_key, &key) == 0){
		bpf_map_delete_elem(g_sizes_fd, &key);
	}

	prev_key = 0;
	while (bpf_map_get_next_key(g_allocs_fd, &prev_key, &key) == 0){
		bpf_map_delete_elem(g_allocs_fd, &key);
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
	
	if(msg->old_state == PROG_START_STATE 
	   	&& msg->new_state == PROG_END_STATE)
	{
		all_mem_statistics_output();

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
			printf("Loaded successfully...\n");
		}else{
			printf("Loaded failed !\n");
		}

		outfiles_init(pid, &cmdparas);
	}

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

	while(1){
		ret = epoll_wait(epoll_fd, events, sizeof(events)/sizeof(struct epoll_event), interval*1000);

		if(skel->bss->g_emleak_prog.prog_state == PROG_START_STATE)
		{
			print_outstanding(NULL, NULL, cmdparas.statisticalfile);
		}
	}
}

void emleak_signal(int sig)
{
	skel->bss->g_emleak_prog.prog_state = PROG_END_STATE;

	all_mem_statistics_output();
	printf("Exporting call stack data successfully. outfile[%s]\n", cmdparas.stackfile);
	exit(1);
}

int main(int argc, char **argv)
{
	int err;
	int ret = 0;
	struct perf_buffer *pb = NULL;

	ret = cmd_opts_analytic(argc, argv, &cmdparas);
	if(ret < 0){

		return -1;
	}

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

	/* Load & verify BPF programs */
	err = emleak_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
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
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	emleak_bpf__destroy(skel);
	return -err;
}

