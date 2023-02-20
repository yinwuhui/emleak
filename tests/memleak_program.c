#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#define MAX_THREAD_NUM 4

enum alloc_type{
    MALLOC_TYPE = 0,
    CALLOC_TYPE,
    REALLOC_TYPE,
    MMAP_TYPE,
    POSIX_MEMALIGN,
    ALIGNED_ALLOC,
    VALLOC,
    MEMALIGN,
    PVALLOC,

    ALLOC_API_MAX
};

int64_t g_memleak_num[ALLOC_API_MAX] = {0};
int64_t g_memleak_max[ALLOC_API_MAX] = {
    102400,
    202400,
    302400,
    402400,
    502400,
    602400,
    702400,
    802400,
    902400,
};

void *malloc_node_get(int num)
{
    char *p = malloc(num);

    return p;
};

void *calloc_node_get(int num)
{
    char *p = calloc(1, num);

    return p;
};

void *realloc_node_get(int num)
{
    char *p = realloc(NULL, num);

    return p;
};

void *mmap_node_get(int num)
{
    static int map_fd = 0;
    char *mapped = NULL;

    if(map_fd == 0){
        map_fd = open("test.txt", O_CREAT | O_RDWR, 0666);
        if (map_fd == -1) {
            perror("failed open mmap.txt");
            exit(1);
        }
    }

    mapped = mmap(NULL, num, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
    if (mapped == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    return mapped;
};

void *posix_memalign_node_get(int num)
{
    void* ptr = NULL;
    int alignment = 16;

    int result = posix_memalign(&ptr, alignment, num);
    if (result != 0) {
        printf("Memory allocation failed with error code %d\n", result);
        return NULL;
    }

    return ptr;
}

void *aligned_alloc_node_get(int num)
{
    int alignment = 16;

    char *p = aligned_alloc(alignment, num);

    return p;
};

void *valloc_node_get(int num)
{
    char *p = valloc(num);

    return p;
};


#if 0
void *memalign_node_get(int num)
{
    int alignment = 16;

    char *p = memalign(alignment, num);

    return p;
};

void *pvalloc_node_get(int num)
{
    char *p = (char *)pvalloc(num);

    return p;
};
#endif

void *memery_get_expand(enum alloc_type type, int num)
{
    switch(type){
        case MALLOC_TYPE:{
            return malloc_node_get(num);
        }
        case CALLOC_TYPE:{
            return calloc_node_get(num);
        }
        case REALLOC_TYPE:{
            return realloc_node_get(num);
        }
        case MMAP_TYPE:{
            return mmap_node_get(num);
        }
        case POSIX_MEMALIGN:{
            return posix_memalign_node_get(num);
        }
        case ALIGNED_ALLOC:{
            return aligned_alloc_node_get(num);
        }
        case VALLOC:{
            return valloc_node_get(num);
        }
        #if 0
        case MEMALIGN:{
            return memalign_node_get(num);
        }
        case PVALLOC:{
            return pvalloc_node_get(num);
        }
        #endif
        default:{
            return NULL;
        }
    }

    return NULL;
}

volatile int g_memery_index = 0;

void *thread_function(void *arg) {
    int malloc_num = 0;
    int index = *(int*)arg;
    char *q = NULL; 
    enum alloc_type type = MALLOC_TYPE;
    srand(time(NULL)); 

    while(1){
        type = g_memery_index % ALLOC_API_MAX;
        malloc_num = 1024*(ALLOC_API_MAX - type);

        printf("+++ g_memleak_num[%d] = %ld, g_memleak_max[%d] = %ld\n", 
                        type, g_memleak_num[type], type, g_memleak_max[type]);
        if(g_memleak_num[type] >= g_memleak_max[type]){
            usleep(500000);
            continue;
        }
        
        q = memery_get_expand(type, malloc_num);
        if(q == NULL){
            malloc_num = 0;
        }
        
        sleep(1);

        g_memleak_num[type] += malloc_num;
        g_memery_index++;
    }

    pthread_exit(NULL);
}

int main()
{
    printf("pid =%d...\n", getpid());

    pthread_t thread[MAX_THREAD_NUM];
    int tpara[MAX_THREAD_NUM] = {0};
    
    for(int i = 0; i < MAX_THREAD_NUM; i++){
        tpara[i] = i;
        pthread_create(&thread[i], NULL, thread_function, (void *)&tpara[i]);
    }

    for(int i = 0; i < MAX_THREAD_NUM; i++){
        pthread_join(thread[i], NULL);
    }

    return 0;
}
