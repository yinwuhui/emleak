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

#define MAX_THREAD_NUM 4

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
    void* ptr;
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
    int index = *(int*)arg;
    char *q = NULL; 
    enum alloc_type type = MALLOC_TYPE;

    while(1){
        type = g_memery_index % ALLOC_API_MAX;
        
        printf("memery_get_expand %d %d\n", type, 100);
        q = memery_get_expand(type, 100);

        if(q != NULL){
           //memset(q, 0xf, 10);
        }
        
        sleep(1);

        g_memery_index++;
    }

    pthread_exit(NULL);
}

/*共6个调用栈申请内存*/
int main()
{
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
