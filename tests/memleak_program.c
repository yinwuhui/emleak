#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

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
    char *p = malloc(num);

    return p;
};

void *memery_get_expand(enum alloc_type type, int num)
{
    switch(type){
        case MALLOC_TYPE:{
            return malloc_node_get(num);
        }
        case CALLOC_TYPE:{
            return calloc_node_get(num);
        }
        default:{
            return NULL;
        }
    }

    return NULL;
}

void *thread_function(void *arg) {
    int index = *(int*)arg;
    char *q = NULL; 

    while(1){
        if(index == 0){
            q = memery_get_expand(MALLOC_TYPE, 100);
            memset(q, 0xe, 100);
            q = memery_get_expand(CALLOC_TYPE, 120);
            memset(q, 0xe, 100);
        }
        sleep(1);
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
