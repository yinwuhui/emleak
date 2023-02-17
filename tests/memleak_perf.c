#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <stdint.h>

#define MALLOC_NUMS (uint64_t)(1024*1024*5)
char *ptr[MALLOC_NUMS];

int main()
{
    uint64_t times = 1;
    struct timeval starttime, endtime;
    gettimeofday(&starttime, NULL);
    
    while(times--){
        printf("times = %ld.....\n", times);
        for(int i = 0; i < MALLOC_NUMS ; i++){
            ptr[i] = malloc(1024);
            memset(ptr[i], 0xe, 1024);
        }

        for(int i = 0; i < MALLOC_NUMS ; i++){
            free(ptr[i]);
        }
    }

    gettimeofday(&endtime, NULL);
    
    printf("malloc times = %ld, free times = %ld.\n", MALLOC_NUMS, MALLOC_NUMS);
    printf("starttime: starttime.tv_sec = %ld starttime.tv_usec = %ld\n", starttime.tv_sec, starttime.tv_usec);
    printf("endtime  : endtime.tv_sec   = %ld   endtime.tv_usec = %ld\n", endtime.tv_sec, endtime.tv_usec);
    printf("difftime : diff.tv_sec      = %ld      diff.tv_usec = %ld\n", endtime.tv_sec - starttime.tv_sec, endtime.tv_usec - starttime.tv_usec);

    return 0;
}
