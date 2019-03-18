#ifndef __SLENG_TEST_H__
#define __SLENG_TEST_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define SLENG_DEBUG
// #include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef SLENG_DEBUG
#define sleng_debug(FORMAT, ARGS...) do {printf("[%s@%d]:", __func__, __LINE__); printf(FORMAT, ## ARGS);} while(0)
#else
#define sleng_debug(FORMAT, ARGS...)
#define sleng_debug_test(FORMAT, ARGS...) do {printf("[%s@%d]:", __func__, __LINE__); printf(FORMAT, ## ARGS); printf("\n");} while(0)
#endif
#define sleng_error(FORMAT, ARGS...) do {fprintf(stderr, "[%s@%d]:", __func__, __LINE__); fprintf(stderr, FORMAT, ## ARGS); fprintf(stderr, ", errno=%d:%s\n", errno, strerror(errno));} while(0)

#define align_to(SIZE, ALIGN) ((SIZE % ALIGN)? ((SIZE/ALIGN) + 1) * ALIGN: SIZE)

#ifdef __cplusplus
};
#endif

#endif