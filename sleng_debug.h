#ifndef __SLENG_DEBUG_H__
#define __SLENG_DEBUG_H__

#ifdef __cplusplus
extern "C"
{
#endif


#define SLENG_DEBUG
#include <stdio.h>
#include <string.h>
#include <errno.h>
#ifdef SLENG_DEBUG

#define NONE         "\033[m"
#define RED          "\033[0;32;31m"
#define LIGHT_RED    "\033[1;31m"
#define GREEN        "\033[0;32;32m"
#define LIGHT_GREEN  "\033[1;32m"
#define BLUE         "\033[0;32;34m"
#define LIGHT_BLUE   "\033[1;34m"
#define DARY_GRAY    "\033[1;30m"
#define CYAN         "\033[0;36m"
#define LIGHT_CYAN   "\033[1;36;43m"
#define PURPLE       "\033[0;35m"
#define LIGHT_PURPLE "\033[1;35m"
#define BROWN        "\033[0;33m"
#define YELLOW       "\033[1;33m"
#define LIGHT_GRAY   "\033[0;37m"
#define WHITE        "\033[1;37m"

#define sleng_debug(FORMAT, ARGS...) do {printf(LIGHT_BLUE "[%s#%d]:" NONE, __func__, __LINE__); printf(FORMAT, ## ARGS);} while(0)
#else
#define sleng_debug(FORMAT, ARGS...)
#define sleng_debug_test(FORMAT, ARGS...) do {printf("[%s#%d]:", __func__, __LINE__); printf(FORMAT, ## ARGS); printf("\n");} while(0)
#endif
#define sleng_info(FORMAT, ARGS...) do {printf(CYAN "[%s#%d]:" NONE, __func__, __LINE__); printf(FORMAT, ## ARGS);} while(0)
#define sleng_rel(FORMAT, ARGS...) do {printf(LIGHT_GREEN "[%s#%d]:" NONE, __func__, __LINE__); printf(FORMAT, ## ARGS);} while(0)
#define sleng_print(FORMAT, ARGS...) do {printf(WHITE "[%s#%d]:" NONE, __func__, __LINE__); printf(FORMAT, ## ARGS);} while(0)
#define sleng_warning(FORMAT, ARGS...) do {printf(YELLOW "[%s#%d]:" NONE, __func__, __LINE__); printf(FORMAT, ## ARGS);} while(0)
#define sleng_error(FORMAT, ARGS...) do {fprintf(stderr, RED "[%s#%d]:" NONE, __func__, __LINE__); fprintf(stderr, FORMAT, ## ARGS); fprintf(stderr, ", errno=%d:%s\n", errno, strerror(errno));} while(0)

#define align_to(SIZE, ALIGN) (((SIZE) % (ALIGN))? (((SIZE) / (ALIGN)) + 1) * (ALIGN): (SIZE))

/**********************************************************************
 * function:print info in format like Ultra Edit
 * input:	buf to print,
 * 			length to print,
 * 			prestr before info,
 * 			endstr after info
 * output:	void
 **********************************************************************/
extern void print_in_hex(const void *buf, int len, char *pre, char *end);

/**************************************************
* tv1, tv2 : struct timeval *, pointer
**************************************************/
#include <stdint.h>
#define TIMEVAL_DIFF_USEC(tv1, tv2) (((uint64_t)(tv1)->tv_sec - (uint64_t)(tv2)->tv_sec) * 1000000 + (tv1)->tv_usec - (tv2)->tv_usec)


#ifdef __cplusplus
};
#endif

#endif	/* End of __SLENG_DEUBG_H__ */
