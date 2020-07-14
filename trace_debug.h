/***********************************************************************
 * @ file trace_debug.h
       __TRACE_DEBUG_H__
 * @ brief trace debug header file
 * @ history
 * Date        Version  Author     description
 * ==========  =======  =========  ====================================
 * 2020-07-03  V1.0     sleng      Create
 *
 * @ Copyright (C)  2020  BHYN  all right reserved
 ***********************************************************************/
#ifndef __TRACE_DEBUG_H__
#define __TRACE_DEBUG_H__

#ifdef __cplusplus
extern "C"
{
#endif


/******************************************************************************
* 修改提示字符颜色,对应颜色表
* none         = "\033[0m"
* black        = "\033[0;30m"
* dark_gray    = "\033[1;30m"
* blue         = "\033[0;34m"
* light_blue   = "\033[1;34m"
* green        = "\033[0;32m"
* light_green -= "\033[1;32m"
* cyan         = "\033[0;36m"
* light_cyan   = "\033[1;36m"
* red          = "\033[0;31m"
* light_red    = "\033[1;31m"
* purple       = "\033[0;35m"
* light_purple = "\033[1;35m"
* brown        = "\033[0;33m"
* yellow       = "\033[1;33m"
* light_gray   = "\033[0;37m"
* white        = "\033[1;37m"
*****************************************************************************/
#define COLOR_STR_NONE          "\033[0m"
#define COLOR_STR_TWINKLE       "\033[5m"
#define COLOR_STR_BLACK         "\033[0;30m"
#define COLOR_STR_LIGHT_GRAY    "\033[0;37m"
#define COLOR_STR_DARK_GRAY     "\033[1;30m"
#define COLOR_STR_BLUE          "\033[0;34m"
#define COLOR_STR_LIGHT_BLUE    "\033[1;34m"
#define COLOR_STR_GREEN         "\033[0;32m"
#define COLOR_STR_LIGHT_GREEN   "\033[1;32m"
#define COLOR_STR_CYAN          "\033[0;36m"
#define COLOR_STR_LIGHT_CYAN    "\033[1;36m"
#define COLOR_STR_RED           "\033[0;31m"
#define COLOR_STR_LIGHT_RED     "\033[1;31m"
#define COLOR_STR_PURPLE        "\033[0;35m"
#define COLOR_STR_LIGHT_PURPLE  "\033[1;35m"
#define COLOR_STR_BROWN         "\033[0;33m"
#define COLOR_STR_YELLOW        "\033[1;33m"
#define COLOR_STR_WHITE         "\033[1;37m"

#define TIME_STR                "[%04d-%02d-%02d %02d:%02d:%02d]"

#define TRACE_LVL_PRN(mod_name, level, fmt, args...)  \
        trace_lvl_prn(mod_name, level, "%s>%s#%d: "fmt, __FILE__, __FUNCTION__, __LINE__, ## args)

typedef enum print_level
{
    PRN_LVL_NONE,       /* NONE */
    PRN_LVL_ERR,        /* 错误 */
    PRN_LVL_WARN,       /* 警告 */
    PRN_LVL_WORKFLOW,   /* 流程 */
    PRN_LVL_INFO,       /* 信息 */
    PRN_LVL_DBG0,       /* 调试 */
    PRN_LVL_DBG1,       /* 调试 */
    PRN_LVL_DBG2,       /* 调试 */
    PRN_LVL_DBG3,       /* 调试 */
    PRN_LVL_DBG4,       /* 调试 */
    PRN_LVL_DBG5,       /* 调试 */
    PRN_LVL_MAX
} PRN_LVL_E, prn_lvl_e;

/**********************************************************************
* function:print info in format like Ultra Edit
* input:	buf to print,
* 			length to print,
* 			prestr before info,
* 			endstr after info
* output:	void
**********************************************************************/
extern void print_in_hex(const void *buf, int len, char *pre, char *end);

int trace_lvl_prn(const char *mod_name, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));


#ifdef __cplusplus
extern "C"
};
#endif

#endif //End of __TRACE_DEBUG_H__
