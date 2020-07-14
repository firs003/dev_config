/***********************************************************************
 * @ file dth_util.h
       __DTH_UTIL_H__
 * @ brief util header file
 * @ history
 * Date        Version  Author     description
 * ==========  =======  =========  ====================================
 * 2019-11-14  V1.0     sleng      Create
 *
 * @ Copyright (C)  2019  Disthen  all right reserved
 ***********************************************************************/
#ifndef __DTH_UTIL_H__
#define __DTH_UTIL_H__

#ifdef __cplusplus
extern "C"
{
#endif


#include <stdint.h>  //uint8_t ~ uint64_t
#if !defined(__mips__)
#include <bits/stdint-uintn.h>  //uint8_t ~ uint64_t
#endif // __mips__
#include "sleng_debug.h"

extern unsigned int get_file_size(const char *path);
extern uint8_t atox(const char *str);
extern uint8_t atox8(const char *str);
extern uint16_t atox16(const char *str);
extern uint32_t atox32(const char *str);
extern uint64_t atox64(const char *str);
extern int get_md5str(const char *path, char *out, int size);
extern int get_md5sum(const char *path, unsigned char *out, int size);


#ifdef __cplusplus
extern "C"
};
#endif

#endif //End of __DTH_UTIL_H__
