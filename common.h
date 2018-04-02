#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

#define ERR(fmt, ...) fprintf(stderr, "*** ERR [%s-%d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define DBG(fmt, ...) fprintf(stdout, "[%s-%d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#endif

