#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

#define ERR(fmt, ...) fprintf(stderr, "*** ERR [%s-%d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)
#define PRT(fmt, ...) fprintf(stdout, fmt, ##__VA_ARGS__)

#ifdef _DNS_PARSER_DBG_

#define DBG(fmt, ...) fprintf(stdout, "[%s-%d]: "fmt, __func__, __LINE__, ##__VA_ARGS__)

#else

#define DBG

#endif

#endif

