#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>

#define ERR(fmt, ...) do { \
	fprintf(stderr, "*** ERR [%s-%d]: "fmt, __func__, __LINE__, ##__VA_ARGS__); \
	fflush(stderr); \
} while (0)
#define PRT(fmt, ...) do { \
	fprintf(stdout, fmt, ##__VA_ARGS__); \
	fflush(stdout); \
} while (0)

#ifdef _DNS_PARSER_DBG_

#define DBG(fmt, ...) do { \
	fprintf(stdout, "[%s-%d]: "fmt, __func__, __LINE__, ##__VA_ARGS__); \
	fflush(stdout); \
} while (0)

#else

#define DBG

#endif

#endif

