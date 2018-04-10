#ifndef __POLICY_H__
#define __POLICY_H__

#include "dns.h"

struct policy {
	const char *name;
	unsigned int (*handle)(void *);
};
enum {
	POLICY_REQ,
	POLICY_QUEST,
	POLICY_MAX,
};
enum {
	POLICY_REQ_SIZE,
	POLICY_REQ_MAX,
};

enum {
	POLICY_QUEST_NAME_SIZE,
	POLICY_QUEST_UNIQUE_CHAR,
	POLICY_QUEST_LONGEST_REPEAT,
	POLICY_QUEST_MAX,
};

int policy_req_init(void);

struct policy *get_policy_req(void);
struct policy *get_policy_quest(void);

#endif

