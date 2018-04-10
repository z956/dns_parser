#ifndef __POLICY_H__
#define __POLICY_H__

#include "dns.h"

struct policy {
	const char *name;
	unsigned int (*handle)(void *);
};

enum {
	POLICY_REQ_SIZE,
	POLICY_REQ_MAX,
};
enum {
	POLICY_REP_SIZE,
	POLICY_REP_MAX,
};

enum {
	POLICY_QUEST_NAME_SIZE,
	POLICY_QUEST_LABEL_SIZE,
	POLICY_QUEST_UNIQUE_CHAR,
	POLICY_QUEST_LONGEST_REPEAT,
	POLICY_QUEST_MAX,
};

struct policy *get_policy_req(void);
struct policy *get_policy_quest(void);

struct policy *get_policy_rep(void);

#endif

