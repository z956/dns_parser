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
	POLICY_QUEST_TYPE_A,
	POLICY_QUEST_TYPE_AAAA,
	POLICY_QUEST_TYPE_NULL,
	POLICY_QUEST_TYPE_TXT,
	POLICY_QUEST_TYPE_MX,
	POLICY_QUEST_TYPE_CNAME,
	POLICY_QUEST_MAX,
};
enum {
	POLICY_ANS_TYPE_A,
	POLICY_ANS_TYPE_AAAA,
	POLICY_ANS_TYPE_NULL,
	POLICY_ANS_TYPE_TXT,
	POLICY_ANS_TYPE_MX,
	POLICY_ANS_TYPE_CNAME,
	POLICY_ANS_MAX,
};

struct policy *get_policy_req(void);
struct policy *get_policy_quest(void);

struct policy *get_policy_rep(void);
struct policy *get_policy_ans(void);

#endif

