#ifndef __POLICY_H__
#define __POLICY_H__

#include "dns.h"

struct stats;
struct policy {
	const char *name;
	int (*handle)(struct dns_pkt *, struct stats *);
};

enum {
	POLICY_REQ,
	POLICY_REP,
	POLICY_MAX,
};

enum {
	POLICY_REQ_SIZE,

	POLICY_REQ_QUEST_NAME_SIZE,
	POLICY_REQ_QUEST_LABEL_SIZE,
	POLICY_REQ_QUEST_UNIQUE_CHAR,
	POLICY_REQ_QUEST_LONGEST_REPEAT,
	POLICY_REQ_QUEST_TYPE_A,
	POLICY_REQ_QUEST_TYPE_AAAA,
	POLICY_REQ_QUEST_TYPE_NULL,
	POLICY_REQ_QUEST_TYPE_TXT,
	POLICY_REQ_QUEST_TYPE_MX,
	POLICY_REQ_QUEST_TYPE_CNAME,

	POLICY_REQ_MAX,
};
enum {
	POLICY_REP_SIZE,
	POLICY_REP_NXDOMAIN,

	POLICY_REP_ANS_TYPE_A,
	POLICY_REP_ANS_TYPE_AAAA,
	POLICY_REP_ANS_TYPE_NULL,
	POLICY_REP_ANS_TYPE_TXT,
	POLICY_REP_ANS_TYPE_MX,
	POLICY_REP_ANS_TYPE_CNAME,

	POLICY_REP_MAX,
};

struct policies {
	struct policy *p;
	int size;
};
struct policies *get_policies(void);

struct policy *get_policy_req(void);

struct policy *get_policy_rep(void);

#endif

