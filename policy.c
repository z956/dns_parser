#include "policy.h"

#include <string.h>

#define _DNS_PARSER_DBG_
#include "stats.h"
#include "common.h"

#define policy_field(name, fn) \
	[name] = { #name, fn }

/* generic handler */
static int policy_pkt_size(struct dns_pkt *dp, struct stats *st);
static void policy_type_a(struct dns_sec_base *base, struct stats *st);
static void policy_type_aaaa(struct dns_sec_base *base, struct stats *st);
static void policy_type_null(struct dns_sec_base *base, struct stats *st);
static void policy_type_txt(struct dns_sec_base *base, struct stats *st);
static void policy_type_mx(struct dns_sec_base *base, struct stats *st);
static void policy_type_cname(struct dns_sec_base *base, struct stats *st);

/* request policy */
static int policy_req_quest_name_size(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_label_size(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_unique_char(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_longest_repeat(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_type_a(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_type_aaaa(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_type_null(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_type_txt(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_type_mx(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_type_cname(struct dns_pkt *dp, struct stats *st);
static struct policy policy_req[] = {
	policy_field(POLICY_REQ_SIZE, policy_pkt_size),

	policy_field(POLICY_REQ_QUEST_NAME_SIZE, policy_req_quest_name_size),
	policy_field(POLICY_REQ_QUEST_LABEL_SIZE, policy_req_quest_label_size),
	policy_field(POLICY_REQ_QUEST_UNIQUE_CHAR, policy_req_quest_unique_char),
	policy_field(POLICY_REQ_QUEST_LONGEST_REPEAT, policy_req_quest_longest_repeat),
	policy_field(POLICY_REQ_QUEST_TYPE_A, policy_req_quest_type_a),
	policy_field(POLICY_REQ_QUEST_TYPE_AAAA, policy_req_quest_type_aaaa),
	policy_field(POLICY_REQ_QUEST_TYPE_NULL, policy_req_quest_type_null),
	policy_field(POLICY_REQ_QUEST_TYPE_TXT, policy_req_quest_type_txt),
	policy_field(POLICY_REQ_QUEST_TYPE_MX, policy_req_quest_type_mx),
	policy_field(POLICY_REQ_QUEST_TYPE_CNAME, policy_req_quest_type_cname),
};

/* response policy */
static int policy_rep_nxdomain(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_type_a(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_type_aaaa(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_type_null(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_type_txt(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_type_mx(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_type_cname(struct dns_pkt *dp, struct stats *st);
static struct policy policy_rep[] = {
	policy_field(POLICY_REP_SIZE, policy_pkt_size),
	policy_field(POLICY_REP_NXDOMAIN, policy_rep_nxdomain),

	policy_field(POLICY_REP_ANS_TYPE_A, policy_rep_ans_type_a),
	policy_field(POLICY_REP_ANS_TYPE_AAAA, policy_rep_ans_type_aaaa),
	policy_field(POLICY_REP_ANS_TYPE_NULL, policy_rep_ans_type_null),
	policy_field(POLICY_REP_ANS_TYPE_TXT, policy_rep_ans_type_txt),
	policy_field(POLICY_REP_ANS_TYPE_MX, policy_rep_ans_type_mx),
	policy_field(POLICY_REP_ANS_TYPE_CNAME, policy_rep_ans_type_cname),
};

struct policies policies[] = {
	[POLICY_REQ] = { policy_req, POLICY_REQ_MAX },
	[POLICY_REP] = { policy_rep, POLICY_REP_MAX },
};
struct policies *get_policies(void)
{
	return policies;
}
struct policy *get_policy_req(void)
{
	return policy_req;
}
struct policy *get_policy_rep(void)
{
	return policy_rep;
}

/* generic handler */
int policy_pkt_size(struct dns_pkt *dp, struct stats *st)
{
	if (!dp || !st)
		return -1;

	update_stats(st, dp->len);
	return 0;
}
void policy_type_a(struct dns_sec_base *base, struct stats *st)
{
	if (base && st)
		update_stats(st, base->qtype == DNS_TYPE_A);
}
void policy_type_aaaa(struct dns_sec_base *base, struct stats *st)
{
	if (base && st)
		update_stats(st, base->qtype == DNS_TYPE_AAAA);
}
void policy_type_null(struct dns_sec_base *base, struct stats *st)
{
	if (base && st)
		update_stats(st, base->qtype == DNS_TYPE_NULL);
}
void policy_type_txt(struct dns_sec_base *base, struct stats *st)
{
	if (base && st)
		update_stats(st, base->qtype == DNS_TYPE_TXT);
}
void policy_type_mx(struct dns_sec_base *base, struct stats *st)
{
	if (base && st)
		update_stats(st, base->qtype == DNS_TYPE_MX);
}
void policy_type_cname(struct dns_sec_base *base, struct stats *st)
{
	if (base && st)
		update_stats(st, base->qtype == DNS_TYPE_CNAME);
}

/* quest policy */
typedef void (*quest_policy)(struct dns_quest *, struct stats *);
static int apply_quest_policy(struct dns_pkt *dp, struct stats *st, quest_policy qp)
{
	if (!dp || !st || !qp)
		return -1;

	for (int i = 0; i < dp->hdr->qd_count; i++) {
		struct dns_quest *q = &dp->quests[i];
		if (!is_checking_type(q->base.qtype))
			continue;
		qp(q, st);
	}
	return 0;
}

static void quest_policy_name_size(struct dns_quest *q, struct stats *st)
{
	update_stats(st, q->base.qname.len);
}
int policy_req_quest_name_size(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_name_size);
}

static void quest_policy_label_size(struct dns_quest *q, struct stats *st)
{
	unsigned int r = 0;
	//count the avg of the 1st and 2nd label
	unsigned char *p = q->base.qname.name;

	//1st
	int label1_len = *p;
	if (label1_len == 0)
		r = 0;
	else {
		p += label1_len + 1;
		int label2_len = *p;

		if (label2_len == 0)
			r = label1_len;
		else
			r = (label1_len + label2_len) / 2;
	}
	update_stats(st, r);
}
int policy_req_quest_label_size(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_name_size);
}

static void quest_policy_unique_char(struct dns_quest *q, struct stats *st)
{
	unsigned char charset[256];
	unsigned int r = 0;
	int len = q->base.qname.len;
	unsigned char name[MAX_DOMAIN_LEN];
	convert_domain_name(&q->base.qname, name);

	memset(charset, 0, 256);
	for (int i = 0; i < len; i++)
		charset[name[i]]++;

	for (int i = 0; i < 256; i++)
		r += !!charset[i];
	update_stats(st, r);
}

int policy_req_quest_unique_char(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_unique_char);
}
static void quest_policy_longest_repeat(struct dns_quest *q, struct stats *st)
{
	int len = q->base.qname.len;
	unsigned char name[MAX_DOMAIN_LEN];
	convert_domain_name(&q->base.qname, name);

	unsigned int max_len = 0;
	unsigned int non_vowel_len = 0;
	for (int i = 0; i < len; i++) {
		switch (name[i]) {
		case 'a':
		case 'e':
		case 'i':
		case 'o':
		case 'u':
		case 'A':
		case 'E':
		case 'I':
		case 'O':
		case 'U':
		case '.':
		case '-':
			if (non_vowel_len > max_len)
				max_len = non_vowel_len;
			non_vowel_len = 0;
			break;
		default:
			non_vowel_len++;
			break;
		}
	}
	update_stats(st, max_len);
}
int policy_req_quest_longest_repeat(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_longest_repeat);
}

static inline void quest_policy_type_a(struct dns_quest *q, struct stats *st)
{
	return policy_type_a((struct dns_sec_base *)q, st);
}
int policy_req_quest_type_a(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_type_a);
}

static inline void quest_policy_type_aaaa(struct dns_quest *q, struct stats *st)
{
	return policy_type_aaaa((struct dns_sec_base *)q, st);
}
int policy_req_quest_type_aaaa(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_type_aaaa);
}

static inline void quest_policy_type_null(struct dns_quest *q, struct stats *st)
{
	return policy_type_null((struct dns_sec_base *)q, st);
}
int policy_req_quest_type_null(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_type_null);
}

static inline void quest_policy_type_txt(struct dns_quest *q, struct stats *st)
{
	return policy_type_txt((struct dns_sec_base *)q, st);
}
int policy_req_quest_type_txt(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_type_txt);
}

static inline void quest_policy_type_mx(struct dns_quest *q, struct stats *st)
{
	return policy_type_mx((struct dns_sec_base *)q, st);
}
int policy_req_quest_type_mx(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_type_mx);
}

static inline void quest_policy_type_cname(struct dns_quest *q, struct stats *st)
{
	return policy_type_cname((struct dns_sec_base *)q, st);
}
int policy_req_quest_type_cname(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_type_cname);
}

/* response policy */
typedef void (*ans_policy)(struct dns_answer *, struct stats *);
static int apply_answer_policy(struct dns_pkt *dp, struct stats *st, ans_policy ap)
{
	if (!dp || !st || !ap)
		return -1;

	for (int i = 0; i < dp->hdr->an_count; i++) {
		struct dns_answer *a = &dp->answers[i];
		if (!is_checking_type(a->base.qtype))
			continue;
		ap(a, st);
	}
	return 0;
}
int policy_rep_nxdomain(struct dns_pkt *dp, struct stats *st)
{
	if (!dp || !st)
		return -1;

	update_stats(st, DNS_FLAG_RCODE(dp->hdr->flag_code) == DNS_RCODE_NAME_ERR);
	return 0;
}
static inline void answer_policy_type_a(struct dns_answer *a, struct stats *st)
{
	return policy_type_a((struct dns_sec_base *)a, st);
}
int policy_rep_ans_type_a(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, answer_policy_type_a);
}

static inline void answer_policy_type_aaaa(struct dns_answer *a, struct stats *st)
{
	return policy_type_aaaa((struct dns_sec_base *)a, st);
}
int policy_rep_ans_type_aaaa(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, answer_policy_type_aaaa);
}

static inline void answer_policy_type_null(struct dns_answer *a, struct stats *st)
{
	return policy_type_null((struct dns_sec_base *)a, st);
}
int policy_rep_ans_type_null(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, answer_policy_type_null);
}

static inline void answer_policy_type_txt(struct dns_answer *a, struct stats *st)
{
	return policy_type_txt((struct dns_sec_base *)a, st);
}
int policy_rep_ans_type_txt(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, answer_policy_type_txt);
}

static inline void answer_policy_type_mx(struct dns_answer *a, struct stats *st)
{
	return policy_type_mx((struct dns_sec_base *)a, st);
}
int policy_rep_ans_type_mx(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, answer_policy_type_mx);
}

static inline void answer_policy_type_cname(struct dns_answer *a, struct stats *st)
{
	return policy_type_cname((struct dns_sec_base *)a, st);
}
int policy_rep_ans_type_cname(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, answer_policy_type_cname);
}

