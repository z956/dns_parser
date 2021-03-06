#include "policy.h"

#include <string.h>

#define _DNS_PARSER_DBG_
#include "stats.h"
#include "common.h"

#define policy_field(name, fn) \
	[name] = { #name, fn }

/* generic handler */
static int policy_pkt_size(struct dns_pkt *dp, struct stats *st);

static int policy_type_a(struct dns_pkt *dp, struct stats *st);
static int policy_type_aaaa(struct dns_pkt *dp, struct stats *st);
static int policy_type_null(struct dns_pkt *dp, struct stats *st);
static int policy_type_txt(struct dns_pkt *dp, struct stats *st);
static int policy_type_mx(struct dns_pkt *dp, struct stats *st);
static int policy_type_cname(struct dns_pkt *dp, struct stats *st);

/* request policy */
static int policy_req_quest_name_size(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_label_size(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_unique_char(struct dns_pkt *dp, struct stats *st);
static int policy_req_quest_longest_repeat(struct dns_pkt *dp, struct stats *st);
static struct policy policy_req[] = {
	policy_field(POLICY_REQ_SIZE, policy_pkt_size),

	policy_field(POLICY_REQ_QUEST_NAME_SIZE, policy_req_quest_name_size),
	policy_field(POLICY_REQ_QUEST_LABEL_SIZE, policy_req_quest_label_size),
	policy_field(POLICY_REQ_QUEST_UNIQUE_CHAR, policy_req_quest_unique_char),
	policy_field(POLICY_REQ_QUEST_LONGEST_REPEAT, policy_req_quest_longest_repeat),
	policy_field(POLICY_REQ_QUEST_TYPE_A, policy_type_a),
	policy_field(POLICY_REQ_QUEST_TYPE_AAAA, policy_type_aaaa),
	policy_field(POLICY_REQ_QUEST_TYPE_NULL, policy_type_null),
	policy_field(POLICY_REQ_QUEST_TYPE_TXT, policy_type_txt),
	policy_field(POLICY_REQ_QUEST_TYPE_MX, policy_type_mx),
	policy_field(POLICY_REQ_QUEST_TYPE_CNAME, policy_type_cname),
};

/* response policy */
static int policy_rep_nxdomain(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_name_size(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_unique_char(struct dns_pkt *dp, struct stats *st);
static int policy_rep_ans_longest_repeat(struct dns_pkt *dp, struct stats *st);
static struct policy policy_rep[] = {
	policy_field(POLICY_REP_SIZE, policy_pkt_size),
	policy_field(POLICY_REP_NXDOMAIN, policy_rep_nxdomain),

	policy_field(POLICY_REP_ANS_NAME_SIZE, policy_rep_ans_name_size),
	policy_field(POLICY_REP_ANS_UNIQUE_CHAR, policy_rep_ans_unique_char),
	policy_field(POLICY_REP_ANS_LONGEST_REPEAT, policy_rep_ans_longest_repeat),
	policy_field(POLICY_REP_ANS_TYPE_A, policy_type_a),
	policy_field(POLICY_REP_ANS_TYPE_AAAA, policy_type_aaaa),
	policy_field(POLICY_REP_ANS_TYPE_NULL, policy_type_null),
	policy_field(POLICY_REP_ANS_TYPE_TXT, policy_type_txt),
	policy_field(POLICY_REP_ANS_TYPE_MX, policy_type_mx),
	policy_field(POLICY_REP_ANS_TYPE_CNAME, policy_type_cname),
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

static int policy_type_check(struct dns_pkt *dp, struct stats *st, int type)
{
	int qr = dns_qr(dp->hdr);
	int offset;
	void *p;
	int count;

	if (qr == DNS_QR_QUERY) {
		offset = sizeof(struct dns_quest);
		p = dp->quests;
		count = dp->hdr->qd_count;
	}
	else if (qr == DNS_QR_REPLY) {
		offset = sizeof(struct dns_answer);
		p = dp->answers;
		count = dp->hdr->an_count;
	}
	else
		return -1;

	for (int i = 0; i < count; i++) {
		struct dns_sec_base *base = p + i * offset;
		if (is_checking_type(base->qtype))
			update_stats(st, base->qtype == type);
	}
	return 0;
}
int policy_type_a(struct dns_pkt *dp, struct stats *st)
{
	return policy_type_check(dp, st, DNS_TYPE_A);
}
int policy_type_aaaa(struct dns_pkt *dp, struct stats *st)
{
	return policy_type_check(dp, st, DNS_TYPE_AAAA);
}
int policy_type_null(struct dns_pkt *dp, struct stats *st)
{
	return policy_type_check(dp, st, DNS_TYPE_NULL);
}
int policy_type_txt(struct dns_pkt *dp, struct stats *st)
{
	return policy_type_check(dp, st, DNS_TYPE_TXT);
}
int policy_type_mx(struct dns_pkt *dp, struct stats *st)
{
	return policy_type_check(dp, st, DNS_TYPE_MX);
}
int policy_type_cname(struct dns_pkt *dp, struct stats *st)
{
	return policy_type_check(dp, st, DNS_TYPE_CNAME);
}

static void policy_domain_name_size(struct domain_name *dn, struct stats *st)
{
	update_stats(st, dn->len);
}
static void policy_domain_label_size(struct domain_name *dn, struct stats *st)
{
	unsigned int r = 0;
	//count the avg of the 1st and 2nd label
	unsigned char *p = dn->name;

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
static void policy_domain_unique_char(struct domain_name *dn, struct stats *st)
{
	unsigned char charset[256];
	unsigned int r = 0;
	int len = dn->len;
	unsigned char name[MAX_DOMAIN_LEN];
	convert_domain_name(dn, name);

	memset(charset, 0, 256);
	for (int i = 0; i < len; i++)
		charset[name[i]]++;

	for (int i = 0; i < 256; i++)
		r += !!charset[i];
	update_stats(st, r);
}
static void policy_domain_longest_repeat(struct domain_name *dn, struct stats *st)
{
	int len = dn->len;
	unsigned char name[MAX_DOMAIN_LEN];
	convert_domain_name(dn, name);

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
	policy_domain_name_size(&q->base.qname, st);
}
int policy_req_quest_name_size(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_name_size);
}

static void quest_policy_label_size(struct dns_quest *q, struct stats *st)
{
	policy_domain_label_size(&q->base.qname, st);
}
int policy_req_quest_label_size(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_name_size);
}

static void quest_policy_unique_char(struct dns_quest *q, struct stats *st)
{
	policy_domain_unique_char(&q->base.qname, st);
}

int policy_req_quest_unique_char(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_unique_char);
}

static void quest_policy_longest_repeat(struct dns_quest *q, struct stats *st)
{
	policy_domain_longest_repeat(&q->base.qname, st);
}
int policy_req_quest_longest_repeat(struct dns_pkt *dp, struct stats *st)
{
	return apply_quest_policy(dp, st, quest_policy_longest_repeat);
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

static void ans_policy_name_size(struct dns_answer *a, struct stats *st)
{
	switch (a->base.qtype) {
	case DNS_TYPE_CNAME:
	case DNS_TYPE_MX:
		policy_domain_name_size(&a->content_name, st);
		break;
	default:
		break;
	}
}
int policy_rep_ans_name_size(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, ans_policy_name_size);
}

static void ans_policy_unique_char(struct dns_answer *a, struct stats *st)
{
	switch (a->base.qtype) {
	case DNS_TYPE_CNAME:
	case DNS_TYPE_MX:
		policy_domain_unique_char(&a->content_name, st);
		break;
	default:
		break;
	}
}
int policy_rep_ans_unique_char(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, ans_policy_unique_char);
}

static void ans_policy_longest_repeat(struct dns_answer *a, struct stats *st)
{
	switch (a->base.qtype) {
	case DNS_TYPE_CNAME:
	case DNS_TYPE_MX:
		policy_domain_longest_repeat(&a->content_name, st);
		break;
	default:
		break;
	}
}
int policy_rep_ans_longest_repeat(struct dns_pkt *dp, struct stats *st)
{
	return apply_answer_policy(dp, st, ans_policy_longest_repeat);
}

