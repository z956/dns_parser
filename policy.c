#include "policy.h"

#include <string.h>

#define _DNS_PARSER_DBG_
#include "stats.h"
#include "common.h"

#define policy_field(name, fn) \
	[name] = { #name, fn }

/* generic handler */
static int policy_pkt_size(void *data, struct stats *st);
static int policy_type_a(void *data, struct stats *st);
static int policy_type_aaaa(void *data, struct stats *st);
static int policy_type_null(void *data, struct stats *st);
static int policy_type_txt(void *data, struct stats *st);
static int policy_type_mx(void *data, struct stats *st);
static int policy_type_cname(void *data, struct stats *st);

/* request policy */
static struct policy policy_req[] = {
	policy_field(POLICY_REQ_SIZE, policy_pkt_size),
};

/* quest policy */
static int policy_quest_name_size(void *data, struct stats *st);
static int policy_quest_label_size(void *data, struct stats *st);
static int policy_quest_unique_char(void *data, struct stats *st);
static int policy_quest_longest_repeat(void *data, struct stats *st);
static struct policy policy_quest[] = {
	policy_field(POLICY_QUEST_NAME_SIZE, policy_quest_name_size),
	policy_field(POLICY_QUEST_LABEL_SIZE, policy_quest_label_size),
	policy_field(POLICY_QUEST_UNIQUE_CHAR, policy_quest_unique_char),
	policy_field(POLICY_QUEST_LONGEST_REPEAT, policy_quest_longest_repeat),
	policy_field(POLICY_QUEST_TYPE_A, policy_type_a),
	policy_field(POLICY_QUEST_TYPE_AAAA, policy_type_aaaa),
	policy_field(POLICY_QUEST_TYPE_NULL, policy_type_null),
	policy_field(POLICY_QUEST_TYPE_TXT, policy_type_txt),
	policy_field(POLICY_QUEST_TYPE_MX, policy_type_mx),
	policy_field(POLICY_QUEST_TYPE_CNAME, policy_type_cname),
};

/* response policy */
static int policy_rep_nxdomain(void *data, struct stats *st);
static struct policy policy_rep[] = {
	policy_field(POLICY_REP_SIZE, policy_pkt_size),
	policy_field(POLICY_REP_NXDOMAIN, policy_rep_nxdomain),
};

/* answer poilcy */
static struct policy policy_ans[] = {
	policy_field(POLICY_ANS_TYPE_A, policy_type_a),
	policy_field(POLICY_ANS_TYPE_AAAA, policy_type_aaaa),
	policy_field(POLICY_ANS_TYPE_NULL, policy_type_null),
	policy_field(POLICY_ANS_TYPE_TXT, policy_type_txt),
	policy_field(POLICY_ANS_TYPE_MX, policy_type_mx),
	policy_field(POLICY_ANS_TYPE_CNAME, policy_type_cname),
};

struct policies policies[] = {
	[POLICY_REQ] = { policy_req, POLICY_REQ_MAX },
	[POLICY_QUEST] = { policy_quest, POLICY_QUEST_MAX },
	[POLICY_REP] = { policy_rep, POLICY_REP_MAX },
	[POLICY_ANS] = { policy_ans, POLICY_ANS_MAX },
};
struct policies *get_policies(void)
{
	return policies;
}
struct policy *get_policy_req(void)
{
	return policy_req;
}
struct policy *get_policy_quest(void)
{
	return policy_quest;
}
struct policy *get_policy_rep(void)
{
	return policy_rep;
}
struct policy *get_policy_ans(void)
{
	return policy_ans;
}

/* generic handler */
int policy_pkt_size(void *data, struct stats *st)
{
	struct dns_pkt *dp = data;
	if (!dp || !st)
		return -1;

	update_stats(st, dp->len);
	return 0;
}
int policy_type_a(void *data, struct stats *st)
{
	struct dns_sec_base *base = data;

	if (!base || !st)
		return -1;

	update_stats(st, base->qtype == DNS_TYPE_A);
	return 0;
}
int policy_type_aaaa(void *data, struct stats *st)
{
	struct dns_sec_base *base = data;

	if (!base || !st)
		return -1;

	update_stats(st, base->qtype == DNS_TYPE_AAAA);
	return 0;
}
int policy_type_null(void *data, struct stats *st)
{
	struct dns_sec_base *base = data;

	if (!base || !st)
		return -1;

	update_stats(st, base->qtype == DNS_TYPE_NULL);
	return 0;
}
int policy_type_txt(void *data, struct stats *st)
{
	struct dns_sec_base *base = data;

	if (!base || !st)
		return -1;

	update_stats(st, base->qtype == DNS_TYPE_TXT);
	return 0;
}
int policy_type_mx(void *data, struct stats *st)
{
	struct dns_sec_base *base = data;

	if (!base || !st)
		return -1;

	update_stats(st, base->qtype == DNS_TYPE_MX);
	return 0;
}
int policy_type_cname(void *data, struct stats *st)
{
	struct dns_sec_base *base = data;

	if (!base || !st)
		return -1;

	update_stats(st, base->qtype == DNS_TYPE_CNAME);
	return 0;
}

/* quest policy */
int policy_quest_name_size(void *data, struct stats *st)
{
	struct dns_quest *quest = data;

	if (!quest || !st)
		return -1;

	update_stats(st, quest->base.qname.len);
	return 0;
}
int policy_quest_label_size(void *data, struct stats *st)
{
	struct dns_quest *quest = data;
	if (!quest || !st)
		return -1;

	unsigned int r = 0;
	//count the avg of the 1st and 2nd label
	unsigned char *p = quest->base.qname.name;

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
	return 0;
}
int policy_quest_unique_char(void *data, struct stats *st)
{
	struct dns_quest *quest = data;

	if (!quest || !st)
		return -1;

	unsigned char charset[256];
	unsigned int r = 0;
	int len = quest->base.qname.len;
	unsigned char name[MAX_DOMAIN_LEN];
	convert_domain_name(&quest->base.qname, name);

	memset(charset, 0, 256);
	for (int i = 0; i < len; i++)
		charset[name[i]]++;

	for (int i = 0; i < 256; i++)
		r += !!charset[i];
	update_stats(st, r);
	return 0;
}
int policy_quest_longest_repeat(void *data, struct stats *st)
{
	struct dns_quest *quest = data;

	if (!quest || !st)
		return -1;

	int len = quest->base.qname.len;
	unsigned char name[MAX_DOMAIN_LEN];
	convert_domain_name(&quest->base.qname, name);

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
	return 0;
}

/* response policy */
int policy_rep_nxdomain(void *data, struct stats *st)
{
	struct dns_pkt *dp = data;

	if (!dp || !st)
		return -1;

	update_stats(st, DNS_FLAG_RCODE(dp->hdr->flag_code) == DNS_RCODE_NAME_ERR);
	return 0;
}

