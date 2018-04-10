#include "policy.h"

#include <string.h>

#define _DNS_PARSER_DBG_
#include "common.h"

#define policy_field(name, fn) \
	[name] = { #name, fn }

/* generic handler */
static unsigned int policy_pkt_size(void *data);
static unsigned int policy_type_a(void *data);
static unsigned int policy_type_aaaa(void *data);
static unsigned int policy_type_null(void *data);
static unsigned int policy_type_txt(void *data);
static unsigned int policy_type_mx(void *data);
static unsigned int policy_type_cname(void *data);

/* request policy */
static struct policy policy_req[] = {
	policy_field(POLICY_REQ_SIZE, policy_pkt_size),
};

/* quest policy */
static unsigned int policy_quest_name_size(void *data);
static unsigned int policy_quest_label_size(void *data);
static unsigned int policy_quest_unique_char(void *data);
static unsigned int policy_quest_longest_repeat(void *data);
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
static struct policy policy_rep[] = {
	policy_field(POLICY_REP_SIZE, policy_pkt_size),
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
unsigned int policy_pkt_size(void *data)
{
	struct dns_pkt *dp = data;
	return dp? dp->len : 0;
}
unsigned int policy_type_a(void *data)
{
	struct dns_sec_base *base = data;
	return base? base->qtype == DNS_TYPE_A : 0;
}
unsigned int policy_type_aaaa(void *data)
{
	struct dns_sec_base *base = data;
	return base? base->qtype == DNS_TYPE_AAAA : 0;
}
unsigned int policy_type_null(void *data)
{
	struct dns_sec_base *base = data;
	return base? base->qtype == DNS_TYPE_NULL : 0;
}
unsigned int policy_type_txt(void *data)
{
	struct dns_sec_base *base = data;
	return base? base->qtype == DNS_TYPE_TXT : 0;
}
unsigned int policy_type_mx(void *data)
{
	struct dns_sec_base *base = data;
	return base? base->qtype == DNS_TYPE_MX : 0;
}
unsigned int policy_type_cname(void *data)
{
	struct dns_sec_base *base = data;
	return base? base->qtype == DNS_TYPE_CNAME : 0;
}

/* quest policy */
unsigned int policy_quest_name_size(void *data)
{
	struct dns_quest *quest = data;
	return quest? quest->base.qname.len : 0;
}
unsigned int policy_quest_label_size(void *data)
{
	struct dns_quest *quest = data;
	if (quest) {
		//count the avg of the 1st and 2nd label
		unsigned char *p = quest->base.qname.name;

		//1st
		int label1_len = *p;
		if (label1_len == 0)
			return 0;
		p += label1_len + 1;
		int label2_len = *p;

		if (label2_len == 0)
			return label1_len;
		return (label1_len + label2_len) / 2;
	}
	else
		return 0;
}
unsigned int policy_quest_unique_char(void *data)
{
	struct dns_quest *quest = data;

	if (quest) {
		unsigned char charset[256];
		unsigned int r = 0;
		int len = quest->base.qname.len;
		const unsigned char *name = quest->base.qname.name;

		memset(charset, 0, 256);
		for (int i = 0; i < len; i++)
			charset[name[i]]++;

		for (int i = 0; i < 256; i++)
			r += !!charset[i];
		return r;
	}
	else
		return 0;
}
unsigned int policy_quest_longest_repeat(void *data)
{
	struct dns_quest *quest = data;

	if (quest) {
		int len = quest->base.qname.len;
		const unsigned char *name = quest->base.qname.name;

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
		return max_len;
	}
	else
		return 0;

}

