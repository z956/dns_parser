#include "policy.h"

#include <string.h>

#define _DNS_PARSER_DBG_
#include "common.h"

static unsigned int policy_pkt_size(void *data);

/* request policy */
static struct policy policy_req[] = {
	[POLICY_REQ_SIZE] = { "POLICY_REQ_SIZE", policy_pkt_size },
};

/* quest policy */
static unsigned int policy_quest_name_size(void *data);
static unsigned int policy_quest_label_size(void *data);
static unsigned int policy_quest_unique_char(void *data);
static unsigned int policy_quest_longest_repeat(void *data);
static struct policy policy_quest[] = {
	[POLICY_QUEST_NAME_SIZE] = { "POLICY_QUEST_NAME_SIZE", policy_quest_name_size },
	[POLICY_QUEST_LABEL_SIZE] = { "POLICY_QUEST_LABEL_SIZE", policy_quest_label_size },
	[POLICY_QUEST_UNIQUE_CHAR] = { "POLICY_QUEST_UNIQUE_CHAR", policy_quest_unique_char },
	[POLICY_QUEST_LONGEST_REPEAT] = { "POLICY_QUEST_LONGEST_REPEAT", policy_quest_longest_repeat },
};

/* response policy */
static struct policy policy_rep[] = {
	[POLICY_REP_SIZE] = { "POLICY_REP_SIZE", policy_pkt_size },
};

int policy_req_init(void)
{
	//FIXME should imp?
	return 0;
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

unsigned int policy_pkt_size(void *data)
{
	struct dns_pkt *dp = data;
	return dp? dp->len : 0;
}

/* quest policy */
unsigned int policy_quest_name_size(void *data)
{
	struct dns_quest *quest = data;
	return quest? quest->name.len : 0;
}
unsigned int policy_quest_label_size(void *data)
{
	struct dns_quest *quest = data;
	if (quest) {
		//count the avg of the 1st and 2nd label
		unsigned char *p = quest->name.name;

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
		int len = quest->name.len;
		const unsigned char *name = quest->name.name;

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
		int len = quest->name.len;
		const unsigned char *name = quest->name.name;

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

