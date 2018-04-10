#include "policy.h"

#include <string.h>

#define _DNS_PARSER_DBG_
#include "common.h"

/* request policy */
static unsigned int policy_req_size(void *data);
static struct policy policy_req[] = {
	[POLICY_REQ_SIZE] = { "POLICY_REQ_SIZE", policy_req_size },
};

/* quest policy */
static unsigned int policy_quest_name_size(void *data);
static unsigned int policy_quest_unique_char(void *data);
static unsigned int policy_quest_longest_repeat(void *data);
static struct policy policy_quest[] = {
	[POLICY_QUEST_NAME_SIZE] = { "POLICY_QUEST_NAME_SIZE", policy_quest_name_size },
	[POLICY_QUEST_UNIQUE_CHAR] = { "POLICY_QUEST_UNIQUE_CHAR", policy_quest_unique_char },
	[POLICY_QUEST_LONGEST_REPEAT] = { "POLICY_QUEST_LONGEST_REPEAT", policy_quest_longest_repeat },
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

/* request policy */
unsigned int policy_req_size(void *data)
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
unsigned int policy_quest_unique_char(void *data)
{
	struct dns_quest *quest = data;

	if (quest) {
		unsigned char charset[256];
		int i;
		unsigned int r = 0;
		int len = quest->name.len;
		const unsigned char *name = quest->name.name;

		memset(charset, 0, 256);
		for (i = 0; i < len; i++)
			charset[name[i]]++;

		for (i = 0; i < 256; i++)
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

		int i;
		unsigned int max_len = 0;
		unsigned int non_vowel_len = 0;
		for (i = 0; i < len; i++) {
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

