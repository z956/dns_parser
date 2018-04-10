#include "post_proc.h"

#include "policy.h"
#include "stats.h"
#include "dns.h"

#include "common.h"

static void apply_policy(struct policy *p, int count, void *data, struct stats *sts)
{
	for (int i = 0; i < count; i++) {
		unsigned int r = (p[i].handle)(data);
		update_stats(&sts[i], r);
	}
}
void post_proc_req(struct list_head *head)
{
	struct dns_pkt *dp, *tmp;
	struct policy *req_policy = get_policy_req();
	struct policy *quest_policy = get_policy_quest();

	struct stats req_stats[POLICY_REQ_MAX];
	struct stats quest_stats[POLICY_QUEST_MAX];

	for (int i = 0; i < POLICY_REQ_MAX; i++)
		init_stats(req_policy[i].name, &req_stats[i]);
	for (int i = 0; i < POLICY_QUEST_MAX; i++)
		init_stats(quest_policy[i].name, &quest_stats[i]);
	unsigned int qd_count = 0, pkt_count = 0;
	list_for_each_entry_safe (dp, tmp, head, list) {
		for (int i = 0; i < dp->hdr->qd_count; i++) {
			apply_policy(quest_policy, POLICY_QUEST_MAX,
					&dp->quests[i], quest_stats);
		}
		qd_count += dp->hdr->qd_count;

		apply_policy(req_policy, POLICY_REQ_MAX, dp, req_stats);
		pkt_count++;
	}

	PRT("Total query packet: %u\n", pkt_count);
	PRT("Total question: %u\n", qd_count);
	for (int i = 0; i < POLICY_REQ_MAX; i++)
		print_stats(&req_stats[i]);
	for (int i = 0; i < POLICY_QUEST_MAX; i++)
		print_stats(&quest_stats[i]);
}


