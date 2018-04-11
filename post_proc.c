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
	unsigned int qd_count = 0, pkt_count = 0;
	struct stats req_stats[POLICY_REQ_MAX];
	struct stats quest_stats[POLICY_QUEST_MAX];

	for (int i = 0; i < POLICY_REQ_MAX; i++)
		init_stats(req_policy[i].name, &req_stats[i]);
	for (int i = 0; i < POLICY_QUEST_MAX; i++)
		init_stats(quest_policy[i].name, &quest_stats[i]);

	list_for_each_entry_safe (dp, tmp, head, list) {
		for (int i = 0; i < dp->hdr->qd_count; i++) {
			if (!is_checking_type(dp->quests[i].base.qtype))
				continue;

			apply_policy(quest_policy, POLICY_QUEST_MAX,
					&dp->quests[i], quest_stats);
			qd_count += dp->hdr->qd_count;
		}

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

void post_proc_rep(struct list_head *head)
{
	struct dns_pkt *dp, *tmp;
	struct policy *rep_policy = get_policy_rep();
	struct policy *ans_policy = get_policy_ans();
	unsigned int pkt_count = 0, ans_count = 0;
	struct stats rep_stats[POLICY_REP_MAX];
	struct stats ans_stats[POLICY_ANS_MAX];

	for (int i = 0; i < POLICY_REP_MAX; i++)
		init_stats(rep_policy[i].name, &rep_stats[i]);
	for (int i = 0; i < POLICY_ANS_MAX; i++)
		init_stats(ans_policy[i].name, &ans_stats[i]);

	list_for_each_entry_safe (dp, tmp, head, list) {
		for (int i = 0; i < dp->hdr->an_count; i++) {
			if (!is_checking_type(dp->answers[i].base.qtype))
				continue;
			apply_policy(ans_policy, POLICY_ANS_MAX,
					&dp->answers[i], ans_stats);
			ans_count += dp->hdr->an_count;
		}

		apply_policy(rep_policy, POLICY_REP_MAX, dp, rep_stats);
		pkt_count++;
	}

	PRT("Total response packets: %u\n", pkt_count);
	PRT("Total answers: %u\n", ans_count);
	for (int i = 0; i < POLICY_REP_MAX; i++)
		print_stats(&rep_stats[i]);
	for (int i = 0; i < POLICY_ANS_MAX; i++)
		print_stats(&ans_stats[i]);
}

