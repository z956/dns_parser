#include "post_proc.h"

#include "policy.h"
#include "stats.h"
#include "dns.h"

#include "common.h"

static void apply_policy(struct policy *p, int count, struct dns_pkt *dp, struct stats *sts)
{
	for (int i = 0; i < count; i++) {
		if ((p[i].handle)(dp, &sts[i]))
			ERR("apply policy failed!\n");
	}
}
void post_proc_req(struct list_head *head)
{
	struct dns_pkt *dp, *tmp;

	unsigned int pkt_count = 0;
	struct policy *req_policy = get_policy_req();
	struct stats req_stats[POLICY_REQ_MAX];

	for (int i = 0; i < POLICY_REQ_MAX; i++)
		init_stats(req_policy[i].name, &req_stats[i]);

	list_for_each_entry_safe (dp, tmp, head, list) {
		apply_policy(req_policy, POLICY_REQ_MAX, dp, req_stats);
		pkt_count++;
	}
	PRT("Total query packet: %u\n", pkt_count);
	for (int i = 0; i < POLICY_REQ_MAX; i++)
		print_stats(&req_stats[i]);
}

void post_proc_rep(struct list_head *head)
{
	struct dns_pkt *dp, *tmp;

	unsigned int pkt_count = 0;
	struct policy *rep_policy = get_policy_rep();
	struct stats rep_stats[POLICY_REP_MAX];

	for (int i = 0; i < POLICY_REP_MAX; i++)
		init_stats(rep_policy[i].name, &rep_stats[i]);

	list_for_each_entry_safe (dp, tmp, head, list) {
		apply_policy(rep_policy, POLICY_REP_MAX, dp, rep_stats);
		pkt_count++;
	}

	PRT("Total response packets: %u\n", pkt_count);
	for (int i = 0; i < POLICY_REP_MAX; i++)
		print_stats(&rep_stats[i]);
}

