#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"

struct pkt_proc {
	const u_char *pkt;
	int offset;
	unsigned int len;
};

static inline int dns_qr(const struct dns_header *hdr)
{
	return hdr? DNS_FLAG_QR(hdr->flag_code) : -1;
}

static struct dns_header *dns_header_alloc(struct pkt_proc *pp)
{
	struct dns_header *h, *dh;

	if (pp->offset + sizeof(struct dns_header) > pp->len) {
		ERR("Invalid parameter\n");
		return NULL;
	}

	dh = calloc(1, sizeof(struct dns_header));
	if (!dh) {
		ERR("Cannot alloc for dns header\n");
		return NULL;
	}

	h = (struct dns_header *)(pp->pkt + pp->offset);
	pp->offset += sizeof(struct dns_header);

	dh->id = ntohs(h->id);
	dh->flag_code = ntohs(h->flag_code);
	dh->qd_count = ntohs(h->qd_count);
	dh->an_count = ntohs(h->an_count);
	dh->ns_count = ntohs(h->ns_count);
	dh->ar_count = ntohs(h->ar_count);

	DBG("\nparse header:\n"
		"\tid(0x%x)\n"
		"\tflag_code(0x%x)\n"
		"\tqd_count(%d)\n"
		"\tan_count(%d)\n"
		"\tns_count(%d)\n"
		"\tar_count(%d)\n",
		dh->id, dh->flag_code, dh->qd_count,
		dh->an_count, dh->ns_count, dh->ar_count);

	return dh;
}
static int parse_domain_name(struct pkt_proc *pp, struct dns_quest *dq)
{
	const u_char *p = pp->pkt + pp->offset;
	const u_char *tail = pp->pkt + pp->len;

	int total_len = 0;
	int label_len = 0;
	int in_ptr = 0;
	memset(dq, 0, sizeof(struct dns_quest));

	while (p < tail && *p && total_len < MAX_DOMAIN_LEN) {
		if (!in_ptr)
			pp->offset++;
		if (*p == 0xc0) {
			//ptr
			int offset = (*p) & 0x3F;
			p++;
			if (p >= tail || *p)
				break;
			offset = offset * 16 + *p;
			if (offset >= pp->len)
				break;
			p = pp->pkt + offset;
			label_len = 0;
			in_ptr = 1;
		}
		else if (label_len) {
			dq->qname[total_len++] = *p;
			p++;
			label_len--;
		}
		else {
			dq->qname[total_len++] = '.';
			label_len = *p;
			p++;
		}
	}
	if (*p || p == tail)
		return -1;
	dq->qname[total_len] = 0;
	DBG("parsed domain name: %s\n", dq->qname);
	return total_len;
}
static int parse_quest_section(struct pkt_proc *pp,
				int qd_count, struct dns_quest *dq)
{
	int i;
	for (i = 0; i < qd_count; i++) {
		//parse name
		if (parse_domain_name(pp, &dq[i]) < 0) {
			ERR("parse_domain_name %d failed\n", i);
			return -1;
		}

		//parse type and class
		if (pp->offset + sizeof(uint16_t) * 2 > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}
		dq[i].qtype = ntohs(*((uint16_t *)pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		dq[i].qclass = ntohs(*((uint16_t *)pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);
	}
	return 0;
}
static struct dns_quest *dns_query_alloc(const struct dns_header *hdr,
					struct pkt_proc *pp)
{
	struct dns_quest *dq = calloc(1, sizeof(struct dns_quest) * hdr->qd_count);
	if (!dq) {
		ERR("Cannot allocate for dns quest\n");
		return NULL;
	}

	if (parse_quest_section(pp, hdr->qd_count, dq)) {
		ERR("parse_quest_section failed\n");
		goto err;
	}

	return dq;
err:
	free(dq);
	return NULL;
}
static struct dns_rr *dns_reply_alloc(const struct dns_header *hdr,
					struct pkt_proc *pp)
{
	//TODO
	return NULL;
}
struct dns_pkt *dns_alloc(const u_char *pkt, unsigned int len)
{
	int qr_code;
	int offset = 0;
	struct pkt_proc pp;
	if (!pkt) {
		ERR("Invalid parameter\n");
		return NULL;
	}

	struct dns_pkt *dp = calloc(1, sizeof(struct dns_pkt));
	if (!dp) {
		ERR("Cannot alloc for dns packet\n");
		goto err;
	}

	pp.pkt = pkt;
	pp.offset = 0;
	pp.len = len;

	//parse header
	dp->hdr = dns_header_alloc(&pp);
	if (!dp->hdr) {
		ERR("dns_header_alloc failed\n");
		goto err;
	}

	qr_code = dns_qr(dp->hdr);
	switch (qr_code) {
	case DNS_QR_QUERY:
		dp->quests = dns_query_alloc(dp->hdr, &pp);
		if (!dp->quests) {
			ERR("dns_query_alloc failed\n");
			goto err;
		}
		break;
	case DNS_QR_REPLY:
		dp->rrs = dns_reply_alloc(dp->hdr, &pp);
		if (!dp->rrs) {
			ERR("dns_reply_alloc failed\n");
			goto err;
		}
		break;
	default:
		ERR("Invalid qr code: %d\n", qr_code);
		goto err;
	}

	return dp;

err:
	dns_del(dp);
	return NULL;
}
void dns_del(struct dns_pkt *dp)
{
	if (!dp)
		return;
	free(dp->quests);
	free(dp->rrs);
}

