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

	return dh;
}
static int parse_domain_name(struct pkt_proc *pp, struct dns_quest *dq)
{
	//TODO
	return -1;
}
static struct dns_quest *dns_query_alloc(const struct dns_header *hdr,
					struct pkt_proc *pp)
{
	int i;
	struct dns_quest *dq = calloc(1, sizeof(struct dns_quest) * hdr->qd_count);
	if (!dq) {
		ERR("Cannot allocate for dns quest\n");
		return NULL;
	}
	for (i = 0; i < hdr->qd_count; i++) {
		//parse name first
		if (!parse_domain_name(pp, &dq[i])) {
			ERR("parse_domain_name %d failed\n", i);
			goto err;
		}

		if (pp->offset + sizeof(uint16_t) * 2 > pp->len) {
			ERR("Invalid pkt\n");
			goto err;
		}
		dq[i].qtype = ntohs(*((uint16_t *)pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		dq[i].qclass = ntohs(*((uint16_t *)pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);
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
	if (qr_code == DNS_QR_QUERY) {
	}
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

