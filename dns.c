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
static int parse_domain_name(struct pkt_proc *pp, unsigned char *qname)
{
	const u_char *p = pp->pkt + pp->offset;
	const u_char *tail = pp->pkt + pp->len;

	int total_len = 0;
	int label_len = 0;
	int in_ptr = 0;

	while (p < tail && *p && total_len < MAX_DOMAIN_LEN) {
		if (!in_ptr)
			pp->offset++;
		if (*p == 0xc0) {
			//ptr
			const u_char *cur = p;
			int offset = (*p) & 0x3F;
			p++;
			if (p >= tail || !*p)
				break;
			offset = offset * 16 + *p;
			if (offset >= pp->len)
				break;

			if (offset >= (p - pp->pkt - 1))
				break;
			if (!in_ptr)
				pp->offset += 1;
			p = pp->pkt + offset;
			label_len = 0;
			in_ptr = 1;
		}
		else if (label_len) {
			qname[total_len++] = *p;
			p++;
			label_len--;
		}
		else {
			qname[total_len++] = '.';
			label_len = *p;
			p++;
		}
	}
	if (*p || p == tail)
		return -1;
	qname[total_len] = 0;
	if (!in_ptr)
		pp->offset++;
	DBG("parsed domain name: %s, offset: %d\n", qname, pp->offset);
	return total_len;
}
static int parse_quest_section(struct pkt_proc *pp,
				int qd_count, struct dns_quest *dq)
{
	int i;
	for (i = 0; i < qd_count; i++) {
		if (parse_domain_name(pp, dq[i].qname) < 0) {
			ERR("parse_domain_name %d failed\n", i);
			return -1;
		}

		//parse type and class
		if (pp->offset + sizeof(uint16_t) * 2 > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}
		dq[i].qtype = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		dq[i].qclass = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);
	}
	return 0;
}
static int dns_query(struct dns_pkt *dp, struct pkt_proc *pp)
{
	const struct dns_header *hdr = dp->hdr;
	struct dns_quest *dq = calloc(hdr->qd_count, sizeof(struct dns_quest));
	if (!dq) {
		ERR("Cannot allocate for dns quest\n");
		return -1;
	}

	if (parse_quest_section(pp, hdr->qd_count, dq)) {
		ERR("parse_quest_section failed\n");
		free(dq);
		return -1;
	}

	dp->quests = dq;
	return 0;
}
static int parse_answer_section(struct pkt_proc *pp,
				int ans_count, struct dns_answer *ans)
{
	int i, j;
	for (i = 0; i < ans_count; i++) {
		if (parse_domain_name(pp, ans[i].qname) < 0) {
			ERR("parse_domain_name %d failed\n", i);
			return -1;
		}

		if (pp->offset + sizeof(uint16_t) * 3 + sizeof(uint32_t) > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}

		ans[i].qtype = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		ans[i].qclass = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		ans[i].ttl = ntohl(*(uint32_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint32_t);

		ans[i].rd_len = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		DBG("type: %d, class: %d, ttl: %d, rd_len: %d\n", ans[i].qtype, ans[i].qclass, ans[i].ttl, ans[i].rd_len);
		if (pp->offset + ans[i].rd_len > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}

		switch (ans[i].qtype) {
		case DNS_TYPE_A:
			ans[i].addr[0] = ntohl(*(uint32_t *)(pp->pkt + pp->offset));
			pp->offset += sizeof(uint32_t);
			break;
//		case DNS_TYPE_NS:
//			break;
		case DNS_TYPE_CNAME:
			if (parse_domain_name(pp, ans[i].cname) < 0) {
				ERR("parse_domain_name cname failed\n");
				return -1;
			}
			break;
		case DNS_TYPE_NULL:
			ans[i].data = malloc(ans[i].rd_len + 1);
			memcpy(ans[i].data, pp->pkt + pp->offset, ans[i].rd_len);
			ans[i].data[ans[i].rd_len] = 0;
			pp->offset += ans[i].rd_len;
			break;
//		case DNS_TYPE_MX:
//			break;
		case DNS_TYPE_TXT:
			ans[i].data = malloc(ans[i].rd_len + 1);
			memcpy(ans[i].data, pp->pkt + pp->offset, ans[i].rd_len);
			ans[i].data[ans[i].rd_len] = 0;
			pp->offset += ans[i].rd_len;
			break;
		case DNS_TYPE_AAAA:
			for (j = 0; j < 4; j++) {
				ans[i].addr[j] = ntohl(*(uint32_t *)(pp->pkt + pp->offset));
				pp->offset += sizeof(uint32_t);
			}
			break;
		default:
			DBG("unknown type\n");
			return -1;
		}
	}
	return 0;
}
static int dns_reply(struct dns_pkt *dp, struct pkt_proc *pp)
{
	struct dns_header *hdr;
	struct dns_answer *ans;

	if (dns_query(dp, pp)) {
		ERR("dns_query failed\n");
		return -1;
	}

	hdr = dp->hdr;
	ans = calloc(hdr->an_count, sizeof(struct dns_answer));
	if (!ans) {
		ERR("Cannot alloc for dns answer\n");
		return -1;
	}
	if (parse_answer_section(pp, hdr->an_count, ans)) {
		ERR("parse_answer_section failed\n");
		free(ans);
		return -1;
	}
	dp->answers = ans;
	return 0;
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
		if (dns_query(dp, &pp)) {
			ERR("dns_query failed\n");
			goto err;
		}
		break;
	case DNS_QR_REPLY:
		if (dns_reply(dp, &pp)) {
			ERR("dns_reply failed\n");
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
	int i;
	if (!dp)
		return;
	free(dp->quests);

	if (dp->hdr && dp->answers) {
		for (i = 0; i < dp->hdr->an_count; i++) {
			switch (dp->answers[i].qtype) {
			case DNS_TYPE_NULL:
			case DNS_TYPE_TXT:
				free(dp->answers[i].data);
				break;
			default:
				break;
			}
		}
	}
	free(dp->answers);
	free(dp->hdr);
}

