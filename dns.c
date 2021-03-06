#include "dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <ctype.h>

//#define _DNS_PARSER_DBG_
#include "common.h"

struct pkt_proc {
	const u_char *pkt;
	int offset;
	unsigned int len;
};

static int dns_header_valid(struct dns_header *dh)
{
	uint16_t id = ntohs(dh->id);
	int flag_code = ntohs(dh->flag_code);

	int qr = DNS_FLAG_QR(flag_code);
	int opcode = DNS_FLAG_OPCODE(flag_code);

	switch (qr) {
	case DNS_QR_QUERY:
	case DNS_QR_REPLY:
		break;
	default:
		ERR("Invalid qr, id: 0x%04x, qr: %d\n", id, qr);
		return 0;
	}

	switch (opcode) {
	case DNS_OPCODE_QUERY:
		break;
	default:
		ERR("Not expect opcode, id: 0x%04x, op: %d\n", id, opcode);
		return 0;
	}
	return 1;
}
static struct dns_header *dns_header_alloc(struct pkt_proc *pp)
{
	struct dns_header *h, *dh;

	if (pp->offset + sizeof(struct dns_header) > pp->len) {
		ERR("Invalid parameter\n");
		return NULL;
	}

	h = (struct dns_header *)(pp->pkt + pp->offset);
	if (!dns_header_valid(h)) {
		ERR("Not expected header\n");
		return NULL;
	}

	dh = calloc(1, sizeof(struct dns_header));
	if (!dh) {
		ERR("Cannot alloc for dns header\n");
		return NULL;
	}

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
static int parse_domain_name(struct pkt_proc *pp, struct domain_name *name)
{
	const u_char *p = pp->pkt + pp->offset;
	const u_char *tail = pp->pkt + pp->len;

	int total_len = 0;
	int label_len = 0;
	int in_ptr = 0;

	DBG("offset: %d, len: %u\n", pp->offset, pp->len);
	while (p < tail && total_len < MAX_DOMAIN_LEN) {
		if (!in_ptr)
			pp->offset++;

		if (label_len) {
			name->name[total_len++] = *p;
			p++;
			label_len--;
		}
		else if (*p == 0xc0) {
			//ptr
			const u_char *cur = p;
			int offset = (*p) & 0x3F;
			p++;
			if (p >= tail || !*p) {
				ERR("p >= tail: %d, *p: %d\n", p >= tail, *p);
				break;
			}
			offset = offset * 16 + *p;
			if (offset >= pp->len) {
				ERR("offset(%d) >= pp->len(%u)\n", offset, pp->len);
				break;
			}

			if (offset >= (p - pp->pkt - 1)) {
				ERR("offset(%d) >= p - pp->pkt - 1(%ld)\n", offset, p - pp->pkt - 1);
				break;
			}
			if (!in_ptr)
				pp->offset += 1;
			p = pp->pkt + offset;
			label_len = 0;
			in_ptr = 1;
		}
		else {
			if (*p == 0)
				break;
			name->name[total_len++] = *p;
			label_len = *p;
			p++;
		}
	}
	if (*p || p == tail) {
		ERR("*p: 0x%02x, p == tail? %d\n", *p, p == tail);
		return -1;
	}
	name->name[total_len] = 0;
	name->len = total_len;

	DBG("offset: %d, len: %d, name: %s\n", pp->offset, name->len, name->name);
	return total_len;
}
static int parse_quest_section(struct pkt_proc *pp,
				int qd_count, struct dns_quest *dq)
{
	for (int i = 0; i < qd_count; i++) {
		if (parse_domain_name(pp, &dq[i].base.qname) < 0) {
			ERR("parse_domain_name %d failed\n", i);
			return -1;
		}

		//parse type and class
		if (pp->offset + sizeof(uint16_t) * 2 > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}
		dq[i].base.qtype = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		dq[i].base.qclass = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);
	}
	return 0;
}
static int dns_query(struct dns_pkt *dp, struct pkt_proc *pp)
{
	const struct dns_header *hdr = dp->hdr;

	DBG("start!\n");
	if (hdr->qd_count == 0) {
		ERR("request(0x%04x) does not have question section\n", hdr->id);
		return -1;
	}

	struct dns_quest *dq = calloc(hdr->qd_count, sizeof(struct dns_quest));
	if (!dq) {
		ERR("Cannot allocate for dns quest\n");
		return -1;
	}

	if (parse_quest_section(pp, hdr->qd_count, dq)) {
		ERR("parse_quest_section(0x%04x) failed\n", hdr->id);
		free(dq);
		return -1;
	}

	dp->quests = dq;
	return 0;
}
static int parse_answer_section(struct pkt_proc *pp,
				int ans_count, struct dns_answer *ans)
{
	for (int i = 0; i < ans_count; i++) {
		if (parse_domain_name(pp, &ans[i].base.qname) < 0) {
			ERR("parse_domain_name %d failed\n", i);
			return -1;
		}

		if (pp->offset + sizeof(uint16_t) * 3 + sizeof(uint32_t) > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}

		ans[i].base.qtype = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		ans[i].base.qclass = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		ans[i].ttl = ntohl(*(uint32_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint32_t);

		ans[i].rd_len = ntohs(*(uint16_t *)(pp->pkt + pp->offset));
		pp->offset += sizeof(uint16_t);

		DBG("type: %d, class: %d, ttl: %d, rd_len: %d\n",
			ans[i].base.qtype, ans[i].base.qclass,
			ans[i].ttl, ans[i].rd_len);
		if (pp->offset + ans[i].rd_len > pp->len) {
			ERR("Invalid pkt\n");
			return -1;
		}

		switch (ans[i].base.qtype) {
		case DNS_TYPE_A:
			ans[i].addr[0] = ntohl(*(uint32_t *)(pp->pkt + pp->offset));
			pp->offset += sizeof(uint32_t);
			break;
//		case DNS_TYPE_NS:
//			break;
		case DNS_TYPE_CNAME:
			if (parse_domain_name(pp, &ans[i].content_name) < 0) {
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
		case DNS_TYPE_MX:
			//ignore preference
			if (pp->offset + sizeof(uint16_t) > pp->len) {
				ERR("Invalid packet\n");
				return -1;
			}
			pp->offset += sizeof(uint16_t);
			if (parse_domain_name(pp, &ans[i].content_name) < 0) {
				ERR("parse_domain_name mx failed\n");
				return -1;
			}
			break;
		case DNS_TYPE_TXT:
			ans[i].data = malloc(ans[i].rd_len + 1);
			memcpy(ans[i].data, pp->pkt + pp->offset, ans[i].rd_len);
			ans[i].data[ans[i].rd_len] = 0;
			pp->offset += ans[i].rd_len;
			break;
		case DNS_TYPE_AAAA:
			for (int j = 0; j < 4; j++) {
				ans[i].addr[j] = ntohl(*(uint32_t *)(pp->pkt + pp->offset));
				pp->offset += sizeof(uint32_t);
			}
			break;
		default:
			ERR("unknown type(%d)\n", ans[i].base.qtype);
			return -1;
		}
	}
	return 0;
}
static int dns_reply(struct dns_pkt *dp, struct pkt_proc *pp)
{
	struct dns_header *hdr;
	struct dns_answer *ans;

	DBG("start!\n");
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
		ERR("parse_answer_section(0x%04x) failed\n", hdr->id);
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

	INIT_LIST_HEAD(&dp->list);
	dp->len = len;

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
	if (!dp)
		return;
	free(dp->quests);

	if (dp->hdr && dp->answers) {
		for (int i = 0; i < dp->hdr->an_count; i++) {
			switch (dp->answers[i].base.qtype) {
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
void convert_domain_name(const struct domain_name *dn, unsigned char *name)
{
	memset(name, 0, MAX_DOMAIN_LEN);
	memcpy(name, dn->name, dn->len);
	int offset = 0;
	while (offset < dn->len) {
		int label_len = name[offset];
		if (label_len == 0)
			break;
		name[offset] = '.';
		offset += label_len + 1;
	}
}
void printable_domain_name(const struct domain_name *dn, unsigned char *name)
{
	memset(name, 0, MAX_DOMAIN_LEN);
	for (int i = 0; i < dn->len; i++) {
		if (isprint(dn->name[i]))
			name[i] = dn->name[i];
		else
			name[i] = '.';
	}
}

