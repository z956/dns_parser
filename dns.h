#ifndef __DNS_H__
#define __DNS_H__

#include <sys/types.h>
#include <stdint.h>

#include "list.h"

struct dns_header {
	/* query id */
	uint16_t id;

	/* flag and code */
	uint16_t flag_code;

	/* question count */
	uint16_t qd_count;

	/* answer count */
	uint16_t an_count;

	/* authority record count */
	uint16_t ns_count;

	/* additional record count */
	uint16_t ar_count;
} __attribute__ ((packed));

#define MAX_DOMAIN_LEN (256)

/* DNS flag code */
#define DNS_FLAG_QR(flag)	((flag &0x8000) >> 15)
#define DNS_FLAG_OPCODE(flag)	((flag & 0x7800) >> 11)
#define DNS_FLAG_AA(flag)	((flag & 0x0400) >> 10)
#define DNS_FLAG_TC(flag)	((flag & 0x0200) >> 9)
#define DNS_FLAG_RD(flag)	((flag & 0x0100) >> 8)
#define DNS_FLAG_RA(flag)	((flag & 0x0080) >> 7)
#define DNS_FLAG_ZERO(flag)	((flag & 0x0070) >> 4) //TODO
#define DNS_FLAG_RCODE(flag)	((flag & 0x000F))

/* DNS qr value */
#define DNS_QR_QUERY	(0)
#define DNS_QR_REPLY	(1)

/* DNS opcode value */
#define DNS_OPCODE_QUERY	(0)
#define DNS_OPCODE_IQUERY	(1)
#define DNS_OPCODE_STATUS	(2)

/* DNS rcode value */
#define DNS_RCODE_NO_ERR	(0)
#define DNS_RCODE_FMT_ERR	(1)
#define DNS_RCODE_SERV_FAIL	(2)
#define DNS_RCODE_NAME_ERR	(3)
#define DNS_RCODE_NOT_IMP	(4)
#define DNS_RCODE_REFUSED	(5)

/* DNS type */
#define DNS_TYPE_A	(0x0001)
#define DNS_TYPE_NS	(0x0002)
#define DNS_TYPE_CNAME	(0x0005)
#define DNS_TYPE_NULL	(0x000A)
#define DNS_TYPE_MX	(0x000F)
#define DNS_TYPE_TXT	(0x0010)
#define DNS_TYPE_AAAA	(0x001C)

struct domain_name {
	int len;
	unsigned char name[MAX_DOMAIN_LEN];
};
struct dns_quest {
	struct domain_name name;
	uint16_t qtype;
	uint16_t qclass;
};

struct dns_answer {
	struct domain_name name;
	uint16_t qtype;
	uint16_t qclass;
	uint32_t ttl;
	uint16_t rd_len;
	union {
		uint32_t addr[4]; //A and AAAA
		struct domain_name content_name; //CNAME, NS, MX
		unsigned char *data; //NULL, TXT
	};
};

struct dns_pkt {
	struct list_head list;
	unsigned int len;
	struct dns_header *hdr;
	struct dns_quest *quests;
	struct dns_answer *answers;
};

struct dns_pkt *dns_alloc(const u_char *pkt, unsigned int len);
void dns_del(struct dns_pkt *dp);

static inline int dns_qr(const struct dns_header *hdr)
{
	return hdr? DNS_FLAG_QR(hdr->flag_code) : -1;
}
static inline int dns_opcode(const struct dns_header *hdr)
{
	return hdr? DNS_FLAG_OPCODE(hdr->flag_code) : -1;
}

#endif
