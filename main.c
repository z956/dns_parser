#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

#define _DNS_PARSER_DBG_
#include "dns.h"
#include "common.h"
#include "post_proc.h"
#include "list.h"

static LIST_HEAD(query_head);
static LIST_HEAD(reply_head);

static void del_list(void)
{
	struct dns_pkt *dp;
	while (!list_empty(&query_head)) {
		dp = list_first_entry(&query_head, struct dns_pkt, list);
		list_del(&dp->list);
		dns_del(dp);
	}

	while (!list_empty(&reply_head)) {
		dp = list_first_entry(&reply_head, struct dns_pkt, list);
		list_del(&dp->list);
		dns_del(dp);
	}
}

static void cb_pkt(u_char *data, const struct pcap_pkthdr* hdr, const u_char* pkt);

int main(int argc, char **argv)
{
	pcap_t *descr;
	char err[PCAP_ERRBUF_SIZE];

	if (argc < 2) {
		ERR("Need a file to read\n");
		return -1;
	}
	descr = pcap_open_offline(argv[1], err);
	if (!descr) {
		ERR("open pcap file %s failed: %s\n", argv[1], err);
		return -1;
	}

	if (pcap_loop(descr, 0, cb_pkt, NULL) < 0) {
		ERR("packet_loop failed: %s\n", err);
		return -1;
	}

	DBG("ready to check tunnel\n");
	post_proc_req(&query_head);

	del_list();
	DBG("parse pcap done\n");
	return 0;
}

static int is_dns(const u_char *pkt)
{
	const struct ether_header *eh;
	const struct ip *iph;
	int l2_offset, l4_offset;
	u_int src, dst;

	eh = (struct ether_header *)pkt;
	if (ntohs(eh->ether_type) == ETHERTYPE_IP)
		l2_offset = sizeof(struct ether_header);
	else {
		int v = ntohs(*(uint16_t *)(pkt + 14));
		l2_offset = 16;
		if (v != 0x0800)
			return 0;
	}
	l4_offset = sizeof(struct ip) + l2_offset;

	iph = (struct ip *)(pkt + l2_offset);
	if (iph->ip_p == IPPROTO_TCP) {
		const struct tcphdr *tcph = (const struct tcphdr *)(pkt + l4_offset);
		src = ntohs(tcph->source);
		dst = ntohs(tcph->dest);
		if (src == 53 || dst == 53)
			return l4_offset + sizeof(struct tcphdr);
	}
	else if (iph->ip_p == IPPROTO_UDP) {
		const struct udphdr *udph = (const struct udphdr *)(pkt + l4_offset);
		src = ntohs(udph->source);
		dst = ntohs(udph->dest);
		if (src == 53 || dst == 53)
			return l4_offset + sizeof(struct udphdr);
	}

	return 0;
}

static void cb_pkt(u_char *data, const struct pcap_pkthdr* hdr, const u_char* pkt)
{
	struct dns_pkt *dp;
	int offset;
	unsigned int dns_len;
	if (!(offset = is_dns(pkt)))
		return;
	dns_len = hdr->caplen - offset;
	dp = dns_alloc(pkt + offset, dns_len);
	if (!dp) {
		ERR("parse_dns failed\n");
		return;
	}

	switch (dns_qr(dp->hdr)) {
	case DNS_QR_QUERY:
		list_add_tail(&dp->list, &query_head);
		break;
	case DNS_QR_REPLY:
		list_add_tail(&dp->list, &reply_head);
		break;
	default:
		break;
	}
}

