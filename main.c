#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>

#include "dns.h"
#include "common.h"

static void cb_pkt(u_char *data, const struct pcap_pkthdr* hdr, const u_char* pkt);

int main(int argc, char **argv)
{
	pcap_t *descr;
	char err[PCAP_ERRBUF_SIZE];

	if (argc != 2) {
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

	DBG("parse pcap done\n");
	return 0;
}

static int is_dns(const u_char *pkt)
{
#define L4_OFFSET (sizeof(struct ether_header) + sizeof(struct ip))
	const struct ether_header *eh;
	const struct ip *iph;
	u_int src, dst;

	eh = (struct ether_header *)pkt;
	if (ntohs(eh->ether_type) != ETHERTYPE_IP)
		return 0;

	iph = (struct ip *)(pkt + sizeof(struct ether_header));
	if (iph->ip_p == IPPROTO_TCP) {
		const struct tcphdr *tcph = (const struct tcphdr *)(pkt + L4_OFFSET);
		src = ntohs(tcph->source);
		dst = ntohs(tcph->dest);
		if (src == 53 || dst == 53)
			return L4_OFFSET + sizeof(struct tcphdr);
	}
	else if (iph->ip_p == IPPROTO_UDP) {
		const struct udphdr *udph = (const struct udphdr *)(pkt + L4_OFFSET);
		src = ntohs(udph->source);
		dst = ntohs(udph->dest);
		if (src == 53 || dst == 53)
			return L4_OFFSET + sizeof(struct udphdr);
	}
	return 0;
#undef L4_OFFSET
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

	dns_del(dp);
}

