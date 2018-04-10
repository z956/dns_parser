#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#define _DNS_PARSER_DBG_
#include "dns.h"
#include "common.h"
#include "list.h"

static LIST_HEAD(query_head);
static LIST_HEAD(reply_head);

static LIST_HEAD(non_tunnel_head);
static LIST_HEAD(tunnel_head);

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

	while (!list_empty(&non_tunnel_head)) {
		dp = list_first_entry(&non_tunnel_head, struct dns_pkt, list);
		list_del(&dp->list);
		dns_del(dp);
	}
	while (!list_empty(&tunnel_head)) {
		dp = list_first_entry(&tunnel_head, struct dns_pkt, list);
		list_del(&dp->list);
		dns_del(dp);
	}
}

static void cb_pkt(u_char *data, const struct pcap_pkthdr* hdr, const u_char* pkt);
static unsigned int get_unique_char(const unsigned char *str, int len)
{
	unsigned char charset[256];
	int i;
	unsigned int r = 0;

	memset(charset, 0, 256);
	for (i = 0; i < len; i++) {
		charset[str[i]]++;
	}

	for (i = 0; i < 256; i++) {
		r += !!charset[i];
	}
	return r;
}
static unsigned int get_longest_repeat(const unsigned char *str, int len)
{
	int i;
	unsigned int max_len = 0;
	unsigned int non_vowel_len = 0;
	for (i = 0; i < len; i++) {
		switch (str[i]) {
		case 'a':
		case 'e':
		case 'i':
		case 'o':
		case 'u':
		case 'A':
		case 'E':
		case 'I':
		case 'O':
		case 'U':
		case '.':
		case '-':
			if (non_vowel_len > max_len)
				max_len = non_vowel_len;
			non_vowel_len = 0;
			break;
		default:
			non_vowel_len++;
			break;
		}
	}
	return max_len;
}

struct statistic {
	unsigned int total;
	unsigned int max;
	unsigned int min;
};
void init_statistic(struct statistic *s)
{
	s->total = 0;
	s->max = 0;
	s->min = INT_MAX;
}
void update_statistic(struct statistic *s, unsigned int v)
{
	s->total += v;
	if (v > s->max)
		s->max = v;
	if (v < s->min)
		s->min = v;
}
static void print_statistic(const char *tag, struct statistic *s, int n)
{
	PRT("\n%s:\n"
		"\tTotal: %u\n"
		"\tAvg: %lf\n"
		"\tMax: %u\n"
		"\tMin: %u\n",
		tag, s->total, ((double)s->total) / n,
		s->max, s->min);
}
static void check_query(void)
{
	struct dns_pkt *dp, *tmp;

	struct statistic query_name_len, query_unique_char, query_longest_repeat;

	init_statistic(&query_name_len);
	init_statistic(&query_unique_char);
	init_statistic(&query_longest_repeat);
	unsigned int qd_count = 0;
	list_for_each_entry_safe (dp, tmp, &query_head, list) {
		int i;
		for (i = 0; i < dp->hdr->qd_count; i++) {
			struct domain_name *name = &dp->quests[i].name;
			unsigned int domain_len = name->len;
			unsigned int unique_len = get_unique_char(name->name, name->len);
			unsigned int longest_len = get_longest_repeat(name->name, name->len);

			if (longest_len < 15 && domain_len < 70) {
				list_del_init(&dp->list);
				list_add(&dp->list, &non_tunnel_head);
			}
			else {
				list_del_init(&dp->list);
				list_add(&dp->list, &tunnel_head);
			}

			update_statistic(&query_name_len, domain_len);
			update_statistic(&query_unique_char, unique_len);
			update_statistic(&query_longest_repeat, longest_len);
			qd_count++;
		}
	}

	PRT("Total question: %u\n", qd_count);
	print_statistic("Query domain name len", &query_name_len, qd_count);
	print_statistic("Query unique char len", &query_unique_char, qd_count);
	print_statistic("Query longest repeat len", &query_longest_repeat, qd_count);
}
static void print_tunnel_pkt(struct list_head *head)
{
	struct dns_pkt *dp;
	unsigned int count = 0;
	struct statistic name_len, unique_char, longest_repeat;
	init_statistic(&name_len);
	init_statistic(&unique_char);
	init_statistic(&longest_repeat);

	list_for_each_entry(dp, head, list) {
		int i;
		for (i = 0; i < dp->hdr->qd_count; i++) {
			struct domain_name *name = &dp->quests[i].name;
			unsigned int domain_len = name->len;
			unsigned int unique_len = get_unique_char(name->name, name->len);
			unsigned int longest_len = get_longest_repeat(name->name, name->len);

			update_statistic(&name_len, domain_len);
			update_statistic(&unique_char, unique_len);
			update_statistic(&longest_repeat, longest_len);

			PRT("id: 0x%04x, type: %d, name: %s\n",
			dp->hdr->id, dp->quests[i].qtype, dp->quests[i].name.name);
			count++;
		}
	}
	if (count) {
		PRT("Total packet: %u\n", count);
		print_statistic("Domain name len", &name_len, count);
		print_statistic("Unique char len", &unique_char, count);
		print_statistic("Longest repeat len", &longest_repeat, count);
	}
}

int main(int argc, char **argv)
{
	pcap_t *descr;
	char err[PCAP_ERRBUF_SIZE];
	int print_tunnel = 1, print_non_tunnel = 1;

	if (argc < 2) {
		ERR("Need a file to read\n");
		return -1;
	}
	if (argc > 2) {
		if (strcmp(argv[2], "-t") == 0) {
			print_tunnel = 1;
			print_non_tunnel = 0;
		}
		else if (strcmp(argv[2], "-n") == 0) {
			print_tunnel = 0;
			print_non_tunnel = 1;
		}
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
	check_query();
	if (print_tunnel) {
		PRT("*** print tunnel pkt start\n");
		print_tunnel_pkt(&tunnel_head);
		PRT("*** print tunnel pkt end\n");
	}
	if (print_non_tunnel) {
		PRT("*** print non-tunnel pkt start\n");
		print_tunnel_pkt(&non_tunnel_head);
		PRT("*** print non-tunnel pkt end\n");
	}

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
		list_add(&dp->list, &query_head);
		break;
	case DNS_QR_REPLY:
		list_add(&dp->list, &reply_head);
		break;
	default:
		break;
	}
}

