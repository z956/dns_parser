#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

#define _DNS_PARSER_DBG_
#include "dns.h"
#include "common.h"
#include "post_proc.h"
#include "list.h"

static LIST_HEAD(query_head);
static LIST_HEAD(reply_head);

static int is_single_file;
static char *file_name;

static int parse_opt(int argc, char **argv);
static int parse_pkt(const char *pcap);
static int is_dns(const u_char *pkt);
static void cb_pkt(u_char *data, const struct pcap_pkthdr* hdr, const u_char* pkt);
static void del_list(void);

int main(int argc, char **argv)
{

	if (parse_opt(argc, argv))
		return -1;

	if (is_single_file) {
		PRT("single file name: %s\n", file_name);
		if (parse_pkt(file_name))
			return -1;
	}
	else {
		//for each file in file list, run parse_pkt
		char *line = NULL;
		size_t len = 0;
		ssize_t read;
		FILE *fp = fopen(file_name, "r");
		if (!fp) {
			ERR("Open file %s failed\n", file_name);
			return -1;
		}

		while ((read = getline(&line, &len, fp)) != -1) {
			if (line[read - 1] == '\n')
				line[read - 1] = 0;
			if (parse_pkt(line)) {
				fclose(fp);
				return -1;
			}
		}
		fclose(fp);
	}

	DBG("ready to check tunnel\n");
	post_proc_req(&query_head);
	post_proc_rep(&reply_head);

	del_list();
	DBG("parse pcap done\n");
	return 0;
}

int parse_opt(int argc, char **argv)
{
	struct option opts[] = {
		{ "single", 0, 0, 's' },
		{ 0, 0, 0, 0 },
	};

	int idx, res;
	while ((res = getopt_long(argc, argv, "s", opts, &idx)) != -1) {
		switch (res) {
		case 's':
			is_single_file = 1;
			break;
		default:
			return -1;
		}
	}
	if (optind < argc)
		file_name = strdup(argv[optind]);
	else
		return -1;
	return 0;
}
int parse_pkt(const char *pcap)
{
	char err[PCAP_ERRBUF_SIZE];
	char *name;
	int r = 0;
	pcap_t *descr = pcap_open_offline(pcap, err);
	if (!descr) {
		ERR("open pcap file %s failed: %s\n", pcap, err);
		return -1;
	}

	name = strdup(pcap);
	if (pcap_loop(descr, 0, cb_pkt, name) < 0) {
		ERR("packet_loop failed on file %s: %s\n", name, err);
		r = -1;
	}

	free(name);
	return r;
}
int is_dns(const u_char *pkt)
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
void cb_pkt(u_char *data, const struct pcap_pkthdr* hdr, const u_char* pkt)
{
	struct dns_pkt *dp;
	int offset;
	unsigned int dns_len;
	if (!(offset = is_dns(pkt)))
		return;
	dns_len = hdr->caplen - offset;
	dp = dns_alloc(pkt + offset, dns_len);
	if (!dp) {
		ERR("parse_dns(%s) failed\n", data);
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
void del_list(void)
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

