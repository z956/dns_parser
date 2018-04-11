#ifndef __PER_FILE_INFO_H__
#define __PER_FILE_INFO_H__

#include "stats.h"
#include "policy.h"

//struct per_pkt_info {
struct ppi {
	struct stats *sts[POLICY_MAX];
	struct policies *ps;
};
//struct per_file_info {
struct pfi {
	char *file_name;
	int pkt_count;
	struct ppi ppi;
};

struct pfi *pfi_alloc(const char *name);
void pfi_del(struct pfi *pfi);

void reset_ppi(struct ppi *ppi);

#endif

