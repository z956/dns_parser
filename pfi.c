#include "pfi.h"

#include <string.h>
#include <stdlib.h>

static void init_ppi(struct ppi *ppi)
{
	ppi->ps = get_policies();
	for (int i = 0; i < POLICY_MAX; i++) {
		struct policy *p = ppi->ps[i].p;
		int size = ppi->ps[i].size;
		ppi->sts[i] = malloc(sizeof(struct stats) * size);
		for (int j = 0; j < size; j++)
			init_stats(p->name, &ppi->sts[i][j]);
	}
}
static void deinit_ppi(struct ppi *ppi)
{
	ppi->ps = NULL;
	for (int i = 0; i < POLICY_MAX; i++) {
		free(ppi->sts[i]);
		ppi->sts[i] = NULL;
	}
}

struct pfi *pfi_alloc(const char *name)
{
	struct pfi *pfi = calloc(1, sizeof(struct pfi));
	if (pfi) {
		pfi->file_name = strdup(name);
		init_ppi(&pfi->ppi);
	}
	return pfi;
}
void pfi_del(struct pfi *pfi)
{
	if (pfi) {
		free(pfi->file_name);
		deinit_ppi(&pfi->ppi);
	}
	free(pfi);
}

void reset_ppi(struct ppi *ppi) {
	for (int i = 0; i < POLICY_MAX; i++) {
		int size = ppi->ps[i].size;
		for (int j = 0; j < size; j++)
			reset_stats(&ppi->sts[i][j]);
	}
}


