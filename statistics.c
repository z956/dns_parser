#include "statistics.h"

#include <limits.h>

#include "common.h"

void init_statistics(struct statistics *s)
{
	s->total = 0;
	s->max = 0;
	s->min = INT_MAX;
}
void update_statistics(struct statistics *s, unsigned int v)
{
	s->total += v;
	if (v > s->max)
		s->max = v;
	if (v < s->min)
		s->min = v;
}
void print_statistics(const char *tag, struct statistics *s, int n)
{
	PRT("\n%s:\n"
		"\tTotal: %u\n"
		"\tAvg: %lf\n"
		"\tMax: %u\n"
		"\tMin: %u\n",
		tag, s->total, ((double)s->total) / n,
		s->max, s->min);
}

