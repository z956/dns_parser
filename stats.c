#include "stats.h"

#include <limits.h>

#include "common.h"

void init_stats(const char *tag, struct stats *s)
{
	s->tag = tag;
	reset_stats(s);
}
void reset_stats(struct stats *s)
{
	s->total = 0;
	s->max = 0;
	s->min = INT_MAX;
	s->count = 0;
}
void update_stats(struct stats *s, unsigned int v)
{
	s->total += v;
	if (v > s->max)
		s->max = v;
	if (v < s->min)
		s->min = v;
	s->count++;
}
void print_stats(struct stats *s)
{
	PRT("\n%s:\n"
		"\tTotal: %u\n"
		"\tCount: %d\n"
		"\tAvg: %lf\n"
		"\tMax: %u\n"
		"\tMin: %u\n",
		s->tag, s->total, s->count,
		((double)s->total) / s->count,
		s->max, s->min);
}

