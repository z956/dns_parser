#ifndef __STATS_H__
#define __STATS_H__

struct stats {
	const char *tag;
	unsigned int total;
	unsigned int max;
	unsigned int min;
	int count;
};

void init_stats(const char *tag, struct stats *s);
void update_stats(struct stats *s, unsigned int v);
void print_stats(struct stats *s);

#endif

