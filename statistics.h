#ifndef __STATISTICS_H__
#define __STATISTICS_H__

struct statistics {
	unsigned int total;
	unsigned int max;
	unsigned int min;
};

void init_statistics(struct statistics *s);
void update_statistics(struct statistics *s, unsigned int v);
void print_statistics(const char *tag, struct statistics *s, int n);

#endif

