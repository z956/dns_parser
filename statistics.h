#ifndef __STATISTICS_H__
#define __STATISTICS_H__

struct statistics {
	const char *tag;
	unsigned int total;
	unsigned int max;
	unsigned int min;
	int count;
};

void init_statistics(const char *tag, struct statistics *s);
void update_statistics(struct statistics *s, unsigned int v);
void print_statistics(struct statistics *s);

#endif

