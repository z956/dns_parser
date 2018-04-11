all:
	gcc -o dns dns.c main.c stats.c policy.c post_proc.c pfi.c -lpcap --std=gnu11
