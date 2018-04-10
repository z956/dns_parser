all:
	gcc -o dns dns.c main.c stats.c policy.c post_proc.c -lpcap --std=gnu11
