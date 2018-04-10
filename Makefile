all:
	gcc -o dns dns.c main.c stats.c policy.c -lpcap --std=gnu11
