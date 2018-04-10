all:
	gcc -o dns dns.c main.c statistics.c -lpcap
