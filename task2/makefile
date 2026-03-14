CC      = gcc
CFLAGS  = -Wall -Wextra -Werror -pedantic -O2 -std=c11
LDPCAP  = -lpcap

all: syn_flood syn_detect POD_detect 

syn_flood: syn_flood.c
	$(CC) $(CFLAGS) -o $@ $<

syn_detect: syn_detect.c
	$(CC) $(CFLAGS) -o $@ $< $(LDPCAP)

POD_detect: POD_detect.c
	$(CC) $(CFLAGS) -o $@ $< $(LDPCAP)

clean:
	rm -f syn_flood syn_detect pod_detect

.PHONY: all clean
