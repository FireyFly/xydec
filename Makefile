
CC=clang

.PHONY: all
all: xydec

.PHONY: clean
clean:
	rm *.o xydec

xydec: hexdump.o pcap.o pkx.o protocols.o xydec.o
	$(CC) -o $@ $^
