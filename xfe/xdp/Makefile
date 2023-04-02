CLANG ?= clang

all:
	$(CLANG) -O2 -Wall -g -target bpf -c xdp_pospesevalnik.c -o xdp_pospesevalnik.o -I../../linux/tools/lib/

clean:
	rm -rf xdp_pospesevalnik.ll xdp_pospesevalnik.o
