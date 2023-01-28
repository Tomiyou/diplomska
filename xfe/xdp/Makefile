LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_CFLAGS ?= -I../headers/ -I../../linux/tools/lib/

all:
	$(CLANG) -O2 -Wall $(BPF_CFLAGS) -g -target bpf -c xdp_pospesevalnik.c -o xdp_pospesevalnik.o
generate:
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o xdp_pospesevalnik.ll xdp_pospesevalnik.c
	llc -march=bpf -filetype=obj -o xdp_pospesevalnik.o xdp_pospesevalnik.ll
clean:
	rm -rf xdp_pospesevalnik.ll xdp_pospesevalnik.o
