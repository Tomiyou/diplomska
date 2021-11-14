LLC ?= llc
CLANG ?= clang
CC ?= gcc

BPF_CFLAGS ?= -I../headers/ -I ../../linux/tools/lib/

all:
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o xfe_accelerator.ll xfe_accelerator.c
	llc -march=bpf -filetype=obj -o xfe_accelerator.o xfe_accelerator.ll
clean:
	rm -rf xfe_accelerator.ll xfe_accelerator.o
