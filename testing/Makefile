CC ?= gcc

CFLAGSlmao ?= -I../xfe/headers/ -I../linux/tools/lib/
LFLAGSlmao ?= -L../linux/tools/lib/bpf -lbpf

obj-m += simple_lookup_kern.o

lookup_only:
	$(CC) $(CFLAGSlmao) simple_lookup.c -o simple_lookup $(LFLAGSlmao)
kern:
	$(MAKE) -C ../../linux/ M=$(CURDIR) modules
clean:
	rm -rf simple_lookup
	$(MAKE) -C ../../linux/ M=$(CURDIR) clean