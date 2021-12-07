CC ?= gcc

CFLAGS ?= -I../xfe/headers/ -I../linux/tools/lib/
LFLAGS ?= -L../linux/tools/lib/bpf -lbpf

obj-m += simple_lookup_kern.o

lookup_only:
	$(CC) $(CFLAGS) simple_lookup.c -o simple_lookup $(LFLAGS)
kern:
	$(MAKE) -C ../linux/ M=$(CURDIR) modules
clean:
	rm -rf simple_lookup
	$(MAKE) -C ../linux/ M=$(CURDIR) clean
