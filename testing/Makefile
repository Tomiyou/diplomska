CC ?= gcc

CFLAGS ?= -I../xfe/headers/ -I../linux/tools/lib/
LFLAGS ?= -L../linux/tools/lib/bpf -lbpf

lookup_only:
	$(CC) $(CFLAGS) simple_lookup.c -o simple_lookup $(LFLAGS)
clean:
	rm simple_lookup
