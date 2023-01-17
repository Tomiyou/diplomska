CC ?= gcc
CLANG ?= clang

CFLAGS ?= -I../xfe/headers/ -I../linux/tools/lib/
LFLAGS ?= -L../linux/tools/lib/bpf -lbpf

forward:
	$(CLANG) -O2 -Wall $(CFLAGS) -g -target bpf -c forward.c -o forward.o
lookup:
	$(CC) $(CFLAGS) simple_lookup.c -o simple_lookup $(LFLAGS)
clean:
	rm simple_lookup
