CC ?= gcc

CFLAGS ?= -I../headers/ -I../../linux/tools/lib/
LFLAGS ?= -L../../linux/tools/lib/bpf -lbpf

all:
	$(CC) $(CFLAGS) xfe_ctl.c -o xfe_ctl $(LFLAGS)
clean:
	rm -rf xfe_ctl
