CC ?= gcc
CFLAGS ?= -I../../linux/tools/lib/
LDFLAGS ?= -L../../linux/tools/lib/bpf

all:
	$(CC) -c -o xfe_ctl.o xfe_ctl.c -I../headers/ $(CFLAGS)
	$(CC) -o xfe_ctl xfe_ctl.o -lbpf $(LDFLAGS)

clean:
	rm -rf xfe_ctl *.o
