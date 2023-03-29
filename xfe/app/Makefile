include ../Makefile.variable

CFLAGS := -I$(XFE_HEADERS_DIR) -I$(BPF_HEADERS_DIR)
LFLAGS := -L$(LIBBPF_LINK_DIR) -lbpf

all:
	$(CC) $(CFLAGS) xfe_ctl.c -o xfe_ctl $(LFLAGS)
clean:
	rm -rf xfe_ctl
