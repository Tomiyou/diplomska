obj-m := xfe.o
xfe-objs := ./xfe_kmod_main.o ./xfe_kmod_xdp.o

ccflags-y += -I$(obj)/../headers/

KERNEL_SRC ?= ../../linux/

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(CURDIR) clean
