obj-m := xfe.o
xfe-objs := ./xfe_kmod_main.o ./xfe_kmod_xdp.o

ccflags-y += -I$(obj)/../headers/

all:
	$(MAKE) -C ../../linux/ M=$(CURDIR) modules
clean:
	$(MAKE) -C ../../linux/ M=$(CURDIR) clean
