obj-m += xfe_main.o
ccflags-y += -I$(obj)/../headers/

all:
	$(MAKE) -C ../../linux/ M=$(CURDIR) modules
clean:
	$(MAKE) -C ../../linux/ M=$(CURDIR) clean
