obj-m += xfe_main.o

CURRENT_DIR = $(shell pwd)

all:
	make -C ../../linux/ M=$(CURRENT_DIR) modules
clean:
	make -C ../../linux/ M=$(CURRENT_DIR) clean
