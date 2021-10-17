obj-m += xfe_main.o

CURRENT_DIR = $(shell pwd)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURRENT_DIR) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURRENT_DIR) clean