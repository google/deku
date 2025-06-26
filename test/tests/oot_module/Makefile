obj-m += test_module.o
test_module-objs := module.o module_helper.o

all:
	make -C $(KERNEL_DIR) M=/tmp/deku_test_oot_module modules
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C $(KERNEL_DIR) M=/tmp/deku_test_oot_module clean
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean