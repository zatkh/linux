# Add netlink to /etc/modules in order to load the module on boot
KDIR := /lib/modules/4.19.42+/build


obj-m += tpt_module.o 

tpt_module-objs+= door.o netlinktest.o


EXTCFLAGS = -Wall -Wextra -g


all:
	#$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc $(EXTCFLAGS) test_send.c -o send
	gcc $(EXTCFLAGS) test_recv.c -o recv
	gcc $(EXTCFLAGS) test_send_recv.c -o send_recv


	#sudo cp ./netlink.ko /lib/modules/4.19.42+/


clean:
	rm -rf *.o *.ko *.mod.* *.cmd .module* modules* Module* .*.cmd .tmp*
	rm send
	rm recv
	make -C $(KDIR) M=$(PWD) clean