# Add netlink to /etc/modules in order to load the module on boot
obj-m += netlink.o
netlink-objs := tpt-netlink.o
PWD := $(PWD)
all:
	sudo make -C ../ M=$(PWD) CFLAGS="-g3" modules
	sudo cp ./netlink.ko /lib/modules/4.19.42+/
clean:
	rm *.o *.ko *.mod.c *.symvers *.order

