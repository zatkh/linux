cmd_drivers/rtc/built-in.a := rm -f drivers/rtc/built-in.a; /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-ar rcSTPD drivers/rtc/built-in.a drivers/rtc/rtc-lib.o drivers/rtc/hctosys.o drivers/rtc/systohc.o drivers/rtc/class.o drivers/rtc/interface.o drivers/rtc/nvmem.o drivers/rtc/rtc-dev.o drivers/rtc/rtc-proc.o drivers/rtc/rtc-sysfs.o drivers/rtc/rtc-pl031.o
