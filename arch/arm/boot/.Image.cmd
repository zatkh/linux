cmd_arch/arm/boot/Image := /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-objcopy -O binary -R .comment -S  vmlinux arch/arm/boot/Image
