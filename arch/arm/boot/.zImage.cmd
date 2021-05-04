cmd_arch/arm/boot/zImage := /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-objcopy -O binary -R .comment -S  arch/arm/boot/compressed/vmlinux arch/arm/boot/zImage
