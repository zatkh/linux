cmd_drivers/video/backlight/lcd.ko := /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-ld -r  -EL -T ./scripts/module-common.lds -T ./arch/arm/kernel/module.lds  --build-id  -o drivers/video/backlight/lcd.ko drivers/video/backlight/lcd.o drivers/video/backlight/lcd.mod.o ;  true
