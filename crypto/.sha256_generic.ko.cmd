cmd_crypto/sha256_generic.ko := /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-ld -r  -EL -T ./scripts/module-common.lds -T ./arch/arm/kernel/module.lds  --build-id  -o crypto/sha256_generic.ko crypto/sha256_generic.o crypto/sha256_generic.mod.o ;  true
