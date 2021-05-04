cmd_vmlinux := /bin/bash scripts/link-vmlinux.sh /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-ld  -EL -p --no-undefined -X --pic-veneer  --build-id ;  true
