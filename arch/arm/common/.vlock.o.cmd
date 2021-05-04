cmd_arch/arm/common/vlock.o := /usr/bin/ccache /home/zt/optee/build/../toolchains/aarch32/bin/arm-linux-gnueabihf-gcc -Wp,-MD,arch/arm/common/.vlock.o.d  -nostdinc -isystem /home/zt/optee/toolchains/aarch32/bin/../lib/gcc/arm-linux-gnueabihf/8.2.1/include -I./arch/arm/include -I./arch/arm/include/generated  -I./include -I./arch/arm/include/uapi -I./arch/arm/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -D__KERNEL__ -mlittle-endian -D__ASSEMBLY__ -fno-PIE -DCC_HAVE_ASM_GOTO -mabi=aapcs-linux -mfpu=vfp -funwind-tables -marm -Wa,-mno-warn-deprecated -D__LINUX_ARM_ARCH__=7 -march=armv7-a -include asm/unified.h -msoft-float -Wa,-gdwarf-2 -march=armv7-a   -c -o arch/arm/common/vlock.o arch/arm/common/vlock.S

source_arch/arm/common/vlock.o := arch/arm/common/vlock.S

deps_arch/arm/common/vlock.o := \
  include/linux/kconfig.h \
    $(wildcard include/config/cpu/big/endian.h) \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \
  arch/arm/include/asm/unified.h \
    $(wildcard include/config/cpu/v7m.h) \
    $(wildcard include/config/thumb2/kernel.h) \
  include/linux/linkage.h \
  include/linux/compiler_types.h \
    $(wildcard include/config/have/arch/compiler/h.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/stringify.h \
  include/linux/export.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/module/rel/crcs.h) \
    $(wildcard include/config/have/arch/prel32/relocations.h) \
    $(wildcard include/config/trim/unused/ksyms.h) \
    $(wildcard include/config/unused/symbols.h) \
  arch/arm/include/asm/linkage.h \
  arch/arm/common/vlock.h \
  arch/arm/include/asm/mcpm.h \
    $(wildcard include/config/mcpm/quad/cluster.h) \
  arch/arm/include/asm/asm-offsets.h \
  include/generated/asm-offsets.h \

arch/arm/common/vlock.o: $(deps_arch/arm/common/vlock.o)

$(deps_arch/arm/common/vlock.o):
