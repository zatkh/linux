	.arch armv7-a
	.eabi_attribute 20, 1	@ Tag_ABI_FP_denormal
	.eabi_attribute 21, 1	@ Tag_ABI_FP_exceptions
	.eabi_attribute 23, 3	@ Tag_ABI_FP_number_model
	.eabi_attribute 24, 1	@ Tag_ABI_align8_needed
	.eabi_attribute 25, 1	@ Tag_ABI_align8_preserved
	.eabi_attribute 26, 2	@ Tag_ABI_enum_size
	.eabi_attribute 30, 2	@ Tag_ABI_optimization_goals
	.eabi_attribute 34, 1	@ Tag_CPU_unaligned_access
	.eabi_attribute 18, 2	@ Tag_ABI_PCS_wchar_t
	.file	"bounds.c"
@ GNU C89 (GNU Toolchain for the A-profile Architecture 8.2-2018-08 (arm-rel-8.23)) version 8.2.1 20180802 (arm-linux-gnueabihf)
@	compiled by GNU C version 4.8.1, GMP version 4.3.2, MPFR version 3.1.6, MPC version 0.8.2, isl version isl-0.15-1-g835ea3a-GMP

@ GGC heuristics: --param ggc-min-expand=100 --param ggc-min-heapsize=131072
@ options passed:  -nostdinc -I ./arch/arm/include
@ -I ./arch/arm/include/generated -I ./include -I ./arch/arm/include/uapi
@ -I ./arch/arm/include/generated/uapi -I ./include/uapi
@ -I ./include/generated/uapi
@ -iprefix /home/zt/optee/toolchains/aarch32/bin/../lib/gcc/arm-linux-gnueabihf/8.2.1/
@ -isysroot /home/zt/optee/toolchains/aarch32/bin/../arm-linux-gnueabihf/libc
@ -D __KERNEL__ -D CC_HAVE_ASM_GOTO -D __LINUX_ARM_ARCH__=7 -U arm
@ -D KBUILD_BASENAME="bounds" -D KBUILD_MODNAME="bounds"
@ -isystem /home/zt/optee/toolchains/aarch32/bin/../lib/gcc/arm-linux-gnueabihf/8.2.1/include
@ -include ./include/linux/kconfig.h
@ -include ./include/linux/compiler_types.h kernel/bounds.c -mlittle-endian
@ -mabi=aapcs-linux -mfpu=vfp -marm -mfloat-abi=soft -mtls-dialect=gnu
@ -march=armv7-a -auxbase-strip kernel/bounds.s -g -O2 -Wall -Wundef
@ -Wstrict-prototypes -Wno-trigraphs -Werror=implicit-function-declaration
@ -Wno-format-security -Wno-frame-address -Wformat-truncation=0
@ -Wformat-overflow=0 -Wno-int-in-bool-context -Wframe-larger-than=1024
@ -Wno-unused-but-set-variable -Wunused-const-variable=0
@ -Wdeclaration-after-statement -Wno-pointer-sign -Wno-stringop-truncation
@ -Werror=implicit-int -Werror=strict-prototypes -Werror=date-time
@ -Werror=incompatible-pointer-types -Werror=designated-init
@ -Wno-packed-not-aligned -std=gnu90 -fno-strict-aliasing -fno-common
@ -fshort-wchar -fno-PIE -fno-dwarf2-cfi-asm -fno-ipa-sra -funwind-tables
@ -fno-delete-null-pointer-checks -fstack-protector-strong
@ -fomit-frame-pointer -fno-var-tracking-assignments -fno-strict-overflow
@ -fno-merge-all-constants -fmerge-constants -fstack-check=no
@ -fconserve-stack -fmacro-prefix-map=./= -fverbose-asm
@ --param allow-store-data-races=0
@ options enabled:  -faggressive-loop-optimizations -falign-jumps
@ -falign-labels -falign-loops -fauto-inc-dec -fbranch-count-reg
@ -fcaller-saves -fchkp-check-incomplete-type -fchkp-check-read
@ -fchkp-check-write -fchkp-instrument-calls -fchkp-narrow-bounds
@ -fchkp-optimize -fchkp-store-bounds -fchkp-use-static-bounds
@ -fchkp-use-static-const-bounds -fchkp-use-wrappers -fcode-hoisting
@ -fcombine-stack-adjustments -fcompare-elim -fcprop-registers
@ -fcrossjumping -fcse-follow-jumps -fdefer-pop -fdevirtualize
@ -fdevirtualize-speculatively -fearly-inlining
@ -feliminate-unused-debug-types -fexpensive-optimizations
@ -fforward-propagate -ffp-int-builtin-inexact -ffunction-cse -fgcse
@ -fgcse-lm -fgnu-runtime -fgnu-unique -fguess-branch-probability
@ -fhoist-adjacent-loads -fident -fif-conversion -fif-conversion2
@ -findirect-inlining -finline -finline-atomics
@ -finline-functions-called-once -finline-small-functions -fipa-bit-cp
@ -fipa-cp -fipa-icf -fipa-icf-functions -fipa-icf-variables -fipa-profile
@ -fipa-pure-const -fipa-ra -fipa-reference -fipa-vrp -fira-hoist-pressure
@ -fira-share-save-slots -fira-share-spill-slots
@ -fisolate-erroneous-paths-dereference -fivopts -fkeep-static-consts
@ -fleading-underscore -flifetime-dse -flra-remat -flto-odr-type-merging
@ -fmath-errno -fmerge-constants -fmerge-debug-strings
@ -fmove-loop-invariants -fomit-frame-pointer -foptimize-sibling-calls
@ -foptimize-strlen -fpartial-inlining -fpeephole -fpeephole2 -fplt
@ -fprefetch-loop-arrays -freg-struct-return -freorder-blocks
@ -freorder-functions -frerun-cse-after-loop
@ -fsched-critical-path-heuristic -fsched-dep-count-heuristic
@ -fsched-group-heuristic -fsched-interblock -fsched-last-insn-heuristic
@ -fsched-pressure -fsched-rank-heuristic -fsched-spec
@ -fsched-spec-insn-heuristic -fsched-stalled-insns-dep -fschedule-insns
@ -fschedule-insns2 -fsection-anchors -fsemantic-interposition
@ -fshow-column -fshrink-wrap -fshrink-wrap-separate -fsigned-zeros
@ -fsplit-ivs-in-unroller -fsplit-wide-types -fssa-backprop -fssa-phiopt
@ -fstack-protector-strong -fstdarg-opt -fstore-merging
@ -fstrict-volatile-bitfields -fsync-libcalls -fthread-jumps
@ -ftoplevel-reorder -ftrapping-math -ftree-bit-ccp -ftree-builtin-call-dce
@ -ftree-ccp -ftree-ch -ftree-coalesce-vars -ftree-copy-prop -ftree-cselim
@ -ftree-dce -ftree-dominator-opts -ftree-dse -ftree-forwprop -ftree-fre
@ -ftree-loop-if-convert -ftree-loop-im -ftree-loop-ivcanon
@ -ftree-loop-optimize -ftree-parallelize-loops= -ftree-phiprop -ftree-pre
@ -ftree-pta -ftree-reassoc -ftree-scev-cprop -ftree-sink -ftree-slsr
@ -ftree-sra -ftree-switch-conversion -ftree-tail-merge -ftree-ter
@ -ftree-vrp -funit-at-a-time -funwind-tables -fvar-tracking -fverbose-asm
@ -fwrapv -fwrapv-pointer -fzero-initialized-in-bss -marm -mbe32 -mglibc
@ -mlittle-endian -mpic-data-is-text-relative -msched-prolog
@ -munaligned-access -mvectorize-with-neon-quad

	.text
.Ltext0:
	.syntax divided
	.syntax unified
	.arm
	.syntax unified
	.section	.text.startup,"ax",%progbits
	.align	2
	.global	main
	.syntax unified
	.arm
	.fpu softvfp
	.type	main, %function
main:
	.fnstart
.LFB291:
	.file 1 "kernel/bounds.c"
	.loc 1 17 1 view -0
	@ args = 0, pretend = 0, frame = 0
	@ frame_needed = 0, uses_anonymous_args = 0
	@ link register save eliminated.
	.loc 1 19 2 view .LVU1
	.syntax divided
@ 19 "kernel/bounds.c" 1
	
.ascii "->NR_PAGEFLAGS #21 __NR_PAGEFLAGS"	@
@ 0 "" 2
	.loc 1 20 2 view .LVU2
@ 20 "kernel/bounds.c" 1
	
.ascii "->MAX_NR_ZONES #2 __MAX_NR_ZONES"	@
@ 0 "" 2
	.loc 1 22 2 view .LVU3
@ 22 "kernel/bounds.c" 1
	
.ascii "->NR_CPUS_BITS #3 ilog2(CONFIG_NR_CPUS)"	@
@ 0 "" 2
	.loc 1 24 2 view .LVU4
@ 24 "kernel/bounds.c" 1
	
.ascii "->SPINLOCK_SIZE #4 sizeof(spinlock_t)"	@
@ 0 "" 2
	.loc 1 27 2 view .LVU5
@ kernel/bounds.c:28: }
	.loc 1 28 1 is_stmt 0 view .LVU6
	.arm
	.syntax unified
	mov	r0, #0	@,
	bx	lr	@
.LFE291:
	.fnend
	.size	main, .-main
	.section	.debug_frame,"",%progbits
.Lframe0:
	.4byte	.LECIE0-.LSCIE0
.LSCIE0:
	.4byte	0xffffffff
	.byte	0x3
	.ascii	"\000"
	.uleb128 0x1
	.sleb128 -4
	.uleb128 0xe
	.byte	0xc
	.uleb128 0xd
	.uleb128 0
	.align	2
.LECIE0:
.LSFDE0:
	.4byte	.LEFDE0-.LASFDE0
.LASFDE0:
	.4byte	.Lframe0
	.4byte	.LFB291
	.4byte	.LFE291-.LFB291
	.align	2
.LEFDE0:
	.text
.Letext0:
	.file 2 "./include/linux/types.h"
	.file 3 "./arch/arm/include/asm/barrier.h"
	.file 4 "./arch/arm/include/asm/hwcap.h"
	.file 5 "./include/linux/init.h"
	.file 6 "./include/linux/printk.h"
	.file 7 "./include/linux/kernel.h"
	.file 8 "./include/linux/page-flags.h"
	.file 9 "./include/linux/mmzone.h"
	.file 10 "./include/linux/lockdep.h"
	.section	.debug_info,"",%progbits
.Ldebug_info0:
	.4byte	0x4c9
	.2byte	0x4
	.4byte	.Ldebug_abbrev0
	.byte	0x4
	.uleb128 0x1
	.4byte	.LASF106
	.byte	0x1
	.4byte	.LASF107
	.4byte	.LASF108
	.4byte	.Ldebug_ranges0+0
	.4byte	0
	.4byte	.Ldebug_line0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	.LASF0
	.uleb128 0x2
	.byte	0x4
	.byte	0x7
	.4byte	.LASF1
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF2
	.uleb128 0x3
	.4byte	0x33
	.uleb128 0x2
	.byte	0x1
	.byte	0x6
	.4byte	.LASF3
	.uleb128 0x2
	.byte	0x1
	.byte	0x8
	.4byte	.LASF4
	.uleb128 0x2
	.byte	0x2
	.byte	0x5
	.4byte	.LASF5
	.uleb128 0x2
	.byte	0x2
	.byte	0x7
	.4byte	.LASF6
	.uleb128 0x4
	.byte	0x4
	.byte	0x5
	.ascii	"int\000"
	.uleb128 0x2
	.byte	0x8
	.byte	0x5
	.4byte	.LASF7
	.uleb128 0x2
	.byte	0x8
	.byte	0x7
	.4byte	.LASF8
	.uleb128 0x2
	.byte	0x4
	.byte	0x5
	.4byte	.LASF9
	.uleb128 0x5
	.byte	0x4
	.4byte	0x33
	.uleb128 0x6
	.4byte	.LASF11
	.byte	0x2
	.byte	0x1e
	.byte	0x11
	.4byte	0x89
	.uleb128 0x2
	.byte	0x1
	.byte	0x2
	.4byte	.LASF10
	.uleb128 0x7
	.byte	0x4
	.byte	0x2
	.byte	0xb0
	.byte	0x9
	.4byte	0xa7
	.uleb128 0x8
	.4byte	.LASF60
	.byte	0x2
	.byte	0xb1
	.byte	0x6
	.4byte	0x5b
	.byte	0
	.byte	0
	.uleb128 0x6
	.4byte	.LASF12
	.byte	0x2
	.byte	0xb2
	.byte	0x3
	.4byte	0x90
	.uleb128 0x9
	.uleb128 0xa
	.4byte	.LASF13
	.byte	0x3
	.byte	0x38
	.byte	0xf
	.4byte	0xc0
	.uleb128 0x5
	.byte	0x4
	.4byte	0xb3
	.uleb128 0xa
	.4byte	.LASF14
	.byte	0x4
	.byte	0xe
	.byte	0x15
	.4byte	0x2c
	.uleb128 0xa
	.4byte	.LASF15
	.byte	0x4
	.byte	0xe
	.byte	0x20
	.4byte	0x2c
	.uleb128 0x6
	.4byte	.LASF16
	.byte	0x5
	.byte	0x74
	.byte	0xf
	.4byte	0xea
	.uleb128 0x5
	.byte	0x4
	.4byte	0xf0
	.uleb128 0xb
	.4byte	0x5b
	.uleb128 0x6
	.4byte	.LASF17
	.byte	0x5
	.byte	0x7f
	.byte	0x14
	.4byte	0xde
	.uleb128 0xc
	.4byte	0xf5
	.4byte	0x10c
	.uleb128 0xd
	.byte	0
	.uleb128 0xa
	.4byte	.LASF18
	.byte	0x5
	.byte	0x87
	.byte	0x19
	.4byte	0x101
	.uleb128 0xa
	.4byte	.LASF19
	.byte	0x5
	.byte	0x87
	.byte	0x31
	.4byte	0x101
	.uleb128 0xa
	.4byte	.LASF20
	.byte	0x5
	.byte	0x88
	.byte	0x19
	.4byte	0x101
	.uleb128 0xa
	.4byte	.LASF21
	.byte	0x5
	.byte	0x88
	.byte	0x36
	.4byte	0x101
	.uleb128 0xc
	.4byte	0x33
	.4byte	0x147
	.uleb128 0xd
	.byte	0
	.uleb128 0xa
	.4byte	.LASF22
	.byte	0x5
	.byte	0x8f
	.byte	0x18
	.4byte	0x13c
	.uleb128 0xa
	.4byte	.LASF23
	.byte	0x5
	.byte	0x90
	.byte	0xe
	.4byte	0x77
	.uleb128 0xa
	.4byte	.LASF24
	.byte	0x5
	.byte	0x91
	.byte	0x15
	.4byte	0x2c
	.uleb128 0xa
	.4byte	.LASF25
	.byte	0x5
	.byte	0x9a
	.byte	0xd
	.4byte	0x7d
	.uleb128 0xa
	.4byte	.LASF26
	.byte	0x5
	.byte	0xa0
	.byte	0xf
	.4byte	0xc0
	.uleb128 0xa
	.4byte	.LASF27
	.byte	0x5
	.byte	0xa2
	.byte	0xd
	.4byte	0x7d
	.uleb128 0xc
	.4byte	0x3a
	.4byte	0x19a
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.4byte	0x18f
	.uleb128 0xa
	.4byte	.LASF28
	.byte	0x6
	.byte	0xb
	.byte	0x13
	.4byte	0x19a
	.uleb128 0xa
	.4byte	.LASF29
	.byte	0x6
	.byte	0xc
	.byte	0x13
	.4byte	0x19a
	.uleb128 0xc
	.4byte	0x5b
	.4byte	0x1c2
	.uleb128 0xd
	.byte	0
	.uleb128 0xa
	.4byte	.LASF30
	.byte	0x6
	.byte	0x3f
	.byte	0xc
	.4byte	0x1b7
	.uleb128 0xa
	.4byte	.LASF31
	.byte	0x6
	.byte	0x53
	.byte	0xd
	.4byte	0x13c
	.uleb128 0xa
	.4byte	.LASF32
	.byte	0x6
	.byte	0xc0
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xa
	.4byte	.LASF33
	.byte	0x6
	.byte	0xc1
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF34
	.byte	0x6
	.2byte	0x121
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xf
	.4byte	.LASF36
	.uleb128 0x3
	.4byte	0x1ff
	.uleb128 0xe
	.4byte	.LASF35
	.byte	0x6
	.2byte	0x1e1
	.byte	0x25
	.4byte	0x204
	.uleb128 0xf
	.4byte	.LASF37
	.uleb128 0xe
	.4byte	.LASF38
	.byte	0x7
	.2byte	0x144
	.byte	0x24
	.4byte	0x216
	.uleb128 0x10
	.4byte	0x70
	.4byte	0x237
	.uleb128 0x11
	.4byte	0x5b
	.byte	0
	.uleb128 0xe
	.4byte	.LASF39
	.byte	0x7
	.2byte	0x145
	.byte	0xf
	.4byte	0x244
	.uleb128 0x5
	.byte	0x4
	.4byte	0x228
	.uleb128 0xe
	.4byte	.LASF40
	.byte	0x7
	.2byte	0x210
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF41
	.byte	0x7
	.2byte	0x211
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF42
	.byte	0x7
	.2byte	0x212
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF43
	.byte	0x7
	.2byte	0x213
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF44
	.byte	0x7
	.2byte	0x214
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF45
	.byte	0x7
	.2byte	0x215
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF46
	.byte	0x7
	.2byte	0x216
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF47
	.byte	0x7
	.2byte	0x217
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF48
	.byte	0x7
	.2byte	0x219
	.byte	0xd
	.4byte	0x7d
	.uleb128 0xe
	.4byte	.LASF49
	.byte	0x7
	.2byte	0x220
	.byte	0x11
	.4byte	0xa7
	.uleb128 0xe
	.4byte	.LASF50
	.byte	0x7
	.2byte	0x234
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xe
	.4byte	.LASF51
	.byte	0x7
	.2byte	0x236
	.byte	0xd
	.4byte	0x7d
	.uleb128 0x12
	.4byte	.LASF67
	.byte	0x7
	.byte	0x4
	.4byte	0x2c
	.byte	0x7
	.2byte	0x23c
	.byte	0xd
	.4byte	0x324
	.uleb128 0x13
	.4byte	.LASF52
	.byte	0
	.uleb128 0x13
	.4byte	.LASF53
	.byte	0x1
	.uleb128 0x13
	.4byte	.LASF54
	.byte	0x2
	.uleb128 0x13
	.4byte	.LASF55
	.byte	0x3
	.uleb128 0x13
	.4byte	.LASF56
	.byte	0x4
	.uleb128 0x13
	.4byte	.LASF57
	.byte	0x5
	.uleb128 0x13
	.4byte	.LASF58
	.byte	0x6
	.byte	0
	.uleb128 0xe
	.4byte	.LASF59
	.byte	0x7
	.2byte	0x244
	.byte	0x3
	.4byte	0x2e6
	.uleb128 0x14
	.4byte	.LASF109
	.byte	0x3
	.byte	0x7
	.2byte	0x25b
	.byte	0x8
	.4byte	0x36a
	.uleb128 0x15
	.4byte	.LASF61
	.byte	0x7
	.2byte	0x25c
	.byte	0x7
	.4byte	0x33
	.byte	0
	.uleb128 0x15
	.4byte	.LASF62
	.byte	0x7
	.2byte	0x25d
	.byte	0x7
	.4byte	0x33
	.byte	0x1
	.uleb128 0x15
	.4byte	.LASF63
	.byte	0x7
	.2byte	0x25e
	.byte	0x7
	.4byte	0x7d
	.byte	0x2
	.byte	0
	.uleb128 0x3
	.4byte	0x331
	.uleb128 0xc
	.4byte	0x36a
	.4byte	0x37f
	.uleb128 0x16
	.4byte	0x2c
	.byte	0x11
	.byte	0
	.uleb128 0x3
	.4byte	0x36f
	.uleb128 0xe
	.4byte	.LASF64
	.byte	0x7
	.2byte	0x261
	.byte	0x20
	.4byte	0x37f
	.uleb128 0xe
	.4byte	.LASF65
	.byte	0x7
	.2byte	0x263
	.byte	0x13
	.4byte	0x19a
	.uleb128 0xe
	.4byte	.LASF66
	.byte	0x7
	.2byte	0x26e
	.byte	0x13
	.4byte	0x19a
	.uleb128 0x17
	.4byte	.LASF68
	.byte	0x7
	.byte	0x4
	.4byte	0x2c
	.byte	0x8
	.byte	0x46
	.byte	0x6
	.4byte	0x478
	.uleb128 0x13
	.4byte	.LASF69
	.byte	0
	.uleb128 0x13
	.4byte	.LASF70
	.byte	0x1
	.uleb128 0x13
	.4byte	.LASF71
	.byte	0x2
	.uleb128 0x13
	.4byte	.LASF72
	.byte	0x3
	.uleb128 0x13
	.4byte	.LASF73
	.byte	0x4
	.uleb128 0x13
	.4byte	.LASF74
	.byte	0x5
	.uleb128 0x13
	.4byte	.LASF75
	.byte	0x6
	.uleb128 0x13
	.4byte	.LASF76
	.byte	0x7
	.uleb128 0x13
	.4byte	.LASF77
	.byte	0x8
	.uleb128 0x13
	.4byte	.LASF78
	.byte	0x9
	.uleb128 0x13
	.4byte	.LASF79
	.byte	0xa
	.uleb128 0x13
	.4byte	.LASF80
	.byte	0xb
	.uleb128 0x13
	.4byte	.LASF81
	.byte	0xc
	.uleb128 0x13
	.4byte	.LASF82
	.byte	0xd
	.uleb128 0x13
	.4byte	.LASF83
	.byte	0xe
	.uleb128 0x13
	.4byte	.LASF84
	.byte	0xf
	.uleb128 0x13
	.4byte	.LASF85
	.byte	0x10
	.uleb128 0x13
	.4byte	.LASF86
	.byte	0x11
	.uleb128 0x13
	.4byte	.LASF87
	.byte	0x12
	.uleb128 0x13
	.4byte	.LASF88
	.byte	0x13
	.uleb128 0x13
	.4byte	.LASF89
	.byte	0x14
	.uleb128 0x13
	.4byte	.LASF90
	.byte	0x15
	.uleb128 0x13
	.4byte	.LASF91
	.byte	0x9
	.uleb128 0x13
	.4byte	.LASF92
	.byte	0x9
	.uleb128 0x13
	.4byte	.LASF93
	.byte	0xd
	.uleb128 0x13
	.4byte	.LASF94
	.byte	0x9
	.uleb128 0x13
	.4byte	.LASF95
	.byte	0x4
	.uleb128 0x13
	.4byte	.LASF96
	.byte	0x9
	.uleb128 0x13
	.4byte	.LASF97
	.byte	0xc
	.uleb128 0x13
	.4byte	.LASF98
	.byte	0xd
	.uleb128 0x13
	.4byte	.LASF99
	.byte	0x11
	.byte	0
	.uleb128 0x12
	.4byte	.LASF100
	.byte	0x7
	.byte	0x4
	.4byte	0x2c
	.byte	0x9
	.2byte	0x12e
	.byte	0x6
	.4byte	0x49e
	.uleb128 0x13
	.4byte	.LASF101
	.byte	0
	.uleb128 0x13
	.4byte	.LASF102
	.byte	0x1
	.uleb128 0x13
	.4byte	.LASF103
	.byte	0x2
	.byte	0
	.uleb128 0xa
	.4byte	.LASF104
	.byte	0xa
	.byte	0x11
	.byte	0xc
	.4byte	0x5b
	.uleb128 0xa
	.4byte	.LASF105
	.byte	0xa
	.byte	0x12
	.byte	0xc
	.4byte	0x5b
	.uleb128 0x18
	.4byte	.LASF110
	.byte	0x1
	.byte	0x10
	.byte	0x5
	.4byte	0x5b
	.4byte	.LFB291
	.4byte	.LFE291-.LFB291
	.uleb128 0x1
	.byte	0x9c
	.byte	0
	.section	.debug_abbrev,"",%progbits
.Ldebug_abbrev0:
	.uleb128 0x1
	.uleb128 0x11
	.byte	0x1
	.uleb128 0x25
	.uleb128 0xe
	.uleb128 0x13
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1b
	.uleb128 0xe
	.uleb128 0x55
	.uleb128 0x17
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x10
	.uleb128 0x17
	.byte	0
	.byte	0
	.uleb128 0x2
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0xe
	.byte	0
	.byte	0
	.uleb128 0x3
	.uleb128 0x26
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x4
	.uleb128 0x24
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0x3
	.uleb128 0x8
	.byte	0
	.byte	0
	.uleb128 0x5
	.uleb128 0xf
	.byte	0
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x6
	.uleb128 0x16
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x7
	.uleb128 0x13
	.byte	0x1
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x8
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x9
	.uleb128 0x15
	.byte	0
	.uleb128 0x27
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xa
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xb
	.uleb128 0x15
	.byte	0
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xc
	.uleb128 0x1
	.byte	0x1
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0xd
	.uleb128 0x21
	.byte	0
	.byte	0
	.byte	0
	.uleb128 0xe
	.uleb128 0x34
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0xf
	.uleb128 0x13
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3c
	.uleb128 0x19
	.byte	0
	.byte	0
	.uleb128 0x10
	.uleb128 0x15
	.byte	0x1
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x11
	.uleb128 0x5
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x12
	.uleb128 0x4
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x13
	.uleb128 0x28
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x1c
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x14
	.uleb128 0x13
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x15
	.uleb128 0xd
	.byte	0
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0x5
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x38
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x16
	.uleb128 0x21
	.byte	0
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x2f
	.uleb128 0xb
	.byte	0
	.byte	0
	.uleb128 0x17
	.uleb128 0x4
	.byte	0x1
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3e
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0xb
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x1
	.uleb128 0x13
	.byte	0
	.byte	0
	.uleb128 0x18
	.uleb128 0x2e
	.byte	0
	.uleb128 0x3f
	.uleb128 0x19
	.uleb128 0x3
	.uleb128 0xe
	.uleb128 0x3a
	.uleb128 0xb
	.uleb128 0x3b
	.uleb128 0xb
	.uleb128 0x39
	.uleb128 0xb
	.uleb128 0x27
	.uleb128 0x19
	.uleb128 0x49
	.uleb128 0x13
	.uleb128 0x11
	.uleb128 0x1
	.uleb128 0x12
	.uleb128 0x6
	.uleb128 0x40
	.uleb128 0x18
	.uleb128 0x2117
	.uleb128 0x19
	.byte	0
	.byte	0
	.byte	0
	.section	.debug_aranges,"",%progbits
	.4byte	0x1c
	.2byte	0x2
	.4byte	.Ldebug_info0
	.byte	0x4
	.byte	0
	.2byte	0
	.2byte	0
	.4byte	.LFB291
	.4byte	.LFE291-.LFB291
	.4byte	0
	.4byte	0
	.section	.debug_ranges,"",%progbits
.Ldebug_ranges0:
	.4byte	.LFB291
	.4byte	.LFE291
	.4byte	0
	.4byte	0
	.section	.debug_line,"",%progbits
.Ldebug_line0:
	.section	.debug_str,"MS",%progbits,1
.LASF106:
	.ascii	"GNU C89 8.2.1 20180802 -mlittle-endian -mabi=aapcs-"
	.ascii	"linux -mfpu=vfp -marm -mfloat-abi=soft -mtls-dialec"
	.ascii	"t=gnu -march=armv7-a -g -O2 -std=gnu90 -fno-strict-"
	.ascii	"aliasing -fno-common -fshort-wchar -fno-PIE -fno-dw"
	.ascii	"arf2-cfi-asm -fno-ipa-sra -funwind-tables -fno-dele"
	.ascii	"te-null-pointer-checks -fstack-protector-strong -fo"
	.ascii	"mit-frame-pointer -fno-var-tracking-assignments -fn"
	.ascii	"o-strict-overflow -fno-merge-all-constants -fmerge-"
	.ascii	"constants -fstack-check=no -fconserve-stack --param"
	.ascii	" allow-store-data-races=0\000"
.LASF91:
	.ascii	"PG_checked\000"
.LASF108:
	.ascii	"/home/zt/optee/linux\000"
.LASF100:
	.ascii	"zone_type\000"
.LASF35:
	.ascii	"kmsg_fops\000"
.LASF66:
	.ascii	"hex_asc_upper\000"
.LASF28:
	.ascii	"linux_banner\000"
.LASF43:
	.ascii	"panic_on_unrecovered_nmi\000"
.LASF8:
	.ascii	"long long unsigned int\000"
.LASF57:
	.ascii	"SYSTEM_RESTART\000"
.LASF39:
	.ascii	"panic_blink\000"
.LASF17:
	.ascii	"initcall_entry_t\000"
.LASF55:
	.ascii	"SYSTEM_HALT\000"
.LASF90:
	.ascii	"__NR_PAGEFLAGS\000"
.LASF7:
	.ascii	"long long int\000"
.LASF3:
	.ascii	"signed char\000"
.LASF21:
	.ascii	"__security_initcall_end\000"
.LASF23:
	.ascii	"saved_command_line\000"
.LASF46:
	.ascii	"sysctl_panic_on_rcu_stall\000"
.LASF82:
	.ascii	"PG_private_2\000"
.LASF52:
	.ascii	"SYSTEM_BOOTING\000"
.LASF68:
	.ascii	"pageflags\000"
.LASF107:
	.ascii	"kernel/bounds.c\000"
.LASF53:
	.ascii	"SYSTEM_SCHEDULING\000"
.LASF9:
	.ascii	"long int\000"
.LASF13:
	.ascii	"soc_mb\000"
.LASF45:
	.ascii	"panic_on_warn\000"
.LASF109:
	.ascii	"taint_flag\000"
.LASF79:
	.ascii	"PG_arch_1\000"
.LASF58:
	.ascii	"SYSTEM_SUSPEND\000"
.LASF49:
	.ascii	"panic_cpu\000"
.LASF29:
	.ascii	"linux_proc_banner\000"
.LASF48:
	.ascii	"crash_kexec_post_notifiers\000"
.LASF69:
	.ascii	"PG_locked\000"
.LASF74:
	.ascii	"PG_lru\000"
.LASF71:
	.ascii	"PG_referenced\000"
.LASF16:
	.ascii	"initcall_t\000"
.LASF36:
	.ascii	"file_operations\000"
.LASF99:
	.ascii	"PG_isolated\000"
.LASF1:
	.ascii	"unsigned int\000"
.LASF81:
	.ascii	"PG_private\000"
.LASF50:
	.ascii	"root_mountflags\000"
.LASF64:
	.ascii	"taint_flags\000"
.LASF0:
	.ascii	"long unsigned int\000"
.LASF34:
	.ascii	"kptr_restrict\000"
.LASF37:
	.ascii	"atomic_notifier_head\000"
.LASF30:
	.ascii	"console_printk\000"
.LASF54:
	.ascii	"SYSTEM_RUNNING\000"
.LASF6:
	.ascii	"short unsigned int\000"
.LASF25:
	.ascii	"rodata_enabled\000"
.LASF11:
	.ascii	"bool\000"
.LASF95:
	.ascii	"PG_savepinned\000"
.LASF33:
	.ascii	"dmesg_restrict\000"
.LASF19:
	.ascii	"__con_initcall_end\000"
.LASF104:
	.ascii	"prove_locking\000"
.LASF61:
	.ascii	"c_true\000"
.LASF86:
	.ascii	"PG_reclaim\000"
.LASF62:
	.ascii	"c_false\000"
.LASF70:
	.ascii	"PG_error\000"
.LASF94:
	.ascii	"PG_pinned\000"
.LASF47:
	.ascii	"sysctl_panic_on_stackoverflow\000"
.LASF24:
	.ascii	"reset_devices\000"
.LASF59:
	.ascii	"system_state\000"
.LASF83:
	.ascii	"PG_writeback\000"
.LASF105:
	.ascii	"lock_stat\000"
.LASF89:
	.ascii	"PG_mlocked\000"
.LASF41:
	.ascii	"panic_timeout\000"
.LASF98:
	.ascii	"PG_double_map\000"
.LASF102:
	.ascii	"ZONE_MOVABLE\000"
.LASF20:
	.ascii	"__security_initcall_start\000"
.LASF38:
	.ascii	"panic_notifier_list\000"
.LASF85:
	.ascii	"PG_mappedtodisk\000"
.LASF15:
	.ascii	"elf_hwcap2\000"
.LASF101:
	.ascii	"ZONE_NORMAL\000"
.LASF72:
	.ascii	"PG_uptodate\000"
.LASF10:
	.ascii	"_Bool\000"
.LASF4:
	.ascii	"unsigned char\000"
.LASF67:
	.ascii	"system_states\000"
.LASF92:
	.ascii	"PG_swapcache\000"
.LASF27:
	.ascii	"initcall_debug\000"
.LASF5:
	.ascii	"short int\000"
.LASF60:
	.ascii	"counter\000"
.LASF63:
	.ascii	"module\000"
.LASF77:
	.ascii	"PG_slab\000"
.LASF103:
	.ascii	"__MAX_NR_ZONES\000"
.LASF73:
	.ascii	"PG_dirty\000"
.LASF56:
	.ascii	"SYSTEM_POWER_OFF\000"
.LASF40:
	.ascii	"oops_in_progress\000"
.LASF2:
	.ascii	"char\000"
.LASF12:
	.ascii	"atomic_t\000"
.LASF84:
	.ascii	"PG_head\000"
.LASF97:
	.ascii	"PG_slob_free\000"
.LASF88:
	.ascii	"PG_unevictable\000"
.LASF42:
	.ascii	"panic_on_oops\000"
.LASF22:
	.ascii	"boot_command_line\000"
.LASF78:
	.ascii	"PG_owner_priv_1\000"
.LASF32:
	.ascii	"printk_delay_msec\000"
.LASF51:
	.ascii	"early_boot_irqs_disabled\000"
.LASF44:
	.ascii	"panic_on_io_nmi\000"
.LASF80:
	.ascii	"PG_reserved\000"
.LASF14:
	.ascii	"elf_hwcap\000"
.LASF75:
	.ascii	"PG_active\000"
.LASF65:
	.ascii	"hex_asc\000"
.LASF93:
	.ascii	"PG_fscache\000"
.LASF96:
	.ascii	"PG_foreign\000"
.LASF18:
	.ascii	"__con_initcall_start\000"
.LASF76:
	.ascii	"PG_waiters\000"
.LASF26:
	.ascii	"late_time_init\000"
.LASF87:
	.ascii	"PG_swapbacked\000"
.LASF110:
	.ascii	"main\000"
.LASF31:
	.ascii	"devkmsg_log_str\000"
	.ident	"GCC: (GNU Toolchain for the A-profile Architecture 8.2-2018-08 (arm-rel-8.23)) 8.2.1 20180802"
	.section	.note.GNU-stack,"",%progbits
