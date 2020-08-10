#!/bin/sh


#make ARCH=x86_64 x86_64_defconfig

qemu-system-x86_64 -s -kernel arch/x86/boot/bzImage -boot c -m 2049M -hda $HOME/Documents/git/buildroot/output/images/rootfs.ext2 -append "root=/dev/sda rw console=ttyS0,115200 acpi=off nokaslr" -serial stdio -display none

#qemu-system-x86_64 -cpu host -net nic -drive file=ubuntu.snapshot.qcow2,format=qcow2   -enable-kvm   -m 4G   -smp 2   -vga virtio ;


