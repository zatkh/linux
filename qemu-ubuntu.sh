#!/bin/sh

#wget http://releases.ubuntu.com/xenial/ubuntu-18.04-desktop-amd64.iso

qemu-img create -f qcow2 ubuntu-16.04.4-desktop-amd64.img.qcow2 16G
qemu-system-x86_64 \
  -cdrom ~/Downloads/ubuntu-16.04.4-desktop-amd64.iso \
  -drive file=ubuntu-16.04.4-desktop-amd64.img.qcow2,format=qcow2 \
  -enable-kvm \
  -m 4G \
  -smp 2 \
  -vga virtio \
;

qemu-img create -f qcow2 -b ubuntu-16.04.4-desktop-amd64.img.qcow2 ubuntu.snapshot.qcow2

qemu-system-x86_64 \
  -cpu host -net nic \
  -drive file=ubuntu.snapshot.qcow2,format=qcow2 \
  -enable-kvm \
  -m 4G \
  -smp 2 \
  -vga virtio \
;

#qemu-system-x86_64 -cpu host -net nic -drive file=ubuntu.snapshot.qcow2,format=qcow2   -enable-kvm   -m 4G   -smp 2   -vga virtio ;


