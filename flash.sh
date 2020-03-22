#!/bin/bash

sudo mkdir -p /media/boot
sudo mount /dev/mmcblk0p1 /media/boot
cd /media
sudo gunzip -cd /home/zt/rpi-optee/build/../out-br/images/rootfs.cpio.gz | sudo cpio -idmv "boot/*"
sudo umount boot



sudo mkdir -p /media/rootfs
sudo mount /dev/mmcblk0p2 /media/rootfs
cd rootfs
sudo gunzip -cd /home/zt/rpi-optee/build/../out-br/images/rootfs.cpio.gz | sudo cpio -idmv
sudo rm -rf /media/rootfs/boot/*
cd .. 
sudo umount rootfs
