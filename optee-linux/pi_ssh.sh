#!/bin/bash

sudo systemctl enable ssh
sudo systemctl start ssh
sshfs pi@192.168.201.218:/home/pi/Documents/ustar-sandbox /home/zt233/pi
#sshfs pi@192.168.201.218:/boot /home/zt233/Desktop/boot
#sshfs pi@192.168.201.218:/lib/modules /home/zt233/Desktop/rootfs
sshfs -o idmap=user root@192.168.201.218:/boot /home/zt233/Desktop/boot
sshfs -o idmap=user root@192.168.201.218:/lib/modules /home/zt233/Desktop/rootfs

