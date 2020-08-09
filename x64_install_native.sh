#!/bin/bash
# Install kernel image on local machine

echo "===================== [x64-kernel] Compiling kernel image.  ====================="
make ARCH=x86_64 -j 8;
if [ $? -eq 0 ]; then
    echo " ====================== Kernel compiled successfully. =========================="
else
    echo " ====================== Kernel failed to compile, check error messages. error code: $? ========================"
    exit $?
fi

echo "===================== [x64-kernel] Compiling kernel modules. ====================="
make ARCH=x86_64 -j 8 modules;
if [ $? -eq 0 ]; then
    echo " ===================== Kernel modules compiled successfully. ========================="
else
    echo " ========================= Kernel modules failed to compile, check error messages. error code: $? ======================="
    exit $?
fi

sudo make ARCH=x86_64 -j 8 modules_install;
if [ $? -eq 0 ]; then
    echo " ================== kernel modules installed successfully. ======================"
else
    echo " ================== kernel modules failed to install, check error messages. error code: $? =============="
    exit $?
fi


#sudo make ARCH=x86_64 -j 8 install;
#if [ $? -eq 0 ]; then
#    echo " ================== kernel image installed successfully. ======================"
#else
#    echo " ================== kernel image failed to install, check error messages. error code: $? =============="
#    exit $?
#fi
#cd ..

# Compile netlink module
#NETLINK_DIR=./netlink-module/
#echo "===================== [x64-kernel] Compile netlink module . ============================"
#cd $NETLINK_DIR
#make
#cd ..

