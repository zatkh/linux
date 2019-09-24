#!/bin/bash
LOGNAME=$1
TOP=$2


echo -e "*******************\n" >> $LOGNAME
free >> $LOGNAME
echo -e "*******************\n" >> $LOGNAME
cat /proc/meminfo >> $LOGNAME
echo -e "*******************\n" >> $LOGNAME
vmstat -s | grep memory >> $LOGNAME
echo -e "*******************\n" >> $LOGNAME
sudo vmstat --slabs >> $LOGNAME
echo -e "*******************\n" >> $LOGNAME

dmesg |grep Memory >> $LOGNAME
echo -e "*******************\n" >> $LOGNAME

sudo cat /proc/slabinfo >> $LOGNAME
echo -e "*******************\n" >> $LOGNAME
