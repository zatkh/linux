#!/bin/bash

NEW_KERNEL=$1
OLD_KERNEl=$2
LOGNAME=$3

FILENAME=$LOGNAME.diff

echo -e "********compare $NEW_KERNEL to $OLD_KERNEl***********\n" >> $FILENAME
./scripts/bloat-o-meter $OLD_KERNEl $NEW_KERNEL >> $FILENAME
