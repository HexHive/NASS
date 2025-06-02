#!/bin/bash

if [ -z "$1" ]; then
	echo "device_id needed."
	echo "Usage: $0 <device_id>"
	exit 1
fi

adb -s $1 push ../tools/gef.py /data/local/tmp
adb -s $1 push com.termux.tar.gz /data/local/tmp
adb -s $1 shell "su 0 sh -c 'cd /data/data && tar xvf /data/local/tmp/com.termux.tar.gz'"

echo "PATH=$PATH:/data/data/com.termux/files/usr/bin"
echo "gdb -iex "source /data/local/tmp/gef.py" "
