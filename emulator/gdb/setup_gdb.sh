#!/bin/sh

if [ -z "$1" ]; then
  echo "Error: device_id required."
  exit 1
fi

adb -s $1 install termux.apk
sleep 2
adb -s $1 push termux_install.sh /data/local/tmp/
adb -s $1 shell su root 'chmod +x /data/local/tmp/termux_install.sh'
adb -s $1 shell su root 'sh /data/local/tmp/termux_install.sh'

