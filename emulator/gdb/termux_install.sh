#!env /bin/sh

am start -n com.termux/.app.TermuxActivity
sleep 5
input text "env > termux-env" && input keyevent 113 && input keyevent 66
cd /data/data/com.termux/files/home
su $(dumpsys package com.termux | grep userId | head -n 1 | cut -d = -f 2) << eof

source ./termux-env
export HOME=/data/data/com.termux/files/home
export PATH=/data/data/com.termux/files/usr/bin
export SHELL=/data/data/com.termux/files/usr/bin/bash 
yes | pkg update
yes | pkg install gdb
yes | pkg install vim
yes | pkg install git
eof
