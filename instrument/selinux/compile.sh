#!/bin/sh

~/Android/Sdk/ndk/26.1.10909125/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang++ -ggdb -O0 -static-libstdc++ -o secheck secheck.cc -I. libselinux.so
