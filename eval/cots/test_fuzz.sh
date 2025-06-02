#!/bin/bash

export NDK_BASE=/android-ndk-r27c
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
DEVICE_ID=47030DLAQ0012N

if [ ! -d "../$DEVICE_ID/fuzzer" ]; then
        echo "compiling fuzzer"
        pushd "$SCRIPT_DIR/../../device"
        make $DEVICE_ID
        popd
        pushd "$SCRIPT_DIR/../../fuzz"
        make $DEVICE_ID
fi


python3 "$SCRIPT_DIR/../../instrument/interface.py" -d 47030DLAQ0012N -s hardware.google.ril_ext.IRilExt/slot2 
python3 "$SCRIPT_DIR/../../fuzz/orchestrate.py" -d 47030DLAQ0012N -s hardware.google.ril_ext.IRilExt/slot2 -t 120
