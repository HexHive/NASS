#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
export NDK_BASE=/android-ndk-r27c
export FUZZ_TIME=600
export FUZZ_COV_RATE_MAX_TIME=300

if [ -z "$1" ]; then
	echo "usage ./fuzz-run.sh [device_id]"
	echo "possible devices:"
	adb devices
	exit 1
fi

if ! adb devices | grep -wq "$1"; then
    echo "Device $1 is not connected via ADB."
    exit
fi

if [ ! -d "../$1/fuzzer" ]; then
        echo "compiling fuzzer"
        pushd "$SCRIPT_DIR/../../device"
        make $1
        popd
        pushd "$SCRIPT_DIR/../../fuzz"
        make $1
fi


if [[ -n "$2" && "$2" == "all" ]]; then
	fuzzall=true
else
	fuzzall=false
	mapfile -t services < "$SCRIPT_DIR/sample_services/$1.txt"
	echo $services
fi


echo "++EVAL++: extracting onTransact functions"

if [[ "$fuzzall" == true ]]; then
	python3 "$SCRIPT_DIR/enumerate.py" -d $1 --no_system_server
else
	for s in "${services[@]}"; do
	    echo "Processing: $s"
	    python3 "$SCRIPT_DIR/../../instrument/interface.py" -s $s -d $1
	done
fi

echo "++EVAL++: preprocessing and fuzzing services"

if [[ "$fuzzall" == true ]]; then
	python3 "$SCRIPT_DIR/run.py" -d $1 -n $1
else
	python3 "$SCRIPT_DIR/run.py" -d $1 -n $1 -s "$SCRIPT_DIR/sample_services/$1.txt" 
fi

echo "++EVAL++: triaging crashes"

python3 "$SCRIPT_DIR/run-triage.py" -j "$SCRIPT_DIR/run_out/$1_$1.json"

echo "++EVAL++: analyzing crashes"

python3 "$SCRIPT_DIR/run-analyze.py" -j "$SCRIPT_DIR/run_out/$1_$1.json"
