#!/bin/bash

export META_TARGET=aarch64emu28
export PARALLEL_EMULATORS=8


SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

cd $SCRIPT_DIR

if [ !"$(hostname)" == "honeycomb-01" ]; then
	echo "Needs to be run on the FANS evaluation server!!"
	exit 1
fi

echo "++EVAL++: extracting entrypoint address"

python3 instr_services.py

echo "++EVAL++: extracting interface"

python3 nass-preprocess.py

echo "++EVAL++: printing table"

python3.12 ground_truth.py
