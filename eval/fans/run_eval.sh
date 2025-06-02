#!/bin/bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

if [ !"$(hostname)" == "honeycomb-01" ]; then
	echo "Needs to be run on the FANS evaluation server!!"
	exit 1
fi

if [ -z "$1" ]; then
	echo "usage ./run_eval [run_name]"
	exit 1
fi

export META_TARGET=aarch64emu28
export CAMPAIGN_RUNTIME=3600
export CAMPAIGN_RUNS=2
export NASS_ABLATION=1
export PARALLEL_EMULATORS=8
export CAMPAIGN_SERVICES="$SCRIPT_DIR/fans_eval_services_explorable.txt"

cd $SCRIPT_DIR

echo "++EVAL++: extracting entrypoint address"

python3 instr_services.py

echo "++EVAL++: extracting interface"

python3 nass-preprocess.py

echo "++EVAL++: fuzzing (NASS, NASS(NI), FANS)"

python3 emu-run.py $1 2>error.log

echo "++EVAL++: generating coverage graphs"

python3 graph.py --jsonperc covp.json -j ./run_out/$1_out.json

echo "++EVAL++ coverage graphs at ./run_out/$1_out/"
