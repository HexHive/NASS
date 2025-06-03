#!/bin/bash

export META_TARGET=aarch64emu28

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )


python3 "$SCRIPT_DIR/../../instrument/interface.py" -d emulator-5554 -s wificond 
python3 "$SCRIPT_DIR/../../fuzz/orchestrate.py" -d emulator-5554 -s wificond -t 120
