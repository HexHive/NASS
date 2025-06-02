# FANS

This folder contains the files relevant for FANS including a modified version of FANS and FANS specific orchestrator to run FANS and collect coverage. 
Used by `eval/fans/emu-run.py`.

### Requirements

Do all the FANS analysis, see the `fans_analysis` folder -> workdir with a bunch of fucking json in this folder. (used by fans to generate inputs)

Compile the FANS fuzzer, see the `fuzzer-engine` folder -> `native_fuzzer*` binaries in this folder

AARCH64 emulator and aosp built for emulator, see ../emulator directory running on AARCH64 host with kvm.

Set the `META_TARGET` env variable so the fuzzer knows we're fuzzing a bunch of emulators running the same image:

```
export AARCH64_EMU_28=aarch64emu28
``` 

#### 1. Get the relevant services:

run the `get_fans_services.py` script to extract the relevant services.
(standalone native services for which FANS has an interface model)

#### 2. Do preprocessing for NASS

start an emulator with our image (see ../emulator directory)

```
python3 instr_services.py emulator-5554
``` 

As a result all relevant services should be inside the binder database for the aarch64emu28 target.

Now we can run Nass preprocessing.

```
python3 run_preprocessing.py 
```

Now for the aarch64emu28 target for each relevant service there should exist a preprocess/final directory with reference seeds.

#### 3. Run evaluaton

Testing:
```
FANS_RUNTIME=180 FANS_NREMU=1 python3 fans-run.py
``` 

#### 3. Run both nass and fans on these targets: (DEPRECATED FIX TODO)

(WIP) runs nass/fans on the specified targets

```
python3 fans/fans-run.py [nass/fans] -d [pixel2_xl_device]  -r [run_name]
``` 
See -h for more options. 

internally this script just calls `fans-orchestrate.py` or `../fuzz/orchestrate.py`

The result will be written to:
`fans/run_out/fans|nass-run_name-data.json` 
contains the seed and crash output paths

**TODO**
- detect broken adb and remediate automatically
- detect other messed up device states
- nass 2 phases fuzzing

#### 4. Get Drcov TODO BROKEN UPDATE

To make sure we get a good and consistent coverage metric we use drcov.

Run the following to extract the drcov files for all the seeds in the out paths:
``` 
python3 fans/fans-cov.py -d [pixel_2_xl_device] -r [path_to_run_out_json]
``` 

This will basically iteratively call `fans-replay.py`

Now in each output folder there will be a `drcov` folder that contains 
drcov information.

#### 4. TODO Generate coverage plot BROKEN UPDATE



### Adding Coverage to FANS Notes

#### Seed replayability

Added transaction serialization/deserialization functions in transaction.cpp

Changed util/random.h to use a pseudoRNG to make the generated numbers predictable.
=> backing up the rng state and dumping it along with the seeds

