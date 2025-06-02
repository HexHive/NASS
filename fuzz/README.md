# Fuzzing Proprietary vendor service

## Building

Use: 
```
make [device-id]
```

If building for Android 9 (Pixel 2 XL for Fans comparison) the NDK needs to be version 21.0...
```
[path-to-sdk]/ndk/21.0... make [device-id]
```

To add a new device just add it to the makefile using the correct android api clang version.

## Fuzzing

```
python3 fuzz/orchestrate.py -s Demo -d 4bd1d32 --pid_filter
``` 

## Testing

On the host sets up instrumentation:
```
python3 fuzz/orchestrate.py -s Demo -d 4bd1d32 --dont_fuzz
```

On the device:
```
SERVICE_NAME=Demo INTERFACE_NAME=Demo DESER_PATH=./deserializers_used.txt ./fuzzer data 
```

Non-reproducible crashes (hack for low nr of execs), run fuzzer with DUMPALL=1 then use
$(ls dmp | sort -n | awk '{print "dmp/" $0}' | paste -sd ' ' -) to get all dmp files and then the crash for libfuzzer to replay all

## Triage

Run triage on the fuzzing output:
```
python3 fuzz/triage.py -i targets/4bd1d32/Demo/fuzz_out/<fuzz_out_folder>
```

This will create a folder with deduplicated crashes in 
`targets/4bd1d32/Demo/fuzz_out/deduplicated`

Some crashes are state dependent, if the replay.sh has a large number of seeds you can try minimizing the crash:

```
python3 fuzz/triage.py -i targets/4bd1d32/Demo/fuzz_out/deduplicated/<crash-id> -m
```

To debug the reproduced and deduplicated crashes use:
```
python3 fuzz/triage.py -i targets/4bd1d32/Demo/fuzz_out/deduplicated -t
```

## Refinement

Replay seeds after fuzzing for a bit to extract the exact onTransact functions used

```
python3 fuzz/replay.py refine -s Demo -d 4bd1d32 -f <path to fuzzing output directory>
```

Afterwards a bunch of new seeds should be written to `<fuzz_out directory>/phase_2_seeds`.

These can then be used to run again:

```
python3 fuzz/orchestrate.py -s Demo -d 4bd1d32 --pid_filter --phase2 <fuzzing output directory>
```

## Drcov

Extract drcov by replaying all seeds

```
python3 fuzz/replay.py drcov -s Demo -d 4bd1d32 -f <path to fuzzing output directory>
```

This generates drcov DynmaicRio files at 
`targets/<device>/<service>/fuzz_out/<date>/drcov

View coverage using: https://github.com/datalocaltmp/Cartographer/tree/GHIDRA-UPDATE-DRCOV-UPDATE
(import merged-cov.txt)

Alternative:
To view the coverage in ghidra, I'm using dragondance:
Download zip for ghidra 10.2.3: `https://github.com/0ffffffffh/dragondance/files/10862489/ghidra_10.2.3_PUBLIC_20230301_dragondance-master.zip`
Download ghidra 10.2.3

Then for each file import the corresponding DynamicRio coverage file.

**If the coverage looks wrong, set the base address manually to 0 in ghidra**

## Run For all connected devices

```
python3 fuzz/run.py
```

Afterwards analyze the results, see which crashes reproduce:

```
python3 fuzz/analyze.py -j fuzz/<output json with timestamp> -t 
``` 
