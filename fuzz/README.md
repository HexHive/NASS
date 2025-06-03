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

Adding a new device:
```
clean:
+ rm -rf ../device/[device_id]/fuzzer_build ../device/[device_id]/fuzzer ../device/[device_id]/libfuzz ../device/[device_id]/seedinfo
+[device_id]: DEVICE=[device_id]
+[device_id]: CXX=$(NDK_PATH)/[isa]-linux-android[api-version]-clang++
+[device_id]: $(FUZZER) $(SEEDINFO) $(REPLAY)
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

