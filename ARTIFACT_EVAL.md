# Artifact Evaluation

## COTS

The script expects five specific devices to be connected. If you are running this script outside of 
USENIX artifact evaluation you will need to adjust the script and insert your device ids.

During USENIX artifact evaluation on the provided server the following devices should be connected:

```shell
adb devices
```

```
List of devices attached
089092526K000893        device
47030DLAQ0012N  device
RZCX312P76A     device
a497c295        device
bai7gujvtchqeaus        device
```

### Numbers on prop. native services

Generate the statistics on proprietary native services:

```shell
./eval/cots/native-service-stats.sh
```

### Fuzzing prop. native services

The script `eval/cots/run-fuzz.sh` takes care of fuzzing services on a specific device. By default 
fuzzing is only 10 minutes on a subset of native services.

For example fuzz three native services on the Pixel 9:

```shell
./eval/cots/run-fuzz.sh 47030DLAQ0012N
```

## FANS

The following scripts assume that you have setup the Android28 emulator as described in `emulator/README.md`. 
During USENIX artifact evaluation the emulator is already setup on the server.

### DGIE interface extraction

Extract the interface information from the evaluation services:

```shell
./eval/fans/ground-truth.sh
```

The numbers of exactly extracted RPC functions were done manually. 
This was done by comparing the ground truth json against the extracted interface.

View the ground truth:

```shell
cat eval/fans/ground_truth/aarch64emu28/installd.json | jq
```

View the extracted interface:

```shell
cat targets/aarch64emu28/installd/preprocess/interface.json | jq
```

### FANS fuzzing campaign

Run the FANS fuzzing campaign: 

```shell
./eval/fans/run_eval.sh ae
```

By default each service is fuzzed for 1 hours one time. These values can be adjusted

The generated coverage pdfs can be found at:

```
/eval/fans/run_out/ae/
```
