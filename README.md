# NASS: Fuzz Native Android System Services

Use dynamic binary instrumentation to enumerate the binder interface and then fuzz the services.

## Requirements

- adb
- Android [NDK](https://developer.android.com/ndk/downloads) version r26
- python3.9+ and requirements

We provide a docker setup to run the host component of NASS. 
Use `./setup.sh` to build the docker and `./run.sh` to spawn a shell in the docker.

## Preparation New Device

NASS only works on rooted Android phones, so step 0 is to root the device or use an emulator.
Note that we mainly tested NASS on arm64 phones, but an x86 Android emulator may not work.

NASS works with the adb device id. If you want to fuzz services on a specific device, 
you need to first add this device to the following Makefiles:
- `device/Makefile` # download libraries
- `fuzz/Makefile` # build fuzzer

Check the README in the specific folders for more detailed instructions.

Afterwards build the fuzzer:
```bash
cd device && make [device_id]
cd fuzz && NDK_BASE=[path-to-nkd] make [device_id]
```

On the device install termux [v0.118.0](https://github.com/termux/termux-app/releases/tag/v0.118.0) and 
install gdb:
```bash
pkg install gdb
apt upgrade
```

The following command should open gdb:
```bash
adb -s [device_id] shell su -c /data/data/com.termux/files/usr/bin/gdb
```

## Usage

With the device ready we can finally start fuzzing.

You can obtain a list of services using
```bash
adb -s [device_id] shell 'service list'
```

Extract the address of the entrypoint function (`onTransact`) from the target service.
```bash
python3 instrument/interface.py -s [target_service] -d [device_id]
```

Result should be a new/updated row in the service table.
```sql
sqlite3 <repo>/data/binder.db
select * from service;
```

Additionally the service binary is downloaded to `targets/[device_id]/[target_service]/`

Extract the interface.
```bash
python3 fuzz/preprocess.py -s [target_service] -d [device_id]
```

As a result interface aware seeds are generated in `targets/[device_id]/[target_service]/preprocess/final`

The extracted interface can be found at: `targets/[device_id]/[target_service]/preprocess/interface.json`

Fuzz the service with the interface aware seeds:

```bash
python3 fuzz/orchestrate.py -s [target_service] -d [device_id] --fuzz_data -c targets/[device_id]/[target_service]/preprocess/final
```

The resulting seeds/crashes are written to the output directory:

```bash
targets/[device_id]/[target_service]/fuzz_out/nass_[date_time]/
```

Attempt to reproduce and deduplicate crashes:

```bash
python3 fuzz/triage.py -i targets/[device_id]/[target_service]/fuzz_out/nass_[date_time]/
``` 

If crashes are not reproducing, try running `orchestrate.py` with `--dump` to write all sent ipc requests to disk (will be used during triage to setup the state again).

Setup debugging on the phone to triage crashes manually:
```bash
python3 fuzz/triage.py -t -s [target_service] -d [device_id]
```

## USENIX Artifact Evaluation

The artifact evaluation for COTS services is run on an Ubuntu 22.04 Linux x86 machine, with the 
relevant Android devices accessible over ADB via port forwarding.
The five devices are:
```
Transsion Infinix X670: 089092526K000893 (Infinix/X670-EU/Infinix-X670:12/SP1A.210812.016/231114V163:user/release-keys)
Google Pixel 9: 47030DLAQ0012N (google/tokay/tokay:15/BP1A.250305.020.A2/13038733:user/release-keys)
Samsung S23: RZCX312P76A (samsung/dm1qxxx/dm1q:13/TP1A.220624.014/S911BXXS5CXDF:user/release-keys)
OnePlus 12R: a497c295 (oplus/ossi/ossi:13/TP1A.220905.001/1739378839116:user/release-keys)
Redmi Note 13 5G: bai7gujvtchqeaus (Redmi/vnd_gold/gold:12/UP1A.231005.007/V816.0.18.0.UNQEUXM:user/release-keys)
```

The artifact evaluation for FANS is run on an Ubuntu 22.04 Linux aarch64 machine, with the 
Android 28 emulator setup as described in `emulator/README.md`.

### COTS

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

#### Numbers on prop. native services

Generate the statistics on proprietary native services:

```shell
./eval/cots/native-service-stats.sh
```

#### Fuzzing prop. native services

The script `eval/cots/run-fuzz.sh` takes care of fuzzing services on a specific device. By default
fuzzing is only 10 minutes on a subset of native services.

For example fuzz three native services on the Pixel 9:

```shell
./eval/cots/run-fuzz.sh 47030DLAQ0012N
```

### FANS

The following scripts assume that you have setup the Android28 emulator as described in `emulator/README.md`.
During USENIX artifact evaluation the emulator is already setup on the server.

#### DGIE interface extraction

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

#### FANS fuzzing campaign

Run the FANS fuzzing campaign:

```shell
./eval/fans/run_eval.sh ae
```

By default each service is fuzzed for 1 hours one time. These values can be adjusted

The generated coverage pdfs can be found at:

```
/eval/fans/run_out/ae/
```

## Troubleshooting

*onTransact Address in libandroid_runtime.so*: This means the service is a Java service out of scope for NASS.

*Hook not Working*:  This could be due to the service running in self-imposed seccomp sandbox (via libminijail). 
If minijail is not loaded from `/apex`, check the `fuzz/minijail` for an example of how to use Magisk modules to patch out the libminijail seccomp sandbox.

*Unable to find onTransact address*: Our script hooks at a specific function to then read the vtables. The offsets used there could be wrong. Additionally on some devices the hooked function is inlined so we need to hook in the middle of another function. See `instrument/fridajs/hook_onTransact_XXXX.js`.

## Repository Structure

Structure: 
```
binderlib/       # AOSP header files + example service/client 
coverometry/     # ghidra scripts to estimate max coverage
data/            # database + python3 scripts to interact with the db 
device/          # binaries for target devices
emulator/        # code to handle Android emulator
eval/            # scripts to run various aspects of evaluation
fans/            # modified FANS to run FANS with coverage
fuzz/            # code to fuzz target service
instrument/      # code to extract entrypoint function of service
service/         # utility code
targets/         # output folder for target devices
tools/           # third party tools
utils/           # more utility code 
```

### Frida Dealing with More than 8 Emulators

If there are more than 8 devices connected frida will not show them. To deal with this need to build own frida client.

Clone Frida (github.com/frida) and run make. Then apply the frida-core.patch to the frida-core subproject then make again and replace the existing frida client library with the built one:

if you get a pyconfig error during building:
```
sudo ln -s /usr/include /usr/lib/include
```

```
cp build/subprojects/frida-python/frida/_frida/_frida.abi3.so /usr/local/lib/python3.10/dist-packages/frida/_frida.abi3.so
```

