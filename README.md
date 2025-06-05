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

## Troubleshooting

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

