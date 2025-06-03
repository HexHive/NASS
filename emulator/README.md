# AARCH64 emulator

## Required Files

- emulator_dist.tar.gz: compiled emulator for aarch64, see "Building the Emulator" section
- sdk-repo-linux-system-images-eng..zip: compiled aosp (in this case for fans) for aarch64, see "Building AOSP"

Both files can be downloaded here:
https://zenodo.org/records/15582902

## Run on AARCH64 Host

Build the docker 

`docker build . -t emu`

Run the docker, mnt is in the unpacked emulator directory:

`docker run --rm --name emu -it --network host --privileged emu /bin/bash`

copy ~/.emulator_console_auth_token from docker file to host to be able to talk to emulator

Run the emulator inside the docker

`emulator @dev -cores 2 -memory 4096 -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel`

If not running for the first time and you want multiple instances use this:

`emulator @dev -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -read-only`

For the fans system image loading the snapshot does not restart adb, but booting is very fast so do: 

`emulator @dev -cores 2 -memory 4096 -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -read-only -no-snapshot-load`

### Api Level 34 Emulator

Generate a default boot snapshot (needed because of startup time), start the emulator once. 
Then copy the folder /root/.android/avd from the docker to the host and compress it. 
Result should be avd.tar.gz, which is needed by the Dockerfile.34

Build the docker

`docker build --file Dockerfile.34 -t emu34`

Afterwards start the emulator simply with:

`emulator @dev -cores 2 -memory 4096 -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -read-only`

#### Snapshot setup

Start emulator without snapshot:
`emulator @dev -no-window -no-audio -skip-adb-auth -no-boot-anim -show-kernel -no-snapshot-load`

`service list` may hang, kill the `android.hardware.bluetooth-service.default` process

then Ctrl^C and let the snapshot be saved then navigate to /root/.android/ and archive the avd folder: 

`tar cvfz avd.tar.gz avd/` copy the file from the docker then rebuild the docker

### emulator naming

determing by the two ports `-ports 5558,5559`  emulator will be named emulator-5558

### binderfuzz venv

Setup a virtual environment to install frida, frida-tools etc

## Building the emulator (Don't download ci shit)

Insructions: 
https://android.googlesource.com/platform/external/qemu/+/refs/heads/emu-34-release/android/docs/DEVELOPMENT.md

(DEBUG build check android/CmakeLists.txt to disable ASAN on DEBUG builds)

Afterwards tar the stuff in objs/distribution/emulator

```
cd objs/distribution && tar cvfz emulator_dist.tar.gz ./emulator
```

## Building the AOSP for emulator

checkout desired AOSP version (follow whichever guide, this was for FANS AOSP)

```
source build/envsetup.sh
lunch sdk_phone_arm64
make -jXX
make -jXX sdk sdk_repo
```

Resulting file should be at:
`should result in `out/host/linux-x86-64/sdk/sdk_phone_arm64/sdk-repo-linux-system-images-eng....zip`

## GDB on the emulator

To install gdb on the emulator I used the following setup: install termux and use the builtin package manager to install 
gdb. Then tar the entire `/data/data/com.termux` directory. Afterwards upload and unpack that directory on the emulator and 
include `/data/data/com.termux/files/usr/bin` in the PATH.

Link to the com.termux.tar.gz: `https://drive.google.com/file/d/1LtVXxOpZwxxEYmhOzn40mRkIGzPkrbUt/view?usp=sharing`
