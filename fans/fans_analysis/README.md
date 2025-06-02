# FANS Analysis

*Running all the fans preprocessing for an Android API level 28 emulator (arm64)*

```
docker build . -t fans
```

```
git clone https://github.com/iromise/fans
cd fans
git apply ../fans.patch
```

running the docker for stuff that needs to be done in docker:

```
docker run -it -v $(path to aosp/..):/root -v .:/mnt fans /bin/bash
```

## 1. AOSP

checkout the aosp for FANS Android 9 version:

```
mkdir aosp_asan
cd aosp_asan
repo init --partial-clone -b android-9.0.0_r46 -u https://android.googlesource.com/platform/manifest
repo sync -c -jXX
```

Modify aosp build makefiles slightly to help with fuzzing:
```
# build/core/main.mk

# line 273
## before modifying
ifneq (,$(user_variant))
  # Target is secure in user builds.
  ADDITIONAL_DEFAULT_PROPERTIES += ro.secure=1
  ADDITIONAL_DEFAULT_PROPERTIES += security.perf_harden=1

  ifeq ($(user_variant),user)
    ADDITIONAL_DEFAULT_PROPERTIES += ro.adb.secure=1
  endif
## after modifying
ifneq (,$(user_variant))
  # Target is secure in user builds.
  ADDITIONAL_DEFAULT_PROPERTIES += ro.secure=1
  ADDITIONAL_DEFAULT_PROPERTIES += security.perf_harden=1

  ADDITIONAL_DEFAULT_PROPERTIES += ro.adb.secure=0
  ADDITIONAL_DEFAULT_PROPERTIES += persist.sys.disable_rescue=1

  #ifeq ($(user_variant),user)
  #  ADDITIONAL_DEFAULT_PROPERTIES += ro.adb.secure=1
  #endif

# build/make/target/product/core_minimal.mk

# line 170
## before modifying
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    tombstoned.max_tombstone_count=50
endif
## after modifying
ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    tombstoned.max_tombstone_count=99999
endif
```

build the relevant files:

```
source build/envsetup.sh
lunch sdk_phone_arm64-userdebug
make -jXX showcommands 2>&1 >cmd.txt
make -jXX
make -jXX sdk sdk_repo # for emulator image (need to run the emulator, not needed for fans analysis)
```

**Result**: cmd.txt file in aosp dir + userdebug build

## 2. LLVM-Plugin

Either rebuild the llvm plugin following the directions here: https://github.com/iromise/fans/tree/master/interface-model-extractor/pre-process#compile-clang-plugin-binderiface


Or download the a archive with everything from here: https://drive.google.com/drive/folders/1GxmB0pevlBxcca1bFdh5lbGyw0TDM8-c?usp=sharing

Important: the one from gdrive does not work in the docker
`ln -s <path to fans> /mnt/fans` to reuse fans.cfg


unpack the archive in the fans directory, the following file should exist: fans/llvm-android/build/lib/BinderIface.so

## 2. Fans config

Using the docker the fans.cfg in this directory should be fine, otherwise you'll need to update the paths accordingly.

```
cp fans.cfg fans/
```

## 3. Service related files (in docker)

```
cd /mnt/fans/service-related-file-collector
python collector.py
```

## 4. Interface Model Extractor (in docker)

```
mkdir /mnt/fans/workdir/interface-model-extractor
cd /mnt/fans/interface-model-extractor/pre-process
python gen_all_related_cc1_cmd.py
```

do the "MANUAL PATCHING" of the AOSP by using the pached_aosp_file folder

**THIS IS IMPORANT BECAUSE FANS CAN NOT HANDLE SWITCH STATEMENTS WITHOUT BRACKETS AND ALSO REWRITES? THE SURFACEFLINGER.CPP**
(this is in the github repo: https://github.com/iromise/fans/tree/master/interface-model-extractor/pre-process#deal-with-corner-cases

```
cd patched_aosp_files
./patch.sh /root/aosp_asan
```

```
cd /root/aosp_asan
ln -s /mnt/fans/workdir/service-related-file/misc_parcel_related_function.txt .
ln -s /mnt/fans/workdir/service-related-file/special_parcelable_function.txt .
```

Note that you might need to run the next step outside of docker if you've downloaded from gdrive

```
cd /mnt/fans/interface-model-extractor/pre-process
python extract_from_ast.py
```

```
cd /mnt/fans/interface-model-extractor/post-process
sh postprocess.sh
```

## 5. Infer Dependencies (in docker)

```
cd /mnt/fans/dependency-inferer
sh infer_dependency.sh
```

## 6. Grab Analysis Results

All of FANS data is now inside the workdir folder

Copy this folder to `binderfuzz/fans` directory 

