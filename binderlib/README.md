# Binderlib

Build with Binder symbols out of AOSP tree.

Structure: 
```
include/       # AOSP 34(ish) header files
include_android9/      # Android 9 header files 
*cc *h        # source files for example system service and client
```

Compile an example service and client for a specific device:

`make [device_id]`

## Add new target

```
clean: 
+ rm -rf ../device/[device_id]/example_service
+ .PHONY ... [device_id]
+ [device_id]: DEVICE=[device_id]
+ [device_id]: CXX=$(NDK_PATH)/[isa]-linux-android[android_version]-clang++ ## ..
+ [device_id]: $(EXTRA_LIB) $(CLIENT) $(SERVICE) $(HWCLIENT)
```
