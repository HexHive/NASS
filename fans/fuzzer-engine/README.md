# FANS fuzzer-engine (with & without coverage)

this folder contains the fans fuzzer-engine with and without support for collecting coverage

## Compiling

Need to have compiled the AOSP for the phone already, see the fans_analysis folder.

``` 
$AOSP = <path to aosp dir>
rm -rf "$AOSP/frameworks/native/cmds/native-service-fuzzer"
cp -r <fuzzer|fuzzer-coverage> "$AOSP/frameworks/native/cmds/native-service-fuzzer"
cd $AOSP
source build/envsetup.sh
lunch sdk_phone_arm64-userdebug
cd frameworks/native/cmds/native-service-fuzzer
mm
``` 

### fuzzer-coverage-novarmap

A version of fans that does not use Fans's manual variable->semantic mapping
