#!/bin/bash
source build/envsetup.sh
lunch sdk_phone_arm64-userdebug
rm -rf frameworks/native/cmds/native-service-fuzzer
cp -r /tmp/fuzzer-engine/fuzzer-coverage-novarmap  frameworks/native/cmds/native-service-fuzzer
cd frameworks/native/cmds/native-service-fuzzer
mm
