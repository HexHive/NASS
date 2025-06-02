#!/bin/sh
LIBFUZZER_SRC_DIR=$(dirname $0)
CXX="${CXX:-clang}"
if [ -z "${ASAN}" ]; then
    CFLAGS="-g -O2 -fno-omit-frame-pointer -std=c++17"
else
    CFLAGS="-ggdb -O3 -fsanitize=address -fno-omit-frame-pointer -std=c++17"
fi
if [ -z "${DEBUG}" ]; then
    CFLAGS="-g -O2 -fno-omit-frame-pointer -std=c++17"
else
    CFLAGS="-ggdb -O3 -fno-omit-frame-pointer -std=c++17"
fi
echo $CFLAGS
for f in $LIBFUZZER_SRC_DIR/*.cpp; do
  $CXX $CFLAGS $f -c &
done
wait
rm -f libFuzzer.a
ar r libFuzzer.a Fuzzer*.o
rm -f Fuzzer*.o

