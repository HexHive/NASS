help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

INCLUDES = -I ../binderlib/include \
		   -I include 

NDK_BASE ?= ~/Android/Sdk/ndk/26.1.10909125/
NDK_PATH = $(NDK_BASE)/toolchains/llvm/prebuilt/linux-x86_64/bin

ifndef ASAN
	CFLAGS1 = $(INCLUDES) -fno-rtti -Wall 
else
	CFLAGS1 = $(INCLUDES) -fno-rtti -Wall -fsanitize=address 
endif	

ifdef DEBUG
	CFLAGS = $(CFLAGS1) -ggdb -O0
else
	CFLAGS = $(CFLAGS1) -O2
endif

clean: ## cleanup all build artifacts 
	rm -rf ../device/libfuzz 
	rm -rf ../device/fuzzer_build
	rm -rf ../device/4bd1d32/fuzzer_build ../device/4bd1d32/libfuzz ../device/4bd1d32/fuzzer ../device/4bd1d32/seedinfo
	rm -rf ../device/bai7gujvtchqeaus/fuzzer_build ../device/bai7gujvtchqeaus/libfuzz ../device/bai7gujvtchqeaus/fuzzer ../device/bai7gujvtchqeaus/seedinfo
	rm -rf ../device/emulator-5554/fuzzer_build ../device/emulator-5554/libfuzz ../device/emulator-5554/fuzzer ../device/emulator-5554/seedinfo
	rm -rf ../device/R58N349B0BL/fuzzer_build ../device/R58N349B0BL/libfuzz ../device/R58N349B0BL/fuzzer ../device/R58N349B0BL/seedinfo
	rm -rf ../device/3C161FDJHS0651/fuzzer_build ../device/3C161FDJHS0651/libfuzz ../device/3C161FDJHS0651/fuzzer ../device/3C161FDJHS0651/seedinfo

.PHONY: 4bd1d32 bai7gujvtchqeaus emulator-5554 R58N349B0BL a497c295 3C161FDJHS0651 109443739F105084 089092526K000893 fuzzparcel 47030DLAQ0012N 712KPBF1235565 710KPZK0476701 ONFYMRTKROLBRSHA aarch64_emu_28 48161FDJHS0DQ0 R58Y105KVBA

R58Y105KVBA: DEVICE=R58Y105KVBA
R58Y105KVBA: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for R58Y105KVBA (Samsung A16)
4bd1d32: DEVICE=4bd1d32
4bd1d32: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for 4bd1d32 (OnePlus 12R)
bai7gujvtchqeaus: DEVICE=bai7gujvtchqeaus
bai7gujvtchqeaus: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for bai7gujvtchqeaus (Xm Redmi Note 13 5G) 
emulator-5554: DEVICE=emulator-5554
emulator-5554: CXX=$(NDK_PATH)/x86_64-linux-android34-clang++ ## compile for Android 14 emulator (x86_64)
R58N349B0BL: DEVICE=R58N349B0BL
R58N349B0BL: CXX=$(NDK_PATH)/aarch64-linux-android31-clang++ ## compile for R58N349B0BL (Samsung S10)
a497c295: DEVICE=a497c295
a497c295: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for a497c295 (OnePlus 12R)
3C161FDJHS0651: DEVICE=3C161FDJHS0651
3C161FDJHS0651: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for 3C161FDJHS0651 (Google Pixel 8)
48161FDJHS0DQ0: DEVICE=48161FDJHS0DQ0
48161FDJHS0DQ0: CXX=$(NDK_PATH)/aarch64-linux-android35-clang++ ## compile for 48161FDJHS0DQ0 (Google Pixel 8)
47030DLAQ0012N: DEVICE=47030DLAQ0012N
47030DLAQ0012N: CXX=$(NDK_PATH)/aarch64-linux-android35-clang++ ## compile for 47030DLAQ0012N (Google Pixel 9)
RZCX312P76A: DEVICE=RZCX312P76A
RZCX312P76A: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for RZCX312P76A (Samsung S23)
089092526K000893: DEVICE=089092526K000893
089092526K000893: CXX=$(NDK_PATH)/aarch64-linux-android31-clang++ ## compile for 089092526K000893 (Infinix Note 12)
109443739F105084: DEVICE=109443739F105084
109443739F105084: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for 109443739F105084 (Pova Pro 5)
RKXK7HDIRWGMDYWO: DEVICE=RKXK7HDIRWGMDYWO
RKXK7HDIRWGMDYWO: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for RKXK7HDIRWGMDYWO (Redmi Note 11)
ONFYMRTKROLBRSHA: DEVICE=ONFYMRTKROLBRSHA
ONFYMRTKROLBRSHA: CXX=$(NDK_PATH)/aarch64-linux-android30-clang++ ## compile for ONFYMRTKROLBRSHA (Redmi Note 12s)
710KPZK0476701: DEVICE:=710KPZK0476701
710KPZK0476701: CXX=$(NDK_PATH)/aarch64-linux-android28-clang++ ## compile for 710KPZK0476701 (Pixel 2 XL)
710KPZK0476701: CFLAGS = -DANDROID9 -O2 -fno-rtti -Wall -I ../binderlib/include_android9 -Iinclude -I../binderlib/
712KPBF1235565: DEVICE:=712KPBF1235565
712KPBF1235565: CXX=$(NDK_PATH)/aarch64-linux-android28-clang++ ## compile for 712KPBF1235565 (Pixel 2 XL)
712KPBF1235565: CFLAGS = -DANDROID9 -O2 -fno-rtti -Wall -I ../binderlib/include_android9 -Iinclude -I../binderlib/
aarch64emu28: DEVICE:=aarch64emu28
aarch64emu28: CXX=$(NDK_PATH)/aarch64-linux-android28-clang++ ## compile for aarch64 emulator Android 11 
aarch64emu28: CFLAGS = -DANDROID9 -O2 -fno-rtti -Wall -I ../binderlib/include_android9 -Iinclude -I../binderlib/
aarch64emu34: DEVICE:=aarch64emu34
aarch64emu34: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for aarch64 emulator Android 14


fuzzparcel: fuzzparcel.cc fuzzparcel.h ## compile fuzzparcel as a shared library
	g++ -shared -std=c++17 -fPIC -DLOCALLIB=1 -o ./fuzzparcel_lib/fuzzparcel.so fuzzparcel.cc

FUZZER = ../device/$(DEVICE)/fuzzer
REPLAY = ../device/$(DEVICE)/replay
SEEDINFO = ../device/$(DEVICE)/seedinfo
BUILD_DIR = ../device/$(DEVICE)/fuzzer_build
LIBS=../device/$(DEVICE)/lib/liblog.so ../device/$(DEVICE)/lib/libbinder.so ../device/$(DEVICE)/lib/libcutils.so ../device/$(DEVICE)/lib/libutils.so

$(BUILD_DIR)/%.o: %.cc
	mkdir -p $(BUILD_DIR)
	$(CXX) $(CFLAGS) -D_$(DEVICE) $< -c -o $(BUILD_DIR)/$(@F)

../device/$(DEVICE)/libfuzz/libFuzzer.a: $(wildcard libfuzzer/*)
	mkdir -p ../device/$(DEVICE)/libfuzz
	cd libfuzzer && CXX=$(CXX) DEBUG=$(DEBUG) ASAN=$(ASAN) ./build.sh && cd ..
	mv libfuzzer/libFuzzer.a ../device/$(DEVICE)/libfuzz/

$(FUZZER): $(BUILD_DIR)/fuzzer.o $(BUILD_DIR)/fuzzparcel.o ../device/$(DEVICE)/libfuzz/libFuzzer.a
	$(CXX) $(CFLAGS) -static-libstdc++ -D_$(DEVICE) $(BUILD_DIR)/fuzzer.o $(BUILD_DIR)/fuzzparcel.o ../device/$(DEVICE)/libfuzz/libFuzzer.a -o $(FUZZER) $(LIBS)

$(REPLAY): ../device/$(DEVICE)/libfuzz/libFuzzer.a
	$(CXX) $(CFLAGS) -DREPLAYONLY -D_$(DEVICE) fuzzer.cc -c -o $(BUILD_DIR)/fuzzer_replay.o
	$(CXX) $(CFLAGS) -DREPLAYONLY -D_$(DEVICE) fuzzparcel.cc -c -o $(BUILD_DIR)/fuzzparcel_replay.o
	$(CXX) $(CFLAGS) -DREPLAYONLY -static-libstdc++ -D_$(DEVICE) $(BUILD_DIR)/fuzzer_replay.o $(BUILD_DIR)/fuzzparcel_replay.o ../device/$(DEVICE)/libfuzz/libFuzzer.a -o $(REPLAY) $(LIBS)

$(SEEDINFO): $(BUILD_DIR)/seedinfo.o $(BUILD_DIR)/fuzzparcel.o 
	$(CXX) $(CFLAGS) -static-libstdc++ -D_$(DEVICE) $(BUILD_DIR)/seedinfo.o $(BUILD_DIR)/fuzzparcel.o -o $(SEEDINFO) $(LIBS)

R58Y105KVBA: $(FUZZER) $(SEEDINFO) $(REPLAY)
4bd1d32: $(FUZZER) $(SEEDINFO) $(REPLAY)
bai7gujvtchqeaus: $(FUZZER) $(SEEDINFO) $(REPLAY)
emulator-5554: $(FUZZER) $(SEEDINFO) $(REPLAY)
R58N349B0BL: $(FUZZER) $(SEEDINFO) $(REPLAY)
a497c295: $(FUZZER) $(SEEDINFO) $(REPLAY)
3C161FDJHS0651: $(FUZZER) $(SEEDINFO) $(REPLAY)
47030DLAQ0012N: $(FUZZER) $(SEEDINFO) $(REPLAY)
RZCX312P76A: $(FUZZER) $(SEEDINFO) $(REPLAY)
089092526K000893: $(FUZZER) $(SEEDINFO) $(REPLAY)
109443739F105084: $(FUZZER) $(SEEDINFO) $(REPLAY)
RKXK7HDIRWGMDYWO: $(FUZZER) $(SEEDINFO) $(REPLAY)
ONFYMRTKROLBRSHA: $(FUZZER) $(SEEDINFO) $(REPLAY)
aarch64emu34: $(FUZZER) $(SEEDINFO) $(REPLAY)
48161FDJHS0DQ0: $(FUZZER) $(SEEDINFO) $(REPLAY)

710KPZK0476701: LIBS= ../device/$(DEVICE)/lib/liblog.so ../device/$(DEVICE)/lib/libbinder.so ../device/$(DEVICE)/lib/libcutils.so ../device/$(DEVICE)/lib/libutils.so ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so 
710KPZK0476701: $(FUZZER) $(SEEDINFO) $(REPLAY) 

712KPBF1235565: LIBS= ../device/$(DEVICE)/lib/liblog.so ../device/$(DEVICE)/lib/libbinder.so ../device/$(DEVICE)/lib/libcutils.so ../device/$(DEVICE)/lib/libutils.so ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so 
712KPBF1235565: $(FUZZER) $(SEEDINFO) $(REPLAY) 

aarch64emu28: LIBS= ../device/$(DEVICE)/lib/liblog.so ../device/$(DEVICE)/lib/libbinder.so ../device/$(DEVICE)/lib/libcutils.so ../device/$(DEVICE)/lib/libutils.so ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so 
aarch64emu28: $(FUZZER) $(SEEDINFO) $(REPLAY)
