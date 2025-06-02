help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

NDK_BASE ?= ~/Android/Sdk/ndk/26.1.10909125/
NDK_PATH = $(NDK_BASE)/toolchains/llvm/prebuilt/linux-x86_64/bin

CFLAGS := -g3 -O0 -Iinclude -Wall -Wextra -fno-rtti -static-libstdc++
CFLAGSSO := -fPIC -shared -g3 -O0 -Iinclude -Wall -Wextra -static-libstdc++ 

clean: ## cleanup all build artifacts 
	rm -rf ../device/4bd1d32/example_service
	rm -rf ../device/emulator-5554/example_service
	rm -rf ../device/R58N349B0BL/example_service
	rm -rf ../device/bai7gujvtchqeaus/example_service
	rm -rf ../device/a497c295/example_service
	rm -rf ../device/3C161FDJHS0651/example_service
	rm -rf ../device/710KPZK0476701/example_service


.PHONY: 4bd1d32 bai7gujvtchqeaus emulator-5554 R58N349B0BL a497c295 3C161FDJHS0651 RZCX312P76A 710KPZK0476701 712KPBF1235565 47030DLAQ0012N RKXK7HDIRWGMDYWO

RKXK7HDIRWGMDYWO: DEVICE=RKXK7HDIRWGMDYWO
RKXK7HDIRWGMDYWO: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for RKXK7HDIRWGMDYWO (Redmi Note 11)
bai7gujvtchqeaus: DEVICE=bai7gujvtchqeaus
bai7gujvtchqeaus: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for bai7gujvtchqeaus (Xm Redmi Note 13 5G)
4bd1d32: DEVICE=4bd1d32
4bd1d32: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for 4bd1d32 (Xm Redmi Note 11)
emulator-5554: DEVICE=emulator-5554
emulator-5554: CXX=$(NDK_PATH)/x86_64-linux-android34-clang++ ## compile for Android 14 emulator (x86_64)
R58N349B0BL: DEVICE=R58N349B0BL
R58N349B0BL: CXX=$(NDK_PATH)/aarch64-linux-android31-clang++ ## compile for R58N349B0BL (Samsung S10)
a497c295: DEVICE=a497c295
a497c295: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for a497c295 (OnePlus 12R)
3C161FDJHS0651: DEVICE=3C161FDJHS0651
3C161FDJHS0651: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for 3C161FDJHS0651 (Google Pixel 8)
RZCX312P76A: DEVICE=RZCX312P76A
RZCX312P76A: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for RZCX312P76A (Samsung S23)
089092526K000893: DEVICE=089092526K000893
089092526K000893: CXX=$(NDK_PATH)/aarch64-linux-android31-clang++ ## compile for 089092526K000893 (Infinix Note 12)
109443739F105084: DEVICE=109443739F105084
109443739F105084: CXX=$(NDK_PATH)/aarch64-linux-android33-clang++ ## compile for 109443739F105084 (Pova Pro 5)
710KPZK0476701: DEVICE:=710KPZK0476701
710KPZK0476701: CXX=$(NDK_PATH)/aarch64-linux-android28-clang++ ## compile for 710KPZK0476701 (Pixel 2 XL)
712KPBF1235565: DEVICE:=712KPBF1235565
712KPBF1235565: CXX=$(NDK_PATH)/aarch64-linux-android28-clang++ ## compile for 712KPBF1235565 (Pixel 2 XL)
47030DLAQ0012N: DEVICE=47030DLAQ0012N
47030DLAQ0012N: CXX=$(NDK_PATH)/aarch64-linux-android35-clang++ ## compile for Pixel 9

OUT = ../device/$(DEVICE)/example_service/
LIBS=../device/$(DEVICE)/lib/liblog.so ../device/$(DEVICE)/lib/libbinder.so ../device/$(DEVICE)/lib/libcutils.so ../device/$(DEVICE)/lib/libutils.so
HWLIBS=$(LIBS) ../device/$(DEVICE)/lib/libhidlbase.so #../device/$(DEVICE)/lib/libhwbinder.so
EXTRA_LIB = $(OUT)/extra_lib.so
CLIENT = $(OUT)/client
SERVICE = $(OUT)/service
HWCLIENT = $(OUT)/hwclient

$(EXTRA_LIB): extra_lib.cc
	mkdir -p $(OUT)
	$(CXX) $(CFLAGSSO) -DD$(DEVICE) extra_lib.cc -o $(OUT)/extra_lib.so $(LIBS)

$(CLIENT): client.cc
	mkdir -p $(OUT)
	$(CXX) $(CFLAGS) -DD$(DEVICE) client.cc -o $(OUT)/client $(LIBS)

$(SERVICE): service.cc
	mkdir -p $(OUT)
	$(CXX) $(CFLAGS) -DD$(DEVICE) -L$(OUT) -Wl,-rpath,'.' -Wl,-rpath,'/data/local/tmp' service.cc -o $(OUT)/service -l:extra_lib.so $(LIBS) 

$(HWCLIENT): hwclient.cc
	mkdir -p $(OUT)
	$(CXX) $(CFLAGS) -DD$(DEVICE) hwclient.cc -o $(OUT)/hwclient $(HWLIBS) 


RKXK7HDIRWGMDYWO: $(EXTRA_LIB) $(CLIENT) $(SERVICE) $(HWCLIENT)
bai7gujvtchqeaus: $(EXTRA_LIB) $(CLIENT) $(SERVICE) 
4bd1d32: $(EXTRA_LIB) $(CLIENT) $(SERVICE)  
emulator-5554: $(EXTRA_LIB) $(CLIENT) $(SERVICE) 
R58N349B0BL: $(EXTRA_LIB) $(CLIENT) $(SERVICE) 
a497c295: $(EXTRA_LIB) $(CLIENT) $(SERVICE) 
3C161FDJHS0651: $(EXTRA_LIB) $(CLIENT) $(SERVICE) 
47030DLAQ0012N: $(EXTRA_LIB) $(CLIENT) $(SERVICE) $(HWCLIENT)
RZCX312P76A: $(EXTRA_LIB) $(CLIENT) $(SERVICE)  $(HWCLIENT)
089092526K000893: $(EXTRA_LIB) $(CLIENT) $(SERVICE)  
109443739F105084: $(EXTRA_LIB) $(CLIENT) $(SERVICE) $(HWCLIENT)

710KPZK0476701: extra_lib.cc client.cc service.cc
	$(info FOR 710KPZK0476701 MAKE SURE TO USE NDK version 21... OTHERWISE IT WILL NOT COMPILE!!!!!)
	mkdir -p $(OUT)
	$(CXX) -fPIC -shared -g3 -O0 -Iinclude_android9 -Wall -Wextra -static-libstdc++ -DANDROID9 -DD$(DEVICE) extra_lib.cc -o $(OUT)/extra_lib.so $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so
	$(CXX) -g3 -O0 -Iinclude_android9 -Wall -Wextra -fno-rtti -static-libstdc++ -DANDROID9 -DD$(DEVICE) client.cc -o $(OUT)/client $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so
	$(CXX) -g3 -O0 -Iinclude_android9 -Wall -Wextra -fno-rtti -static-libstdc++ -DANDROID9 -DD$(DEVICE) -L$(OUT) -Wl,-rpath,'/data/local/tmp' service.cc -o $(OUT)/service -l:extra_lib.so $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so
	$(CXX) -g3 -O0 -Iinclude_android9 -Wall -Wextra -fno-rtti -static-libstdc++ -DANDROID9 -DD$(DEVICE) -L$(OUT) dumpsys_diy.cc -o $(OUT)/../dumpsys $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so

712KPBF1235565: extra_lib.cc client.cc service.cc
	$(info FOR 712KPBF1235565 MAKE SURE TO USE NDK version 21... OTHERWISE IT WILL NOT COMPILE!!!!!)
	mkdir -p $(OUT)
	$(CXX) -fPIC -shared -g3 -O0 -Iinclude_android9 -Wall -Wextra -static-libstdc++ -DANDROID9 -DD$(DEVICE) extra_lib.cc -o $(OUT)/extra_lib.so $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so
	$(CXX) -g3 -O0 -Iinclude_android9 -Wall -Wextra -fno-rtti -static-libstdc++ -DANDROID9 -DD$(DEVICE) client.cc -o $(OUT)/client $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so
	$(CXX) -g3 -O0 -Iinclude_android9 -Wall -Wextra -fno-rtti -static-libstdc++ -DANDROID9 -DD$(DEVICE) -L$(OUT) -Wl,-rpath,'/data/local/tmp' service.cc -o $(OUT)/service -l:extra_lib.so $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so
	$(CXX) -g3 -O0 -Iinclude_android9 -Wall -Wextra -fno-rtti -static-libstdc++ -DANDROID9 -DD$(DEVICE) -L$(OUT) dumpsys_diy.cc -o $(OUT)/../dumpsys $(LIBS) ../device/$(DEVICE)/lib/libc++.so ../device/$(DEVICE)/lib/libbase.so ../device/$(DEVICE)/lib/libutilscallstack.so ../device/$(DEVICE)/lib/libvndksupport.so ../device/$(DEVICE)/lib/libbacktrace.so ../device/$(DEVICE)/lib/libunwind.so ../device/$(DEVICE)/lib/libdexfile.so  ../device/$(DEVICE)/lib/libunwindstack.so ../device/$(DEVICE)/lib/libz.so ../device/$(DEVICE)/lib/liblzma.so

