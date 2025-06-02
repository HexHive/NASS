help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

NDK_BASE ?= ~/Android/Sdk/ndk/26.1.10909125/
NDK_PATH = $(NDK_BASE)/toolchains/llvm/prebuilt/linux-x86_64/bin

CFLAGS = -g3 -O0 -I. -Wall -Wextra -fno-rtti -static-libstdc++

clean: ## cleanup all build artifacts 
	rm -rf ../../device/4bd1d32/secheck
	rm -rf ../../device/emulator-5554/secheck
	rm -rf ../../device/R58N349B0BL/secheck
	rm -rf ../../device/bai7gujvtchqeaus/secheck
	rm -rf ../../device/a497c295/secheck
	rm -rf ../../device/3C161FDJHS0651/secheck


.PHONY: 4bd1d32 bai7gujvtchqeaus emulator-5554 R58N349B0BL a497c295 3C161FDJHS0651 RZCX312P76A 47030DLAQ0012N R58Y105KVBA

R58N349AKNY: DEVICE=R58N349AKNY
R58N349AKNY: CXX=$(NDK_PATH)/aarch64-linux-android30-clang++ ## compile for R58N349AKNY (Samsung S10)
R58Y105KVBA: DEVICE=R58Y105KVBA
R58Y105KVBA: CXX=$(NDK_PATH)/aarch64-linux-android34-clang++ ## compile for R58Y105KVBA (Samsung A16)
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
RKXK7HDIRWGMDYWO: DEVICE=RKXK7HDIRWGMDYWO
RKXK7HDIRWGMDYWO: CXX=$(NDK_PATH)/aarch64-linux-android30-clang++ ## compile for RKXK7HDIRWGMDYWO (Xiaomi Note 11) 
47030DLAQ0012N: DEVICE=47030DLAQ0012N
47030DLAQ0012N: CXX=$(NDK_PATH)/aarch64-linux-android35-clang++ ## compile for 47030DLAQ0012N (Google Pixel 9)

OUT = ../../device/$(DEVICE)/
LIBS=../../device/$(DEVICE)/lib/libselinux.so
SECHECK = $(OUT)/secheck

$(SECHECK): secheck.cc
	mkdir -p $(OUT)
	$(CXX) $(CFLAGS) secheck.cc -o $(OUT)/secheck $(LIBS)

R58N349AKNY: $(SECHECK)
R58Y105KVBA: $(SECHECK)
bai7gujvtchqeaus: $(SECHECK) 
4bd1d32: $(SECHECK)  
emulator-5554: $(SECHECK)  
R58N349B0BL: $(SECHECK)  
a497c295: $(SECHECK)  
3C161FDJHS0651: $(SECHECK)  
47030DLAQ0012N: $(SECHECK)  
RZCX312P76A: $(SECHECK)  
089092526K000893: $(SECHECK)   
109443739F105084: $(SECHECK)   
RKXK7HDIRWGMDYWO: $(SECHECK)
