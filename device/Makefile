help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.PHONY: 4bd1d32 bai7gujvtchqeaus emulator-5554 710KPZK0476701 R58N349B0BL a497c295 3C161FDJHS0651 RZCX312P76A 089092526K000893 109443739F105084 download aarch64emu28 aarch64emu34 48161FDJHS0DQ0 RKXK7HDIRWGMDYWO

bai7gujvtchqeaus: DEVICE=bai7gujvtchqeaus
R58Y105KVBA: DEVICE=R58Y105KVBA
RZCX312P76A: DEVICE=RZCX312P76A
089092526K000893: DEVICE=089092526K000893
109443739F105084: DEVICE=109443739F105084
3C161FDJHS0651: DEVICE=3C161FDJHS0651
48161FDJHS0DQ0: DEVICE=48161FDJHS0DQ0
47030DLAQ0012N: DEVICE=47030DLAQ0012N
a497c295: DEVICE=a497c295
RKXK7HDIRWGMDYWO: DEVICE=RKXK7HDIRWGMDYWO
emulator-5554: DEVICE=emulator-5554
710KPZK0476701: DEVICE=710KPZK0476701
712KPBF1235565: DEVICE=712KPBF1235565
R58N349AKNY: DEVICE=R58N349AKNY
aarch64emu28: DEVICE=emulator-5554
aarch64emu34: DEVICE=emulator-5554
.PHONY: $(DEVICE)

download:
	mkdir -p $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/liblog.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libbinder.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libhidlbase.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libfmq.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libcutils.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libutils.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libselinux.so $(DEVICE)/lib/
	#adb -s $(DEVICE) pull /system/lib64/libhwbinder.so $(DEVICE)/lib/

R58N349AKNY: download ## download libraries for R58N349AKNY (Samsung S10)
R58Y105KVBA: download ## download libraries for R58Y105KVBA (Samsung A16)
RZCX312P76A: download ## download libraries for RZCX312P76A (Samsung S23)
4bd1d32: download 
bai7gujvtchqeaus: download ## download libraries for xiaomi redmit note 13 5G
emulator-5554: download ## donwload for emulator
a497c295: download ## download for oneplus 12r
3C161FDJHS0651: download ## donwload librarie for Pixel 8 
47030DLAQ0012N: download ## donwload librarie for Pixel 9
089092526K000893: download ## download libraries for 089092526K000893 (Infinix Note 12)
109443739F105084: download ## download librarief for 109443739F105084 (Pova Pro 5)
RKXK7HDIRWGMDYWO: download ## download libraries for RKXK7HDIRWGMDYWO (xiaomi redmi note 11)
48161FDJHS0DQ0: download ## download for 48161FDJHS0DQ0 (Pixel 8)
710KPZK0476701: download ## download libraries for 710KPZK0476701 (Pixel 2 XL)
710KPZK0476701: 
	mkdir -p $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libc++.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libbase.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libutilscallstack.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libvndksupport.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libbacktrace.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libdexfile.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libunwindstack.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libunwind.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libz.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/liblzma.so $(DEVICE)/lib/
712KPBF1235565: download ## libraries for 712KPBF1235565 (Pixel 2 XL)
	mkdir -p $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libc++.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libbase.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libutilscallstack.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libvndksupport.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libbacktrace.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libdexfile.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libunwindstack.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libunwind.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/libz.so $(DEVICE)/lib/
	adb -s $(DEVICE) pull /system/lib64/liblzma.so $(DEVICE)/lib/
aarch64emu28: ## libraries for aarch64 emulator API LVL 28 
	mkdir -p aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/liblog.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libbinder.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libcutils.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libutils.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libselinux.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libc++.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libbase.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libutilscallstack.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libvndksupport.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libbacktrace.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libdexfile.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libunwindstack.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libunwind.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/libz.so aarch64emu28/lib/
	adb -s $(DEVICE) pull /system/lib64/liblzma.so aarch64emu28/lib/
aarch64emu34: ## download libraries for aarch64 emulator Android 14
	mkdir -p aarch64emu34/lib/	
	adb -s $(DEVICE) pull /system/lib64/liblog.so aarch64emu34/lib/
	adb -s $(DEVICE) pull /system/lib64/libbinder.so aarch64emu34/lib/
	adb -s $(DEVICE) pull /system/lib64/libcutils.so aarch64emu34/lib/
	adb -s $(DEVICE) pull /system/lib64/libutils.so aarch64emu34/lib/
	adb -s $(DEVICE) pull /system/lib64/libselinux.so aarch64emu34/lib/



