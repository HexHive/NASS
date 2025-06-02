help: ## Show this help
	@grep -E -h '\s##\s' $(MAKEFILE_LIST) | sort | \
        awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'


REMOTE ?= root@hexhive014.iccluster.epfl.ch
AOSP_PATH ?= /root/aosp_asan/

.PHONY: original coverage coverage-novarmap

coverage: ## compile the original fans fuzzer
	rsync -aP fuzzer-engine -e ssh $(REMOTE):/tmp/
	ssh $(REMOTE) "cp /tmp/fuzzer-engine/compile_coverage.sh $(AOSP_PATH)"
	ssh $(REMOTE) "cd $(AOSP_PATH) && chmod +x ./compile_coverage.sh && ./compile_coverage.sh"
	scp $(REMOTE):$(AOSP_PATH)/out/target/product/generic_arm64/system/bin/native_service_fuzzer ./native_service_fuzzer_coverage
	scp $(REMOTE):$(AOSP_PATH)/out/target/product/generic_arm64/symbols/system/bin/native_service_fuzzer ./native_service_fuzzer_coverage_debug

original: ## compile the fans fuzzer with coverage
	rsync -aP fuzzer-engine -e ssh $(REMOTE):/tmp/
	ssh $(REMOTE) "cp /tmp/fuzzer-engine/compile_original.sh $(AOSP_PATH)"
	ssh $(REMOTE) "cd $(AOSP_PATH) && chmod +x ./compile_original.sh && ./compile_original.sh"
	scp $(REMOTE):$(AOSP_PATH)/out/target/product/generic_arm64/symbols/system/bin/native_service_fuzzer ./native_service_fuzzer_debug
	scp $(REMOTE):$(AOSP_PATH)/out/target/product/generic_arm64/system/bin/native_service_fuzzer ./native_service_fuzzer

coverage-novarmap: ## compile the fans fuzzer with coverage but without variable name mapping
	rsync -aP fuzzer-engine -e ssh $(REMOTE):/tmp/
	ssh $(REMOTE) "cp /tmp/fuzzer-engine/compile_coverage_novarmap.sh $(AOSP_PATH)"
	ssh $(REMOTE) "cd $(AOSP_PATH) && chmod +x ./compile_coverage_novarmap.sh && ./compile_coverage_novarmap.sh"
	scp $(REMOTE):$(AOSP_PATH)/out/target/product/generic_arm64/symbols/system/bin/native_service_fuzzer ./native_service_fuzzer_coverage_novarmap_debug
	scp $(REMOTE):$(AOSP_PATH)/out/target/product/generic_arm64/system/bin/native_service_fuzzer ./native_service_fuzzer_coverage_novarmap


all: $(original) $(coverage) ## compile both the original and coverage-modified fuzzer
	
